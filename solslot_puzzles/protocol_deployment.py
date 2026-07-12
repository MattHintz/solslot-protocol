"""Solslot Protocol v2 testnet deployment driver.

Given:
  - a faucet (BLS-keyed XCH wallet that pays for launchers)
  - 4 unspent faucet coins reserved for genesis/launcher spends
  - protocol parameters (quorum, voting window, PGT supply, min stake)

Produces:
  - a deterministic ``ProtocolDeploymentPlan`` capturing every launcher id,
    full puzzle hash, mod hash, and curry-derived hash needed to wire the
    protocol together.
  - a single signed ``SpendBundle`` that, when pushed to chain in one block,
    creates the entire protocol stack (PGT genesis + pool singleton + DID
    singleton + governance tracker singleton).

The deployment is designed to be **atomic at the bundle level**: either
all four coins commit together or none commit, eliminating the
chicken-and-egg problem where the tracker needs the DID's full puzhash
(which depends on the DID's launcher id) and the DID needs the tracker's
struct (which depends on the tracker's launcher id).

Resolution: launcher ids are deterministic from their parent coin ids
(see ``launcher_coin_for_parent``), so we compute all launcher ids
**before** the bundle is built — every curried puzzle hash is then
knowable up-front.

Deployment order (in one bundle):

    Cpgt    --> CREATE_COIN(CAT2_PGT_FULL_PH, 1_000_000)  + change
    Cpool   --> CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1)   + change
                  pool_launcher --> CREATE_COIN(POOL_FULL_PH, 1)
    Cdid    --> CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1)   + change
                  did_launcher  --> CREATE_COIN(DID_FULL_PH, 1)
    Cgov    --> CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1)   + change
                  gov_launcher  --> CREATE_COIN(TRACKER_FULL_PH, 1)

The PGT CAT2 coin uses standard genesis-by-coin-id issuance — the resulting
CAT coin's parent is Cpgt, and the curried PGT TAIL accepts that parent.
No separate launcher needed (CAT2 doesn't use the singleton launcher).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia.wallet.util.curry_and_treehash import (
    calculate_hash_of_quoted_mod_hash,
    curry_and_treehash,
)
from chia_rs import AugSchemeMPL, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.pgt_driver import (
    SINGLETON_LAUNCHER_HASH as PGT_SINGLETON_LAUNCHER_HASH,
    pgt_free_inner_mod,
    pgt_locked_inner_mod,
    pgt_tail_hash,
    pgt_tail_puzzle,
    proposal_tracker_inner_puzzle,
    proposal_tracker_mod,
)
from solslot_puzzles.collection_nav_registry_driver import collection_nav_registry_inner_mod_hash


# Sanity: the launcher hash constant must be identical across modules.
assert SINGLETON_LAUNCHER_HASH == PGT_SINGLETON_LAUNCHER_HASH, (
    "SINGLETON_LAUNCHER_HASH constant divergence — check pgt_driver vs chia"
)


# ─── Protocol constants (defaults; tunable per deployment) ──────────────────
DEFAULT_QUORUM_BPS = 5000              # 50%
DEFAULT_VOTING_WINDOW_SECONDS = 300    # 5 min
DEFAULT_PGT_TOTAL_SUPPLY = 1_000_000   # fixed 1M PGT
DEFAULT_MIN_PROPOSAL_STAKE = 10_000    # 1% of supply, anti-spam
DEFAULT_FP_SCALE = 1000                # pool token-to-par exchange rate scale
DEFAULT_MIN_NAV_REGISTRY_VERSION = 0   # deployment-governed NAV freshness floor
SINGLETON_AMOUNT = uint64(1)
DEFAULT_EMPTY_B32 = bytes32(b"\x00" * 32)
DEFAULT_EMPTY_GOV_PUBKEY = b"\x00" * 48
PROTOCOL_VERSION = "solslot-alpha-v2"
POOL_PUZZLE_VERSION = 3
SMART_DEED_PUZZLE_VERSION = 2


def _reject_empty_b32(value: bytes32, name: str) -> None:
    if value == DEFAULT_EMPTY_B32:
        raise ValueError(f"{name} must be configured before deployment")


def _reject_empty_gov_pubkey(value: bytes, name: str) -> None:
    if value == DEFAULT_EMPTY_GOV_PUBKEY:
        raise ValueError(f"{name} must be configured before deployment")


# ─── Lazy-loaded compiled puzzles ───────────────────────────────────────────
_POOL_INNER_MOD: Program | None = None
_POOL_TOKEN_TAIL_MOD: Program | None = None
_QUORUM_DID_MOD: Program | None = None


def _pool_inner_mod() -> Program:
    global _POOL_INNER_MOD
    if _POOL_INNER_MOD is None:
        _POOL_INNER_MOD = load_clvm(
            "pool_singleton_inner_v3.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _POOL_INNER_MOD


def _pool_token_tail_mod() -> Program:
    global _POOL_TOKEN_TAIL_MOD
    if _POOL_TOKEN_TAIL_MOD is None:
        _POOL_TOKEN_TAIL_MOD = load_clvm(
            "pool_token_tail.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _POOL_TOKEN_TAIL_MOD


def _quorum_did_mod() -> Program:
    global _QUORUM_DID_MOD
    if _QUORUM_DID_MOD is None:
        _QUORUM_DID_MOD = load_clvm(
            "quorum_did_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _QUORUM_DID_MOD


def _p2_vault_mod_hash() -> bytes32:
    p2_vault = load_clvm(
        "p2_vault.clsp", package_or_requirement="solslot_puzzles", recompile=True
    )
    return bytes32(p2_vault.get_tree_hash())


def _p2_pool_v2_mod_hash() -> bytes32:
    p2_pool = load_clvm(
        "p2_pool_v2.clsp", package_or_requirement="solslot_puzzles", recompile=True
    )
    return bytes32(p2_pool.get_tree_hash())


def _smart_deed_inner_v2_mod_hash() -> bytes32:
    smart_deed = load_clvm(
        "smart_deed_inner_v2.clsp",
        package_or_requirement="solslot_puzzles",
        recompile=True,
    )
    return bytes32(smart_deed.get_tree_hash())


# ─── Deterministic launcher-coin computation ────────────────────────────────
def launcher_coin_for_parent(parent_coin: Coin) -> Coin:
    """Compute the singleton launcher coin spawned from `parent_coin`.

    Mirrors the standard chia singleton launch pattern: the parent emits a
    CREATE_COIN at SINGLETON_LAUNCHER_HASH with amount 1, producing a
    deterministic launcher coin whose name is computable up-front.
    """
    return Coin(
        parent_coin_info=parent_coin.name(),
        puzzle_hash=SINGLETON_LAUNCHER_HASH,
        amount=SINGLETON_AMOUNT,
    )


def singleton_struct(launcher_id: bytes32) -> Program:
    """Build the standard chia singleton struct (mod_hash, (launcher_id, launcher_ph))."""
    return Program.to((SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH)))


def singleton_full_puzzle_hash(launcher_id: bytes32, inner_puzzle_hash: bytes32) -> bytes32:
    """Compute the singleton's full puzzle hash given its launcher id + inner ph."""
    return bytes32(
        curry_and_treehash(
            calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH),
            bytes32(singleton_struct(launcher_id).get_tree_hash()),
            inner_puzzle_hash,
        )
    )


# ─── Curry helpers for protocol singleton inners ────────────────────────────
def pool_token_tail_hash(pool_launcher_id: bytes32) -> bytes32:
    """Compute the pool-token CAT2 TAIL puzzle hash for a given pool launcher id."""
    curried = _pool_token_tail_mod().curry(
        SINGLETON_MOD_HASH,
        pool_launcher_id,
        SINGLETON_LAUNCHER_HASH,
    )
    return bytes32(curried.get_tree_hash())


def pool_inner_puzzle(
    pool_launcher_id: bytes32,
    protocol_did_full_puzhash: bytes32,
    governance_launcher_id: bytes32,
    *,
    nav_registry_mod_hash: bytes32 | None = None,
    nav_registry_gov_pubkey: bytes | None = None,
    nav_registry_launcher_id: bytes32 = DEFAULT_EMPTY_B32,
    min_nav_registry_version: int = DEFAULT_MIN_NAV_REGISTRY_VERSION,
    trusted_treasury_reserve_puzhash: bytes32 | None = None,
    trusted_protocol_treasury_puzhash: bytes32 | None = None,
    trusted_governance_rewards_puzhash: bytes32 | None = None,
    trusted_governance_rewards_root: bytes32 = DEFAULT_EMPTY_B32,
    fp_scale: int = DEFAULT_FP_SCALE,
    pool_status: int = 1,        # ACTIVE
    tvl: int = 0,
    deed_count: int = 0,
    total_pool_token_supply: int = 0,
    treasury_reserve_tokens: int = 0,
) -> Program:
    """Curry the pool singleton inner puzzle for the given deployment context."""
    _reject_empty_b32(governance_launcher_id, "governance_launcher_id")
    mod = _pool_inner_mod()
    mod_hash = mod.get_tree_hash()
    nav_registry_mod_hash = nav_registry_mod_hash or collection_nav_registry_inner_mod_hash()
    nav_registry_gov_pubkey = nav_registry_gov_pubkey or DEFAULT_EMPTY_GOV_PUBKEY
    if len(nav_registry_gov_pubkey) != 48:
        raise ValueError("nav_registry_gov_pubkey must be 48 bytes")
    if min_nav_registry_version < 0 or min_nav_registry_version >= 2**64:
        raise ValueError("min_nav_registry_version must be a uint64")
    trusted_treasury_reserve_puzhash = trusted_treasury_reserve_puzhash or protocol_did_full_puzhash
    trusted_protocol_treasury_puzhash = trusted_protocol_treasury_puzhash or protocol_did_full_puzhash
    trusted_governance_rewards_puzhash = trusted_governance_rewards_puzhash or protocol_did_full_puzhash
    return mod.curry(
        mod_hash,
        singleton_struct(pool_launcher_id),
        singleton_struct(governance_launcher_id),
        protocol_did_full_puzhash,
        pool_token_tail_hash(pool_launcher_id),
        CAT_MOD_HASH,
        OFFER_MOD_HASH,
        _p2_vault_mod_hash(),
        nav_registry_mod_hash,
        nav_registry_gov_pubkey,
        nav_registry_launcher_id,
        min_nav_registry_version,
        trusted_treasury_reserve_puzhash,
        trusted_protocol_treasury_puzhash,
        trusted_governance_rewards_puzhash,
        trusted_governance_rewards_root,
        fp_scale,
        pool_status,
        tvl,
        deed_count,
        total_pool_token_supply,
        treasury_reserve_tokens,
    )


def quorum_did_inner_puzzle(tracker_launcher_id: bytes32) -> Program:
    """Curry quorum_did_inner with the tracker singleton struct."""
    return _quorum_did_mod().curry(singleton_struct(tracker_launcher_id))


def pgt_free_inner_puzzle_for_owner(
    tracker_launcher_id: bytes32,
    owner_inner_puzhash: bytes32,
) -> Program:
    """Curry pgt_free_inner for a specific owner under the given tracker."""
    free_mod = pgt_free_inner_mod()
    free_mod_hash = bytes32(free_mod.get_tree_hash())
    locked_mod_hash = bytes32(pgt_locked_inner_mod().get_tree_hash())
    return free_mod.curry(
        free_mod_hash,
        locked_mod_hash,
        singleton_struct(tracker_launcher_id),
        owner_inner_puzhash,
    )


def cat2_puzzle_hash_for_pgt(
    tracker_launcher_id: bytes32,
    pgt_genesis_coin_id: bytes32,
    owner_inner_puzhash: bytes32,
) -> bytes32:
    """Compute the on-chain CAT2-wrapped PGT puzzle hash for a given owner.

    This is where 1M PGT lands on genesis: a CAT2 coin whose:
      - outer is curry(CAT_MOD, CAT_MOD_HASH, PGT_TAIL_HASH, INNER)
      - inner is pgt_free_inner curried with (mod_hash, locked_mod_hash,
        tracker_struct, owner_inner_puzhash)
    """
    from chia.wallet.cat_wallet.cat_utils import construct_cat_puzzle, CAT_MOD

    inner = pgt_free_inner_puzzle_for_owner(tracker_launcher_id, owner_inner_puzhash)
    cat_full = construct_cat_puzzle(
        CAT_MOD,
        pgt_tail_hash(pgt_genesis_coin_id),
        inner,
    )
    return bytes32(cat_full.get_tree_hash())


# ─── Deployment plan dataclass ──────────────────────────────────────────────
@dataclass
class ProtocolDeploymentParams:
    """Tunable protocol parameters set at deployment time."""

    quorum_bps: int = DEFAULT_QUORUM_BPS
    voting_window_seconds: int = DEFAULT_VOTING_WINDOW_SECONDS
    pgt_total_supply: int = DEFAULT_PGT_TOTAL_SUPPLY
    min_proposal_stake: int = DEFAULT_MIN_PROPOSAL_STAKE
    fp_scale: int = DEFAULT_FP_SCALE
    min_nav_registry_version: int = DEFAULT_MIN_NAV_REGISTRY_VERSION
    initial_pool_status: int = 1  # 1 = ACTIVE
    initial_total_pool_token_supply: int = 0
    initial_treasury_reserve_tokens: int = 0


@dataclass
class ProtocolDeploymentPlan:
    """All hashes / launcher IDs needed to wire the protocol together.

    Computed deterministically from 4 genesis coin ids and the deployment
    parameters.  Once a plan is built, the bundle that realises it is
    fully determined.
    """

    # ── Inputs (echoed for manifest persistence) ─────────────────────────
    network: str
    params: ProtocolDeploymentParams
    faucet_inner_puzhash: bytes32  # where PGT change / token treasury lands

    pgt_genesis_coin_id: bytes32   # name of Cpgt
    pool_genesis_coin_id: bytes32  # name of Cpool
    did_genesis_coin_id: bytes32   # name of Cdid
    gov_genesis_coin_id: bytes32   # name of Cgov

    # ── Trusted Pool Economic V2 wiring ─────────────────────────────────
    trusted_nav_registry_mod_hash: bytes32 = field(default_factory=collection_nav_registry_inner_mod_hash)
    trusted_nav_registry_gov_pubkey: bytes = DEFAULT_EMPTY_GOV_PUBKEY
    trusted_nav_registry_launcher_id: bytes32 = DEFAULT_EMPTY_B32
    trusted_treasury_reserve_puzhash: bytes32 | None = None
    trusted_protocol_treasury_puzhash: bytes32 | None = None
    trusted_governance_rewards_puzhash: bytes32 | None = None
    trusted_governance_rewards_root: bytes32 = DEFAULT_EMPTY_B32

    # ── Versioned deployment identity ────────────────────────────────────
    protocol_version: str = field(init=False, default=PROTOCOL_VERSION)
    pool_puzzle_version: int = field(init=False, default=POOL_PUZZLE_VERSION)
    smart_deed_puzzle_version: int = field(init=False, default=SMART_DEED_PUZZLE_VERSION)

    # ── Derived launcher IDs ──────────────────────────────────────────────
    pool_launcher_id: bytes32 = field(init=False)
    did_launcher_id: bytes32 = field(init=False)
    tracker_launcher_id: bytes32 = field(init=False)

    # ── Derived puzzle hashes ─────────────────────────────────────────────
    pgt_tail_hash: bytes32 = field(init=False)
    pgt_full_puzhash: bytes32 = field(init=False)        # CAT2(PGT) coin's puzhash

    pool_token_tail_hash: bytes32 = field(init=False)
    pool_inner_mod_hash: bytes32 = field(init=False)
    p2_pool_mod_hash: bytes32 = field(init=False)
    smart_deed_inner_mod_hash: bytes32 = field(init=False)
    governance_singleton_struct_hash: bytes32 = field(init=False)
    pool_inner_puzhash: bytes32 = field(init=False)
    pool_full_puzhash: bytes32 = field(init=False)

    did_inner_puzhash: bytes32 = field(init=False)
    did_full_puzhash: bytes32 = field(init=False)

    tracker_inner_puzhash: bytes32 = field(init=False)
    tracker_full_puzhash: bytes32 = field(init=False)

    def __post_init__(self) -> None:
        # Step 1: launcher ids deterministic from parent coin names
        if len(self.trusted_nav_registry_gov_pubkey) != 48:
            raise ValueError("trusted_nav_registry_gov_pubkey must be 48 bytes")
        if self.trusted_treasury_reserve_puzhash is None:
            self.trusted_treasury_reserve_puzhash = self.faucet_inner_puzhash
        if self.trusted_protocol_treasury_puzhash is None:
            self.trusted_protocol_treasury_puzhash = self.faucet_inner_puzhash
        if self.trusted_governance_rewards_puzhash is None:
            self.trusted_governance_rewards_puzhash = self.faucet_inner_puzhash
        _reject_empty_gov_pubkey(
            self.trusted_nav_registry_gov_pubkey,
            "trusted_nav_registry_gov_pubkey",
        )
        _reject_empty_b32(
            self.trusted_nav_registry_launcher_id,
            "trusted_nav_registry_launcher_id",
        )
        _reject_empty_b32(
            self.trusted_treasury_reserve_puzhash,
            "trusted_treasury_reserve_puzhash",
        )
        _reject_empty_b32(
            self.trusted_protocol_treasury_puzhash,
            "trusted_protocol_treasury_puzhash",
        )
        _reject_empty_b32(
            self.trusted_governance_rewards_puzhash,
            "trusted_governance_rewards_puzhash",
        )
        _reject_empty_b32(
            self.trusted_governance_rewards_root,
            "trusted_governance_rewards_root",
        )

        self.pool_launcher_id = bytes32(
            Coin(self.pool_genesis_coin_id, SINGLETON_LAUNCHER_HASH, SINGLETON_AMOUNT).name()
        )
        self.did_launcher_id = bytes32(
            Coin(self.did_genesis_coin_id, SINGLETON_LAUNCHER_HASH, SINGLETON_AMOUNT).name()
        )
        self.tracker_launcher_id = bytes32(
            Coin(self.gov_genesis_coin_id, SINGLETON_LAUNCHER_HASH, SINGLETON_AMOUNT).name()
        )
        self.pool_inner_mod_hash = bytes32(_pool_inner_mod().get_tree_hash())
        self.p2_pool_mod_hash = _p2_pool_v2_mod_hash()
        self.smart_deed_inner_mod_hash = _smart_deed_inner_v2_mod_hash()
        self.governance_singleton_struct_hash = bytes32(
            singleton_struct(self.tracker_launcher_id).get_tree_hash()
        )

        # Step 2: PGT TAIL hash from genesis coin id
        self.pgt_tail_hash = bytes32(pgt_tail_hash(self.pgt_genesis_coin_id))

        # Step 3: pool token tail hash (depends only on pool launcher id)
        self.pool_token_tail_hash = pool_token_tail_hash(self.pool_launcher_id)

        # Step 4: DID inner / full ph (depends on tracker_launcher_id)
        did_inner = quorum_did_inner_puzzle(self.tracker_launcher_id)
        self.did_inner_puzhash = bytes32(did_inner.get_tree_hash())
        self.did_full_puzhash = singleton_full_puzzle_hash(
            self.did_launcher_id, self.did_inner_puzhash
        )

        # Step 5: pool inner / full ph (depends on did_full_puzhash)
        pool_inner = pool_inner_puzzle(
            self.pool_launcher_id,
            self.did_full_puzhash,
            self.tracker_launcher_id,
            nav_registry_mod_hash=self.trusted_nav_registry_mod_hash,
            nav_registry_gov_pubkey=self.trusted_nav_registry_gov_pubkey,
            nav_registry_launcher_id=self.trusted_nav_registry_launcher_id,
            min_nav_registry_version=self.params.min_nav_registry_version,
            trusted_treasury_reserve_puzhash=self.trusted_treasury_reserve_puzhash,
            trusted_protocol_treasury_puzhash=self.trusted_protocol_treasury_puzhash,
            trusted_governance_rewards_puzhash=self.trusted_governance_rewards_puzhash,
            trusted_governance_rewards_root=self.trusted_governance_rewards_root,
            fp_scale=self.params.fp_scale,
            pool_status=self.params.initial_pool_status,
            total_pool_token_supply=self.params.initial_total_pool_token_supply,
            treasury_reserve_tokens=self.params.initial_treasury_reserve_tokens,
        )
        self.pool_inner_puzhash = bytes32(pool_inner.get_tree_hash())
        self.pool_full_puzhash = singleton_full_puzzle_hash(
            self.pool_launcher_id, self.pool_inner_puzhash
        )

        # Step 6: tracker inner / full ph (depends on did_full_puzhash + pool struct)
        tracker_inner = proposal_tracker_inner_puzzle(
            singleton_struct(self.tracker_launcher_id),
            bytes32(pgt_free_inner_mod().get_tree_hash()),
            bytes32(pgt_locked_inner_mod().get_tree_hash()),
            CAT_MOD_HASH,
            self.pgt_tail_hash,
            self.did_full_puzhash,
            singleton_struct(self.pool_launcher_id),
            self.params.quorum_bps,
            self.params.voting_window_seconds,
            self.params.pgt_total_supply,
            self.params.min_proposal_stake,
        )
        self.tracker_inner_puzhash = bytes32(tracker_inner.get_tree_hash())
        self.tracker_full_puzhash = singleton_full_puzzle_hash(
            self.tracker_launcher_id, self.tracker_inner_puzhash
        )

        # Step 7: PGT CAT2 puzhash where the 1M genesis lands (faucet-owned)
        self.pgt_full_puzhash = cat2_puzzle_hash_for_pgt(
            self.tracker_launcher_id,
            self.pgt_genesis_coin_id,
            self.faucet_inner_puzhash,
        )


# ─── Bundle builder ─────────────────────────────────────────────────────────
@dataclass
class DeploymentBundle:
    """Result of building + signing the deployment SpendBundle."""

    spend_bundle: SpendBundle
    plan: ProtocolDeploymentPlan

    @property
    def spend_bundle_id(self) -> str:
        return "0x" + self.spend_bundle.name().hex()


def build_deployment_bundle(
    *,
    plan: ProtocolDeploymentPlan,
    faucet,                                   # Solslot API faucet implementation
    pgt_coin: Coin,
    pool_coin: Coin,
    did_coin: Coin,
    gov_coin: Coin,
    fee_per_spend: int = 0,
) -> DeploymentBundle:
    """Build and sign the atomic protocol-deployment SpendBundle.

    Each of the 4 input coins must:
      - belong to the faucet (puzzle_hash == faucet.address_puzzle_hash)
      - have name() == the corresponding *_genesis_coin_id in `plan`
      - have amount ≥ (mint_target + fee)
        where mint_target is 1_000_000 for pgt_coin and 1 for the others

    Returns the SpendBundle + the same plan (for downstream manifesting).
    """
    if pgt_coin.name() != plan.pgt_genesis_coin_id:
        raise ValueError("pgt_coin name does not match plan.pgt_genesis_coin_id")
    if pool_coin.name() != plan.pool_genesis_coin_id:
        raise ValueError("pool_coin name does not match plan.pool_genesis_coin_id")
    if did_coin.name() != plan.did_genesis_coin_id:
        raise ValueError("did_coin name does not match plan.did_genesis_coin_id")
    if gov_coin.name() != plan.gov_genesis_coin_id:
        raise ValueError("gov_coin name does not match plan.gov_genesis_coin_id")

    for coin, label in [
        (pgt_coin, "pgt_coin"),
        (pool_coin, "pool_coin"),
        (did_coin, "did_coin"),
        (gov_coin, "gov_coin"),
    ]:
        if coin.puzzle_hash != faucet.address_puzzle_hash:
            raise ValueError(
                f"{label} puzzle_hash must equal faucet.address_puzzle_hash"
            )

    # Build each parent spend (faucet-funded).  Each emits one or two
    # CREATE_COIN conditions (target + change) plus optional fee.
    pgt_spend, pgt_sig = _faucet_parent_spend(
        faucet=faucet,
        coin=pgt_coin,
        target_puzhash=plan.pgt_full_puzhash,
        target_amount=plan.params.pgt_total_supply,
        fee=fee_per_spend,
    )
    pool_parent, pool_parent_sig = _faucet_parent_spend(
        faucet=faucet,
        coin=pool_coin,
        target_puzhash=SINGLETON_LAUNCHER_HASH,
        target_amount=int(SINGLETON_AMOUNT),
        fee=fee_per_spend,
    )
    did_parent, did_parent_sig = _faucet_parent_spend(
        faucet=faucet,
        coin=did_coin,
        target_puzhash=SINGLETON_LAUNCHER_HASH,
        target_amount=int(SINGLETON_AMOUNT),
        fee=fee_per_spend,
    )
    gov_parent, gov_parent_sig = _faucet_parent_spend(
        faucet=faucet,
        coin=gov_coin,
        target_puzhash=SINGLETON_LAUNCHER_HASH,
        target_amount=int(SINGLETON_AMOUNT),
        fee=fee_per_spend,
    )

    # Build each launcher spend (signature-less; the launcher puzzle itself
    # validates the CREATE_COIN to the eventual singleton inner ph).
    pool_launcher_coin = launcher_coin_for_parent(pool_coin)
    did_launcher_coin = launcher_coin_for_parent(did_coin)
    gov_launcher_coin = launcher_coin_for_parent(gov_coin)

    pool_launcher_spend = make_spend(
        pool_launcher_coin,
        SINGLETON_LAUNCHER,
        Program.to([plan.pool_inner_puzhash, SINGLETON_AMOUNT, []]),
    )
    did_launcher_spend = make_spend(
        did_launcher_coin,
        SINGLETON_LAUNCHER,
        Program.to([plan.did_inner_puzhash, SINGLETON_AMOUNT, []]),
    )
    gov_launcher_spend = make_spend(
        gov_launcher_coin,
        SINGLETON_LAUNCHER,
        Program.to([plan.tracker_inner_puzhash, SINGLETON_AMOUNT, []]),
    )

    # Aggregate all four faucet signatures (the launchers don't need sigs).
    aggregated_sig = AugSchemeMPL.aggregate(
        [pgt_sig, pool_parent_sig, did_parent_sig, gov_parent_sig]
    )

    bundle = SpendBundle(
        coin_spends=[
            pgt_spend,
            pool_parent,
            pool_launcher_spend,
            did_parent,
            did_launcher_spend,
            gov_parent,
            gov_launcher_spend,
        ],
        aggregated_signature=aggregated_sig,
    )
    return DeploymentBundle(spend_bundle=bundle, plan=plan)


def _faucet_parent_spend(
    *,
    faucet,
    coin: Coin,
    target_puzhash: bytes32,
    target_amount: int,
    fee: int,
):
    """Produce a (CoinSpend, G2Element) pair: a faucet spend that creates
    one CREATE_COIN(target_puzhash, target_amount), an optional change
    output, and (if `fee > 0`) a RESERVE_FEE."""
    if coin.amount < target_amount + fee:
        raise ValueError(
            f"Faucet coin {coin.name().hex()} amount {coin.amount} < "
            f"{target_amount} + {fee} required"
        )

    change = coin.amount - target_amount - fee
    conditions_list = [Program.to([51, target_puzhash, target_amount])]
    if change > 0:
        conditions_list.append(Program.to([51, faucet.address_puzzle_hash, change]))
    if fee > 0:
        conditions_list.append(Program.to([52, fee]))  # RESERVE_FEE
    conditions = Program.to(conditions_list)

    delegated_puzzle = Program.to((1, conditions))      # (q . conditions)
    delegated_solution = Program.to(0)
    parent_solution = Program.to([0, delegated_puzzle, delegated_solution])

    parent_spend = make_spend(coin, faucet.key.puzzle, parent_solution)

    sig_message = (
        bytes(delegated_puzzle.get_tree_hash())
        + bytes(coin.name())
        + faucet.agg_sig_me_data
    )
    sig = AugSchemeMPL.sign(faucet.key.wallet_sk, sig_message)
    return parent_spend, sig


# ─── Manifest persistence ───────────────────────────────────────────────────
def plan_to_manifest_dict(plan: ProtocolDeploymentPlan) -> dict[str, Any]:
    """Convert a ProtocolDeploymentPlan to a JSON-serializable dict."""
    def _hex(v: Any) -> Any:
        if isinstance(v, (bytes, bytes32)):
            return "0x" + bytes(v).hex()
        if isinstance(v, dict):
            return {k: _hex(value) for k, value in v.items()}
        if isinstance(v, (list, tuple)):
            return [_hex(value) for value in v]
        return v

    raw = asdict(plan)
    return {k: _hex(v) for k, v in raw.items()}


def plan_from_manifest_dict(data: dict[str, Any]) -> ProtocolDeploymentPlan:
    """Reconstruct a ProtocolDeploymentPlan from a manifest dict.

    Re-runs ``__post_init__`` to validate that derived hashes still match
    (catches manifest corruption).
    """
    def _bytes(s: Any) -> bytes:
        if isinstance(s, (bytes, bytes32)):
            return bytes(s)
        return bytes.fromhex(s[2:] if s.startswith("0x") else s)

    def _b32(s: Any) -> bytes32:
        return bytes32.fromhex(s[2:] if s.startswith("0x") else s)

    if data.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported or retired protocol_version: {data.get('protocol_version')!r}"
        )
    if data.get("pool_puzzle_version") != POOL_PUZZLE_VERSION:
        raise ValueError(
            f"Unsupported or retired pool_puzzle_version: {data.get('pool_puzzle_version')!r}"
        )
    if data.get("smart_deed_puzzle_version") != SMART_DEED_PUZZLE_VERSION:
        raise ValueError(
            "Unsupported or retired smart_deed_puzzle_version: "
            f"{data.get('smart_deed_puzzle_version')!r}"
        )

    params = ProtocolDeploymentParams(**data["params"])
    trusted_kwargs: dict[str, Any] = {}
    for key in [
        "trusted_nav_registry_mod_hash",
        "trusted_nav_registry_launcher_id",
        "trusted_treasury_reserve_puzhash",
        "trusted_protocol_treasury_puzhash",
        "trusted_governance_rewards_puzhash",
        "trusted_governance_rewards_root",
    ]:
        if key in data and data[key] is not None:
            trusted_kwargs[key] = _b32(data[key])
    if "trusted_nav_registry_gov_pubkey" in data:
        trusted_kwargs["trusted_nav_registry_gov_pubkey"] = _bytes(
            data["trusted_nav_registry_gov_pubkey"]
        )
    plan = ProtocolDeploymentPlan(
        network=data["network"],
        params=params,
        faucet_inner_puzhash=_b32(data["faucet_inner_puzhash"]),
        pgt_genesis_coin_id=_b32(data["pgt_genesis_coin_id"]),
        pool_genesis_coin_id=_b32(data["pool_genesis_coin_id"]),
        did_genesis_coin_id=_b32(data["did_genesis_coin_id"]),
        gov_genesis_coin_id=_b32(data["gov_genesis_coin_id"]),
        **trusted_kwargs,
    )
    # Sanity: stored derived hashes should match recomputed values.
    for key in [
        "pool_launcher_id", "did_launcher_id", "tracker_launcher_id",
        "pgt_tail_hash", "pgt_full_puzhash",
        "pool_token_tail_hash", "pool_inner_puzhash", "pool_full_puzhash",
        "pool_inner_mod_hash", "p2_pool_mod_hash", "smart_deed_inner_mod_hash",
        "governance_singleton_struct_hash",
        "did_inner_puzhash", "did_full_puzhash",
        "tracker_inner_puzhash", "tracker_full_puzhash",
        "trusted_nav_registry_mod_hash", "trusted_nav_registry_launcher_id",
        "trusted_treasury_reserve_puzhash", "trusted_protocol_treasury_puzhash",
        "trusted_governance_rewards_puzhash", "trusted_governance_rewards_root",
    ]:
        if key in data:
            stored = _b32(data[key])
            actual = getattr(plan, key)
            if stored != actual:
                raise ValueError(
                    f"Manifest corruption: stored {key}={stored.hex()} "
                    f"!= recomputed {actual.hex()}"
                )
    return plan


def save_manifest(plan: ProtocolDeploymentPlan, path: Path) -> None:
    """Persist the plan to disk as a JSON manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan_to_manifest_dict(plan), indent=2, sort_keys=True))


def load_manifest(path: Path) -> ProtocolDeploymentPlan:
    """Load a previously-persisted plan from disk (full reconstruction).

    NOTE: This recomputes every derived hash via ``__post_init__`` to verify
    manifest integrity.  CLVM Program instantiation makes this *thread-bound*
    via chia_rs LazyNode — if you need to read the manifest from a request
    handler that may dispatch across threads, use ``load_manifest_dict``
    instead and avoid Program reconstruction.
    """
    return plan_from_manifest_dict(json.loads(path.read_text()))


def load_manifest_dict(path: Path) -> dict[str, Any]:
    """Load the persisted manifest as a plain dict — no CLVM, no threading hazards.

    Use this from FastAPI request handlers; use ``load_manifest`` only from
    deployment-time / driver code that already runs on a single thread.

    Performs only structural validation (required keys present + 0x-prefixed
    32-byte hex strings) — does NOT recompute hashes against the curried
    puzzles.  Catches typos and corruption without requiring a Program load.
    """
    raw = json.loads(path.read_text())
    required = {
        "network", "params", "protocol_version", "pool_puzzle_version",
        "smart_deed_puzzle_version", "faucet_inner_puzhash",
        "pgt_genesis_coin_id", "pool_genesis_coin_id",
        "did_genesis_coin_id", "gov_genesis_coin_id",
        "pool_launcher_id", "did_launcher_id", "tracker_launcher_id",
        "pgt_tail_hash", "pgt_full_puzhash",
        "pool_token_tail_hash", "pool_inner_puzhash", "pool_full_puzhash",
        "pool_inner_mod_hash", "p2_pool_mod_hash", "smart_deed_inner_mod_hash",
        "governance_singleton_struct_hash",
        "did_inner_puzhash", "did_full_puzhash",
        "tracker_inner_puzhash", "tracker_full_puzhash",
    }
    missing = required - set(raw.keys())
    if missing:
        raise ValueError(f"Manifest missing required fields: {sorted(missing)}")
    # Sanity: all 32-byte hex fields should be 0x-prefixed 64 hex chars
    if raw["protocol_version"] != PROTOCOL_VERSION:
        raise ValueError(f"Unsupported or retired protocol_version: {raw['protocol_version']!r}")
    if raw["pool_puzzle_version"] != POOL_PUZZLE_VERSION:
        raise ValueError(
            f"Unsupported or retired pool_puzzle_version: {raw['pool_puzzle_version']!r}"
        )
    if raw["smart_deed_puzzle_version"] != SMART_DEED_PUZZLE_VERSION:
        raise ValueError(
            "Unsupported or retired smart_deed_puzzle_version: "
            f"{raw['smart_deed_puzzle_version']!r}"
        )
    hex_fields = required - {
        "network", "params", "protocol_version", "pool_puzzle_version",
        "smart_deed_puzzle_version",
    }
    for f in hex_fields:
        v = raw[f]
        if not isinstance(v, str) or not v.startswith("0x") or len(v) != 66:
            raise ValueError(
                f"Manifest field {f} is not a 0x-prefixed 32-byte hex string: {v!r}"
            )
    return raw


__all__ = [
    "PROTOCOL_VERSION",
    "POOL_PUZZLE_VERSION",
    "SMART_DEED_PUZZLE_VERSION",
    "DEFAULT_QUORUM_BPS",
    "DEFAULT_VOTING_WINDOW_SECONDS",
    "DEFAULT_PGT_TOTAL_SUPPLY",
    "DEFAULT_MIN_PROPOSAL_STAKE",
    "DEFAULT_FP_SCALE",
    "DEFAULT_MIN_NAV_REGISTRY_VERSION",
    "ProtocolDeploymentParams",
    "ProtocolDeploymentPlan",
    "DeploymentBundle",
    "build_deployment_bundle",
    "launcher_coin_for_parent",
    "singleton_struct",
    "singleton_full_puzzle_hash",
    "pool_token_tail_hash",
    "pool_inner_puzzle",
    "quorum_did_inner_puzzle",
    "pgt_free_inner_puzzle_for_owner",
    "cat2_puzzle_hash_for_pgt",
    "plan_to_manifest_dict",
    "plan_from_manifest_dict",
    "save_manifest",
    "load_manifest",
    "load_manifest_dict",
]
