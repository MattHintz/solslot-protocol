"""Deterministic fresh-genesis deployment plan for the RC22 protocol."""
from __future__ import annotations

from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
    make_pool_v4_inner,
    pool_v4_inner_mod_hash,
)
from solslot_puzzles.protocol_config_driver import NETWORK_ID_TESTNET11
from solslot_puzzles.protocol_deployment import (
    cat2_puzzle_hash_for_sgt,
    pool_token_tail_hash,
    quorum_did_inner_puzzle,
    singleton_full_puzzle_hash,
    singleton_struct,
)
from solslot_puzzles.protocol_statutes_driver import (
    make_inner_puzzle as make_statutes_inner,
    protocol_statutes_inner_mod_hash,
)
from solslot_puzzles.protocol_statutes_v1 import (
    PermanentRules,
    ProtocolParameters,
    StatutesState,
    initial_state,
)
from solslot_puzzles.sgt_driver import (
    proposal_tracker_v2_inner_puzzle,
    sgt_free_inner_mod,
    sgt_locked_inner_mod,
    sgt_tail_hash,
)
from solslot_puzzles.sols_economics_v3 import SolsEconomicState
from solslot_puzzles.sols_pool_v4 import SolsPoolStateV4, inventory_root


RC22_PROTOCOL_VERSION = "solslot-v2-rc22"
RC22_POOL_PUZZLE_VERSION = 4
RC22_GOVERNANCE_PUZZLE_VERSION = 2
RC22_STATUTES_PUZZLE_VERSION = 1
RC22_VAULT_PUZZLE_VERSION = 2
RC22_INITIAL_STATE_VERSION = 1
RC22_NETWORK = "testnet11"


def _nonzero(value: bytes32, label: str) -> bytes32:
    if value == bytes32.zeros:
        raise ValueError(f"{label} must be nonzero")
    return value


def _launcher_id(parent_coin_id: bytes32) -> bytes32:
    return bytes32(
        Coin(
            parent_coin_id,
            bytes32(SINGLETON_LAUNCHER_HASH),
            uint64(1),
        ).name()
    )


@dataclass(frozen=True)
class RC22ProtocolDeploymentPlan:
    network: str
    parameters: ProtocolParameters
    faucet_inner_puzzle_hash: bytes32
    sgt_genesis_coin_id: bytes32
    pool_genesis_coin_id: bytes32
    did_genesis_coin_id: bytes32
    governance_genesis_coin_id: bytes32
    statutes_genesis_coin_id: bytes32
    admin_authority_genesis_coin_id: bytes32
    governance_bls_pubkey: bytes
    kos_mint_execute_pubkey: bytes
    trusted_treasury_reserve_puzzle_hash: bytes32
    trusted_protocol_treasury_puzzle_hash: bytes32
    trusted_governance_rewards_puzzle_hash: bytes32
    trusted_governance_rewards_root: bytes32
    trusted_zkpassport_bridge_policy_hash: bytes32
    pool_launcher_id: bytes32
    did_launcher_id: bytes32
    governance_launcher_id: bytes32
    statutes_launcher_id: bytes32
    admin_authority_launcher_id: bytes32
    sgt_tail_hash: bytes32
    sols_tail_hash: bytes32
    sgt_full_puzzle_hash: bytes32
    did_inner_puzzle_hash: bytes32
    did_full_puzzle_hash: bytes32
    statutes_inner_mod_hash: bytes32
    statutes_inner_puzzle_hash: bytes32
    statutes_full_puzzle_hash: bytes32
    pool_inner_mod_hash: bytes32
    pool_inner_puzzle_hash: bytes32
    pool_full_puzzle_hash: bytes32
    governance_inner_puzzle_hash: bytes32
    governance_full_puzzle_hash: bytes32
    governance_singleton_struct_hash: bytes32
    statutes_singleton_struct_hash: bytes32
    p2_pool_mod_hash: bytes32
    p2_vault_mod_hash: bytes32
    vault_inner_mod_hash: bytes32
    smart_deed_inner_mod_hash: bytes32
    permanent_rules: PermanentRules
    statutes_state: StatutesState
    pool_state: SolsPoolStateV4
    pool_config: PoolV4Config
    protocol_version: str = RC22_PROTOCOL_VERSION
    pool_puzzle_version: int = RC22_POOL_PUZZLE_VERSION
    governance_puzzle_version: int = RC22_GOVERNANCE_PUZZLE_VERSION
    statutes_puzzle_version: int = RC22_STATUTES_PUZZLE_VERSION
    vault_puzzle_version: int = RC22_VAULT_PUZZLE_VERSION


def build_rc22_protocol_deployment_plan(
    *,
    network: str,
    parameters: ProtocolParameters,
    faucet_inner_puzzle_hash: bytes32,
    sgt_genesis_coin_id: bytes32,
    pool_genesis_coin_id: bytes32,
    did_genesis_coin_id: bytes32,
    governance_genesis_coin_id: bytes32,
    statutes_genesis_coin_id: bytes32,
    admin_authority_genesis_coin_id: bytes32,
    governance_bls_pubkey: bytes,
    kos_mint_execute_pubkey: bytes,
    trusted_treasury_reserve_puzzle_hash: bytes32,
    trusted_protocol_treasury_puzzle_hash: bytes32,
    trusted_governance_rewards_puzzle_hash: bytes32,
    trusted_governance_rewards_root: bytes32,
    trusted_zkpassport_bridge_policy_hash: bytes32,
    sgt_total_supply: int = 1_000_000,
) -> RC22ProtocolDeploymentPlan:
    if network != RC22_NETWORK:
        raise ValueError("RC22 fresh genesis is restricted to testnet11")
    parameters.validate(sgt_total_supply=sgt_total_supply)
    if len(governance_bls_pubkey) != 48:
        raise ValueError("governance_bls_pubkey must be 48 bytes")
    if (
        len(kos_mint_execute_pubkey) != 48
        or kos_mint_execute_pubkey == b"\x00" * 48
    ):
        raise ValueError(
            "kos_mint_execute_pubkey must be a nonzero 48-byte BLS key"
        )
    for label, value in (
        ("faucet_inner_puzzle_hash", faucet_inner_puzzle_hash),
        ("sgt_genesis_coin_id", sgt_genesis_coin_id),
        ("pool_genesis_coin_id", pool_genesis_coin_id),
        ("did_genesis_coin_id", did_genesis_coin_id),
        ("governance_genesis_coin_id", governance_genesis_coin_id),
        ("statutes_genesis_coin_id", statutes_genesis_coin_id),
        (
            "admin_authority_genesis_coin_id",
            admin_authority_genesis_coin_id,
        ),
        (
            "trusted_treasury_reserve_puzzle_hash",
            trusted_treasury_reserve_puzzle_hash,
        ),
        (
            "trusted_protocol_treasury_puzzle_hash",
            trusted_protocol_treasury_puzzle_hash,
        ),
        (
            "trusted_governance_rewards_puzzle_hash",
            trusted_governance_rewards_puzzle_hash,
        ),
        ("trusted_governance_rewards_root", trusted_governance_rewards_root),
        (
            "trusted_zkpassport_bridge_policy_hash",
            trusted_zkpassport_bridge_policy_hash,
        ),
    ):
        _nonzero(value, label)

    pool_launcher_id = _launcher_id(pool_genesis_coin_id)
    did_launcher_id = _launcher_id(did_genesis_coin_id)
    governance_launcher_id = _launcher_id(governance_genesis_coin_id)
    statutes_launcher_id = _launcher_id(statutes_genesis_coin_id)
    admin_launcher_id = _launcher_id(admin_authority_genesis_coin_id)
    governance_struct = singleton_struct(governance_launcher_id)
    statutes_struct = singleton_struct(statutes_launcher_id)

    fixed_sgt_tail = bytes32(sgt_tail_hash(sgt_genesis_coin_id))
    fixed_sols_tail = pool_token_tail_hash(pool_launcher_id)
    permanent_rules = PermanentRules(
        sgt_tail_hash=fixed_sgt_tail,
        sgt_total_supply=sgt_total_supply,
        sols_tail_hash=fixed_sols_tail,
        zkpassport_policy_hash=trusted_zkpassport_bridge_policy_hash,
        protocol_treasury_puzzle_hash=trusted_protocol_treasury_puzzle_hash,
        network_id=NETWORK_ID_TESTNET11,
    ).validate()
    statutes_state = initial_state(
        parameters=parameters,
        permanent_rules=permanent_rules,
    )
    statutes_inner = make_statutes_inner(
        singleton_struct=statutes_struct,
        governance_singleton_struct=governance_struct,
        permanent_rules=permanent_rules,
        state=statutes_state,
    )
    statutes_inner_hash = bytes32(statutes_inner.get_tree_hash())

    did_inner = quorum_did_inner_puzzle(governance_launcher_id)
    did_inner_hash = bytes32(did_inner.get_tree_hash())
    did_full_hash = singleton_full_puzzle_hash(
        did_launcher_id,
        did_inner_hash,
    )

    initial_pool_state = SolsPoolStateV4(
        inventory_root=inventory_root(()),
        economics=SolsEconomicState(
            bootstrap_complete=False,
            inventory_nav_micro_usd=0,
            treasury_assets_micro_usd=0,
            proven_liabilities_micro_usd=0,
            deed_count=0,
            total_sols_mojos=0,
            reserve_sols_mojos=0,
        ),
        state_version=RC22_INITIAL_STATE_VERSION,
    )
    initial_pool_state.validate(())
    pool_config = PoolV4Config(
        pool_launcher_id=pool_launcher_id,
        statutes_inner_mod_hash=protocol_statutes_inner_mod_hash(),
        statutes_singleton_struct=statutes_struct,
        governance_singleton_struct=governance_struct,
        permanent_rules=permanent_rules,
        cat_mod_hash=CAT_MOD_HASH,
        offer_mod_hash=OFFER_MOD_HASH,
        p2_vault_mod_hash=bytes32(
            load_puzzle("p2_vault.clsp").get_tree_hash()
        ),
        vault_v2_mod_hash=bytes32(
            load_puzzle("vault_singleton_inner_v2.clsp").get_tree_hash()
        ),
        p2_pool_v2_mod_hash=bytes32(
            load_puzzle("p2_pool_v2.clsp").get_tree_hash()
        ),
        reserve_puzzle_hash=trusted_treasury_reserve_puzzle_hash,
        sgt_rewards_puzzle_hash=trusted_governance_rewards_puzzle_hash,
    )
    pool_inner = make_pool_v4_inner(pool_config, initial_pool_state)
    pool_inner_hash = bytes32(pool_inner.get_tree_hash())
    pool_full_hash = singleton_full_puzzle_hash(
        pool_launcher_id,
        pool_inner_hash,
    )

    governance_inner = proposal_tracker_v2_inner_puzzle(
        governance_struct,
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        CAT_MOD_HASH,
        fixed_sgt_tail,
        did_full_hash,
        singleton_struct(pool_launcher_id),
        singleton_struct(admin_launcher_id),
        statutes_struct,
        parameters.quorum_bps,
        parameters.voting_window_seconds,
        sgt_total_supply,
        parameters.min_proposal_stake,
        kos_mint_execute_pubkey,
    )
    governance_inner_hash = bytes32(governance_inner.get_tree_hash())
    governance_full_hash = singleton_full_puzzle_hash(
        governance_launcher_id,
        governance_inner_hash,
    )

    return RC22ProtocolDeploymentPlan(
        network=network,
        parameters=parameters,
        faucet_inner_puzzle_hash=faucet_inner_puzzle_hash,
        sgt_genesis_coin_id=sgt_genesis_coin_id,
        pool_genesis_coin_id=pool_genesis_coin_id,
        did_genesis_coin_id=did_genesis_coin_id,
        governance_genesis_coin_id=governance_genesis_coin_id,
        statutes_genesis_coin_id=statutes_genesis_coin_id,
        admin_authority_genesis_coin_id=admin_authority_genesis_coin_id,
        governance_bls_pubkey=governance_bls_pubkey,
        kos_mint_execute_pubkey=kos_mint_execute_pubkey,
        trusted_treasury_reserve_puzzle_hash=(
            trusted_treasury_reserve_puzzle_hash
        ),
        trusted_protocol_treasury_puzzle_hash=(
            trusted_protocol_treasury_puzzle_hash
        ),
        trusted_governance_rewards_puzzle_hash=(
            trusted_governance_rewards_puzzle_hash
        ),
        trusted_governance_rewards_root=trusted_governance_rewards_root,
        trusted_zkpassport_bridge_policy_hash=(
            trusted_zkpassport_bridge_policy_hash
        ),
        pool_launcher_id=pool_launcher_id,
        did_launcher_id=did_launcher_id,
        governance_launcher_id=governance_launcher_id,
        statutes_launcher_id=statutes_launcher_id,
        admin_authority_launcher_id=admin_launcher_id,
        sgt_tail_hash=fixed_sgt_tail,
        sols_tail_hash=fixed_sols_tail,
        sgt_full_puzzle_hash=cat2_puzzle_hash_for_sgt(
            governance_launcher_id,
            sgt_genesis_coin_id,
            faucet_inner_puzzle_hash,
        ),
        did_inner_puzzle_hash=did_inner_hash,
        did_full_puzzle_hash=did_full_hash,
        statutes_inner_mod_hash=protocol_statutes_inner_mod_hash(),
        statutes_inner_puzzle_hash=statutes_inner_hash,
        statutes_full_puzzle_hash=singleton_full_puzzle_hash(
            statutes_launcher_id,
            statutes_inner_hash,
        ),
        pool_inner_mod_hash=pool_v4_inner_mod_hash(),
        pool_inner_puzzle_hash=pool_inner_hash,
        pool_full_puzzle_hash=pool_full_hash,
        governance_inner_puzzle_hash=governance_inner_hash,
        governance_full_puzzle_hash=governance_full_hash,
        governance_singleton_struct_hash=bytes32(
            governance_struct.get_tree_hash()
        ),
        statutes_singleton_struct_hash=bytes32(
            statutes_struct.get_tree_hash()
        ),
        p2_pool_mod_hash=pool_config.p2_pool_v2_mod_hash,
        p2_vault_mod_hash=pool_config.p2_vault_mod_hash,
        vault_inner_mod_hash=pool_config.vault_v2_mod_hash,
        smart_deed_inner_mod_hash=bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        ),
        permanent_rules=permanent_rules,
        statutes_state=statutes_state,
        pool_state=initial_pool_state,
        pool_config=pool_config,
    )


__all__ = [
    "RC22_GOVERNANCE_PUZZLE_VERSION",
    "RC22_POOL_PUZZLE_VERSION",
    "RC22_PROTOCOL_VERSION",
    "RC22_STATUTES_PUZZLE_VERSION",
    "RC22_VAULT_PUZZLE_VERSION",
    "RC22ProtocolDeploymentPlan",
    "build_rc22_protocol_deployment_plan",
]
