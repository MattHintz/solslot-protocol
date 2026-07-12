"""Tests for the protocol deployment driver.

Verifies:
1. ``ProtocolDeploymentPlan`` derives all hashes deterministically from a
   fixed set of genesis coin ids.
2. The manifest round-trip (``plan_to_manifest_dict`` →
   ``plan_from_manifest_dict``) preserves every field and re-validates
   derived hashes against recomputed values.
3. ``build_deployment_bundle`` produces a structurally-valid SpendBundle
   with the expected 7 coin spends (4 faucet parents + 3 launchers) and a
   well-formed aggregated BLS signature.
4. The deployment plan uses the post-fix mode-0x10 governance puzzle
   (regression check after the v2 governance + DoS hardening + MINT
   routing repair).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from chia.wallet.derive_keys import master_sk_to_wallet_sk_unhardened
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    MOD as P2_DELEGATED_MOD,
    calculate_synthetic_secret_key,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs import AugSchemeMPL, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.protocol_deployment import (
    DEFAULT_MIN_PROPOSAL_STAKE,
    DEFAULT_MIN_NAV_REGISTRY_VERSION,
    DEFAULT_PGT_TOTAL_SUPPLY,
    DEFAULT_QUORUM_BPS,
    ProtocolDeploymentParams,
    ProtocolDeploymentPlan,
    build_deployment_bundle,
    cat2_puzzle_hash_for_pgt,
    launcher_coin_for_parent,
    plan_from_manifest_dict,
    plan_to_manifest_dict,
    save_manifest,
    load_manifest,
    singleton_full_puzzle_hash,
    singleton_struct,
)


# ── Test fixtures ────────────────────────────────────────────────────────────
PGT_GENESIS = bytes32(b"\xa0" * 32)
POOL_GENESIS = bytes32(b"\xb0" * 32)
DID_GENESIS = bytes32(b"\xc0" * 32)
GOV_GENESIS = bytes32(b"\xd0" * 32)
TRUSTED_NAV_REGISTRY_GOV_PUBKEY = b"\x91" * 48
TRUSTED_NAV_REGISTRY_LAUNCHER_ID = bytes32(b"\x92" * 32)
TRUSTED_GOVERNANCE_REWARDS_ROOT = bytes32(b"\x93" * 32)


def trusted_v2_kwargs() -> dict:
    return {
        "trusted_nav_registry_gov_pubkey": TRUSTED_NAV_REGISTRY_GOV_PUBKEY,
        "trusted_nav_registry_launcher_id": TRUSTED_NAV_REGISTRY_LAUNCHER_ID,
        "trusted_governance_rewards_root": TRUSTED_GOVERNANCE_REWARDS_ROOT,
    }


class _FakeFaucet:
    """Minimal Faucet stand-in for unit tests.

    Real Faucet (in populis_api) wraps a BIP32-derived BLS key + a
    standard ``puzzle_for_pk`` puzzle.  This stand-in mirrors the same
    contract using a deterministic seed.
    """

    def __init__(self, seed: bytes = b"populis-test-deployment-faucet-x" * 1):
        # Pad to 32 bytes deterministic
        seed_bytes = (seed * 4)[:32]
        self.master_sk = AugSchemeMPL.key_gen(seed_bytes)
        wallet_sk = master_sk_to_wallet_sk_unhardened(self.master_sk, 0)
        synth_sk = calculate_synthetic_secret_key(wallet_sk, DEFAULT_HIDDEN_PUZZLE_HASH)
        wallet_pk = wallet_sk.get_g1()
        self.key = type("FaucetKey", (), {
            "wallet_sk": wallet_sk,
            "wallet_pk": wallet_pk,
            "synthetic_sk": synth_sk,
            "puzzle": Program.from_bytes(bytes(P2_DELEGATED_MOD)).curry(wallet_pk),
        })()
        self.address_puzzle_hash = bytes32(self.key.puzzle.get_tree_hash())
        # testnet11 AGG_SIG_ME data (matches populis_api.faucet)
        self.agg_sig_me_data = bytes.fromhex(
            "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
        )


@pytest.fixture
def faucet() -> _FakeFaucet:
    return _FakeFaucet()


@pytest.fixture
def plan(faucet) -> ProtocolDeploymentPlan:
    return ProtocolDeploymentPlan(
        network="testnet11",
        params=ProtocolDeploymentParams(),
        faucet_inner_puzhash=faucet.address_puzzle_hash,
        pgt_genesis_coin_id=PGT_GENESIS,
        pool_genesis_coin_id=POOL_GENESIS,
        did_genesis_coin_id=DID_GENESIS,
        gov_genesis_coin_id=GOV_GENESIS,
        **trusted_v2_kwargs(),
    )


# ── Plan derivation ──────────────────────────────────────────────────────────
class TestPlanDerivation:
    def test_launcher_ids_deterministic_from_genesis_coins(self, plan):
        """Launcher ids = sha256(parent_coin_id || SINGLETON_LAUNCHER_HASH || amount)."""
        expected_pool = Coin(
            POOL_GENESIS, SINGLETON_LAUNCHER_HASH, uint64(1)
        ).name()
        expected_did = Coin(
            DID_GENESIS, SINGLETON_LAUNCHER_HASH, uint64(1)
        ).name()
        expected_gov = Coin(
            GOV_GENESIS, SINGLETON_LAUNCHER_HASH, uint64(1)
        ).name()

        assert plan.pool_launcher_id == bytes32(expected_pool)
        assert plan.did_launcher_id == bytes32(expected_did)
        assert plan.tracker_launcher_id == bytes32(expected_gov)

    def test_pgt_tail_hash_depends_on_pgt_genesis(self, plan, faucet):
        """A different PGT genesis coin produces a different tail hash."""
        other = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=bytes32(b"\xee" * 32),  # different
            pool_genesis_coin_id=POOL_GENESIS,
            did_genesis_coin_id=DID_GENESIS,
            gov_genesis_coin_id=GOV_GENESIS,
            **trusted_v2_kwargs(),
        )
        assert plan.pgt_tail_hash != other.pgt_tail_hash

    def test_did_full_ph_uses_singleton_struct(self, plan):
        """DID lives at calculate_full_puzzle_hash(DID_STRUCT, did_inner_ph)."""
        expected = singleton_full_puzzle_hash(
            plan.did_launcher_id, plan.did_inner_puzhash
        )
        assert plan.did_full_puzhash == expected

    def test_tracker_full_ph_uses_singleton_struct(self, plan):
        expected = singleton_full_puzzle_hash(
            plan.tracker_launcher_id, plan.tracker_inner_puzhash
        )
        assert plan.tracker_full_puzhash == expected

    def test_pool_full_ph_uses_singleton_struct(self, plan):
        expected = singleton_full_puzzle_hash(
            plan.pool_launcher_id, plan.pool_inner_puzhash
        )
        assert plan.pool_full_puzhash == expected

    def test_pgt_full_ph_is_cat2_wrapped(self, plan):
        """The 1M PGT lands at a CAT2-wrapped pgt_free_inner curried for the
        faucet — the 'protocol treasury' bag."""
        expected = cat2_puzzle_hash_for_pgt(
            plan.tracker_launcher_id,
            plan.pgt_genesis_coin_id,
            plan.faucet_inner_puzhash,
        )
        assert plan.pgt_full_puzhash == expected

    def test_changing_governance_params_changes_tracker_hash(self, faucet):
        """Different MIN_PROPOSAL_STAKE → different tracker inner ph."""
        a = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(min_proposal_stake=10_000),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=PGT_GENESIS,
            pool_genesis_coin_id=POOL_GENESIS,
            did_genesis_coin_id=DID_GENESIS,
            gov_genesis_coin_id=GOV_GENESIS,
            **trusted_v2_kwargs(),
        )
        b = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(min_proposal_stake=20_000),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=PGT_GENESIS,
            pool_genesis_coin_id=POOL_GENESIS,
            did_genesis_coin_id=DID_GENESIS,
            gov_genesis_coin_id=GOV_GENESIS,
            **trusted_v2_kwargs(),
        )
        assert a.tracker_inner_puzhash != b.tracker_inner_puzhash

    def test_changing_nav_registry_floor_changes_pool_hash(self, faucet):
        """Different minimum NAV registry versions commit different pool inners."""
        a = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(min_nav_registry_version=7),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=PGT_GENESIS,
            pool_genesis_coin_id=POOL_GENESIS,
            did_genesis_coin_id=DID_GENESIS,
            gov_genesis_coin_id=GOV_GENESIS,
            **trusted_v2_kwargs(),
        )
        b = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(min_nav_registry_version=8),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=PGT_GENESIS,
            pool_genesis_coin_id=POOL_GENESIS,
            did_genesis_coin_id=DID_GENESIS,
            gov_genesis_coin_id=GOV_GENESIS,
            **trusted_v2_kwargs(),
        )
        assert a.pool_inner_puzhash != b.pool_inner_puzhash

    def test_empty_v2_trust_anchors_rejected(self, faucet):
        """Deployment plans must not silently curry sentinel V2 trust anchors."""
        with pytest.raises(ValueError, match="trusted_nav_registry_gov_pubkey"):
            ProtocolDeploymentPlan(
                network="testnet11",
                params=ProtocolDeploymentParams(),
                faucet_inner_puzhash=faucet.address_puzzle_hash,
                pgt_genesis_coin_id=PGT_GENESIS,
                pool_genesis_coin_id=POOL_GENESIS,
                did_genesis_coin_id=DID_GENESIS,
                gov_genesis_coin_id=GOV_GENESIS,
            )


# ── Manifest round-trip ──────────────────────────────────────────────────────
class TestManifestRoundtrip:
    def test_to_dict_contains_all_fields(self, plan):
        m = plan_to_manifest_dict(plan)
        assert m["params"]["min_nav_registry_version"] == DEFAULT_MIN_NAV_REGISTRY_VERSION
        for required in [
            "network", "params", "faucet_inner_puzhash",
            "pgt_genesis_coin_id", "pool_genesis_coin_id",
            "did_genesis_coin_id", "gov_genesis_coin_id",
            "pool_launcher_id", "did_launcher_id", "tracker_launcher_id",
            "pgt_tail_hash", "pgt_full_puzhash",
            "pool_token_tail_hash", "pool_inner_puzhash", "pool_full_puzhash",
            "did_inner_puzhash", "did_full_puzhash",
            "tracker_inner_puzhash", "tracker_full_puzhash",
        ]:
            assert required in m, f"manifest missing {required}"

    def test_to_dict_uses_0x_hex_for_bytes(self, plan):
        m = plan_to_manifest_dict(plan)
        for key in ["pgt_tail_hash", "pool_launcher_id", "tracker_full_puzhash"]:
            assert m[key].startswith("0x")
            assert len(m[key]) == 66  # 0x + 64 hex chars

    def test_from_dict_reconstructs_identical_plan(self, plan):
        m = plan_to_manifest_dict(plan)
        restored = plan_from_manifest_dict(m)
        # All derived hashes match
        for field in [
            "pool_launcher_id", "did_launcher_id", "tracker_launcher_id",
            "pgt_tail_hash", "pgt_full_puzhash",
            "pool_full_puzhash", "did_full_puzhash", "tracker_full_puzhash",
        ]:
            assert getattr(restored, field) == getattr(plan, field)

    def test_corrupt_manifest_rejected(self, plan):
        """If a stored derived hash doesn't match recomputation, raise."""
        m = plan_to_manifest_dict(plan)
        # Corrupt the stored pool_full_puzhash
        m["pool_full_puzhash"] = "0x" + ("00" * 32)
        with pytest.raises(ValueError, match="Manifest corruption"):
            plan_from_manifest_dict(m)

    def test_save_load_round_trip(self, plan, tmp_path):
        path = tmp_path / "deployment.json"
        save_manifest(plan, path)
        assert path.exists()
        restored = load_manifest(path)
        assert restored.tracker_full_puzhash == plan.tracker_full_puzhash


# ── Bundle builder ──────────────────────────────────────────────────────────
def _make_faucet_coin(faucet: _FakeFaucet, name: bytes32, amount: int) -> Coin:
    """Create a synthetic Coin matching ``name()`` exactly.

    A coin's name is sha256(parent || puzhash || amount).  We don't need
    a real on-chain parent for unit tests — we just need the resulting
    ``coin.name()`` to equal the chosen genesis coin id.  We brute-force a
    parent that yields the desired name — but that's expensive.  Instead,
    we synthesize a Coin with a fake parent and use its ACTUAL name as
    the genesis id (callers must use the resulting name() in their plan).
    """
    fake_parent = bytes32(b"\x00" * 31 + bytes([name[-1]]))
    return Coin(
        parent_coin_info=fake_parent,
        puzzle_hash=faucet.address_puzzle_hash,
        amount=uint64(amount),
    )


class TestBundleBuilder:
    def test_bundle_has_7_coin_spends(self, faucet):
        """The atomic deployment bundle contains:
        - 4 faucet parent spends (PGT, pool, DID, gov)
        - 3 launcher spends (pool, DID, gov; PGT has no launcher)
        Total: 7
        """
        # Build coins, then derive plan FROM their actual names
        pgt_coin = _make_faucet_coin(faucet, PGT_GENESIS, DEFAULT_PGT_TOTAL_SUPPLY)
        pool_coin = _make_faucet_coin(faucet, POOL_GENESIS, 100)
        did_coin = _make_faucet_coin(faucet, DID_GENESIS, 100)
        gov_coin = _make_faucet_coin(faucet, GOV_GENESIS, 100)

        plan = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=pgt_coin.name(),
            pool_genesis_coin_id=pool_coin.name(),
            did_genesis_coin_id=did_coin.name(),
            gov_genesis_coin_id=gov_coin.name(),
            **trusted_v2_kwargs(),
        )

        result = build_deployment_bundle(
            plan=plan,
            faucet=faucet,
            pgt_coin=pgt_coin,
            pool_coin=pool_coin,
            did_coin=did_coin,
            gov_coin=gov_coin,
            fee_per_spend=0,
        )

        assert len(result.spend_bundle.coin_spends) == 7

    def test_bundle_has_aggregated_signature(self, faucet):
        pgt_coin = _make_faucet_coin(faucet, PGT_GENESIS, DEFAULT_PGT_TOTAL_SUPPLY)
        pool_coin = _make_faucet_coin(faucet, POOL_GENESIS, 100)
        did_coin = _make_faucet_coin(faucet, DID_GENESIS, 100)
        gov_coin = _make_faucet_coin(faucet, GOV_GENESIS, 100)
        plan = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=pgt_coin.name(),
            pool_genesis_coin_id=pool_coin.name(),
            did_genesis_coin_id=did_coin.name(),
            gov_genesis_coin_id=gov_coin.name(),
            **trusted_v2_kwargs(),
        )
        result = build_deployment_bundle(
            plan=plan, faucet=faucet,
            pgt_coin=pgt_coin, pool_coin=pool_coin,
            did_coin=did_coin, gov_coin=gov_coin,
        )
        # Aggregated sig is non-empty G2 (96 bytes serialised)
        assert isinstance(result.spend_bundle.aggregated_signature, G2Element)
        assert len(bytes(result.spend_bundle.aggregated_signature)) == 96
        # And not the zero element (real signatures from 4 spends)
        assert bytes(result.spend_bundle.aggregated_signature) != bytes(G2Element())

    def test_bundle_aggregate_signature_verifies_against_emitted_conditions(self, faucet):
        pgt_coin = _make_faucet_coin(faucet, PGT_GENESIS, DEFAULT_PGT_TOTAL_SUPPLY)
        pool_coin = _make_faucet_coin(faucet, POOL_GENESIS, 100)
        did_coin = _make_faucet_coin(faucet, DID_GENESIS, 100)
        gov_coin = _make_faucet_coin(faucet, GOV_GENESIS, 100)
        plan = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=pgt_coin.name(),
            pool_genesis_coin_id=pool_coin.name(),
            did_genesis_coin_id=did_coin.name(),
            gov_genesis_coin_id=gov_coin.name(),
            **trusted_v2_kwargs(),
        )
        result = build_deployment_bundle(
            plan=plan, faucet=faucet,
            pgt_coin=pgt_coin, pool_coin=pool_coin,
            did_coin=did_coin, gov_coin=gov_coin,
        )

        pks = []
        messages = []
        for coin_spend in result.spend_bundle.coin_spends:
            conditions = conditions_dict_for_solution(
                Program.from_bytes(bytes(coin_spend.puzzle_reveal)),
                Program.from_bytes(bytes(coin_spend.solution)),
                INFINITE_COST,
            )
            for pk, message in pkm_pairs_for_conditions_dict(
                conditions,
                coin_spend.coin,
                faucet.agg_sig_me_data,
            ):
                pks.append(pk)
                messages.append(message)

        assert len(pks) == 4
        assert all(pk == faucet.key.wallet_pk for pk in pks)
        assert AugSchemeMPL.aggregate_verify(
            pks,
            messages,
            result.spend_bundle.aggregated_signature,
        )

    def test_bundle_coin_mismatch_rejected(self, faucet):
        """Bundle builder must reject coins whose name doesn't match the plan."""
        pgt_coin = _make_faucet_coin(faucet, PGT_GENESIS, DEFAULT_PGT_TOTAL_SUPPLY)
        pool_coin = _make_faucet_coin(faucet, POOL_GENESIS, 100)
        did_coin = _make_faucet_coin(faucet, DID_GENESIS, 100)
        gov_coin = _make_faucet_coin(faucet, GOV_GENESIS, 100)
        plan = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=bytes32(b"\xff" * 32),  # WRONG
            pool_genesis_coin_id=pool_coin.name(),
            did_genesis_coin_id=did_coin.name(),
            gov_genesis_coin_id=gov_coin.name(),
            **trusted_v2_kwargs(),
        )
        with pytest.raises(ValueError, match="pgt_coin name does not match"):
            build_deployment_bundle(
                plan=plan, faucet=faucet,
                pgt_coin=pgt_coin, pool_coin=pool_coin,
                did_coin=did_coin, gov_coin=gov_coin,
            )

    def test_bundle_insufficient_amount_rejected(self, faucet):
        """A faucet coin smaller than (target + fee) must fail."""
        # Only 100 mojos, but PGT needs 1_000_000
        pgt_coin = _make_faucet_coin(faucet, PGT_GENESIS, 100)
        pool_coin = _make_faucet_coin(faucet, POOL_GENESIS, 100)
        did_coin = _make_faucet_coin(faucet, DID_GENESIS, 100)
        gov_coin = _make_faucet_coin(faucet, GOV_GENESIS, 100)
        plan = ProtocolDeploymentPlan(
            network="testnet11",
            params=ProtocolDeploymentParams(),
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=pgt_coin.name(),
            pool_genesis_coin_id=pool_coin.name(),
            did_genesis_coin_id=did_coin.name(),
            gov_genesis_coin_id=gov_coin.name(),
            **trusted_v2_kwargs(),
        )
        with pytest.raises(ValueError, match="amount.*<.*required"):
            build_deployment_bundle(
                plan=plan, faucet=faucet,
                pgt_coin=pgt_coin, pool_coin=pool_coin,
                did_coin=did_coin, gov_coin=gov_coin,
            )


# ── Regression: post-fix governance puzzle is in use ────────────────────────
class TestPostFixGovernance:
    def test_tracker_uses_min_proposal_stake_curry(self, faucet):
        """Sanity: changing MIN_PROPOSAL_STAKE changes tracker hash, proving
        the curried governance puzzle is the post-DoS-fix version."""
        params_default = ProtocolDeploymentParams()
        params_doubled = ProtocolDeploymentParams(min_proposal_stake=20_000)

        kwargs = dict(
            network="testnet11",
            faucet_inner_puzhash=faucet.address_puzzle_hash,
            pgt_genesis_coin_id=PGT_GENESIS,
            pool_genesis_coin_id=POOL_GENESIS,
            did_genesis_coin_id=DID_GENESIS,
            gov_genesis_coin_id=GOV_GENESIS,
            **trusted_v2_kwargs(),
        )
        a = ProtocolDeploymentPlan(params=params_default, **kwargs)
        b = ProtocolDeploymentPlan(params=params_doubled, **kwargs)

        assert a.tracker_inner_puzhash != b.tracker_inner_puzhash, (
            "Tracker inner puzhash must depend on MIN_PROPOSAL_STAKE — "
            "indicates the post-DoS-fix puzzle is curried correctly."
        )
