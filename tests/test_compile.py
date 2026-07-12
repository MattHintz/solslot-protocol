"""Smoke tests: verify every .clsp file compiles via load_clvm."""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm


class TestCompile:
    """Each test loads one .clsp and asserts it produces a non-None Program."""

    def test_singleton_launcher_with_did(self):
        mod: Program = load_clvm(
            "singleton_launcher_with_did.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_smart_deed_inner(self):
        mod: Program = load_clvm(
            "smart_deed_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_smart_deed_inner_v2(self):
        mod: Program = load_clvm(
            "smart_deed_inner_v2.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_vault_singleton_inner(self):
        mod: Program = load_clvm(
            "vault_singleton_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_p2_vault(self):
        mod: Program = load_clvm(
            "p2_vault.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_p2_pool(self):
        mod: Program = load_clvm(
            "p2_pool.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_p2_pool_v2(self):
        mod: Program = load_clvm(
            "p2_pool_v2.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_pool_token_tail(self):
        mod: Program = load_clvm(
            "pool_token_tail.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_pool_singleton_inner(self):
        mod: Program = load_clvm(
            "pool_singleton_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_pool_singleton_inner_v3(self):
        mod: Program = load_clvm(
            "pool_singleton_inner_v3.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_governance_singleton_inner(self):
        mod: Program = load_clvm(
            "governance_singleton_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_quorum_did_inner(self):
        mod: Program = load_clvm(
            "quorum_did_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_mint_offer_delegate(self):
        mod: Program = load_clvm(
            "mint_offer_delegate.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_purchase_payment(self):
        mod: Program = load_clvm(
            "purchase_payment.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_protocol_config_inner(self):
        mod: Program = load_clvm(
            "protocol_config_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_admin_authority_inner(self):
        mod: Program = load_clvm(
            "admin_authority_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_admin_authority_v2_inner(self):
        mod: Program = load_clvm(
            "admin_authority_v2_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_property_registry_inner(self):
        mod: Program = load_clvm(
            "property_registry_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_mint_proposal_inner(self):
        mod: Program = load_clvm(
            "mint_proposal_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None
        assert mod.get_tree_hash() is not None
