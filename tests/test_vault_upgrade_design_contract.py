"""Docs-contract test pinning the Solslot vault-upgrade design.

Brick 1 of the vault-upgrade feature. This test does not exercise runtime
behaviour; it pins the invariants that later bricks (registry singleton,
migrate spend case, portal detection/upgrade) must not silently drift from.

The design lives in ``research/SOLSLOT_VAULT_UPGRADE_DESIGN.md`` and mirrors the
proven ``protocol_config_inner.clsp`` on-chain state-machine pattern.
"""
from __future__ import annotations

from pathlib import Path

import pytest

DESIGN_DOC = (
    Path(__file__).resolve().parent.parent
    / "research"
    / "SOLSLOT_VAULT_UPGRADE_DESIGN.md"
)


@pytest.fixture(scope="module")
def doc_text() -> str:
    assert DESIGN_DOC.is_file(), f"missing design doc: {DESIGN_DOC}"
    return DESIGN_DOC.read_text(encoding="utf-8")


def _lower(doc_text: str) -> str:
    # Collapse markdown line-wrapping so multi-word prose phrases match
    # regardless of where the source happens to wrap.
    return " ".join(doc_text.split()).lower()


def test_decentralized_no_backend(doc_text: str) -> None:
    """Detection + upgrade must read chain directly with no Solslot backend."""
    low = _lower(doc_text)
    assert "decentralized" in low
    assert "no solslot backend" in low
    assert "no solslot backend dependency" in low
    assert "coinset.org" in low
    # Non-custodial: the wallet signs; the backend never moves assets.
    assert "non-custodial" in low
    assert "wallet signs every spend" in low


def test_on_chain_version_registry_is_the_source(doc_text: str) -> None:
    """A dedicated on-chain registry singleton is the version source of truth."""
    assert "vault_version_registry_inner.clsp" in doc_text
    assert "VAULT_INNER_MOD_HASH" in doc_text
    assert "CANONICAL_PARAMS_HASH" in doc_text
    assert "ADMIN_AUTHORITY_LAUNCHER_ID" in doc_text
    # Mirrors the proven protocol-config state machine.
    assert "protocol_config_inner" in doc_text


def test_publish_authority_binds_to_quorum_not_a_key(doc_text: str) -> None:
    """Publishes bind to the admin_authority_v2 live quorum, never a fixed key.

    1-of-1 (the admin) today via mofn1of1, MofN committee as the roster grows,
    with no registry/vault redeploy. Nothing is singly centralized.
    """
    assert "ADMIN_AUTHORITY_LAUNCHER_ID" in doc_text
    # The live testnet11 admin_authority_v2 launcher the registry binds to.
    assert (
        "0xf3fd2dedfc77a5b8f65acdfaff04d3786844a8c4d0529d3dbc4d37dc4012bb84"
        in doc_text
    )
    low = _lower(doc_text)
    assert "no key of its own" in low
    assert "never singly centralized" in low
    assert "mofn1of1" in low
    assert "supermajority" in low
    assert "admin_roster_update" in low


def test_governance_model_decision_is_documented(doc_text: str) -> None:
    """The SGT-vs-admin authorization decision must be explicitly pinned.

    Answers "is this properly documented?": the current reality (SGT governance
    is mint-scoped; vaults out of scope; committee vote unwired; admin<->SGT
    hook reserved) plus the open A/B/C decision for vault-version publishes.
    """
    low = _lower(doc_text)
    assert "governance model" in low
    # Current reality: SGT governance is mint-scoped; vaults are out of scope.
    assert "three fixed bills" in low
    for bill in ("MINT", "FREEZE", "SETTLE"):
        assert bill in doc_text
    assert "out of scope" in low
    assert "ratif" in low  # ratify / ratification
    # The admin<->SGT hook is reserved + unwired.
    assert "SGT_GOVERNANCE_PUZZLE_HASH" in doc_text
    # The committee on-chain SGT-VOTE path is not wired (501).
    assert "/admin/committee/vote" in doc_text
    assert "501" in doc_text


def test_emergency_vs_routine_determinant_is_code_vs_params(doc_text: str) -> None:
    """The emergency/routine tier is an objective CLVM-enforced property of the
    diff (does the vault CODE change), never an admin's discretionary label.
    """
    low = _lower(doc_text)
    assert "tiered by code-vs-parameter change" in low
    # Code change (VAULT_INNER_MOD_HASH) => always SGT ratification.
    assert "the vault code changes" in low
    assert "always requires affirmative sgt quorum ratification" in low
    # Params-only (CANONICAL_PARAMS_HASH, code byte-identical) => admin fast-track.
    assert "parameters only" in low
    assert "byte-identical" in low
    assert "fast-track" in low
    # Enforced structurally: the fast path asserts the code hash is unchanged.
    assert "new vault_inner_mod_hash == vault_inner_mod_hash" in low
    # Admin can never unilaterally change code; SGT is supreme (veto + cooldown).
    assert "can never unilaterally change the code" in low
    assert "sgt-vetoable" in low
    assert "cooldown" in low
    assert "sgt is supreme in every path" in low


def test_monotonic_version_guard(doc_text: str) -> None:
    """VAULT_VERSION must be monotonic; upgrade offered only on a higher version."""
    assert "VAULT_VERSION" in doc_text
    low = _lower(doc_text)
    assert "monotonically increasing" in low
    assert "strictly increasing" in low
    # The trigger is strictly an on-chain higher version, never a client value.
    assert "only when a new known vault version exists on chain" in low
    assert "advertises a higher" in low


def test_canonical_params_include_immutable_mint_params(doc_text: str) -> None:
    """Canonical identity must commit to the immutable-at-mint vault params."""
    assert "ZKPASSPORT_BRIDGE_POLICY_HASH" in doc_text
    assert "POOL_LAUNCHER_ID" in doc_text
    assert "POOL_SINGLETON_MOD_HASH" in doc_text
    assert "POOL_SINGLETON_LAUNCHER_PUZZLE_HASH" in doc_text


def test_outdated_detection_is_pure_client_side(doc_text: str) -> None:
    """A vault is current iff its mod-hash AND params-hash match the registry."""
    low = _lower(doc_text)
    assert "version identity" in low
    assert "outdated" in low
    assert "vault_inner_mod_hash" in low
    assert "canonical_params_hash" in low


def test_migrate_is_consensus_change_with_chicken_and_egg(doc_text: str) -> None:
    """Deed migration needs a new consensus spend case; only future vaults gain it."""
    low = _lower(doc_text)
    assert "migrate" in low
    assert "consensus change" in low
    assert "chicken-and-egg" in low
    # Pre-migrate vaults can only move freely-transferable assets.
    assert "freely-transferable" in low or "freely transferable" in low


def test_motivating_example_is_bridge_hash_bug(doc_text: str) -> None:
    """The doc anchors the motivation in the real bridge-policy-hash bug."""
    low = _lower(doc_text)
    assert "a59bd02" in low
    assert "un-enrollable" in low


def test_phased_brick_plan_present(doc_text: str) -> None:
    """The phased brick plan and open decisions must be pinned for follow-up."""
    low = _lower(doc_text)
    assert "phased brick plan" in low
    assert "vault_version_registry_inner.clsp" in doc_text
    assert "open decisions" in low
