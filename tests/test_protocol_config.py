"""Unit tests for protocol_config_inner.clsp + protocol_config_driver.py.

The protocol-config singleton (A.3) is the on-chain replacement for
three off-chain trust roots that the Solslot API previously carried as
environment variables (POOL/GOV/NETWORK launcher ids).  These tests
verify both the puzzle's CLVM behaviour and the Python driver, and —
critically — that the off-chain ``compute_content_hash`` exactly
mirrors the on-chain ``content-hash`` defun.  Any divergence between
the two would silently break the EIP-712 ``protocolConfigHash``
binding, so this test file is the canonical regression for that
contract.
"""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_config_driver import (
    NETWORK_ID_MAINNET,
    NETWORK_ID_TESTNET11,
    ProtocolConfigState,
    UpdateSpendArtifacts,
    build_update_spend,
    compute_content_hash,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    parse_inner_puzzle,
    protocol_config_inner_mod,
    protocol_config_inner_mod_hash,
)


# ── Test fixtures ────────────────────────────────────────────────────────

# Distinct sentinel values so a swapped-arg bug shows up immediately as a
# wrong field rather than a coincidental collision.
GOV_PUBKEY = b"\x33" * 48
POOL_LAUNCHER_ID = bytes32(b"\xaa" * 32)
GOV_TRACKER_LAUNCHER_ID = bytes32(b"\xbb" * 32)
CONFIG_VERSION = 1

NEW_POOL_LAUNCHER_ID = bytes32(b"\xcc" * 32)
NEW_GOV_TRACKER_LAUNCHER_ID = bytes32(b"\xdd" * 32)
NEW_CONFIG_VERSION = 2

SINGLETON_AMOUNT = 1  # singletons use odd amounts


def _make_state() -> ProtocolConfigState:
    return ProtocolConfigState(
        self_mod_hash=protocol_config_inner_mod_hash(),
        gov_pubkey=GOV_PUBKEY,
        pool_launcher_id=POOL_LAUNCHER_ID,
        gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
        network_id=NETWORK_ID_TESTNET11,
        config_version=CONFIG_VERSION,
    )


# ── Compile + module-hash sanity ────────────────────────────────────────


class TestCompile:
    def test_module_compiles(self):
        mod = protocol_config_inner_mod()
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_module_hash_is_stable(self):
        # Computing the hash twice must agree — guards against any
        # non-determinism in the load_clvm cache layer.
        h1 = protocol_config_inner_mod_hash()
        h2 = protocol_config_inner_mod_hash()
        assert h1 == h2
        assert len(h1) == 32


# ── content_hash determinism ────────────────────────────────────────────


class TestContentHash:
    """The single off-chain ↔ on-chain binding point.

    Two flavours of regression here:
      1. Determinism (same inputs → same hash, repeated).
      2. Field sensitivity (any input change → different hash).
    """

    def test_determinism(self):
        h1 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        h2 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        assert h1 == h2
        assert len(h1) == 32

    def test_pool_launcher_change_changes_hash(self):
        h1 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        h2 = compute_content_hash(
            NEW_POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        assert h1 != h2

    def test_gov_tracker_change_changes_hash(self):
        h1 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        h2 = compute_content_hash(
            POOL_LAUNCHER_ID, NEW_GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        assert h1 != h2

    def test_network_change_changes_hash(self):
        h1 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        h2 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_MAINNET, 1
        )
        assert h1 != h2

    def test_version_change_changes_hash(self):
        h1 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )
        h2 = compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 2
        )
        assert h1 != h2

    def test_content_hash_matches_on_chain(self):
        """The Python ``compute_content_hash`` MUST equal the Chialisp
        ``content-hash`` defun.  This is THE contract that lets the
        EIP-712 envelope bind to on-chain state safely.

        We don't have a clean way to call the Chialisp ``content-hash``
        in isolation (it's a defun-inline inside the puzzle body), so
        we exercise it via a successful update spend and inspect the
        ``CREATE_PUZZLE_ANNOUNCEMENT`` message (which embeds the same
        ``content-hash`` output, prefixed by ``PROTOCOL_PREFIX = 0x53``).
        """
        from solslot_puzzles.protocol_config_driver import (
            build_update_spend,
        )

        state = _make_state()
        artifacts = build_update_spend(
            current=state,
            new_pool_launcher_id=NEW_POOL_LAUNCHER_ID,
            new_gov_tracker_launcher_id=NEW_GOV_TRACKER_LAUNCHER_ID,
            new_network_id=NETWORK_ID_TESTNET11,
            new_config_version=NEW_CONFIG_VERSION,
            my_amount=SINGLETON_AMOUNT,
        )

        # Run the puzzle to inspect the conditions list.
        curried = make_inner_puzzle(
            gov_pubkey=GOV_PUBKEY,
            pool_launcher_id=POOL_LAUNCHER_ID,
            gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
            network_id=NETWORK_ID_TESTNET11,
            config_version=CONFIG_VERSION,
        )
        result = curried.run(artifacts.inner_solution)
        conditions = result.as_python()

        # Find the CREATE_PUZZLE_ANNOUNCEMENT (opcode 62).
        announcements = [c for c in conditions if c[0] == bytes([62])]
        assert len(announcements) == 1, "exactly one CREATE_PUZZLE_ANNOUNCEMENT"
        msg = announcements[0][1]

        # Message is PROTOCOL_PREFIX (0x53) || content-hash(new_state).
        assert msg[:1] == b"\x53", "message must start with PROTOCOL_PREFIX"
        on_chain_content_hash = msg[1:]
        assert len(on_chain_content_hash) == 32

        # The off-chain driver's compute_content_hash MUST equal what
        # the Chialisp produced.  This is the canonical assertion.
        off_chain = compute_content_hash(
            NEW_POOL_LAUNCHER_ID,
            NEW_GOV_TRACKER_LAUNCHER_ID,
            NETWORK_ID_TESTNET11,
            NEW_CONFIG_VERSION,
        )
        assert on_chain_content_hash == bytes(off_chain), (
            "off-chain content_hash must equal on-chain content-hash; "
            "any divergence silently breaks the EIP-712 binding"
        )


# ── Inner puzzle round-trip ─────────────────────────────────────────────


class TestParse:
    def test_round_trip(self):
        puzzle = make_inner_puzzle(
            gov_pubkey=GOV_PUBKEY,
            pool_launcher_id=POOL_LAUNCHER_ID,
            gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
            network_id=NETWORK_ID_TESTNET11,
            config_version=CONFIG_VERSION,
        )
        state = parse_inner_puzzle(puzzle)
        assert state.gov_pubkey == GOV_PUBKEY
        assert state.pool_launcher_id == POOL_LAUNCHER_ID
        assert state.gov_tracker_launcher_id == GOV_TRACKER_LAUNCHER_ID
        assert state.network_id == NETWORK_ID_TESTNET11
        assert state.config_version == CONFIG_VERSION
        assert state.self_mod_hash == protocol_config_inner_mod_hash()

    def test_state_content_hash_property(self):
        """``ProtocolConfigState.content_hash`` must equal a fresh compute."""
        state = _make_state()
        assert state.content_hash == compute_content_hash(
            POOL_LAUNCHER_ID, GOV_TRACKER_LAUNCHER_ID, NETWORK_ID_TESTNET11, 1
        )

    def test_parse_rejects_non_curried(self):
        # chia's Program.uncurry() doesn't return None for a bare module
        # — it returns ``(body, body_args)`` where the body's tree hash
        # doesn't match our compiled mod hash.  The parse function
        # therefore rejects with the "does not instantiate" error path
        # rather than the "not curried" path.  Either rejection is
        # acceptable; what matters is the bare puzzle is refused.
        bare = protocol_config_inner_mod()  # not curried
        with pytest.raises(ValueError):
            parse_inner_puzzle(bare)

    def test_parse_rejects_wrong_module(self):
        # A different curried program — same arity but wrong mod hash.
        from chia.wallet.puzzles.load_clvm import load_clvm
        other = load_clvm(
            "quorum_did_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        ).curry(b"\x00" * 32)
        with pytest.raises(ValueError, match="protocol_config_inner"):
            parse_inner_puzzle(other)


# ── Update spend conditions ──────────────────────────────────────────────


class TestUpdateSpend:
    """Drive a full update spend via the curried puzzle and assert that
    every required condition is emitted with the right operands.
    """

    def _run(self, *, version_bump: int = 1) -> tuple[list, UpdateSpendArtifacts]:
        state = _make_state()
        artifacts = build_update_spend(
            current=state,
            new_pool_launcher_id=NEW_POOL_LAUNCHER_ID,
            new_gov_tracker_launcher_id=NEW_GOV_TRACKER_LAUNCHER_ID,
            new_network_id=NETWORK_ID_TESTNET11,
            new_config_version=CONFIG_VERSION + version_bump,
            my_amount=SINGLETON_AMOUNT,
        )
        curried = make_inner_puzzle(
            gov_pubkey=GOV_PUBKEY,
            pool_launcher_id=POOL_LAUNCHER_ID,
            gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
            network_id=NETWORK_ID_TESTNET11,
            config_version=CONFIG_VERSION,
        )
        result = curried.run(artifacts.inner_solution)
        return result.as_python(), artifacts

    def test_emits_four_conditions(self):
        conditions, _ = self._run()
        # AGG_SIG_ME, CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT, ASSERT_MY_AMOUNT
        assert len(conditions) == 4

    def test_agg_sig_me(self):
        conditions, artifacts = self._run()
        agg_sigs = [c for c in conditions if c[0] == bytes([50])]
        assert len(agg_sigs) == 1
        sig_pubkey = agg_sigs[0][1]
        sig_msg = agg_sigs[0][2]
        assert sig_pubkey == GOV_PUBKEY
        # Per the puzzle: AGG_SIG_ME signs the new content_hash directly.
        assert sig_msg == bytes(artifacts.agg_sig_me_message)

    def test_create_coin_recreates_self_with_new_state(self):
        conditions, artifacts = self._run()
        creates = [c for c in conditions if c[0] == bytes([51])]
        assert len(creates) == 1
        dest_puzhash = creates[0][1]
        amount_bytes = creates[0][2]
        assert dest_puzhash == bytes(artifacts.new_inner_puzzle_hash)
        assert int.from_bytes(amount_bytes, "big") == SINGLETON_AMOUNT

    def test_create_puzzle_announcement_carries_new_content_hash(self):
        conditions, artifacts = self._run()
        announcements = [c for c in conditions if c[0] == bytes([62])]
        assert len(announcements) == 1
        msg = announcements[0][1]
        assert msg[:1] == b"\x53", "PROTOCOL_PREFIX"
        assert msg[1:] == bytes(artifacts.new_content_hash)

    def test_assert_my_amount(self):
        conditions, _ = self._run()
        amount_asserts = [c for c in conditions if c[0] == bytes([73])]
        assert len(amount_asserts) == 1
        assert int.from_bytes(amount_asserts[0][1], "big") == SINGLETON_AMOUNT


# ── Replay / version protection ──────────────────────────────────────────


class TestReplayProtection:
    def test_python_rejects_version_downgrade(self):
        state = _make_state()
        with pytest.raises(ValueError, match="strictly exceed"):
            build_update_spend(
                current=state,
                new_pool_launcher_id=NEW_POOL_LAUNCHER_ID,
                new_gov_tracker_launcher_id=NEW_GOV_TRACKER_LAUNCHER_ID,
                new_network_id=NETWORK_ID_TESTNET11,
                new_config_version=CONFIG_VERSION,  # same — must reject
                my_amount=SINGLETON_AMOUNT,
            )

    def test_python_rejects_explicit_downgrade(self):
        state = ProtocolConfigState(
            self_mod_hash=protocol_config_inner_mod_hash(),
            gov_pubkey=GOV_PUBKEY,
            pool_launcher_id=POOL_LAUNCHER_ID,
            gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
            network_id=NETWORK_ID_TESTNET11,
            config_version=10,
        )
        with pytest.raises(ValueError, match="strictly exceed"):
            build_update_spend(
                current=state,
                new_pool_launcher_id=NEW_POOL_LAUNCHER_ID,
                new_gov_tracker_launcher_id=NEW_GOV_TRACKER_LAUNCHER_ID,
                new_network_id=NETWORK_ID_TESTNET11,
                new_config_version=5,
                my_amount=SINGLETON_AMOUNT,
            )

    def test_clvm_rejects_version_downgrade(self):
        """If the Python guard is bypassed somehow (hand-rolled solution),
        the on-chain ``(> new_config_version CONFIG_VERSION)`` assertion
        must still reject.  This is the defence-in-depth check.
        """
        curried = make_inner_puzzle(
            gov_pubkey=GOV_PUBKEY,
            pool_launcher_id=POOL_LAUNCHER_ID,
            gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
            network_id=NETWORK_ID_TESTNET11,
            config_version=10,  # higher current version
        )
        # Hand-rolled solution attempting downgrade to version 5.
        sol = Program.to(
            [
                SINGLETON_AMOUNT,
                NEW_POOL_LAUNCHER_ID,
                NEW_GOV_TRACKER_LAUNCHER_ID,
                NETWORK_ID_TESTNET11,
                5,  # downgrade
            ]
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_clvm_rejects_equal_version(self):
        curried = make_inner_puzzle(
            gov_pubkey=GOV_PUBKEY,
            pool_launcher_id=POOL_LAUNCHER_ID,
            gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
            network_id=NETWORK_ID_TESTNET11,
            config_version=10,
        )
        sol = Program.to(
            [
                SINGLETON_AMOUNT,
                NEW_POOL_LAUNCHER_ID,
                NEW_GOV_TRACKER_LAUNCHER_ID,
                NETWORK_ID_TESTNET11,
                10,  # equal
            ]
        )
        with pytest.raises(ValueError):
            curried.run(sol)


# ── Input validation ────────────────────────────────────────────────────


class TestInputValidation:
    def test_clvm_rejects_short_pool_launcher_id(self):
        curried = make_inner_puzzle(
            gov_pubkey=GOV_PUBKEY,
            pool_launcher_id=POOL_LAUNCHER_ID,
            gov_tracker_launcher_id=GOV_TRACKER_LAUNCHER_ID,
            network_id=NETWORK_ID_TESTNET11,
            config_version=CONFIG_VERSION,
        )
        sol = Program.to(
            [
                SINGLETON_AMOUNT,
                b"\xcc" * 16,  # too short
                NEW_GOV_TRACKER_LAUNCHER_ID,
                NETWORK_ID_TESTNET11,
                NEW_CONFIG_VERSION,
            ]
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_python_rejects_even_amount(self):
        state = _make_state()
        with pytest.raises(ValueError, match="amount must be odd"):
            build_update_spend(
                current=state,
                new_pool_launcher_id=NEW_POOL_LAUNCHER_ID,
                new_gov_tracker_launcher_id=NEW_GOV_TRACKER_LAUNCHER_ID,
                new_network_id=NETWORK_ID_TESTNET11,
                new_config_version=NEW_CONFIG_VERSION,
                my_amount=2,  # even
            )

    def test_python_rejects_short_launcher_id(self):
        state = _make_state()
        with pytest.raises(ValueError, match="must be 32 bytes"):
            build_update_spend(
                current=state,
                new_pool_launcher_id=b"\xcc" * 16,  # type: ignore[arg-type]
                new_gov_tracker_launcher_id=NEW_GOV_TRACKER_LAUNCHER_ID,
                new_network_id=NETWORK_ID_TESTNET11,
                new_config_version=NEW_CONFIG_VERSION,
                my_amount=SINGLETON_AMOUNT,
            )
