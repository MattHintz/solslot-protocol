"""Unit tests for vault_version_registry_inner.clsp + driver (Brick 2).

The vault-version registry singleton publishes the canonical current vault
descriptor on-chain so any client can detect outdated vaults (decentralized,
backend-free).  These tests verify both the CLVM behaviour and the Python
driver, and critically that:

  * the off-chain ``compute_content_hash`` exactly mirrors the on-chain
    ``content-hash`` defun (read out of the published announcement), and
  * the cross-singleton authorization binding (ASSERT_PUZZLE_ANNOUNCEMENT keyed
    by the authorizer's real singleton puzzle hash) matches chia's actual
    singleton puzzle-hash construction, and
  * the tiered governance enforcement holds: the params-only fast-track path
    rejects any change to the vault CODE hash.
"""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_version_registry_driver import (
    PROTOCOL_PREFIX,
    SPEND_CODE_ROUTINE,
    SPEND_PARAMS_FASTTRACK,
    TAG_FASTTRACK,
    TAG_ROUTINE,
    VaultVersionRegistryState,
    build_fasttrack_spend,
    build_launch_registry_bundle,
    build_routine_spend,
    canonical_params_hash_from_vault_inner,
    compute_authorizer_announcement_id,
    compute_canonical_params_hash,
    compute_content_hash,
    is_vault_current,
    make_full_puzzle,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    parse_inner_puzzle,
    vault_version_registry_inner_mod,
    vault_version_registry_inner_mod_hash,
)

# ── CLVM condition opcodes ──────────────────────────────────────────────────
CREATE_COIN = 51
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
ASSERT_MY_AMOUNT = 73

# ── Distinct sentinels so a swapped-arg bug surfaces immediately ────────────
ADMIN_AUTHORITY_LAUNCHER_ID = bytes32(b"\xa1" * 32)
GOVERNANCE_LAUNCHER_ID = bytes32(b"\xb2" * 32)
VAULT_INNER_MOD_HASH = bytes32(b"\xc3" * 32)
CANONICAL_PARAMS_HASH = bytes32(b"\xd4" * 32)
VAULT_VERSION = 1

NEW_CANONICAL_PARAMS_HASH = bytes32(b"\xe5" * 32)
NEW_VAULT_INNER_MOD_HASH = bytes32(b"\xf6" * 32)
NEW_VAULT_VERSION = 2

SINGLETON_AMOUNT = 1

# Stand-in inner puzzles for the authorizing singletons (admin authority /
# governance).  The registry only consumes their tree hashes; their full
# singleton puzzle hash is the announcement key.
AUTHORITY_INNER = Program.to(1)
GOVERNANCE_INNER = Program.to((1, 2))


def _curry(
    *,
    vault_inner_mod_hash: bytes32 = VAULT_INNER_MOD_HASH,
    canonical_params_hash: bytes32 = CANONICAL_PARAMS_HASH,
    vault_version: int = VAULT_VERSION,
) -> Program:
    return make_inner_puzzle(
        admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
        governance_launcher_id=GOVERNANCE_LAUNCHER_ID,
        vault_inner_mod_hash=vault_inner_mod_hash,
        canonical_params_hash=canonical_params_hash,
        vault_version=vault_version,
    )


def _state(**kwargs) -> VaultVersionRegistryState:
    return parse_inner_puzzle(_curry(**kwargs))


def _singleton_full_ph(launcher_id: bytes32, inner_puzzle: Program) -> bytes32:
    """Ground-truth singleton full puzzle hash via chia's real top layer."""
    struct = Program.to((SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH)))
    return bytes32(SINGLETON_MOD.curry(struct, inner_puzzle).get_tree_hash())


def _run(curried: Program, solution: Program) -> list:
    return curried.run(solution).as_python()


def _of(conds: list, opcode: int) -> list:
    return [c for c in conds if int.from_bytes(c[0], "big") == opcode]


# ── Compile + module-hash sanity ────────────────────────────────────────────


class TestCompile:
    def test_module_compiles(self):
        mod = vault_version_registry_inner_mod()
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_module_hash_is_stable(self):
        h1 = vault_version_registry_inner_mod_hash()
        h2 = vault_version_registry_inner_mod_hash()
        assert h1 == h2
        assert len(h1) == 32


# ── content_hash determinism + field sensitivity ────────────────────────────


class TestContentHash:
    def test_determinism(self):
        h1 = compute_content_hash(VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, 1)
        h2 = compute_content_hash(VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, 1)
        assert h1 == h2
        assert len(h1) == 32

    def test_code_change_changes_hash(self):
        h1 = compute_content_hash(VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, 1)
        h2 = compute_content_hash(NEW_VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, 1)
        assert h1 != h2

    def test_params_change_changes_hash(self):
        h1 = compute_content_hash(VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, 1)
        h2 = compute_content_hash(VAULT_INNER_MOD_HASH, NEW_CANONICAL_PARAMS_HASH, 1)
        assert h1 != h2

    def test_version_change_changes_hash(self):
        h1 = compute_content_hash(VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, 1)
        h2 = compute_content_hash(VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, 2)
        assert h1 != h2


# ── State parse round-trip ──────────────────────────────────────────────────


class TestParse:
    def test_round_trip(self):
        state = _state()
        assert state.self_mod_hash == vault_version_registry_inner_mod_hash()
        assert state.singleton_mod_hash == bytes32(SINGLETON_MOD_HASH)
        assert state.launcher_puzzle_hash == bytes32(SINGLETON_LAUNCHER_HASH)
        assert state.admin_authority_launcher_id == ADMIN_AUTHORITY_LAUNCHER_ID
        assert state.governance_launcher_id == GOVERNANCE_LAUNCHER_ID
        assert state.vault_inner_mod_hash == VAULT_INNER_MOD_HASH
        assert state.canonical_params_hash == CANONICAL_PARAMS_HASH
        assert state.vault_version == VAULT_VERSION

    def test_content_hash_property_matches_helper(self):
        state = _state()
        assert state.content_hash == compute_content_hash(
            VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, VAULT_VERSION
        )

    def test_rejects_non_registry_puzzle(self):
        bogus = Program.to((1, [[1, b"nope"]])).curry(b"\x00" * 32)
        with pytest.raises(ValueError, match="does not instantiate"):
            parse_inner_puzzle(bogus)


# ── Params-only fast-track path ─────────────────────────────────────────────


class TestFastTrack:
    def _run_fasttrack(self):
        state = _state()
        art = build_fasttrack_spend(
            current=state,
            authorizer_inner_puzzle_hash=bytes32(AUTHORITY_INNER.get_tree_hash()),
            new_canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            new_vault_version=NEW_VAULT_VERSION,
        )
        conds = _run(_curry(), art.inner_solution)
        return conds, art

    def test_emits_exactly_four_conditions(self):
        conds, _ = self._run_fasttrack()
        assert len(conds) == 4

    def test_authorization_binds_to_admin_authority(self):
        conds, _ = self._run_fasttrack()
        # Code is preserved on the fast path, so the approval commits to the
        # ORIGINAL VAULT_INNER_MOD_HASH with the new params/version.
        authority_full_ph = _singleton_full_ph(
            ADMIN_AUTHORITY_LAUNCHER_ID, AUTHORITY_INNER
        )
        expected = compute_authorizer_announcement_id(
            authorizer_full_puzzle_hash=authority_full_ph,
            path_tag=TAG_FASTTRACK,
            vault_inner_mod_hash=VAULT_INNER_MOD_HASH,
            canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            vault_version=NEW_VAULT_VERSION,
        )
        asserts = _of(conds, ASSERT_PUZZLE_ANNOUNCEMENT)
        assert len(asserts) == 1
        assert asserts[0][1] == bytes(expected)

    def test_create_coin_recreates_self_with_new_state(self):
        conds, art = self._run_fasttrack()
        creates = _of(conds, CREATE_COIN)
        assert len(creates) == 1
        assert creates[0][1] == bytes(art.new_inner_puzzle_hash)
        assert int.from_bytes(creates[0][2], "big") == SINGLETON_AMOUNT

    def test_published_content_hash_matches_off_chain(self):
        conds, art = self._run_fasttrack()
        anns = _of(conds, CREATE_PUZZLE_ANNOUNCEMENT)
        assert len(anns) == 1
        msg = anns[0][1]
        assert msg[:1] == PROTOCOL_PREFIX
        # On-chain content_hash (tail of the announcement) must equal the
        # off-chain driver's computation.
        assert msg[1:] == bytes(art.new_content_hash)
        assert msg[1:] == bytes(
            compute_content_hash(
                VAULT_INNER_MOD_HASH, NEW_CANONICAL_PARAMS_HASH, NEW_VAULT_VERSION
            )
        )

    def test_assert_my_amount(self):
        conds, _ = self._run_fasttrack()
        amounts = _of(conds, ASSERT_MY_AMOUNT)
        assert len(amounts) == 1
        assert int.from_bytes(amounts[0][1], "big") == SINGLETON_AMOUNT

    def test_rejects_code_change_on_fast_path(self):
        # Hand-rolled solution attempting a CODE change via the fast-track case.
        sol = Program.to(
            [
                SPEND_PARAMS_FASTTRACK,
                SINGLETON_AMOUNT,
                bytes32(AUTHORITY_INNER.get_tree_hash()),
                NEW_VAULT_INNER_MOD_HASH,  # code changed — must be rejected
                NEW_CANONICAL_PARAMS_HASH,
                NEW_VAULT_VERSION,
            ]
        )
        with pytest.raises(ValueError):
            _run(_curry(), sol)


# ── Code-change routine path ────────────────────────────────────────────────


class TestRoutine:
    def _run_routine(self):
        state = _state()
        art = build_routine_spend(
            current=state,
            authorizer_inner_puzzle_hash=bytes32(GOVERNANCE_INNER.get_tree_hash()),
            new_vault_inner_mod_hash=NEW_VAULT_INNER_MOD_HASH,
            new_canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            new_vault_version=NEW_VAULT_VERSION,
        )
        conds = _run(_curry(), art.inner_solution)
        return conds, art

    def test_allows_code_change(self):
        conds, art = self._run_routine()
        creates = _of(conds, CREATE_COIN)
        assert len(creates) == 1
        assert creates[0][1] == bytes(art.new_inner_puzzle_hash)

    def test_authorization_binds_to_governance(self):
        conds, _ = self._run_routine()
        gov_full_ph = _singleton_full_ph(GOVERNANCE_LAUNCHER_ID, GOVERNANCE_INNER)
        expected = compute_authorizer_announcement_id(
            authorizer_full_puzzle_hash=gov_full_ph,
            path_tag=TAG_ROUTINE,
            vault_inner_mod_hash=NEW_VAULT_INNER_MOD_HASH,
            canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            vault_version=NEW_VAULT_VERSION,
        )
        asserts = _of(conds, ASSERT_PUZZLE_ANNOUNCEMENT)
        assert len(asserts) == 1
        assert asserts[0][1] == bytes(expected)

    def test_routine_approval_differs_from_fasttrack(self):
        # Same target state, but the two tiers must produce DIFFERENT approval
        # ids (different authorizer + path tag) so approvals can't cross tiers.
        gov_full_ph = _singleton_full_ph(GOVERNANCE_LAUNCHER_ID, GOVERNANCE_INNER)
        authority_full_ph = _singleton_full_ph(
            ADMIN_AUTHORITY_LAUNCHER_ID, GOVERNANCE_INNER
        )
        routine = compute_authorizer_announcement_id(
            authorizer_full_puzzle_hash=gov_full_ph,
            path_tag=TAG_ROUTINE,
            vault_inner_mod_hash=NEW_VAULT_INNER_MOD_HASH,
            canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            vault_version=NEW_VAULT_VERSION,
        )
        fast = compute_authorizer_announcement_id(
            authorizer_full_puzzle_hash=authority_full_ph,
            path_tag=TAG_FASTTRACK,
            vault_inner_mod_hash=NEW_VAULT_INNER_MOD_HASH,
            canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            vault_version=NEW_VAULT_VERSION,
        )
        assert routine != fast


# ── Replay / version protection + dispatch guards ───────────────────────────


class TestGuards:
    def test_driver_rejects_version_downgrade(self):
        state = _state(vault_version=10)
        with pytest.raises(ValueError, match="strictly exceed"):
            build_fasttrack_spend(
                current=state,
                authorizer_inner_puzzle_hash=bytes32(
                    AUTHORITY_INNER.get_tree_hash()
                ),
                new_canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
                new_vault_version=10,  # equal — must reject
            )

    def test_clvm_rejects_version_downgrade(self):
        curried = _curry(vault_version=10)
        sol = Program.to(
            [
                SPEND_PARAMS_FASTTRACK,
                SINGLETON_AMOUNT,
                bytes32(AUTHORITY_INNER.get_tree_hash()),
                VAULT_INNER_MOD_HASH,
                NEW_CANONICAL_PARAMS_HASH,
                5,  # downgrade
            ]
        )
        with pytest.raises(ValueError):
            _run(curried, sol)

    def test_clvm_rejects_equal_version(self):
        curried = _curry(vault_version=10)
        sol = Program.to(
            [
                SPEND_PARAMS_FASTTRACK,
                SINGLETON_AMOUNT,
                bytes32(AUTHORITY_INNER.get_tree_hash()),
                VAULT_INNER_MOD_HASH,
                NEW_CANONICAL_PARAMS_HASH,
                10,  # equal
            ]
        )
        with pytest.raises(ValueError):
            _run(curried, sol)

    def test_clvm_rejects_unknown_spend_case(self):
        sol = Program.to(
            [
                99,  # unknown spend case
                SINGLETON_AMOUNT,
                bytes32(AUTHORITY_INNER.get_tree_hash()),
                VAULT_INNER_MOD_HASH,
                NEW_CANONICAL_PARAMS_HASH,
                NEW_VAULT_VERSION,
            ]
        )
        with pytest.raises(ValueError):
            _run(_curry(), sol)


class TestCanonicalParamsHashAndDetection:
    """compute_canonical_params_hash + outdated detection (Brick 4b).

    These pin the canonical convention the registry publish path and the portal
    detection path BOTH rely on: CANONICAL_PARAMS_HASH = sha256tree of the four
    protocol-level vault params, in a fixed order.
    """

    POOL_MOD = bytes32(b"\x71" * 32)
    POOL_LAUNCHER = bytes32(b"\x72" * 32)
    POOL_LAUNCHER_PH = bytes32(b"\x73" * 32)
    BRIDGE_HASH = bytes32(b"\x74" * 32)

    def _cph(self, **overrides):
        params = dict(
            pool_singleton_mod_hash=self.POOL_MOD,
            pool_launcher_id=self.POOL_LAUNCHER,
            pool_singleton_launcher_puzzle_hash=self.POOL_LAUNCHER_PH,
            zkpassport_bridge_policy_hash=self.BRIDGE_HASH,
        )
        params.update(overrides)
        return compute_canonical_params_hash(**params)

    def test_matches_sha256tree_of_four_atoms_in_order(self):
        """This IS the cross-language contract the TS portal must reproduce."""
        expected = bytes32(
            Program.to(
                [self.POOL_MOD, self.POOL_LAUNCHER, self.POOL_LAUNCHER_PH, self.BRIDGE_HASH]
            ).get_tree_hash()
        )
        assert self._cph() == expected

    def test_is_deterministic(self):
        assert self._cph() == self._cph()

    def test_is_order_sensitive(self):
        # Swapping two distinct params must change the hash (arg-order guard).
        swapped = compute_canonical_params_hash(
            pool_singleton_mod_hash=self.POOL_LAUNCHER,
            pool_launcher_id=self.POOL_MOD,
            pool_singleton_launcher_puzzle_hash=self.POOL_LAUNCHER_PH,
            zkpassport_bridge_policy_hash=self.BRIDGE_HASH,
        )
        assert swapped != self._cph()

    def test_changes_with_each_param(self):
        assert self._cph(pool_singleton_mod_hash=bytes32(b"\x99" * 32)) != self._cph()
        assert self._cph(pool_launcher_id=bytes32(b"\x99" * 32)) != self._cph()
        assert self._cph(pool_singleton_launcher_puzzle_hash=bytes32(b"\x99" * 32)) != self._cph()
        assert self._cph(zkpassport_bridge_policy_hash=bytes32(b"\x99" * 32)) != self._cph()

    def test_rejects_non_32_byte_param(self):
        with pytest.raises(ValueError):
            compute_canonical_params_hash(
                pool_singleton_mod_hash=b"\x71" * 31,
                pool_launcher_id=self.POOL_LAUNCHER,
                pool_singleton_launcher_puzzle_hash=self.POOL_LAUNCHER_PH,
                zkpassport_bridge_policy_hash=self.BRIDGE_HASH,
            )

    def test_from_vault_inner_matches_explicit_params(self):
        """A live vault's canonical params hash == the explicit hash of its
        four protocol-level curried params."""
        from solslot_puzzles.vault_driver import (
            AUTH_TYPE_BLS,
            one_leaf_merkle_root,
            puzzle_for_vault_inner,
        )

        owner = bytes(48)
        pool_launcher = bytes32(b"\x55" * 32)
        bridge = bytes32(b"\x66" * 32)
        vault_inner = puzzle_for_vault_inner(
            bytes32(b"\xaa" * 32),  # per-user vault launcher (not a canonical param)
            owner,
            AUTH_TYPE_BLS,
            one_leaf_merkle_root(owner),
            pool_launcher,
            zkpassport_bridge_policy_hash=bridge,
        )
        got = canonical_params_hash_from_vault_inner(vault_inner)
        expected = compute_canonical_params_hash(
            pool_singleton_mod_hash=bytes32(SINGLETON_MOD_HASH),
            pool_launcher_id=pool_launcher,
            pool_singleton_launcher_puzzle_hash=bytes32(SINGLETON_LAUNCHER_HASH),
            zkpassport_bridge_policy_hash=bridge,
        )
        assert got == expected

    def test_is_vault_current_true_when_matching_false_on_drift(self):
        from solslot_puzzles.vault_driver import (
            VAULT_INNER_MOD,
            AUTH_TYPE_BLS,
            one_leaf_merkle_root,
            puzzle_for_vault_inner,
        )

        owner = bytes(48)
        pool_launcher = bytes32(b"\x55" * 32)
        good_bridge = bytes32(b"\x66" * 32)

        def vault_with(bridge):
            return puzzle_for_vault_inner(
                bytes32(b"\xaa" * 32),
                owner,
                AUTH_TYPE_BLS,
                one_leaf_merkle_root(owner),
                pool_launcher,
                zkpassport_bridge_policy_hash=bridge,
            )

        vault_mod_hash = bytes32(VAULT_INNER_MOD.get_tree_hash())
        cph = canonical_params_hash_from_vault_inner(vault_with(good_bridge))
        registry = _state(vault_inner_mod_hash=vault_mod_hash, canonical_params_hash=cph)

        # Matching vault -> CURRENT.
        assert is_vault_current(
            registry=registry,
            vault_inner_mod_hash=vault_mod_hash,
            vault_canonical_params_hash=cph,
        ) is True

        # Params drift (the bridge-policy-hash bug: zero hash) -> OUTDATED.
        bad_cph = canonical_params_hash_from_vault_inner(vault_with(bytes32(b"\x00" * 32)))
        assert is_vault_current(
            registry=registry,
            vault_inner_mod_hash=vault_mod_hash,
            vault_canonical_params_hash=bad_cph,
        ) is False

        # Code drift (different vault mod hash) -> OUTDATED.
        assert is_vault_current(
            registry=registry,
            vault_inner_mod_hash=bytes32(b"\x01" * 32),
            vault_canonical_params_hash=cph,
        ) is False


class TestRegistryLaunch:
    """Genesis launch builder — deploy the registry singleton (Brick 4c)."""

    def _launch(self, *, amount=1_000_000, **overrides):
        parent_puzzle = Program.to(1)
        parent_coin = Coin(
            bytes32(b"\x01" * 32),
            bytes32(parent_puzzle.get_tree_hash()),
            amount,
        )
        params = dict(
            parent_coin=parent_coin,
            parent_puzzle=parent_puzzle,
            admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
            governance_launcher_id=GOVERNANCE_LAUNCHER_ID,
            vault_inner_mod_hash=VAULT_INNER_MOD_HASH,
            canonical_params_hash=CANONICAL_PARAMS_HASH,
        )
        params.update(overrides)
        return parent_coin, build_launch_registry_bundle(**params)

    def _spend_for(self, art, *, coin_name=None, puzzle_hash=None):
        for s in art.unsigned_bundle.coin_spends:
            if coin_name is not None and bytes32(s.coin.name()) == coin_name:
                return s
            if puzzle_hash is not None and bytes32(s.coin.puzzle_hash) == bytes32(puzzle_hash):
                return s
        raise AssertionError("no matching coin spend")

    def test_bundle_has_parent_and_launcher_spends(self):
        parent_coin, art = self._launch()
        spends = list(art.unsigned_bundle.coin_spends)
        assert len(spends) == 2
        # registry_launcher_id == name of the launcher coin (child of parent).
        launcher = Coin(parent_coin.name(), bytes32(SINGLETON_LAUNCHER_HASH), 1)
        assert art.registry_launcher_id == bytes32(launcher.name())
        spent = {bytes32(s.coin.name()) for s in spends}
        assert parent_coin.name() in spent
        assert bytes32(launcher.name()) in spent

    def test_launcher_solution_commits_to_full_puzzle_hash(self):
        _, art = self._launch()
        launcher_spend = self._spend_for(art, puzzle_hash=SINGLETON_LAUNCHER_HASH)
        sol = Program.from_bytes(bytes(launcher_spend.solution))
        committed_ph = bytes32(list(sol.as_iter())[0].as_atom())
        assert committed_ph == art.registry_full_puzzle_hash
        # And the full puzzle hash is the singleton-wrapped inner at launch state.
        expected = make_full_puzzle(
            launcher_id=art.registry_launcher_id,
            admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
            governance_launcher_id=GOVERNANCE_LAUNCHER_ID,
            vault_inner_mod_hash=VAULT_INNER_MOD_HASH,
            canonical_params_hash=CANONICAL_PARAMS_HASH,
            vault_version=1,
        ).get_tree_hash()
        assert art.registry_full_puzzle_hash == bytes32(expected)

    def test_parent_creates_launcher_and_change(self):
        parent_coin, art = self._launch(amount=1_000_000)
        parent_spend = self._spend_for(art, coin_name=parent_coin.name())
        sol = Program.from_bytes(bytes(parent_spend.solution))
        # solution_for_conditions = [[], delegated_puzzle, 0]
        # delegated_puzzle = (1 . conditions)
        delegated_puzzle = sol.rest().first()
        conditions_list = delegated_puzzle.rest()
        conds = [list(c.as_iter()) for c in conditions_list.as_iter()]
        create = [c for c in conds if c and c[0].as_int() == 51]
        # Launcher coin: CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1).
        assert any(
            bytes32(c[1].as_atom()) == bytes32(SINGLETON_LAUNCHER_HASH) and c[2].as_int() == 1
            for c in create
        )
        # Change: CREATE_COIN(parent puzzle hash, amount - 1).
        assert any(
            bytes32(c[1].as_atom()) == bytes32(parent_coin.puzzle_hash)
            and c[2].as_int() == parent_coin.amount - 1
            for c in create
        )

    def test_launch_state_round_trips_and_content_hash(self):
        _, art = self._launch()
        inner = make_inner_puzzle(
            admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
            governance_launcher_id=GOVERNANCE_LAUNCHER_ID,
            vault_inner_mod_hash=VAULT_INNER_MOD_HASH,
            canonical_params_hash=CANONICAL_PARAMS_HASH,
            vault_version=1,
        )
        state = parse_inner_puzzle(inner)
        assert state.vault_inner_mod_hash == VAULT_INNER_MOD_HASH
        assert state.canonical_params_hash == CANONICAL_PARAMS_HASH
        assert state.vault_version == 1
        assert art.content_hash == state.content_hash
        assert art.registry_inner_puzzle_hash == bytes32(inner.get_tree_hash())

    def test_launch_then_fasttrack_publish_is_consistent(self):
        """A params-only fast-track from the launched state recurries correctly."""
        _, art = self._launch()
        state = parse_inner_puzzle(
            make_inner_puzzle(
                admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
                governance_launcher_id=GOVERNANCE_LAUNCHER_ID,
                vault_inner_mod_hash=VAULT_INNER_MOD_HASH,
                canonical_params_hash=CANONICAL_PARAMS_HASH,
                vault_version=1,
            )
        )
        published = build_fasttrack_spend(
            current=state,
            authorizer_inner_puzzle_hash=bytes32(AUTHORITY_INNER.get_tree_hash()),
            new_canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            new_vault_version=2,
        )
        expected_next = make_inner_puzzle_hash(
            admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
            governance_launcher_id=GOVERNANCE_LAUNCHER_ID,
            vault_inner_mod_hash=VAULT_INNER_MOD_HASH,  # code unchanged on fast-track
            canonical_params_hash=NEW_CANONICAL_PARAMS_HASH,
            vault_version=2,
        )
        assert published.new_inner_puzzle_hash == expected_next

    def test_rejects_small_parent(self):
        with pytest.raises(ValueError):
            self._launch(amount=1, fee=5)

    def test_rejects_non_32_byte_param(self):
        with pytest.raises(ValueError):
            self._launch(vault_inner_mod_hash=b"\xc3" * 31)

    def test_rejects_version_below_1(self):
        with pytest.raises(ValueError):
            self._launch(vault_version=0)
