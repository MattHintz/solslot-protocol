"""Authority state announcements cannot originate in delegated conditions."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.util.errors import Err
from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import FROZEN_CHECKSUM, PUZZLE_FILENAMES, load_puzzle
from solslot_puzzles import admin_authority_v3_driver as driver
from solslot_puzzles.artifact_schema_v4 import (
    _rebuild_plan,
    artifact_hash,
    verify_public_artifact,
)
from tests import test_admin_authority_v3 as authority_tests
from tests.test_artifact_schema_v4 import _accept, _artifact
from tests.test_sols_reserve_seed_v2 import public


def _operational(fixture, conditions):
    delegated = Program.to((1, conditions))
    mips = driver.build_authority_operational_mips_spend(
        authority=fixture.authority,
        current_authority_inner_puzzle=fixture.authority.inner_puzzle,
        current_identities=fixture.authority.identity_vaults,
        current_identity_coin_ids=fixture.identity_coin_ids,
        authority_delegated_puzzle=delegated,
        coadmin_slot=2,
    )
    solution = driver.build_operational_solution(
        my_amount=driver.AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=2,
        mips_reveal=mips.reveal,
        mips_solution=mips.solution,
        authority_delegated_puzzle=delegated,
        identity_records=mips.identity_records,
    )
    return delegated, mips, solution


@pytest.mark.parametrize("tag", (0, 1, 2, 3, 4, 5, 6, 255))
@pytest.mark.parametrize("copies", (1, 2))
def test_operational_rejects_reserved_announcements_even_when_duplicated(tag, copies):
    fixture = authority_tests._fixture(authority_puzzle_version=4)
    injected = b"\x53" + bytes([tag]) + b"\xab" * 32
    _, _, solution = _operational(fixture, [[62, injected]] * copies)
    with pytest.raises(ValueError):
        fixture.authority.inner_puzzle.run(solution, flags=authority_tests.RUN_FLAGS)


@pytest.mark.parametrize(
    "message",
    (b"", b"\x53", b"\x53" + b"x" * 31,
     b"\x52\x03" + b"x" * 32, b"\x53\x03" + b"x" * 33),
)
def test_operational_preserves_unreserved_announcements(message):
    fixture = authority_tests._fixture(authority_puzzle_version=4)
    _, _, solution = _operational(fixture, [[62, message], [62, message]])
    result = fixture.authority.inner_puzzle.run(solution, flags=authority_tests.RUN_FLAGS)
    announcements = authority_tests._condition_values(result, 62)
    assert sum(item[1] == message for item in announcements) == 2
    assert any(
        item[1].startswith(b"\x53\x01") and len(item[1]) == 34
        for item in announcements
    )


@pytest.mark.parametrize("version", (3, 4))
@pytest.mark.parametrize("boundary", ("prepare_mips", "replacement_member"))
@pytest.mark.parametrize(
    "kind",
    (driver.PENDING_ROUTINE, driver.PENDING_LOST, driver.PENDING_RECOVERY_KIT),
)
def test_prepare_checks_each_external_condition_boundary(version, boundary, kind):
    fixture = authority_tests._fixture(authority_puzzle_version=version)
    transition, replacement_key = authority_tests._transition(fixture, slot=1, kind=kind)
    injected = b"\x53\x03" + b"\xab" * 32
    if boundary == "replacement_member":
        member = Program.to((1, [[62, injected], [62, injected]]))
        member_hash = bytes32(member.get_tree_hash())
        binding = driver.compute_prepare_binding_hash(
            pending_kind=kind,
            slot=transition.slot,
            intent_hash=transition.intent_hash,
            current_identity_coin_id=transition.current_identity_coin_id,
            intermediate_identity_coin_id=transition.intermediate_identity_coin_id,
            original_custody_hash=transition.original_custody_hash,
            intermediate_custody_hash=transition.intermediate_custody_hash,
            replacement_custody_hash=transition.final_custody_hash,
            replacement_member_hash=member_hash,
            source_manifest_hash=authority_tests.SOURCE_MANIFEST_HASH,
            current_authority_version=1,
            new_authority_version=2,
            identity_launcher_id=fixture.authority.identity_vaults[1].launcher_id,
        )
        tag = {
            driver.PENDING_ROUTINE: driver.SPEND_PREPARE_ROUTINE,
            driver.PENDING_LOST: driver.SPEND_PREPARE_LOST,
            driver.PENDING_RECOVERY_KIT: driver.SPEND_PREPARE_KIT,
        }[kind]
        action = driver.build_authority_action_puzzle(action_tag=tag, binding_hash=binding)
        transition = replace(
            transition,
            replacement_daily_member_reveal=member,
            replacement_daily_member_hash=member_hash,
            prepare_binding_hash=binding,
            authority_prepare_action=action,
            authority_prepare_action_hash=bytes32(action.get_tree_hash()),
        )
    mips = driver.build_authority_prepare_mips_spend(
        authority=fixture.authority,
        transition=transition,
        current_identities=fixture.authority.identity_vaults,
        current_identity_coin_ids=fixture.identity_coin_ids,
    )
    inner = fixture.authority.inner_puzzle
    if boundary == "prepare_mips":
        # A synthetic committed root exercises the forwarding boundary. It is
        # not a claim that the canonical prepare action can emit this message.
        output = list(
            mips.reveal.run(mips.solution, flags=authority_tests.RUN_FLAGS).as_iter()
        )
        reveal = Program.to((1, [*output, [62, injected], [62, injected]]))
        mod, args = inner.uncurry()
        values = list(args.as_iter())
        root_hash = bytes32(reveal.get_tree_hash())
        if kind == driver.PENDING_LOST:
            roots = list(values[7].as_iter())
            roots[transition.slot] = Program.to(root_hash)
            values[7] = Program.to(roots)
        else:
            values[6] = Program.to(root_hash)
        inner = mod.curry(*values)
        mips = replace(mips, reveal=reveal, solution=Program.to(None))
    solution = driver.build_prepare_solution(
        transition=transition,
        my_amount=driver.AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=2,
        mips_reveal=mips.reveal,
        mips_solution=mips.solution,
        replacement_member_solution=authority_tests._eip_member_solution(
            replacement_key, fixture.authority_coin_id, transition.prepare_binding_hash
        ),
        identity_records=mips.identity_records,
    )
    if version == 4:
        with pytest.raises(ValueError):
            inner.run(solution, flags=authority_tests.RUN_FLAGS)
    else:
        result = inner.run(solution, flags=authority_tests.RUN_FLAGS)
        announcements = authority_tests._condition_values(result, 62)
        assert sum(item[1] == injected for item in announcements) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("version", (3, 4))
async def test_signed_operational_recovery_injection_bundle(version):
    keys = authority_tests._fixture()
    async with authority_tests.SpendSim.managed(
        None, defaults=authority_tests.DEFAULT_CONSTANTS
    ) as sim:
        client = authority_tests.SimClient(sim)
        acs = Program.to(1)
        await sim.farm_block(bytes32(acs.get_tree_hash()))
        records = await client.get_coin_records_by_puzzle_hash(
            bytes32(acs.get_tree_hash()), include_spent_coins=False
        )
        parent = records[0].coin
        authority = driver.build_genesis_admin_authority_v3(
            parent_coin_id=bytes32(parent.name()),
            network="testnet11",
            daily_compressed_pubkeys=tuple(
                authority_tests._compressed_pubkey(key)
                for key in keys.daily_private_keys
            ),
            recovery_bls_pubkeys=tuple(
                bytes(key.get_g1()) for key in keys.recovery_private_keys
            ),
            source_manifest_hash=authority_tests.SOURCE_MANIFEST_HASH,
            authority_puzzle_version=version,
        )
        targets = [(authority.inner_puzzle, driver.AUTHORITY_LAUNCHER_AMOUNT)]
        targets.extend(
            (identity.custody_reveal, identity.launcher_amount)
            for identity in authority.identity_vaults
        )
        conditions, launchers = [], []
        for inner, amount in targets:
            output, spend = launch_conditions_and_coinsol(parent, inner, [], uint64(amount))
            conditions.extend(output)
            launchers.append(spend)
        conditions.append(Program.to([
            51, acs.get_tree_hash(),
            int(parent.amount) - driver.ADMIN_AUTHORITY_FUNDING_AMOUNT,
        ]))
        status, error = await client.push_tx(SpendBundle(
            [make_spend(parent, acs, Program.to(conditions)), *launchers], G2Element()
        ))
        assert error is None and status == authority_tests.MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        coins = [compute_additions(spend)[0] for spend in launchers]
        fixture = replace(
            keys,
            authority=authority,
            authority_coin_id=bytes32(coins[0].name()),
            identity_coin_ids=tuple(bytes32(coin.name()) for coin in coins[1:]),
        )
        transition, replacement_key = authority_tests._transition(
            fixture, slot=1, kind=driver.PENDING_LOST
        )
        prepared, _ = authority_tests._run_authority_prepare(
            fixture, transition, replacement_key
        )
        announcement = next(
            item[1] for item in authority_tests._condition_values(prepared, 62)
            if item[1].startswith(b"\x53\x03")
        )
        delegated, mips, solution = _operational(fixture, [[62, announcement]])

        def spend(index, inner, inner_solution):
            return authority_tests._singleton_spend(
                coin=coins[index],
                launcher_id=bytes32(launchers[index].coin.name()),
                inner_puzzle=inner,
                launcher_spend=launchers[index],
                amount=int(coins[index].amount),
                inner_solution=inner_solution,
            )

        spends = [spend(0, authority.inner_puzzle, solution)]
        for slot in mips.selected_slots:
            identity = authority.identity_vaults[slot]
            action = driver.build_identity_operational_action(
                identity=identity,
                current_authority_inner_puzzle=authority.inner_puzzle,
                authority_delegated_puzzle=delegated,
            )
            inner_solution = driver.build_identity_operational_solution(
                identity=identity,
                current_authority_inner_puzzle=authority.inner_puzzle,
                authority_delegated_puzzle=delegated,
                current_identity_coin_id=fixture.identity_coin_ids[slot],
                daily_member_solution=authority_tests._eip_member_solution(
                    fixture.daily_private_keys[slot],
                    fixture.identity_coin_ids[slot],
                    bytes32(action.get_tree_hash()),
                ),
            )
            spends.append(spend(slot + 1, identity.custody_reveal, inner_solution))
        target = authority.identity_vaults[1]
        recovery_solution = authority_tests._unpaired_recovery_solution_without_authority_assertion(
            identity=target,
            transition=transition,
            pending_authority_state_hash=bytes32(announcement[2:]),
        )
        recovery_conditions = target.custody_reveal.run(
            recovery_solution, flags=authority_tests.RUN_FLAGS
        )
        signature_condition = authority_tests._condition_values(recovery_conditions, 50)[0]
        signature = AugSchemeMPL.sign(
            fixture.recovery_private_keys[1],
            signature_condition[2] + bytes(coins[2].name())
            + bytes(authority_tests.DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA),
        )
        spends.append(spend(2, target.custody_reveal, recovery_solution))
        status, error = await client.push_tx(SpendBundle(spends, signature))
        if version == 3:
            assert error is None and status == authority_tests.MempoolInclusionStatus.SUCCESS
        else:
            assert status == authority_tests.MempoolInclusionStatus.FAILED
            assert error == Err.GENERATOR_RUNTIME_ERROR


def test_v4_genesis_is_hash_bound_and_old_artifacts_remain_exact():
    old = _artifact()
    original = copy.deepcopy(old)
    assert "authorityPuzzleVersion" not in old["genesisPlan"]
    assert _rebuild_plan(old).admin_authority_v3.authority_puzzle_version == 3
    verify_public_artifact(old, signature_verifier=_accept)
    assert old == original
    selected = copy.deepcopy(old)
    selected["genesisPlan"]["authorityPuzzleVersion"] = 4
    plan = _rebuild_plan(selected)
    current = public(plan)
    assert current["genesisPlan"]["authorityPuzzleVersion"] == 4
    assert plan.plan_hash != _rebuild_plan(old).plan_hash
    verify_public_artifact(current, signature_verifier=_accept)
    assert _rebuild_plan(current).canonical_payload() == plan.canonical_payload()
    for invalid in (3, None, True, 0, 5, "4"):
        changed = copy.deepcopy(current)
        changed["genesisPlan"]["authorityPuzzleVersion"] = invalid
        changed["artifactHash"] = artifact_hash(changed)
        with pytest.raises(ValueError):
            verify_public_artifact(changed, signature_verifier=_accept)


@pytest.mark.parametrize("version", (3, 4))
def test_parser_requires_matching_known_module_and_self_hash(version):
    fixture = authority_tests._fixture(authority_puzzle_version=version)
    inner = fixture.authority.inner_puzzle
    assert driver.parse_inner_puzzle(inner).authority_puzzle_version == version
    mod, args = inner.uncurry()
    values = list(args.as_iter())
    values[0] = Program.to(driver.admin_authority_v3_inner_mod_hash(7 - version))
    with pytest.raises(ValueError, match="self module hash"):
        driver.parse_inner_puzzle(mod.curry(*values))
    with pytest.raises(ValueError, match="unsupported authority inner module hash"):
        driver.parse_inner_puzzle(Program.to(1).curry(*values))


def test_v4_manifest_appends_without_changing_historical_puzzles():
    root = Path(__file__).resolve().parents[1]
    manifests = root / "release-manifests"
    previous = json.loads(
        (manifests / "alpha-draft56-pool-v5-puzzle-hashes.json").read_text()
    )
    current = json.loads((manifests / "authority-v4-puzzle-hashes.json").read_text())
    assert current["deployable"] is False and current["replacements"] == []
    assert current["preservedCanonicalChecksum"] == previous["canonicalChecksum"]
    assert current["canonicalChecksum"] == FROZEN_CHECKSUM
    assert tuple(current["puzzleHashes"]) == PUZZLE_FILENAMES
    for name, expected in previous["puzzleHashes"].items():
        assert current["puzzleHashes"][name] == expected
    for name, expected in current["puzzleHashes"].items():
        assert load_puzzle(name).get_tree_hash().hex() == expected
    [addition] = current["additions"]
    assert addition["filename"] == "admin_authority_v4_inner.clsp"
    for suffix, field in [("", "sourceSha256"), (".hex", "hexSha256")]:
        path = root / "solslot_puzzles" / (addition["filename"] + suffix)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == addition[field]
