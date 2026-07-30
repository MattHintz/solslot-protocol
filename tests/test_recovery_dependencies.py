from __future__ import annotations

import importlib.metadata
import json

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.custody import custody_architecture
from chia.wallet.puzzles.custody import member_puzzles
from chia_puzzles_py import programs as puzzle_mods

from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_LICENSE,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
    RECOVERY_DEPENDENCY_MANIFEST_PATH,
    compute_recovery_dependency_manifest_hash,
)


def _tree_hash(program: Program | bytes) -> str:
    resolved = (
        program
        if isinstance(program, Program)
        else Program.from_bytes(program)
    )
    return bytes(resolved.get_tree_hash()).hex()


def test_rc23_recovery_dependency_manifest_is_exactly_pinned() -> None:
    manifest = json.loads(
        RECOVERY_DEPENDENCY_MANIFEST_PATH.read_text(encoding="utf-8")
    )
    upstream = manifest["upstreamRecoverySdk"]
    runtime = manifest["pythonRuntime"]
    browser = manifest["browserEip712Signing"]

    assert manifest["schema"] == "solslot.recovery-dependencies.v1"
    assert manifest["release"] == "RC23"
    assert upstream["repository"] == PINNED_CNI_WALLET_SDK_REPOSITORY
    assert upstream["commit"] == PINNED_CNI_WALLET_SDK_COMMIT
    assert upstream["license"] == PINNED_CNI_WALLET_SDK_LICENSE
    assert compute_recovery_dependency_manifest_hash() == (
        RECOVERY_DEPENDENCY_MANIFEST_HASH
    )
    assert importlib.metadata.version("chia-blockchain") == (
        runtime["chiaBlockchainVersion"]
    )
    assert importlib.metadata.version("chia-puzzles-py") == (
        runtime["chiaPuzzlesPyVersion"]
    )
    assert browser["recoveryAuthority"] is False
    assert browser["purpose"].endswith(
        "this artifact is not recovery authority"
    )


def test_installed_mips_modules_match_pinned_upstream_tree_hashes() -> None:
    expected = json.loads(
        RECOVERY_DEPENDENCY_MANIFEST_PATH.read_text(encoding="utf-8")
    )["mipsModuleTreeHashes"]
    installed = {
        "indexWrapper": custody_architecture.INDEX_WRAPPER,
        "mOfN": custody_architecture.MofN_MOD,
        "oneOfN": custody_architecture.OneOfN_MOD,
        "restrictions": custody_architecture.RESTRICTION_MOD,
        "delegatedPuzzleFeeder": (
            custody_architecture.DELEGATED_PUZZLE_FEEDER
        ),
        "blsWithTaprootMember": (
            member_puzzles.BLS_WITH_TAPROOT_MEMBER_MOD
        ),
        "singletonMemberWithMode": (
            puzzle_mods.SINGLETON_MEMBER_WITH_MODE
        ),
        "forceOneOfTwoWithRestrictedVariable": (
            puzzle_mods.FORCE_1_OF_2_W_RESTRICTED_VARIABLE
        ),
        "timelock": puzzle_mods.TIMELOCK,
        "preventConditionOpcode": (
            puzzle_mods.PREVENT_CONDITION_OPCODE
        ),
        "preventMultipleCreateCoins": (
            puzzle_mods.PREVENT_MULTIPLE_CREATE_COINS
        ),
    }
    assert set(installed) == set(expected)
    assert {
        name: _tree_hash(program)
        for name, program in installed.items()
    } == expected
