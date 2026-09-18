"""Pin the legacy and statutes-aware governance publication wire contracts."""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.protocol_statutes_v1 import ProtocolParameters
from solslot_puzzles.sgt_driver import (
    TEST_KOS_MINT_EXECUTE_PUBKEY, proposal_tracker_inner_puzzle,
    proposal_tracker_v2_inner_puzzle, tracker_propose_policy_from_spend,
    validate_tracker_propose_parameters,
)

B = bytes32(b't' * 32)
STRUCT = singleton_struct(B)
POLICY = ProtocolParameters()


def tracker(version):
    common = [STRUCT, B, B, B, B, B, STRUCT]
    if version == 2:
        common.extend([STRUCT, STRUCT])
    common.extend([5000, 300, 1_000_000, 10_000, TEST_KOS_MINT_EXECUTE_PUBKEY])
    builder = proposal_tracker_v2_inner_puzzle if version == 2 else proposal_tracker_inner_puzzle
    return builder(*common)


def params(evidence=None):
    values = [B, Program.to([1]), B, 10_000, 1_900_000_300]
    if evidence is not None:
        values.append(evidence)
    return list(Program.to(values).as_iter())


def test_versioned_policy_snapshot_and_legacy_control():
    legacy = params()
    v2 = params([B, B, list(POLICY.as_tuple())])
    assert validate_tracker_propose_parameters(tracker(1), legacy) is None
    assert tracker_propose_policy_from_spend(puzzle_for_singleton(B, tracker(2)), v2) == POLICY.as_tuple()
    with pytest.raises(ValueError, match='five parameters'):
        validate_tracker_propose_parameters(tracker(1), v2)
    with pytest.raises(ValueError, match='requires statutes'):
        validate_tracker_propose_parameters(tracker(2), legacy)


@pytest.mark.parametrize('evidence', [[], [B, B], [b'bad', B, list(POLICY.as_tuple())],
    [B, B, []], [B, B, [300, 0, 10000, 86400, 600, 100, 30, 70, 86400]],
    [B, B, [300, 5000, 1_000_001, 86400, 600, 100, 30, 70, 86400]]])
def test_v2_rejects_missing_hashes_or_invalid_policy(evidence):
    with pytest.raises(ValueError):
        validate_tracker_propose_parameters(tracker(2), params(evidence))


def test_unknown_module_or_wrapper_is_rejected():
    with pytest.raises(ValueError, match='unrecognized'):
        validate_tracker_propose_parameters(Program.to(1), params())
    with pytest.raises(ValueError, match='canonical singleton'):
        tracker_propose_policy_from_spend(tracker(2), params())
