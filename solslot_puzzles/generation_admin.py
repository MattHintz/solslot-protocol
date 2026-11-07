"""Typed actions for the unchanged recovery-aware administrator authority.

These return the exact delegated program to be reviewed and signed by owner
plus one current coadministrator identity, using admin_authority_v3_driver.
No private key, signature, broadcast or bootstrap permission lives here.
"""
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import ADMIN_APPROVAL_SECONDS


def publication_action(generation: bytes32, target_puzzle_hash: bytes32,
                       proposal_id: bytes32, issued_at: int) -> Program:
    if type(issued_at) is not int or not 0 < issued_at < 2**64 - ADMIN_APPROVAL_SECONDS:
        raise ValueError('publication start time must be a positive bounded timestamp')
    return load_puzzle('generation_admin_action_v1.clsp').curry(generation, target_puzzle_hash,
        b'PUBLICATION_APPROVAL', proposal_id, issued_at, issued_at + ADMIN_APPROVAL_SECONDS)


def pause_action(generation: bytes32, target_puzzle_hash: bytes32, epoch: int, scope: int) -> Program:
    if type(epoch) is not int or not 0 <= epoch < 2**64:
        raise ValueError('invalid pause epoch')
    if type(scope) is not int or not 0 < scope < 32:
        raise ValueError('pause cannot include protected operations')
    return load_puzzle('generation_admin_action_v1.clsp').curry(generation, target_puzzle_hash,
        b'PAUSE_NEW_OPERATIONS', [epoch, scope], 0, 0)
