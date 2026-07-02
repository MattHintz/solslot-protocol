"""
settlement_splitxch.py — Compute equal-split settlement distribution tree.

Given a total settlement amount and a list of deed launcher IDs, builds
a binary tree of "quote puzzles" (puzzles that just output CREATE_COIN
conditions) whose leaves are p2_deed_settlement coins — one per deed,
each holding an equal share.

Usage (simulation / driver):
    from populis_puzzles.settlement_splitxch import (
        compute_settlement_targets,
        build_splitxch_tree,
    )

    targets = compute_settlement_targets(
        total_amount=1_000_000,
        deed_launcher_ids=[deed1_id, deed2_id, ...],
        p2_settlement_curry_fn=curry_p2_deed_settlement,
    )
    root_puzzle_hash, parent_lookup = build_splitxch_tree(targets)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from populis_puzzles import load_puzzle


CANONICAL_DEED_BURN_INNER_PUZHASH = bytes32(b"\x00" * 32)


def p2_deed_settlement_mod() -> Program:
    return load_puzzle("p2_deed_settlement.clsp")


def curry_p2_deed_settlement(
    *,
    singleton_mod_hash: bytes32,
    deed_launcher_id: bytes32,
    launcher_puzzle_hash: bytes32,
    seconds_delay: int,
    delayed_puzzle_hash: bytes32,
) -> Program:
    """Return the canonical settlement leaf for one deed.

    The burn destination is intentionally not an argument.  The Chialisp
    puzzle hardcodes the all-zero inner puzzle hash so settlement leaves cannot
    redefine what "burned deed" means.
    """
    return p2_deed_settlement_mod().curry(
        singleton_mod_hash,
        deed_launcher_id,
        launcher_puzzle_hash,
        seconds_delay,
        delayed_puzzle_hash,
    )


# ---------------------------------------------------------------------------
# Target: a (puzzle_hash, amount) pair — one leaf of the distribution tree
# ---------------------------------------------------------------------------
@dataclass
class SettlementTarget:
    puzzle_hash: bytes32
    amount: uint64
    deed_launcher_id: bytes32  # for cross-reference

    def create_coin_condition(self) -> list:
        return [
            ConditionOpcode.CREATE_COIN,
            self.puzzle_hash,
            self.amount,
            [self.puzzle_hash],  # hint
        ]


# ---------------------------------------------------------------------------
# TargetCoin: intermediate node in the tree
# ---------------------------------------------------------------------------
@dataclass
class TargetCoin:
    target: SettlementTarget
    puzzle: Program
    puzzle_hash: bytes32
    amount: uint64


# Fees spend asserts this announcement to atomically tie payment to the tree.
EMPTY_COIN_ANNOUNCEMENT = [ConditionOpcode.CREATE_COIN_ANNOUNCEMENT, b"$"]


# ---------------------------------------------------------------------------
# compute_settlement_targets — equal split among deeds
# ---------------------------------------------------------------------------
def compute_settlement_targets(
    total_amount: int,
    deed_launcher_ids: List[bytes32],
    p2_settlement_curry_fn: Callable[[bytes32], Program],
) -> List[SettlementTarget]:
    """
    Compute per-deed settlement targets with equal split.

    Args:
        total_amount: Total XCH (mojos) to distribute.
        deed_launcher_ids: List of deed launcher IDs in the collection.
        p2_settlement_curry_fn: Function that takes a deed_launcher_id and
            returns the curried p2_deed_settlement puzzle for that deed.

    Returns:
        List of SettlementTarget, one per deed, with equal share amounts.
        Any remainder from integer division goes to the last deed.
    """
    n = len(deed_launcher_ids)
    assert n > 0, "Must have at least one deed"
    assert total_amount > 0, "Settlement amount must be positive"

    per_deed = total_amount // n
    remainder = total_amount - (per_deed * n)

    targets: List[SettlementTarget] = []
    for i, deed_id in enumerate(deed_launcher_ids):
        puzzle = p2_settlement_curry_fn(deed_id)
        amount = per_deed + (remainder if i == n - 1 else 0)
        targets.append(
            SettlementTarget(
                puzzle_hash=bytes32(puzzle.get_tree_hash()),
                amount=uint64(amount),
                deed_launcher_id=deed_id,
            )
        )
    return targets


# ---------------------------------------------------------------------------
# build_splitxch_tree — recursive binary split into a CREATE_COIN tree
# ---------------------------------------------------------------------------
def build_splitxch_tree(
    targets: List[SettlementTarget],
    leaf_width: int = 2,
    parent_puzzle_lookup: Optional[Dict[str, TargetCoin]] = None,
) -> Tuple[bytes32, Dict[str, TargetCoin]]:
    """
    Build a binary tree of quote puzzles that distribute XCH to targets.

    Each internal node is a puzzle ``(1 . conditions)`` that, when spent,
    creates its children.  The root puzzle hash is what the pool embeds in
    its SETTLEMENT CREATE_COIN condition.

    Args:
        targets: List of SettlementTarget (leaves).
        leaf_width: Max children per internal node (default 2 = binary tree).
        parent_puzzle_lookup: Accumulator (caller should not pass this).

    Returns:
        (root_puzzle_hash, parent_puzzle_lookup) where the lookup maps each
        target puzzle hash hex to its TargetCoin (puzzle reveal + amount).
    """
    if parent_puzzle_lookup is None:
        parent_puzzle_lookup = {}

    # Base case: single target IS the root
    if len(targets) == 1:
        return targets[0].puzzle_hash, parent_puzzle_lookup

    # Batch targets into groups of leaf_width
    batches: List[List[SettlementTarget]] = []
    batch: List[SettlementTarget] = []
    for i, t in enumerate(targets):
        batch.append(t)
        if len(batch) == leaf_width or i == len(targets) - 1:
            batches.append(batch)
            batch = []

    # Build next level of the tree
    next_level: List[SettlementTarget] = []
    for batch_targets in batches:
        conditions = [EMPTY_COIN_ANNOUNCEMENT]
        total = 0
        for t in batch_targets:
            conditions.append(t.create_coin_condition())
            total += t.amount

        # Quote puzzle: (1 . conditions) — just outputs the conditions
        puzzle = Program.to((1, conditions))
        ph = bytes32(puzzle.get_tree_hash())

        # Register each child target's parent
        for t in batch_targets:
            parent_puzzle_lookup[t.puzzle_hash.hex()] = TargetCoin(
                target=t, puzzle=puzzle, puzzle_hash=ph, amount=uint64(total)
            )

        # This node becomes a target for the next level
        next_level.append(
            SettlementTarget(
                puzzle_hash=ph,
                amount=uint64(total),
                deed_launcher_id=batch_targets[0].deed_launcher_id,
            )
        )

    return build_splitxch_tree(next_level, leaf_width, parent_puzzle_lookup)
