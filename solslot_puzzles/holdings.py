"""Consensus-compatible sparse Merkle-sum proofs for SGT holdings.

The indexer constructs witnesses; it cannot select the eligible denominator.
Both sums are authenticated by the on-chain root. Values use whole SGT units,
matching this generation's fixed 1,000,000-unit CAT issuance.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32


class HoldingKind(IntEnum):
    HOLDER = 1
    LOCKED_HOLDER = 2
    RESERVE = 3
    UNDELIVERED_ESCROW = 4


@dataclass(frozen=True)
class Holding:
    puzzle_hash: bytes32
    amount: int
    kind: HoldingKind
    owner_hash: bytes32
    lock_id: bytes32 | None = None

    def program(self) -> list:
        if not isinstance(self.kind, HoldingKind) or not 0 < self.amount <= 1_000_000:
            raise ValueError("invalid SGT holding")
        if (self.kind == HoldingKind.LOCKED_HOLDER) != (self.lock_id is not None):
            raise ValueError("only a voting lock may have a proposal commitment")
        return [self.puzzle_hash, self.amount, int(self.kind), self.owner_hash, self.lock_id or b""]


@dataclass(frozen=True)
class SumNode:
    hash: bytes32
    eligible: int
    total: int

    def program(self) -> list:
        return [self.hash, self.eligible, self.total]


def leaf(coin_id: bytes32, holding: Holding | None) -> SumNode:
    if holding is None:
        return SumNode(Program.to([b"SGT_EMPTY_V1"]).get_tree_hash(), 0, 0)
    eligible = holding.amount if holding.kind in (HoldingKind.HOLDER, HoldingKind.LOCKED_HOLDER) else 0
    return SumNode(Program.to([b"SGT_HOLDING_V1", coin_id, holding.program()]).get_tree_hash(),
                   eligible, holding.amount)


def branch(left: SumNode, right: SumNode) -> SumNode:
    return SumNode(Program.to([b"SGT_NODE_V1", left.program(), right.program()]).get_tree_hash(),
                   left.eligible + right.eligible, left.total + right.total)


class HoldingsTree:
    """Sparse index of unspent outputs, not a trusted source of voting balances."""
    def __init__(self, holdings: dict[bytes32, Holding]):
        self.holdings = dict(holdings)
        self.empty = [leaf(bytes32.zeros, None)]
        for _ in range(256):
            self.empty.append(branch(self.empty[-1], self.empty[-1]))
        self.levels = [{int.from_bytes(k, "big"): leaf(k, h) for k, h in self.holdings.items()}]
        for height in range(256):
            prior = self.levels[-1]
            self.levels.append({key: branch(prior.get(key * 2, self.empty[height]),
                                            prior.get(key * 2 + 1, self.empty[height]))
                                for key in {n // 2 for n in prior}})

    @property
    def root(self) -> SumNode:
        return self.levels[256].get(0, self.empty[256])

    def proof(self, coin_id: bytes32) -> list[list]:
        key = int.from_bytes(coin_id, "big")
        return [self.levels[level].get((key >> level) ^ 1, self.empty[level]).program()
                for level in range(256)]

    def replace(self, coin_id: bytes32, before: Holding | None, after: Holding | None) -> HoldingsTree:
        if self.holdings.get(coin_id) != before:
            raise ValueError("holding does not match the indexed pre-state")
        result = dict(self.holdings)
        if after is None:
            result.pop(coin_id, None)
        else:
            result[coin_id] = after
        # Rehash only the changed 256-level path. Rebuilding every leaf on
        # each insertion made large snapshots quadratic to prepare. Previous
        # indexes remain immutable; proof bytes match a complete rebuild.
        updated=object.__new__(HoldingsTree)
        updated.holdings=result
        updated.empty=self.empty
        updated.levels=[dict(level) for level in self.levels]
        key=int.from_bytes(coin_id,'big')
        if after is None:updated.levels[0].pop(key,None)
        else:updated.levels[0][key]=leaf(coin_id,after)
        for height in range(256):
            parent=key//2;children=updated.levels[height]
            if parent*2 not in children and parent*2+1 not in children:
                updated.levels[height+1].pop(parent,None)
            else:
                updated.levels[height+1][parent]=branch(children.get(parent*2,self.empty[height]),
                    children.get(parent*2+1,self.empty[height]))
            key=parent
        return updated


def quorum(eligible_supply: int) -> int:
    if not 0 < eligible_supply <= 1_000_000:
        raise ValueError("ordinary governance requires distributed eligible SGT")
    return (eligible_supply + 1) // 2
