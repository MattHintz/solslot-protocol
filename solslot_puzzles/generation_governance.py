"""Deterministic state/witness helpers for new-generation holder governance."""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_sgt import SGTBindings
from solslot_puzzles.holdings import HoldingsTree, HoldingKind, SumNode, quorum

ADMIN_APPROVAL_SECONDS = 86_400
VOTING_SECONDS = 3_600
MINIMUM_SPONSORSHIP = 10_000


class ProposalSet:
    """Sparse authenticated set matching generation_closed_set_v1.clib."""
    def __init__(self, keys=()):
        self.keys = frozenset(keys)
        self.empty = [sha256(b"\x01").digest()]
        for _ in range(256):
            self.empty.append(sha256(b"\x02" + self.empty[-1] * 2).digest())
        self.levels = [{int.from_bytes(k, "big"): sha256(b"\x01" + k).digest() for k in self.keys}]
        for height in range(256):
            prior = self.levels[-1]
            self.levels.append({k: sha256(b"\x02" + prior.get(k * 2, self.empty[height]) +
                                                   prior.get(k * 2 + 1, self.empty[height])).digest()
                                for k in {key // 2 for key in prior}})

    @property
    def root(self) -> bytes32:
        return bytes32(self.levels[256].get(0, self.empty[256]))

    def proof(self, key: bytes32) -> list[bytes]:
        value = int.from_bytes(key, "big")
        return [self.levels[level].get((value >> level) ^ 1, self.empty[level]) for level in range(256)]

    def add(self, key: bytes32) -> ProposalSet:
        if key in self.keys: raise ValueError("duplicate proposal receipt")
        return ProposalSet(self.keys | {key})

    def remove(self, key: bytes32) -> ProposalSet:
        if key not in self.keys: raise ValueError("unapproved or already executed action")
        return ProposalSet(self.keys - {key})


@dataclass(frozen=True)
class OpenProposal:
    proposal_id: bytes32
    bill: Program
    snapshot: SumNode
    ledger_sequence: int
    yes_weight: int
    clock_id: bytes32
    opened_at: int = 0

    def program(self) -> list:
        return [self.proposal_id, self.bill, self.snapshot.program(), self.ledger_sequence,
                self.yes_weight, self.clock_id, self.opened_at]

    @property
    def required_votes(self) -> int:
        return quorum(self.snapshot.eligible)

    @property
    def voting_closes_at(self) -> int | None:
        return self.opened_at + VOTING_SECONDS if self.opened_at else None


@dataclass(frozen=True)
class Governance:
    sgt: SGTBindings
    registry_id: bytes32
    admin_id: bytes32
    mint_id: bytes32
    component_id: bytes32
    module_hash: bytes32
    version: int = 1
    compatibility: int = 1
    nonce: int = 0
    active: OpenProposal | None = None
    closed: ProposalSet | None = None
    approved: ProposalSet | None = None
    upgrade_reserved: bool = False

    def __post_init__(self):
        if self.closed is None: object.__setattr__(self, "closed", ProposalSet())
        if self.approved is None: object.__setattr__(self, "approved", ProposalSet())

    def bindings(self) -> list:
        return [singleton_struct(self.sgt.governance_launcher_id), singleton_struct(self.admin_id),
                singleton_struct(self.sgt.ledger_launcher_id), self.sgt.program(),
                load_puzzle("generation_sgt_coin_v1.clsp").get_tree_hash(),
                load_puzzle("generation_vote_clock_v1.clsp").get_tree_hash(), singleton_struct(self.mint_id)]

    def state(self) -> Program:
        return Program.to([self.bindings(), self.nonce, self.active.program() if self.active else [],
                           self.closed.root, self.approved.root, int(self.upgrade_reserved)])

    def inner(self) -> Program:
        mod = load_puzzle("generation_governance_v1.clsp")
        return mod.curry(mod.get_tree_hash(), self.sgt.generation, singleton_struct(self.registry_id),
                         self.component_id, self.module_hash, self.version, self.compatibility, self.state())

    def proposal_id(self, bill: Program, tree: HoldingsTree) -> bytes32:
        return Program.to([b"HOLDER_PROPOSAL_V1", self.sgt.generation, self.nonce, bill,
                           tree.root.program()]).get_tree_hash()

    def clock_puzzle(self, proposal: bytes32) -> Program:
        return load_puzzle("generation_vote_clock_v1.clsp").curry(
            self.sgt.generation, singleton_struct(self.sgt.governance_launcher_id), proposal)

    def opened(self, coin: Coin, bill: Program, tree: HoldingsTree, sequence: int,
               sponsor_coin_ids: list[bytes32]) -> tuple[Governance, Coin]:
        if self.active: raise ValueError("finish the open vote first")
        bill_kind = bill.first().as_atom()
        if bill_kind == b"UPGRADE" and self.upgrade_reserved:
            raise ValueError("only one unexecuted upgrade proposal is permitted")
        witnesses = ballot_witnesses(tree, sponsor_coin_ids, self.closed)
        weight = sum(row[1][1] for row in witnesses)
        if weight < MINIMUM_SPONSORSHIP: raise ValueError("sponsorship requires 10,000 eligible SGT")
        quorum(tree.root.eligible)
        proposal = self.proposal_id(bill, tree)
        clock = Coin(coin.name(), self.clock_puzzle(proposal).get_tree_hash(), uint64(0))
        return replace(self, nonce=self.nonce + 1,
                       active=OpenProposal(proposal, bill, tree.root, sequence, weight, clock.name()),
                       upgrade_reserved=self.upgrade_reserved or bill_kind == b"UPGRADE"), clock

    def anchored(self, birth_timestamp: int) -> Governance:
        if not self.active or self.active.opened_at or birth_timestamp <= 0:
            raise ValueError("proposal must be awaiting confirmed opening time")
        return replace(self, active=replace(self.active, opened_at=birth_timestamp))

    def voted(self, weight: int) -> Governance:
        if not self.active or not self.active.opened_at or weight <= 0:
            raise ValueError("no confirmed open vote")
        if self.active.yes_weight + weight > self.active.snapshot.eligible:
            raise ValueError("vote weight exceeds opening supply")
        return replace(self, active=replace(self.active, yes_weight=self.active.yes_weight + weight))

    def action_key(self, proposal: bytes32, bill: Program) -> bytes32:
        return Program.to([b"APPROVED_ACTION", self.sgt.generation, proposal, bill]).get_tree_hash()

    def finalized(self) -> Governance:
        if not self.active or not self.active.opened_at: raise ValueError("no open vote to finalize")
        passed = self.active.yes_weight >= self.active.required_votes
        key = self.action_key(self.active.proposal_id, self.active.bill)
        return replace(self, active=None, closed=self.closed.add(self.active.proposal_id),
                       approved=self.approved.add(key) if passed else self.approved,
                       upgrade_reserved=self.upgrade_reserved and
                           not (self.active.bill.first().as_atom() == b"UPGRADE" and not passed))

    def executed(self, proposal: bytes32, bill: Program) -> Governance:
        return replace(self, approved=self.approved.remove(self.action_key(proposal, bill)),
                       upgrade_reserved=False if bill.first().as_atom() == b"UPGRADE" else self.upgrade_reserved)


def ballot_witnesses(snapshot: HoldingsTree, coin_ids: list[bytes32], closed: ProposalSet | None = None) -> list:
    if len(set(coin_ids)) != len(coin_ids): raise ValueError("a holding may vote only once")
    result = []
    for coin_id in coin_ids:
        holding = snapshot.holdings.get(coin_id)
        if holding is None or holding.kind not in (HoldingKind.HOLDER, HoldingKind.LOCKED_HOLDER):
            raise ValueError("vote requires an unspent eligible holding from the opening snapshot")
        prior_closed_proof = []
        if holding.kind == HoldingKind.LOCKED_HOLDER:
            if closed is None or holding.lock_id not in closed.keys:
                raise ValueError("a locked holding requires its prior proposal to be closed")
            prior_closed_proof = closed.proof(holding.lock_id)
        result.append([coin_id, holding.program(), snapshot.proof(coin_id), prior_closed_proof])
    return result
