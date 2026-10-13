"""New-generation SGT outputs, conserved genesis split and ledger witnesses.

Low-level deterministic builders only. Ceremony admission must independently
verify recipient vault confirmation and destination acknowledgements before
calling issuance; a dataclass or indexer record is not chain evidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia_rs import CoinSpend
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.holdings import Holding, HoldingKind, HoldingsTree

TOTAL_SGT = 1_000_000
ADMINISTRATOR_GRANT = 10_000
INITIAL_RESERVE = 970_000


@dataclass(frozen=True)
class SGTBindings:
    generation: bytes32
    ledger_launcher_id: bytes32
    governance_launcher_id: bytes32
    reserve_owner: bytes32
    tail_hash: bytes32

    def program(self) -> list:
        return [self.generation, singleton_struct(self.ledger_launcher_id),
                singleton_struct(self.governance_launcher_id), self.reserve_owner,
                CAT_MOD.get_tree_hash(), self.tail_hash]


@dataclass(frozen=True)
class GenesisIssuancePlan:
    genesis_coin_id: bytes32
    generation: bytes32
    ledger_launcher_id: bytes32
    governance_launcher_id: bytes32
    reserve_owner: bytes32
    recipient_owners: tuple[bytes32, bytes32, bytes32]
    preparation_manifest_hash: bytes32

    def __post_init__(self):
        if len(self.recipient_owners) != 3 or len(set(self.recipient_owners)) != 3:
            raise ValueError("three distinct administrator recipient vaults are required")
        if self.reserve_owner in self.recipient_owners or bytes32.zeros in self.recipient_owners:
            raise ValueError("administrator grants require non-reserve recipient vaults")

    def tail(self) -> Program:
        return load_puzzle("generation_sgt_tail_v1.clsp").curry(
            self.genesis_coin_id, self.generation, singleton_struct(self.ledger_launcher_id),
            singleton_struct(self.governance_launcher_id), self.reserve_owner, list(self.recipient_owners),
            load_puzzle("generation_sgt_eve_v1.clsp").get_tree_hash(),
            load_puzzle("generation_sgt_coin_v1.clsp").get_tree_hash(),
            load_puzzle("generation_holdings_ledger_v1.clsp").get_tree_hash(), CAT_MOD.get_tree_hash(),
            self.preparation_manifest_hash)

    def bindings(self) -> SGTBindings:
        return SGTBindings(self.generation, self.ledger_launcher_id, self.governance_launcher_id,
                           self.reserve_owner, self.tail().get_tree_hash())


@dataclass(frozen=True)
class SGTOutput:
    kind: HoldingKind
    owner: bytes32
    amount: int
    lock_id: bytes32 | None = None

    def descriptor(self) -> list:
        # Share amount/type validation with the authenticated holding record.
        Holding(bytes32.zeros, self.amount, self.kind, self.owner, self.lock_id).program()
        return [int(self.kind), self.owner, self.lock_id or b"", self.amount]

    def inner(self, bindings: SGTBindings) -> Program:
        self.descriptor()
        if self.kind == HoldingKind.RESERVE and self.owner != bindings.reserve_owner:
            raise ValueError("reserve destination is immutable")
        mod = load_puzzle("generation_sgt_coin_v1.clsp")
        return mod.curry(mod.get_tree_hash(), bindings.program(), int(self.kind),
                         self.owner, self.lock_id or b"")

    def full(self, bindings: SGTBindings) -> Program:
        return construct_cat_puzzle(CAT_MOD, bindings.tail_hash, self.inner(bindings))

    def holding(self, bindings: SGTBindings) -> Holding:
        return Holding(self.full(bindings).get_tree_hash(), self.amount,
                       self.kind, self.owner, self.lock_id)

    def coin(self, bindings: SGTBindings, parent: bytes32) -> Coin:
        return Coin(parent, self.full(bindings).get_tree_hash(), uint64(self.amount))


@dataclass(frozen=True)
class InitialIssuance:
    eve_coin: Coin
    eve_spend: CoinSpend
    outputs: tuple[SGTOutput, ...]
    coins: tuple[Coin, ...]
    holdings: HoldingsTree
    insertion_proofs: list

    def ledger_initialization(self) -> Program:
        return Program.to([b'INITIALIZE', [self.eve_coin.name(), self.eve_coin.puzzle_hash]])


def build_initial_issuance(plan: GenesisIssuancePlan) -> InitialIssuance:
    bindings, tail = plan.bindings(), plan.tail()
    outputs = tuple(SGTOutput(HoldingKind.HOLDER, owner, ADMINISTRATOR_GRANT)
                    for owner in plan.recipient_owners) + (
                        SGTOutput(HoldingKind.RESERVE, bindings.reserve_owner, INITIAL_RESERVE),)
    eve_inner = load_puzzle("generation_sgt_eve_v1.clsp").curry(bindings.program(), list(plan.recipient_owners),
                 load_puzzle("generation_sgt_coin_v1.clsp").get_tree_hash(),
                 load_puzzle("generation_holdings_ledger_v1.clsp").get_tree_hash())
    eve = Coin(plan.genesis_coin_id, construct_cat_puzzle(CAT_MOD, bindings.tail_hash, eve_inner).get_tree_hash(),
               uint64(TOTAL_SGT))
    coins = tuple(output.coin(bindings, eve.name()) for output in outputs)
    holdings, proofs = HoldingsTree({}), []
    for coin, output in zip(coins, outputs):
        proofs.append(holdings.proof(coin.name()))
        holdings = holdings.replace(coin.name(), None, output.holding(bindings))
    bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(
        coin=eve, limitations_program_hash=bindings.tail_hash, inner_puzzle=eve_inner,
        inner_solution=Program.to([tail, eve.name(), proofs]), limitations_program_reveal=tail)])
    assert holdings.root.total == TOTAL_SGT and holdings.root.eligible == 30_000
    return InitialIssuance(eve, bundle.coin_spends[0], outputs, coins, holdings, proofs)


def ledger_inner(bindings: SGTBindings, tree: HoldingsTree, sequence: int) -> Program:
    if tree.root.total != TOTAL_SGT:
        raise ValueError("ledger must account for the entire fixed supply")
    mod = load_puzzle("generation_holdings_ledger_v1.clsp")
    return mod.curry(mod.get_tree_hash(), bindings.program(),
                     load_puzzle("generation_sgt_coin_v1.clsp").get_tree_hash(),
                     tree.root.program(), sequence)


def transition_witness(bindings: SGTBindings, tree: HoldingsTree, coin: Coin,
                       output: SGTOutput, action: str, next_outputs: tuple[SGTOutput, ...]) -> tuple[list, HoldingsTree]:
    holding = output.holding(bindings)
    if coin.puzzle_hash != holding.puzzle_hash or coin.amount != holding.amount:
        raise ValueError("input coin does not match its descriptor")
    remove_proof = tree.proof(coin.name())
    next_tree = tree.replace(coin.name(), holding, None)
    insert_proofs = []
    for successor in next_outputs:
        child = successor.coin(bindings, coin.name())
        insert_proofs.append(next_tree.proof(child.name()))
        next_tree = next_tree.replace(child.name(), None, successor.holding(bindings))
    return [coin.parent_coin_info, holding.program(), action.encode(),
            [v.descriptor() for v in next_outputs], remove_proof, insert_proofs], next_tree


def transition_digest(bindings: SGTBindings, coin: Coin, action: str, outputs: tuple[SGTOutput, ...]) -> bytes32:
    return Program.to([b"SGT_TRANSITION_V1", bindings.generation, coin.name(), action.encode(),
                       [v.descriptor() for v in outputs]]).get_tree_hash()
