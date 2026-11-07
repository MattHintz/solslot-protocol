"""Segregated company revenue, exact administrator-approved payments.

The 0.7% company share is spendable by the current owner-plus-one authority.
Backing, 0.3% SGT reward custody and holder redemption leaves remain separate.
This module constructs public intents only: no keys, signatures or dispatch.
"""
from __future__ import annotations
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_transactions import NativeOperation
from solslot_puzzles.generation_sgt import SGTBindings

MAX_REVENUE_NETWORK_FEE = 1_000_000_000
MAX_REVENUE_APPROVAL_SECONDS = 86_400


@dataclass(frozen=True)
class PrimaryFeeSplitter:
    bindings: SGTBindings
    statutes_id: bytes32
    revenue: CompanyRevenue

    def inner(self):
        nonzero(self.statutes_id, 'statutes')
        if self.bindings.generation != self.revenue.generation:
            raise ValueError('primary fees require the same revenue generation')
        mod = load_puzzle('generation_primary_fee_split_v1.clsp')
        return mod.curry(mod.get_tree_hash(), self.bindings.program(), singleton_struct(self.statutes_id),
            self.revenue.inner().get_tree_hash(), CAT_MOD.get_tree_hash(),
            *(load_puzzle(name).get_tree_hash() for name in ('generation_reward_custody_v1.clsp',
                'generation_reward_epoch_v1.clsp', 'generation_sgt_coin_v1.clsp', 'generation_reward_leaf_v1.clsp',
                'generation_sgt_vault_owner_v1.clsp', 'p2_vault.clsp')))

    def operation(self, coin, asset=bytes32.zeros, *, lineage=None):
        full = asset_puzzle(self.inner(), asset)
        if coin.puzzle_hash != full.get_tree_hash() or coin.amount <= 0:
            raise ValueError('primary fee differs from the exact asset and splitter custody')
        solution = Program.to([asset, coin.name(), int(coin.amount)])
        if asset == bytes32.zeros:
            if lineage is not None:
                raise ValueError('native fees cannot supply CAT lineage')
            spends = (make_spend(coin, full, solution),)
        else:
            if type(lineage) is not LineageProof:
                raise ValueError('CAT fees require their exact lineage')
            spends = tuple(unsigned_spend_bundle_for_spendable_cats(CAT_MOD,
                [SpendableCAT(coin, asset, self.inner(), solution, lineage_proof=lineage)]).coin_spends)
        return NativeOperation(self.revenue.generation, 'SPLIT_PRIMARY_FEE', spends, ())


def nonzero(value, label):
    if not isinstance(value, bytes32) or value == bytes32.zeros:
        raise ValueError(label+' must be exact nonzero bytes32')
    return value


def asset_puzzle(inner, asset):
    if not isinstance(asset, bytes32):
        raise ValueError('asset must be exact bytes32; zero denotes native XCH')
    return inner if asset == bytes32.zeros else construct_cat_puzzle(CAT_MOD, asset, inner)


@dataclass(frozen=True)
class BackingCustody:
    generation: bytes32

    def inner(self):
        nonzero(self.generation, 'generation')
        mod = load_puzzle('generation_backing_custody_v1.clsp')
        return mod.curry(mod.get_tree_hash(), self.generation)


@dataclass(frozen=True)
class CompanyRevenue:
    generation: bytes32
    authority_id: bytes32

    def inner(self):
        nonzero(self.generation, 'generation'); nonzero(self.authority_id, 'authority')
        mod = load_puzzle('generation_revenue_custody_v1.clsp')
        return mod.curry(mod.get_tree_hash(), self.generation, singleton_struct(self.authority_id))

    def review(self):
        return {'policy': 'COMPANY_REVENUE_OWNER_PLUS_ONE_V1',
            'generationId': '0x'+self.generation.hex(), 'authorityId': '0x'+self.authority_id.hex(),
            'custodyPuzzleHash': '0x'+self.inner().get_tree_hash().hex(),
            'moduleHash': '0x'+load_puzzle('generation_revenue_custody_v1.clsp').get_tree_hash().hex(),
            'operatingExpensesAllowed': True, 'reinvestmentAllowed': True,
            'standingWithdrawalBudget': False, 'serverSpendingKey': False,
            'maxNetworkFeeMojos': MAX_REVENUE_NETWORK_FEE,
            'maxApprovalSeconds': MAX_REVENUE_APPROVAL_SECONDS,
            'backingCustody': '0x'+BackingCustody(self.generation).inner().get_tree_hash().hex(),
            'protectedCustomerAndRewardFunds': 'SEPARATE_CONTRACTS'}


def _group(custody, coins, asset):
    selected = tuple(sorted(coins, key=lambda c: bytes(c.name())))
    full = asset_puzzle(custody.inner(), asset)
    if (not 0 < len(selected) <= 64 or len({c.name() for c in selected}) != len(selected)
            or any(c.puzzle_hash != full.get_tree_hash() or c.amount <= 0 for c in selected)
            or sum(c.amount for c in selected) >= 2**64):
        raise ValueError('custody requires 1–64 distinct exact same-asset inputs')
    return selected, [[c.parent_coin_info, int(c.amount)] for c in selected]


def _spends(custody, selected, solutions, asset, original, lineages):
    inner = custody.inner()
    if asset == bytes32.zeros:
        if lineages:
            raise ValueError('native inputs must not supply CAT lineage')
        return tuple(make_spend(c, inner, s) for c, s in zip(selected, solutions))
    if len(lineages) != len(original) or any(type(l) is not LineageProof for l in lineages):
        raise ValueError('CAT custody requires the exact lineage of every input')
    mapping = {c.name(): l for c, l in zip(original, lineages)}
    return tuple(unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(c, asset, inner, s,
        lineage_proof=mapping[c.name()]) for c, s in zip(selected, solutions)]).coin_spends)


def merge_custody(custody, coins, *, asset=bytes32.zeros, lineages=()):
    selected, group = _group(custody, coins, asset)
    if len(selected) < 2:
        raise ValueError('clean consolidation does not spend a single input')
    if type(custody) is CompanyRevenue:
        solutions = [Program.to([b'MERGE', asset, c.name(), int(c.amount), group, [], 0, [], 0, 0, []]) for c in selected]
    elif type(custody) is BackingCustody:
        solutions = [Program.to([b'MERGE', asset, c.name(), int(c.amount), group]) for c in selected]
    else:
        raise ValueError('only exact reviewed custody types may consolidate')
    return NativeOperation(custody.generation, 'SAME_CUSTODY_MERGE',
        _spends(custody, selected, solutions, asset, coins, lineages), ())


@dataclass(frozen=True)
class RevenuePayment:
    custody: CompanyRevenue
    asset: bytes32
    coins: tuple
    outputs: tuple[tuple[bytes32, int], ...]
    purpose: bytes32
    issued: int
    expires: int
    fee: int = 0

    def values(self):
        selected, group = _group(self.custody, self.coins, self.asset)
        if type(self.custody) is not CompanyRevenue:
            raise ValueError('company payments cannot use backing custody')
        nonzero(self.purpose, 'payment purpose commitment')
        if (type(self.issued) is not int or type(self.expires) is not int
                or not 0 < self.issued < self.expires < 2**64
                or self.expires - self.issued > MAX_REVENUE_APPROVAL_SECONDS):
            raise ValueError('payment approval must have an exact window of at most 24 hours')
        if (type(self.fee) is not int or not 0 <= self.fee <= MAX_REVENUE_NETWORK_FEE
                or self.asset != bytes32.zeros and self.fee):
            raise ValueError('only native revenue can pay a bounded network fee')
        if not 0 < len(self.outputs) <= 64:
            raise ValueError('payment requires 1–64 exact outputs')
        for destination, amount in self.outputs:
            nonzero(destination, 'payment destination')
            if type(amount) is not int or not 0 < amount < 2**64:
                raise ValueError('payment amounts must be positive bounded integers')
            if destination == self.custody.inner().get_tree_hash():
                raise ValueError('self-directed payments use consolidation instead')
        if (tuple(sorted(self.outputs)) != self.outputs or len({d for d, _ in self.outputs}) != len(self.outputs)):
            raise ValueError('payment outputs require unique destinations in canonical order')
        if sum(amount for _, amount in self.outputs) + self.fee > sum(c.amount for c in selected):
            raise ValueError('payment and fee exceed selected company revenue')
        return selected, group, [[destination, amount] for destination, amount in self.outputs]

    def action(self):
        _, group, outputs = self.values()
        return load_puzzle('generation_revenue_action_v1.clsp').curry(self.custody.generation,
            asset_puzzle(self.custody.inner(), self.asset).get_tree_hash(), self.asset,
            group, outputs, self.fee, self.purpose, self.issued, self.expires)

    def operation(self, authority_inner_hash, *, lineages=()):
        nonzero(authority_inner_hash, 'current authority inner hash')
        selected, group, outputs = self.values()
        solutions = [Program.to([b'PAY', self.asset, c.name(), int(c.amount), group, outputs,
            self.fee, self.purpose, self.issued, self.expires, authority_inner_hash]) for c in selected]
        return NativeOperation(self.custody.generation, 'COMPANY_REVENUE_PAYMENT',
            _spends(self.custody, selected, solutions, self.asset, self.coins, lineages), ())

    def review(self):
        self.values()
        return {'generationId': '0x'+self.custody.generation.hex(),
            'approvalRule': 'OWNER_PLUS_ONE', 'assetId': '0x'+self.asset.hex(),
            'inputs': ['0x'+c.name().hex() for c in sorted(self.coins, key=lambda c: c.name())],
            'outputs': [{'destination': '0x'+d.hex(), 'amount': amount} for d, amount in self.outputs],
            'feeMojos': self.fee, 'issuedAt': self.issued, 'expiresAt': self.expires,
            'purposeCommitment': '0x'+self.purpose.hex(),
            'actionHash': '0x'+self.action().get_tree_hash().hex(),
            'protectedFundsIncluded': False}
