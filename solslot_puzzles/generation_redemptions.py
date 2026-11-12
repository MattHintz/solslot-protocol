"""Exact holder-governed funding through the original permanent redemption code.

No keys, node access, fee selection, broadcast or raw conditions are accepted.
Funding is a new obligation (pause scope 8). Already funded leaf claims use the
unchanged redemption contract and do not consult the pause registry.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.funded_redemption_v1 import (
    FundedRedemptionPlanV1, canonical_redemption_allocations,
    p2_deed_redemption_v1_mod, redemption_funding_puzzle,
)
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_registry import Registry, inner_solution, singleton_struct
from solslot_puzzles.generation_transactions import (
    MAX_NATIVE_COST, NativeOperation, SingletonTip, _authorities,
)
from solslot_puzzles.redemption_treasury_v1 import FundedRedemptionLeaves, redemption_treasury_solution


def treasury_inner(governance: Governance, payment_asset_id: bytes32,
                   deed_launcher_puzzle_hash: bytes32) -> Program:
    """Original funding ABI and leaf; corrected bytewise deed-ID ordering."""
    mod = load_puzzle('generation_redemption_treasury_v1.clsp')
    return mod.curry(mod.get_tree_hash(), singleton_struct(governance.sgt.governance_launcher_id),
        CAT_MOD.get_tree_hash(), payment_asset_id, OFFER_MOD_HASH,
        p2_deed_redemption_v1_mod().get_tree_hash(), SINGLETON_MOD_HASH, deed_launcher_puzzle_hash)


@dataclass(frozen=True)
class TreasuryInput:
    coin: Coin
    parent: CoinSpend

    def validate(self, governance: Governance, plan: FundedRedemptionPlanV1,
                 deed_launcher_puzzle_hash: bytes32) -> LineageProof:
        plan.validate()
        if (not 1 <= len(plan.allocations) <= 100
                or plan.allocations != canonical_redemption_allocations(plan.allocations)
                or any(value == bytes32.zeros for value in (
                    plan.collection_id, plan.settlement_id, plan.payment_asset_id,
                    deed_launcher_puzzle_hash, self.coin.parent_coin_info))
                or any(item.deed_commitment == bytes32.zeros for item in plan.allocations)):
            raise ValueError('redemption requires bounded canonical, nonzero commitments')
        full = construct_cat_puzzle(CAT_MOD, plan.payment_asset_id,
            treasury_inner(governance, plan.payment_asset_id, deed_launcher_puzzle_hash))
        if self.coin.puzzle_hash != full.get_tree_hash() or self.coin.amount != plan.total_payment_amount:
            raise ValueError('redemption requires the exact funded treasury input')
        reveal = Program.from_bytes(bytes(self.parent.puzzle_reveal))
        mod, args = reveal.uncurry()
        values = list(args.as_iter())
        if (self.coin.parent_coin_info != self.parent.coin.name()
                or reveal.get_tree_hash() != self.parent.coin.puzzle_hash
                or mod != CAT_MOD or len(values) != 3 or Program.to(values) != args
                or values[0].as_atom() != CAT_MOD.get_tree_hash()
                or values[1].as_atom() != plan.payment_asset_id):
            raise ValueError('treasury parent differs from the exact CAT lineage')
        additions, _ = compute_additions_with_cost(self.parent, max_cost=MAX_NATIVE_COST)
        if additions.count(self.coin) != 1:
            raise ValueError('treasury parent does not create its exact funded output')
        return LineageProof(self.parent.coin.parent_coin_info, values[2].get_tree_hash(), self.parent.coin.amount)


def redemption_bill(governance: Governance, source: TreasuryInput,
                    plan: FundedRedemptionPlanV1, deed_launcher_puzzle_hash: bytes32) -> Program:
    source.validate(governance, plan, deed_launcher_puzzle_hash)
    return Program.to([b'FUND_REDEMPTION', source.coin.parent_coin_info, plan.collection_id,
        plan.settlement_id, plan.payment_asset_id, plan.total_payment_amount,
        [item.as_program_value() for item in plan.allocations], deed_launcher_puzzle_hash, source.coin.name()])


@dataclass(frozen=True)
class RedemptionFunding:
    operation: NativeOperation
    governance: Governance
    funded: FundedRedemptionLeaves
    bill: Program


def fund_redemption(governance: Governance, gov_tip: SingletonTip, registry: Registry,
                    reg_tip: SingletonTip, proposal: bytes32, source: TreasuryInput,
                    plan: FundedRedemptionPlanV1, deed_launcher_puzzle_hash: bytes32) -> RedemptionFunding:
    _authorities(governance, gov_tip, registry, reg_tip)
    lineage = source.validate(governance, plan, deed_launcher_puzzle_hash)
    bill = redemption_bill(governance, source, plan, deed_launcher_puzzle_hash)
    updated = governance.executed(proposal, bill)
    if registry.pause_mask & 8:
        raise ValueError('new redemption funding is paused; existing funded claims remain available')
    action = governance.action_key(proposal, bill)
    execute = gov_tip.spend(inner_solution('EXECUTE', gov_tip.coin, [proposal, bill,
        governance.approved.proof(action), bytes32.zeros, reg_tip.inner.get_tree_hash()]))
    permission = reg_tip.spend(inner_solution('AUTHORIZE_NEW', reg_tip.coin,
        [8, gov_tip.coin.puzzle_hash, action, bill]))
    inner = treasury_inner(governance, plan.payment_asset_id, deed_launcher_puzzle_hash)
    cat = SpendableCAT(source.coin, plan.payment_asset_id, inner,
        redemption_treasury_solution(treasury_coin=source.coin,
            governance_inner_puzzle_hash=gov_tip.inner.get_tree_hash(), plan=plan), lineage_proof=lineage)
    bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [cat])
    leaves = tuple(Coin(source.coin.name(), redemption_funding_puzzle(
        payment_asset_id=plan.payment_asset_id, collection_id=plan.collection_id,
        settlement_id=plan.settlement_id, allocation=item,
        deed_launcher_puzzle_hash=deed_launcher_puzzle_hash).get_tree_hash(),
        type(source.coin.amount)(item.payment_amount)) for item in plan.allocations)
    funded = FundedRedemptionLeaves(bundle, 0, leaves,
        LineageProof(source.coin.parent_coin_info, inner.get_tree_hash(), source.coin.amount))
    operation = NativeOperation(registry.generation, 'FUND_REDEMPTION',
        (execute, permission, *funded.spend_bundle.coin_spends),
        (gov_tip.advanced(execute, updated.inner()), reg_tip.advanced(permission, registry.inner())),
        funded.leaf_coins)
    operation.bundle()
    return RedemptionFunding(operation, updated, funded, bill)
