"""Exact holder acceptance of an original permanent funded redemption leaf."""
from dataclasses import dataclass
from chia.types.blockchain_format.program import Program
from chia.wallet.conditions import CreateCoin
from chia.wallet.trading.offer import Offer,OFFER_MOD_HASH
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_deed_custody import HeldSmartDeedTip
from solslot_puzzles.vault_driver import DEFAULT_IDENTITY_ATTEST_ROOT,puzzle_for_p2_vault,eip712_typed_data_for_vault_spend
from solslot_puzzles.funded_redemption_v1 import redemption_funding_puzzle,DirectRedemptionAcceptance
from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver,smart_deed_singleton_driver


@dataclass(frozen=True)
class FundedRedemptionReview:
    deed_data:Program
    payment_data:Program
    proof:Program
    operation_hash:bytes32
    notarized:dict
    drivers:dict
    typed_data:dict


def review_funded_redemption(*,vault,deed,leaf_coin,plan,allocation,payment_destination):
    vault.validate()
    if not isinstance(deed,HeldSmartDeedTip):raise ValueError('redemption requires actual SmartDeed lineage')
    deed.validate();plan.validate();allocation.validate()
    mod,args=vault.inner.uncurry();fields=list(args.as_iter())
    if (mod!=load_puzzle('vault_singleton_inner_generation_v1.clsp') or len(fields)!=9
            or fields[4].as_atom() in (bytes(DEFAULT_IDENTITY_ATTEST_ROOT),bytes32.zeros)
            or fields[5].as_atom()==bytes32.zeros or deed.inner!=puzzle_for_p2_vault(vault.launcher_id)):
        raise ValueError('redemption requires current verified generation custody')
    if (allocation not in plan.allocations or allocation.deed_launcher_id!=deed.launcher_id
            or not isinstance(payment_destination,bytes32) or payment_destination==bytes32.zeros):
        raise ValueError('redemption allocation or payout destination changed')
    launcher_hash=deed.launcher_puzzle.get_tree_hash()
    expected=redemption_funding_puzzle(payment_asset_id=plan.payment_asset_id,collection_id=plan.collection_id,
        settlement_id=plan.settlement_id,allocation=allocation,deed_launcher_puzzle_hash=launcher_hash)
    if leaf_coin.puzzle_hash!=expected.get_tree_hash() or leaf_coin.amount!=allocation.payment_amount:
        raise ValueError('redemption requires the exact immutable funded leaf')
    drivers={plan.payment_asset_id:chia_cat_driver(plan.payment_asset_id),
        deed.launcher_id:smart_deed_singleton_driver(deed.launcher_id,launcher_hash)}
    memos=[plan.collection_id,plan.settlement_id,deed.launcher_id,allocation.deed_commitment]
    requested=Offer.notarize_payments({plan.payment_asset_id:[CreateCoin(payment_destination,
        uint64(allocation.payment_amount),memos)]},[deed.coin])
    payment=requested[plan.payment_asset_id][0]
    announcements=Offer.calculate_announcements(requested,drivers)
    if len(announcements)!=1:raise ValueError('redemption requires one exact payout')
    announcement=bytes32(announcements[0].to_program().rest().first().as_atom())
    deed_data=Program.to([deed.launcher_id,allocation.deed_commitment,plan.collection_id,plan.settlement_id])
    payment_data=Program.to([plan.payment_asset_id,allocation.payment_amount,payment_destination,payment.nonce,announcement])
    proof=Program.to([deed.coin.name(),deed.coin.parent_coin_info,launcher_hash,leaf_coin.parent_coin_info,allocation.share_ppm])
    operation=Program.to([b'RDA2',vault.coin.name(),deed_data,payment_data,proof]).get_tree_hash()
    return FundedRedemptionReview(deed_data,payment_data,proof,operation,requested,drivers,
        eip712_typed_data_for_vault_spend(b'd',operation,vault.coin.name()))


def accept_funded_redemption(*,vault,deed,leaf_coin,plan,allocation,payment_destination,signature=b''):
    review=review_funded_redemption(vault=vault,deed=deed,leaf_coin=leaf_coin,plan=plan,
        allocation=allocation,payment_destination=payment_destination)
    vault_spend=vault.spend(Program.to([vault.coin.name(),vault.inner.get_tree_hash(),1,b'd',
        [review.deed_data,review.payment_data,signature,review.proof]]))
    deed_spend=deed.spend(Program.to([vault.inner.get_tree_hash(),vault.coin.name(),deed.launcher_id,
        deed.inner.get_tree_hash(),1,OFFER_MOD_HASH,deed.coin.name()]))
    taker=Offer(review.notarized,WalletSpendBundle([vault_spend,deed_spend],G2Element()),review.drivers)
    return DirectRedemptionAcceptance(taker,vault_spend,deed_spend,review.operation_hash,
        bytes32(review.payment_data.at('rrrf').as_atom()),bytes32(review.payment_data.at('rrrrf').as_atom()))
