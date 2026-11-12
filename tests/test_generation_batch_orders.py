"""Signed-terms preservation and native Offer aggregation, without mint rights.

Synthetic ACS payment inputs exercise Chia's Offer primitives only. Production
signatures, cancellation reconciliation and both-leg native settlement remain
separate acceptance gates; these fixtures are not real Sols issuance.
"""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.conditions import CreateCoin
from chia.wallet.trading.offer import Offer,OFFER_MOD_HASH
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import Coin,G2Element
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_batch_orders import (inspect_buyer_offer,combine_buyer_orders,funding_progress,
    batch_sols_distribution,primary_route_sols_distribution,inspect_primary_route_fees)
from solslot_puzzles.generation_parameters import GenerationParameters
from tests.test_generation_registry_native import b32


SOL=b32(70);GEN=b32(71);DEST=b32(72)
DRIVER=PuzzleInfo({'type':'CAT','tail':'0x'+SOL.hex()})


def offer(index=1,paid=100,wanted=30,destination=DEST,commit=True):
    puzzle=Program.to(1);coin=Coin(b32(index),puzzle.get_tree_hash(),uint64(paid))
    requested=Offer.notarize_payments({SOL:[CreateCoin(destination,uint64(wanted))]},[coin])
    conditions=[[51,OFFER_MOD_HASH,paid]]
    if commit:conditions.extend(v.to_program() for v in Offer.calculate_announcements(requested,{SOL:DRIVER}))
    return Offer(requested,WalletSpendBundle([make_spend(coin,puzzle,Program.to(conditions))],G2Element()),{SOL:DRIVER})


def inspect(source,**changes):
    context=dict(generation=GEN,sols_asset=SOL,sols_driver=DRIVER,payment_asset=None,
        destination_inner_hash=DEST,approved_payment_assets=frozenset())
    return inspect_buyer_offer(source,**(context|changes))


def test_combines_whole_native_offers_without_changing_buyer_amounts_or_custody():
    sources=[offer(i,paid,wanted) for i,paid,wanted in ((1,100,30),(2,200,60),(3,300,90))]
    orders=tuple(inspect(v) for v in sources);originals=[bytes(v) for v in sources]
    batch=combine_buyer_orders(orders)
    aggregate=Offer.from_bytes(batch.aggregate_bytes)
    assert aggregate.get_offered_amounts()=={None:600}
    assert aggregate.get_requested_amounts()=={SOL:180}
    assert [p.amount for p in aggregate.requested_payments[SOL]]==[30,60,90]
    assert [p.puzzle_hash for p in aggregate.requested_payments[SOL]]==[DEST]*3
    assert originals==[bytes(v) for v in sources] and originals==[o.offer_bytes for o in batch.orders]
    assert not aggregate.is_valid() # No backing/Sols settlement leg exists yet.
    with pytest.raises(ValueError,match='incomplete'):aggregate.to_valid_spend()
    low=funding_progress(batch,1000);assert low['remainingAmount']==400 and not low['cashThresholdMet']
    enough=funding_progress(batch,600);assert enough['cashThresholdMet'] and not enough['settlementReady']
    assert not enough['inputsRechecked'] and not enough['signatureValidated']
    assert batch.commitment!=combine_buyer_orders(tuple(reversed(orders))).commitment


@pytest.mark.parametrize('fault',['duplicate-file','overlapping-inputs','generation','asset','metadata'])
def test_rejects_ambiguous_or_forged_order_batches(fault):
    a,b=inspect(offer(1)),inspect(offer(2))
    if fault=='duplicate-file':b=a
    if fault=='overlapping-inputs':b=inspect(offer(1,wanted=31))
    if fault=='generation':b=replace(b,generation=b32(73))
    if fault=='asset':b=replace(b,payment_asset=b32(74))
    if fault=='metadata':b=replace(b,sols_amount=31)
    with pytest.raises(ValueError):combine_buyer_orders((a,b))


@pytest.mark.parametrize('fault',['destination','uncommitted','wrong-driver','unapproved-payment','old-asset'])
def test_inspection_requires_native_requested_payment_and_exact_asset_destination(fault):
    source=offer();context={}
    if fault=='destination':context['destination_inner_hash']=b32(77)
    if fault=='uncommitted':source=offer(commit=False)
    if fault=='wrong-driver':context['sols_driver']=PuzzleInfo({'type':'CAT','tail':'0x'+b32(77).hex()})
    if fault=='unapproved-payment':context['payment_asset']=b32(78)
    if fault=='old-asset':context['sols_asset']=b32(79)
    with pytest.raises(ValueError):inspect(source,**context)


@pytest.mark.parametrize('gross,weights',[(10000,(1,2,7)),(10001,(1,1,1)),(100000,(100,201,299)),(2**63,(1,2,3))])
def test_batch_quote_conserves_proportional_payouts_and_single_70_30_fee(gross,weights):
    authority=GenerationParameters(*(b32(n) for n in range(1,6)))
    outputs,fees=batch_sols_distribution(authority,gross,weights)
    assert sum(outputs)+fees.protocol_fee_sols_mojos+fees.sgt_rewards_fee_sols_mojos==gross
    assert fees==authority.fee_split(gross)
    net=sum(outputs);denominator=sum(weights)
    for amount,weight in zip(outputs,weights):
        assert net*weight//denominator<=amount<=net*weight//denominator+1
    assert all(amount>0 for amount in outputs)


@pytest.mark.parametrize('weights',[(),(0,1),(-1,1),(True,1),(2**64,1),(1,)*33])
def test_batch_quotes_reject_invalid_or_tiny_allocations(weights):
    with pytest.raises(ValueError):batch_sols_distribution(GenerationParameters(*(b32(n) for n in range(1,6))),1,weights)


def primary_terms():
    from solslot_puzzles.stripe_settlement_v1_driver import PrimaryMintTermsV3
    from chia_rs import AugSchemeMPL
    return PrimaryMintTermsV3('testnet11',b32(1),b32(2),b32(3),b32(4),b32(5),b32(6),40000,
        300000,100,3000,303000,b32(7),b32(8),
        tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (11,12,13)),b32(9),3)


def test_primary_route_preserves_mandatory_one_percent_and_adds_no_sols_fee():
    terms=primary_terms();before=replace(terms)
    fees=inspect_primary_route_fees(terms)
    assert (fees['primaryBaseMinor'],fees['primaryFeeMinor'],fees['primarySubtotalMinor'])==(300000,3000,303000)
    assert (fees['requestedProtocolFeeMinor'],fees['requestedSgtFeeMinor'])==(2100,900)
    assert fees['additionalSolsFeeBps']==0 and fees['aggregatorFeeBps']==0
    assert terms==before and fees['currentTreasuryPuzzleHash']=='0x'+terms.protocol_treasury_puzzle_hash.hex()
    assert fees['requiresGovernedPrimarySplit'] and not fees['nativeSplitVerified']
    assert primary_route_sols_distribution(10000,(1010,2020))==(3333,6667)
    assert sum(primary_route_sols_distribution(10000,(1010,2020)))==10000


@pytest.mark.parametrize('fault',['fee','subtotal','negative','boolean','unbounded','legacy'])
def test_primary_route_does_not_ignore_changed_or_invalid_native_terms(fault):
    t=primary_terms()
    if fault=='fee':t=replace(t,technology_fee_minor=1)
    if fault=='subtotal':t=replace(t,subtotal_minor=300000)
    if fault=='negative':t=replace(t,base_amount_minor=-1)
    if fault=='boolean':t=replace(t,technology_fee_bps=True)
    if fault=='unbounded':t=replace(t,technology_fee_bps=1001)
    if fault=='legacy':t=replace(t,inventory_version=1)
    with pytest.raises(ValueError):inspect_primary_route_fees(t)


def test_a_differently_sealed_primary_fee_is_preserved_and_requires_a_new_review():
    t=replace(primary_terms(),technology_fee_bps=200,technology_fee_minor=6000,subtotal_minor=306000)
    fees=inspect_primary_route_fees(t)
    assert fees['primaryFeeBps']==200 and fees['primarySubtotalMinor']==306000
    assert fees['requiresOfferingReview'] and fees['requestedSgtFeeMinor'] is None
    assert fees['additionalSolsFeeBps']==0 and not fees['nativeSplitVerified']
