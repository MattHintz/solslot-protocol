"""Real CAT funding, holder ratification, exact legacy leaves and paused claims.

The isolated authority fixture uses synthetic administrator/holder puzzles.
Time advances only in simulation. The protected claim test uses a synthetic
deed custody singleton; actual BLS/EVM and identity checks remain covered by
the existing unchanged redemption acceptance suites.
"""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.conditions import CreateCoin
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, solution_for_singleton
from chia.wallet.lineage_proof import LineageProof
from solslot_puzzles.mint_publish_driver import deed_singleton_struct, deed_launcher_puzzle_hash
from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
from chia.wallet.trading.offer import Offer, OFFER_MOD_HASH
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles.funded_redemption_v1 import (
    FundedRedemptionAllocation, FundedRedemptionPlanV1, build_permanent_redemption_offer,
    p2_deed_redemption_v1_mod,
)
from solslot_puzzles.generation_governance_reader import reconstruct_governance_successor
from solslot_puzzles.generation_redemptions import TreasuryInput, redemption_bill, fund_redemption, treasury_inner
from solslot_puzzles.generation_registry import singleton_struct, inner_solution
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver, smart_deed_singleton_driver
from solslot_puzzles import load_puzzle
from tests.test_generation_governance_native import generation, open_vote, anchor, finalize, push,perform_upgrade
from tests.test_generation_registry_native import Singleton, authorize, b32


def tip(value):
    return SingletonTip(value.launcher, value.inner, value.coin, value.parent)


async def treasury(c, count=3):
    acs = Program.to(1)
    await c['sim'].farm_block(acs.get_tree_hash())
    origins = [row.coin for row in await c['client'].get_coin_records_by_puzzle_hash(
        acs.get_tree_hash(), include_spent_coins=False)]
    origin, deed_origin = origins[-2:]
    admin = c['admin_coin']
    authority = singleton_struct(admin.launcher)
    launcher_puzzle = load_puzzle('singleton_launcher_with_did.clsp').curry(authority)
    c['deed_launcher_ph'] = deed_launcher_puzzle_hash(protocol_did_singleton_struct=authority)
    launch_coin = Coin(deed_origin.name(), c['deed_launcher_ph'], uint64(1))
    structure = deed_singleton_struct(deed_launcher_id=launch_coin.name(), protocol_did_singleton_struct=authority)
    full = SINGLETON_MOD.curry(structure, acs)
    solution = Program.to([admin.inner.get_tree_hash(), full.get_tree_hash(), 1, []])
    launcher = make_spend(launch_coin, launcher_puzzle, solution)
    from hashlib import sha256
    conditions = [[51, launch_coin.puzzle_hash, 1],
        [51, acs.get_tree_hash(), int(deed_origin.amount)-1],
        [61, sha256(launch_coin.name()+solution.get_tree_hash()).digest()]]
    consent = admin.spend(Program.to([[62, full.get_tree_hash()], [51, admin.inner.get_tree_hash(), 1]]))
    await push(c, [make_spend(deed_origin, acs, Program.to(conditions)), launcher, consent])
    admin.advance(consent, admin.inner)
    deed_coin = Coin(launch_coin.name(), full.get_tree_hash(), uint64(1))
    deed = SimpleNamespace(launcher=launch_coin.name(), coin=deed_coin, structure=structure,
        spend=lambda conditions: make_spend(deed_coin, full,
            solution_for_singleton(LineageProof(launch_coin.parent_coin_info, None, uint64(1)),
                uint64(1), conditions)))
    asset = GENESIS_BY_ID_MOD.curry(origin.name())
    shares = (1000000,) if count == 1 else (500000, 300000, 200000)
    amounts = (1000001,) if count == 1 else (500001, 300000, 200000)
    ids = (deed.launcher,) if count == 1 else tuple(sorted((deed.launcher, b32(21), b32(22))))
    plan = FundedRedemptionPlanV1(b32(30), b32(31), asset.get_tree_hash(), 1000001,
        tuple(FundedRedemptionAllocation(i, b32(41+n), share, amount)
              for n, (i, share, amount) in enumerate(zip(ids, shares, amounts))))
    inner = treasury_inner(c['gov'], plan.payment_asset_id, c['deed_launcher_ph'])
    eve = Coin(origin.name(), construct_cat_puzzle(CAT_MOD, plan.payment_asset_id, acs).get_tree_hash(), uint64(plan.total_payment_amount))
    funding = make_spend(origin, acs, Program.to([
        [51, eve.puzzle_hash, int(eve.amount)],
        [51, acs.get_tree_hash(), int(origin.amount)-int(eve.amount)]]))
    cat = SpendableCAT(eve, plan.payment_asset_id, acs,
        Program.to([[51, inner.get_tree_hash(), int(eve.amount)], [51, [], -113, asset, []]]),
        limitations_program_reveal=asset)
    issued = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [cat])
    await push(c, [funding, *issued.coin_spends])
    coin = Coin(eve.name(), construct_cat_puzzle(CAT_MOD, plan.payment_asset_id, inner).get_tree_hash(), eve.amount)
    source = TreasuryInput(coin, issued.coin_spends[0])
    source.validate(c['gov'], plan, c['deed_launcher_ph'])
    return source, plan, deed


async def ratified(c, bill):
    proposal = await open_vote(c, bill, sponsors=(0, 1))
    born = await anchor(c)
    c['sim'].pass_time(born+3601-int(c['sim'].timestamp))
    await c['sim'].farm_block()
    await finalize(c)
    return proposal


async def pause(c, mask):
    reg, admin = c['registry_coin'], c['admin_coin']
    after = c['registry'].paused(mask)
    spend = reg.spend(inner_solution('PAUSE', reg.coin, [admin.inner.get_tree_hash(), mask]))
    consent = authorize(admin, reg, Program.to([b'PAUSE_NEW_OPERATIONS',
        c['bindings'].generation, c['registry'].pause_epoch, mask]).get_tree_hash())
    await push(c, [spend, consent])
    reg.advance(spend, after.inner()); admin.advance(consent, admin.inner)
    c['registry'] = after


def test_legacy_funding_pins_are_exact_original_modules():
    text = (Path(__file__).parents[1]/'solslot_puzzles/generation_redemption_v1.clib').read_text()
    for module in (load_puzzle('generation_redemption_treasury_v1.clsp'), p2_deed_redemption_v1_mod(), CAT_MOD):
        assert module.get_tree_hash().hex() in text
    assert OFFER_MOD_HASH.hex() in text


def test_replacement_corrects_signed_id_ordering_without_rewriting_the_predecessor():
    from solslot_puzzles.redemption_treasury_v1 import redemption_treasury_inner_puzzle,redemption_treasury_solution
    from solslot_puzzles.generation_sgt import GenesisIssuancePlan
    from solslot_puzzles.generation_governance import Governance
    plan=FundedRedemptionPlanV1(b32(21),b32(22),b32(23),100,(
        FundedRedemptionAllocation(b32(200),b32(24),1000000,100),))
    bindings=GenesisIssuancePlan(b32(1),b32(2),b32(3),b32(4),b32(5),
        (b32(6),b32(7),b32(8)),b32(9)).bindings()
    gov=Governance(bindings,b32(10),b32(11),b32(12),b32(13),load_puzzle('generation_extension_v1.clsp').get_tree_hash())
    old=redemption_treasury_inner_puzzle(governance_singleton_struct=singleton_struct(bindings.governance_launcher_id),
        payment_asset_id=plan.payment_asset_id,deed_launcher_puzzle_hash=b32(25))
    new=treasury_inner(gov,plan.payment_asset_id,b32(25))
    old_coin=Coin(b32(26),construct_cat_puzzle(CAT_MOD,plan.payment_asset_id,old).get_tree_hash(),uint64(100))
    new_coin=Coin(b32(26),construct_cat_puzzle(CAT_MOD,plan.payment_asset_id,new).get_tree_hash(),uint64(100))
    with pytest.raises(ValueError,match='clvm raise'):
        old.run(redemption_treasury_solution(treasury_coin=old_coin,governance_inner_puzzle_hash=gov.inner().get_tree_hash(),plan=plan))
    conditions=new.run(redemption_treasury_solution(treasury_coin=new_coin,governance_inner_puzzle_hash=gov.inner().get_tree_hash(),plan=plan))
    assert len([row for row in conditions.as_iter() if row.first().as_int()==51])==1


@pytest.mark.asyncio
async def test_completed_holder_vote_funds_exact_permanent_leaves_once(generation):
    c = generation
    source, plan, _ = await treasury(c)
    bill = redemption_bill(c['gov'], source, plan, c['deed_launcher_ph'])
    proposal = await open_vote(c, bill, sponsors=(0, 1))
    born = await anchor(c)
    with pytest.raises(ValueError, match='unapproved'):
        fund_redemption(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']),
            proposal, source, plan, c['deed_launcher_ph'])
    c['sim'].pass_time(born+3601-int(c['sim'].timestamp)); await c['sim'].farm_block(); await finalize(c)
    funded = fund_redemption(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']),
        proposal, source, plan, c['deed_launcher_ph'])
    spends = list(funded.operation.spends)
    # Every authority and funding input is mandatory, including the scope-8
    # registry permission. The vote cannot be consumed by an empty transfer.
    for omitted in range(len(spends)):
        result = await c['client'].push_tx(SpendBundle([s for i,s in enumerate(spends) if i!=omitted], G2Element()))
        assert result[0] == MempoolInclusionStatus.FAILED
    before = c['gov']
    await push(c, spends)
    evidence = reconstruct_governance_successor(spends[0], before)
    assert evidence.after.state() == funded.governance.state()
    assert sum(coin.amount for coin in funded.funded.leaf_coins) == plan.total_payment_amount
    for coin, allocation in zip(funded.funded.leaf_coins, plan.allocations):
        row = await c['client'].get_coin_record_by_name(coin.name())
        assert row and not row.spent and coin.amount == allocation.payment_amount
    assert (await c['client'].push_tx(funded.operation.bundle()))[0] == MempoolInclusionStatus.FAILED
    assert not funded.governance.approved.keys


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['asset','collection','settlement','source-parent','source-id','amount','allocation','deed-launcher','generation','lineage','order','duplicate-commitment'])
async def test_funding_cannot_substitute_approved_commitments(generation, fault):
    c = generation
    source, plan, _ = await treasury(c)
    bill = redemption_bill(c['gov'], source, plan, c['deed_launcher_ph'])
    proposal = await ratified(c, bill)
    original = fund_redemption(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']),
        proposal, source, plan, c['deed_launcher_ph'])
    rows = bill.as_python()
    field = {'asset':4, 'collection':2, 'settlement':3, 'source-parent':1, 'source-id':8, 'amount':5, 'deed-launcher':7}
    if fault in field: rows[field[fault]] = b32(92) if fault != 'amount' else plan.total_payment_amount-1
    elif fault == 'allocation': rows[6][0][1] = b32(92)
    elif fault == 'order': rows[6] = list(reversed(rows[6]))
    elif fault == 'duplicate-commitment': rows[6][1][1] = rows[6][0][1]
    elif fault == 'generation':
        with pytest.raises(ValueError):
            fund_redemption(replace(c['gov'], sgt=replace(c['bindings'], generation=b32(92))),
                tip(c['gov_coin']), c['registry'], tip(c['registry_coin']), proposal, source, plan, c['deed_launcher_ph'])
        return
    elif fault == 'lineage':
        with pytest.raises(ValueError, match='lineage'):
            redemption_bill(c['gov'], replace(source, parent=make_spend(source.parent.coin,
                Program.to(1), Program.to([]))), plan, c['deed_launcher_ph'])
        return
    changed = Program.to(rows)
    execute = c['gov_coin'].spend(inner_solution('EXECUTE', c['gov_coin'].coin,
        [proposal, changed, c['gov'].approved.proof(c['gov'].action_key(proposal, bill)),
         b32(0), c['registry_coin'].inner.get_tree_hash()]))
    bad = SpendBundle([execute, *original.operation.spends[1:]], G2Element())
    assert (await c['client'].push_tx(bad))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
async def test_pause_blocks_new_funding_without_consuming_vote(generation):
    c = generation
    source, plan, _ = await treasury(c)
    bill = redemption_bill(c['gov'], source, plan, c['deed_launcher_ph'])
    proposal = await ratified(c, bill)
    original = fund_redemption(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']),
        proposal, source, plan, c['deed_launcher_ph'])
    await pause(c, 8)
    with pytest.raises(ValueError, match='paused'):
        fund_redemption(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']),
            proposal, source, plan, c['deed_launcher_ph'])
    action = c['gov'].action_key(proposal, bill)
    execute = c['gov_coin'].spend(inner_solution('EXECUTE', c['gov_coin'].coin,
        [proposal, bill, c['gov'].approved.proof(action), b32(0), c['registry_coin'].inner.get_tree_hash()]))
    permission = c['registry_coin'].spend(inner_solution('AUTHORIZE_NEW', c['registry_coin'].coin,
        [8, c['gov_coin'].coin.puzzle_hash, action, bill]))
    assert (await c['client'].push_tx(SpendBundle([execute, permission, original.operation.spends[-1]], G2Element())))[0] == MempoolInclusionStatus.FAILED
    assert action in c['gov'].approved.keys
    assert not (await c['client'].get_coin_record_by_name(source.coin.name())).spent


@pytest.mark.asyncio
async def test_governed_code_upgrade_preserves_existing_funding_and_approved_allocations(generation):
    c=generation;source,plan,_=await treasury(c)
    bill=redemption_bill(c['gov'],source,plan,c['deed_launcher_ph'])
    proposal=await ratified(c,bill)
    await perform_upgrade(c)
    assert c['gov'].version==2
    assert c['gov'].action_key(proposal,bill) in c['gov'].approved.keys
    assert not (await c['client'].get_coin_record_by_name(source.coin.name())).spent
    funded=fund_redemption(c['gov'],tip(c['gov_coin']),c['registry'],tip(c['registry_coin']),
        proposal,source,plan,c['deed_launcher_ph'])
    await push(c,list(funded.operation.spends))
    assert not funded.governance.approved.keys
    assert sum(coin.amount for coin in funded.funded.leaf_coins)==plan.total_payment_amount


@pytest.mark.asyncio
async def test_existing_funded_leaf_claim_remains_live_under_full_pause(generation):
    c = generation
    source, plan, deed = await treasury(c, count=1)
    bill = redemption_bill(c['gov'], source, plan, c['deed_launcher_ph'])
    proposal = await ratified(c, bill)
    funding = fund_redemption(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']),
        proposal, source, plan, c['deed_launcher_ph'])
    await push(c, list(funding.operation.spends))
    c['gov_coin'].advance(funding.operation.spends[0], funding.governance.inner())
    c['registry_coin'].advance(funding.operation.spends[1], c['registry'].inner())
    c['gov'] = funding.governance
    await pause(c, 31)
    maker, _ = build_permanent_redemption_offer(funding_coin=funding.funded.leaf_coins[0],
        funding_lineage_proof=funding.funded.leaf_lineage_proof, plan=plan,
        allocation=plan.allocations[0], deed_singleton_struct=deed.structure)
    requested = Offer.notarize_payments({plan.payment_asset_id:
        [CreateCoin(Program.to(1).get_tree_hash(), uint64(plan.total_payment_amount))]}, [deed.coin])
    announcements = Offer.calculate_announcements(requested, maker.driver_dict)
    sale = deed.spend(Program.to([[51, OFFER_MOD_HASH, 1], *[a.to_program() for a in announcements]]))
    taker = Offer(requested, SpendBundle([sale], G2Element()), {
        plan.payment_asset_id: chia_cat_driver(plan.payment_asset_id),
        deed.launcher: smart_deed_singleton_driver(deed.launcher, c['deed_launcher_ph'])})
    aggregate = Offer.aggregate([maker, taker])
    bundle = aggregate.to_valid_spend()
    assert aggregate.is_valid() and aggregate.fees() == 0
    assert c['registry'].pause_mask == 31
    assert c['registry_coin'].coin.name() not in {s.coin.name() for s in bundle.coin_spends}
    await push(c, list(bundle.coin_spends))
    sink = [coin for coin in bundle.additions() if coin.amount == 1
        and coin.name() not in {s.coin.name() for s in bundle.coin_spends}]
    assert len(sink) == 1
    assert (await c['client'].push_tx(bundle))[0] == MempoolInclusionStatus.FAILED
