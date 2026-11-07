"""Actual native pool/CAT custody; no reserve signer or arbitrary conditions.

Fixtures reuse the existing governed valuation, pool, offer, vault and CAT
drivers. Synthetic confirmed lineage isolates the reserve boundary; separate
genesis simulation tests prove the funded one-mojo anchor.
"""
from dataclasses import replace
from copy import deepcopy
from unittest.mock import patch
import tests.test_sols_swap_v4_driver as legacy_swap_tests

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,construct_cat_puzzle
from chia_rs import Coin,SpendBundle,G2Element

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_sols_reserve import reserve_inner
from solslot_puzzles.sols_swap_v4_driver import build_deed_to_sols_protocol_offer
from tests.test_generation_statutes_settlement import source
from tests.test_sols_swap_v4_driver import _reverse_arguments,_assert_signed_consensus,_singleton_child,b32


def reserve_swap(version=1,reserve_balance=None):
    pool,context,_,_=source(version)
    rules=replace(pool.permanent.permanent_rules,network_id=pool.generation)
    custody=reserve_inner(generation=pool.generation,registry_id=pool.registry_id,
        pool_id=pool.launcher_id,component_id=pool.component_id)
    pool=replace(pool,permanent=replace(pool.permanent,reserve_puzzle_hash=custody.get_tree_hash(),permanent_rules=rules))
    statutes=replace(context.statutes,permanent_rules=rules)
    context=replace(context,statutes=statutes)
    stat_coin,lineage,_=_singleton_child(launcher_id=statutes.launcher_id,parent_inner=statutes.inner(),
        current_inner=statutes.inner(),seed=225)
    config=pool.config()
    with patch.object(legacy_swap_tests,'RULES',rules):
        args=_reverse_arguments(parameters=statutes.economic_parameters(),config=config,statutes_state=statutes.economic_view())
    old=args['reserve_cat_coin'];cat=construct_cat_puzzle(CAT_MOD,rules.sols_tail_hash,custody)
    args.update(reserve_inner_puzzle=custody,reserve_cat_coin=Coin(old.parent_coin_info,cat.get_tree_hash(),old.amount),
        statutes_coin=stat_coin,statutes_lineage_proof=lineage,statutes_source=context)
    if reserve_balance is not None:
        from tests.test_sols_swap_v4_driver import _fixture
        from solslot_puzzles.sols_economics_v3 import SolsEconomicState
        from solslot_puzzles.sols_pool_v4 import SolsPoolStateV4,inventory_root,prepare_deed_to_sols
        from chia.wallet.lineage_proof import LineageProof
        with patch.object(legacy_swap_tests,'RULES',rules):
            existing=_fixture(parameters=statutes.economic_parameters(),config=config,statutes_state=statutes.economic_view()).receipt.record
        existing=replace(existing,deed_launcher_id=b32(80),custody_coin_id=b32(81),deed_commitment=b32(82))
        inventory=(existing,)
        state=SolsPoolStateV4(inventory_root(inventory),SolsEconomicState(True,existing.deed_value_micro_usd,
            0,0,1,30000+reserve_balance,reserve_balance),3)
        pool=pool.with_economics(state)
        pc,proof,_=_singleton_child(launcher_id=pool.launcher_id,parent_inner=pool.inner(),current_inner=pool.inner(),seed=228)
        old_receipt=args['receipt']
        receipt=prepare_deed_to_sols(pool_coin_id=pc.name(),state=state,inventory=inventory,
            deed_launcher_id=old_receipt.record.deed_launcher_id,custody_coin_id=old_receipt.record.custody_coin_id,
            deed_commitment=old_receipt.record.deed_commitment,collection=args['collection'],
            share_ppm=old_receipt.record.share_ppm,parameters=args['parameters'],statutes_state=args['statutes_state'],
            pause=None,vault_launcher_id=args['vault_launcher_id'],vault_coin_id=args['vault_coin'].name(),
            seller_sols_puzzle_hash=old_receipt.counterparty_puzzle_hash,quote_expires_at=args['quote_expires_at'])
        parent=Coin(b32(229),cat.get_tree_hash(),reserve_balance)
        reserve_coin=Coin(parent.name(),parent.puzzle_hash,parent.amount)
        args.update(receipt=receipt,pool_coin=pc,pool_lineage_proof=proof,reserve_cat_coin=reserve_coin,
            reserve_cat_lineage_proof=LineageProof(parent.parent_coin_info,custody.get_tree_hash(),parent.amount))
    protocol=build_deed_to_sols_protocol_offer(**args,vault_signature_data=None)
    return pool,args,protocol,protocol.offer.to_valid_spend()


@pytest.mark.parametrize('version',[1,2])
def test_native_pool_deposit_uses_constrained_reserve_without_custodial_signature(version):
    pool,args,protocol,bundle=reserve_swap(version)
    _assert_signed_consensus(bundle)
    # Reserve uses the original pool CAT tail, creates the committed Sols
    # payout and preserves the one-mojo anchor under the same custody puzzle.
    from chia.wallet.util.compute_additions import compute_additions
    reserve=args['reserve_cat_coin'];payout=args['receipt'].deed_to_sols_quote.seller_sols_mojos
    outputs=compute_additions(protocol.reserve_cat_spend)
    assert sorted(c.amount for c in outputs)==[1,payout]
    assert [c for c in outputs if c.puzzle_hash==reserve.puzzle_hash][0].amount==1
    assert not any(v.first().as_int() in range(43,51) for v in protocol.reserve_signing_conditions.as_iter())
    # Pool and buyer/deed authorization still have to complete together.
    missing=SpendBundle([s for s in bundle.coin_spends if s.coin!=args['pool_coin']],G2Element())
    with pytest.raises(ValueError):_assert_signed_consensus(missing)


@pytest.mark.parametrize('fault',['payout','destination','amount','generation','version','policy',
    'reserve-state','omit-group','duplicate-group','tail','mint-parent','operation','arbitrary-conditions'])
def test_native_reserve_rejects_unreviewed_or_unbound_payouts(fault):
    _,args,protocol,_=reserve_swap()
    spend=protocol.reserve_cat_spend
    _,cat_args=Program.from_bytes(bytes(spend.puzzle_reveal)).uncurry()
    inner=list(cat_args.as_iter())[2]
    solution=Program.from_bytes(bytes(spend.solution))
    raw=deepcopy(list(solution.as_iter())[0].as_python())
    action=raw.pop(0)
    if fault=='payout':raw[8][31]=b'\x01'
    if fault=='destination':raw[8][19]=bytes(b32(90))
    if fault=='amount':raw[6]=b'\x02'
    if fault=='generation':raw[0][1][8]=bytes(b32(90))
    if fault=='version':raw[2]=b'\x02'
    if fault=='policy':raw[1]=bytes(b32(90))
    if fault=='reserve-state':raw[0][11]=b'\x02'
    if fault=='omit-group':raw[7]=[]
    if fault=='duplicate-group':raw[7]*=2
    if fault=='tail':raw[9]=[b'\x01',b'\x01']
    if fault=='mint-parent':raw[8][20]=bytes(b32(90))
    if fault=='operation':raw[8][38]=bytes(b32(90))
    if fault=='arbitrary-conditions':raw=[[b'\x33',bytes(b32(90)),b'\x01']]
    raw=[action,*raw]
    try:
        conditions=inner.run(Program.to(raw))
    except ValueError:
        return
    # Authority substitutions can produce well-formed assertions, but the
    # actual current singleton cannot satisfy the substituted announcement.
    changed=list(solution.as_iter());changed[0]=Program.to(raw)
    bad=make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),Program.to(changed))
    bundle=protocol.offer.to_valid_spend()
    altered=SpendBundle([bad if s.coin==spend.coin else s for s in bundle.coin_spends],bundle.aggregated_signature)
    with pytest.raises(ValueError):_assert_signed_consensus(altered)


def merge_fixture():
    pool,*_=source()
    custody=reserve_inner(generation=pool.generation,registry_id=pool.registry_id,
        pool_id=pool.launcher_id,component_id=pool.component_id)
    pool=replace(pool,permanent=replace(pool.permanent,reserve_puzzle_hash=custody.get_tree_hash()))
    full=construct_cat_puzzle(CAT_MOD,pool.permanent.permanent_rules.sols_tail_hash,custody)
    from chia.wallet.lineage_proof import LineageProof
    parents=[Coin(b32(230+i),full.get_tree_hash(),amount) for i,amount in enumerate((1,30000,30000))]
    coins=tuple(Coin(c.name(),c.puzzle_hash,c.amount) for c in parents)
    lineages=tuple(LineageProof(c.parent_coin_info,custody.get_tree_hash(),c.amount) for c in parents)
    return pool,coins,lineages


def test_reuses_native_cat_consolidation_without_changing_custody_or_reserving_other_inputs():
    from solslot_puzzles.generation_sols_reserve import merge_reserve
    pool,coins,lineages=merge_fixture()
    successor,lineage,spends,conditions=merge_reserve(config=pool.config(),coins=coins,lineages=lineages)
    bundle=SpendBundle(list(spends),G2Element());_assert_signed_consensus(bundle)
    assert successor.amount==60001 and successor.puzzle_hash==coins[0].puzzle_hash
    assert len(conditions)==3
    for omitted in range(len(spends)):
        partial=SpendBundle(list(spends[:omitted]+spends[omitted+1:]),G2Element())
        with pytest.raises(ValueError):_assert_signed_consensus(partial)
    # A redirected output cannot be supplied to the immutable merge action.
    changed=list(Program.from_bytes(bytes(spends[0].solution)).as_iter())
    raw=deepcopy(changed[0].as_python());raw[8][0][0]=bytes(b32(95));changed[0]=Program.to(raw)
    bad=make_spend(spends[0].coin,Program.from_bytes(bytes(spends[0].puzzle_reveal)),Program.to(changed))
    with pytest.raises(ValueError):_assert_signed_consensus(SpendBundle([bad,*spends[1:]],G2Element()))


def test_existing_consolidation_coin_id_order_accepts_distinct_outputs_from_one_parent():
    from solslot_puzzles.generation_sols_reserve import merge_reserve
    from chia.wallet.lineage_proof import LineageProof
    pool,coins,_=merge_fixture()
    parent=Coin(b32(240),coins[0].puzzle_hash,31)
    children=tuple(Coin(parent.name(),parent.puzzle_hash,amount) for amount in (1,30))
    proof=LineageProof(parent.parent_coin_info,pool.permanent.reserve_puzzle_hash,31)
    successor,_,spends,_=merge_reserve(config=pool.config(),coins=children,lineages=(proof,proof))
    _assert_signed_consensus(SpendBundle(list(spends),G2Element()))
    assert successor.amount==31 and successor.parent_coin_info==min(children,key=lambda c:c.name()).name()


@pytest.mark.parametrize('fault',['different-owner','duplicate','missing-lineage','zero-amount'])
def test_consolidation_does_not_accept_foreign_or_inconsistent_reserve_sources(fault):
    from solslot_puzzles.generation_sols_reserve import merge_reserve
    pool,coins,lineages=merge_fixture();coins=list(coins)
    if fault=='different-owner':coins[0]=Coin(coins[0].parent_coin_info,b32(99),coins[0].amount)
    if fault=='duplicate':coins[1]=coins[0]
    if fault=='missing-lineage':lineages=lineages[1:]
    if fault=='zero-amount':coins[0]=Coin(coins[0].parent_coin_info,coins[0].puzzle_hash,0)
    with pytest.raises(ValueError):merge_reserve(config=pool.config(),coins=tuple(coins),lineages=lineages)


@pytest.mark.parametrize('reserve_balance',[1,1000,30001])
def test_deposit_reuses_current_reserve_before_minting_any_additional_sols(reserve_balance):
    _,args,protocol,bundle=reserve_swap(reserve_balance=reserve_balance)
    _assert_signed_consensus(bundle)
    quote=args['receipt'].deed_to_sols_quote
    assert quote.seller_sols_mojos==30000
    assert quote.reserve_sols_mojos_paid==min(reserve_balance-1,30000)
    assert quote.fresh_sols_mojos_minted==30000-quote.reserve_sols_mojos_paid
    from chia.wallet.util.compute_additions import compute_additions
    reserve=next(c for c in compute_additions(protocol.reserve_cat_spend)
        if c.puzzle_hash==args['reserve_cat_coin'].puzzle_hash)
    assert reserve.amount==args['receipt'].next_state.economics.reserve_sols_mojos==1
