"""Real native/CAT funds and V4 owner-plus-one EVM approvals in consensus.

All keys are deterministic simulator fixtures. Nothing signs for a real user
or submits outside SpendSim. No API-selected denominator or admin mock is used.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest
import pytest_asyncio
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol
from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles.admin_authority_v3_driver import (
    ADMIN_AUTHORITY_FUNDING_AMOUNT, AUTHORITY_LAUNCHER_AMOUNT,
    build_genesis_admin_authority_v3, build_authority_operational_mips_spend,
    build_identity_operational_action, build_identity_operational_solution, build_operational_solution,
)
from solslot_puzzles.generation_revenue import CompanyRevenue, BackingCustody, PrimaryFeeSplitter, RevenuePayment, merge_custody, asset_puzzle
from tests.test_admin_authority_v3 import _compressed_pubkey, _eip_member_solution, _singleton_spend
from tests.test_generation_registry_native import b32


@pytest_asyncio.fixture
async def revenue():
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client, acs = SimClient(sim), Program.to(1)
        for _ in range(3): await sim.farm_block(acs.get_tree_hash())
        origins = [r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())]
        parent = origins[0]
        daily = tuple(keys.PrivateKey(bytes([v])*32) for v in (0x11,0x22,0x33))
        recovery = tuple(AugSchemeMPL.key_gen(bytes([v])*32) for v in (0x41,0x42,0x43))
        authority = build_genesis_admin_authority_v3(parent_coin_id=parent.name(), network='testnet11',
            daily_compressed_pubkeys=tuple(_compressed_pubkey(k) for k in daily),
            recovery_bls_pubkeys=tuple(bytes(k.get_g1()) for k in recovery),
            source_manifest_hash=b32(88), authority_puzzle_version=4)
        conditions, launches = [], []
        for inner, amount in [(authority.inner_puzzle, AUTHORITY_LAUNCHER_AMOUNT),
                *((i.custody_reveal, i.launcher_amount) for i in authority.identity_vaults)]:
            more, launch = launch_conditions_and_coinsol(parent, inner, [], uint64(amount))
            conditions.extend(more); launches.append(launch)
        conditions.append(Program.to([51, acs.get_tree_hash(), int(parent.amount)-ADMIN_AUTHORITY_FUNDING_AMOUNT]))
        assert await client.push_tx(SpendBundle([make_spend(parent,acs,Program.to(conditions)),*launches],G2Element())) == (MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        sim.pass_time(uint64(1000)); await sim.farm_block()
        yield SimpleNamespace(sim=sim, client=client, acs=acs, origins=origins[1:], authority=authority,
            daily=daily, launches=launches, coins=[compute_additions(s)[0] for s in launches],
            custody=CompanyRevenue(b32(1),authority.authority_launcher_id))


def approvals(c, action, coadmin=1):
    a=c.authority
    mips=build_authority_operational_mips_spend(authority=a,current_authority_inner_puzzle=a.inner_puzzle,
        current_identities=a.identity_vaults,current_identity_coin_ids=tuple(coin.name() for coin in c.coins[1:]),
        authority_delegated_puzzle=action,coadmin_slot=coadmin)
    auth=_singleton_spend(coin=c.coins[0],launcher_id=a.authority_launcher_id,inner_puzzle=a.inner_puzzle,
        launcher_spend=c.launches[0],amount=AUTHORITY_LAUNCHER_AMOUNT,
        inner_solution=build_operational_solution(my_amount=AUTHORITY_LAUNCHER_AMOUNT,new_authority_version=2,
            mips_reveal=mips.reveal,mips_solution=mips.solution,authority_delegated_puzzle=action,identity_records=mips.identity_records))
    spends=[auth]
    for slot in mips.selected_slots:
        identity=a.identity_vaults[slot]
        signed=build_identity_operational_action(identity=identity,current_authority_inner_puzzle=a.inner_puzzle,
            authority_delegated_puzzle=action)
        spends.append(_singleton_spend(coin=c.coins[slot+1],launcher_id=identity.launcher_id,
            inner_puzzle=identity.custody_reveal,launcher_spend=c.launches[slot+1],amount=identity.launcher_amount,
            inner_solution=build_identity_operational_solution(identity=identity,current_authority_inner_puzzle=a.inner_puzzle,
                current_identity_coin_id=c.coins[slot+1].name(),authority_delegated_puzzle=action,
                daily_member_solution=_eip_member_solution(c.daily[slot],c.coins[slot+1].name(),signed.get_tree_hash()))))
    return tuple(spends)


async def fund(c, *, cat=False, backing=False, destination=None):
    custody=destination if destination is not None else BackingCustody(c.custody.generation) if backing else c.custody
    origin=c.origins[1]
    amounts=(5_000_000_000,7_000_000_000)
    if not cat:
        full=custody.inner();asset=bytes32.zeros
        funding=make_spend(origin,c.acs,Program.to([[51,full.get_tree_hash(),n] for n in amounts]+
            [[51,c.acs.get_tree_hash(),int(origin.amount)-sum(amounts)]]))
        bundle=SpendBundle([funding],G2Element())
        coins=tuple(coin for coin in bundle.additions() if coin.puzzle_hash==full.get_tree_hash())
        lineages=()
    else:
        tail=GENESIS_BY_ID_MOD.curry(origin.name());asset=tail.get_tree_hash()
        eve=Coin(origin.name(),construct_cat_puzzle(CAT_MOD,asset,c.acs).get_tree_hash(),uint64(sum(amounts)))
        funding=make_spend(origin,c.acs,Program.to([[51,eve.puzzle_hash,int(eve.amount)],
            [51,c.acs.get_tree_hash(),int(origin.amount)-int(eve.amount)]]))
        minted=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(eve,asset,c.acs,
            Program.to([[51,custody.inner().get_tree_hash(),n] for n in amounts]+[[51,[],-113,tail,[]]]),limitations_program_reveal=tail)])
        bundle=SpendBundle([funding,*minted.coin_spends],G2Element())
        coins=tuple(minted.additions())
        lineages=tuple(LineageProof(eve.parent_coin_info,c.acs.get_tree_hash(),eve.amount) for _ in coins)
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    return custody,coins,asset,lineages


def payment(c,coins,asset):
    now=int(c.sim.timestamp)-1
    return RevenuePayment(c.custody,asset,coins,((b32(70),2_000_000_000),(b32(71),3_000_000_000)),
        b32(72),now,now+86400,10_000_000 if asset==bytes32.zeros else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize('cat,coadmin',[(False,1),(False,2),(True,1),(True,2)])
async def test_exact_company_payments_need_owner_plus_either_coadmin_and_replay_fails(revenue,cat,coadmin):
    c=revenue;_,coins,asset,lineages=await fund(c,cat=cat)
    intent=payment(c,coins,asset);operation=intent.operation(c.authority.inner_puzzle.get_tree_hash(),lineages=lineages)
    spends=[*operation.spends,*approvals(c,intent.action(),coadmin)]
    for omitted in range(len(spends)):
        assert (await c.client.push_tx(SpendBundle(spends[:omitted]+spends[omitted+1:],G2Element())))[0]==MempoolInclusionStatus.FAILED
    bundle=SpendBundle(spends,G2Element())
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    outputs=[coin for coin in operation.bundle().additions()]
    assert sum(coin.amount for coin in outputs)==sum(coin.amount for coin in coins)-intent.fee
    for destination,amount in intent.outputs:
        assert len([coin for coin in outputs if coin.puzzle_hash==asset_puzzle(Program.to(1),asset).get_tree_hash()])==0
        expected=destination
        # CAT destinations are hashes rather than a reveal; check amounts and
        # exact native additions below using curry-treehash construction.
        from chia.wallet.util.curry_and_treehash import curry_and_treehash,calculate_hash_of_quoted_mod_hash
        if asset!=bytes32.zeros:
            from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
            expected=curry_and_treehash(calculate_hash_of_quoted_mod_hash(CAT_MOD_HASH),
                Program.to(CAT_MOD_HASH).get_tree_hash(),Program.to(asset).get_tree_hash(),destination)
        assert len([coin for coin in outputs if coin.puzzle_hash==expected and coin.amount==amount])==1
    assert (await c.client.push_tx(bundle))[0]==MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['destination','amount','purpose','fee','expiry','inputs','generation','asset','authority'])
async def test_signatures_cannot_authorize_another_payment(revenue,fault):
    c=revenue;_,coins,asset,lineages=await fund(c)
    intent=payment(c,coins,asset);original=approvals(c,intent.action())
    changed=intent
    if fault=='destination':changed=replace(intent,outputs=((b32(69),2_000_000_000),intent.outputs[1]))
    if fault=='amount':changed=replace(intent,outputs=((b32(70),2_000_000_001),intent.outputs[1]))
    if fault=='purpose':changed=replace(intent,purpose=b32(73))
    if fault=='fee':changed=replace(intent,fee=intent.fee+1)
    if fault=='expiry':changed=replace(intent,expires=intent.expires-1)
    if fault=='inputs':changed=replace(intent,coins=(coins[1],),outputs=((b32(70),1_000_000_000),))
    if fault in ('generation','asset'):
        changed=replace(intent,custody=replace(c.custody,generation=b32(2))) if fault=='generation' else replace(intent,asset=b32(2))
        with pytest.raises(ValueError):changed.operation(c.authority.inner_puzzle.get_tree_hash())
        return
    operation=changed.operation(b32(90) if fault=='authority' else c.authority.inner_puzzle.get_tree_hash())
    assert (await c.client.push_tx(SpendBundle([*operation.spends,*original],G2Element())))[0]==MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
async def test_expired_signed_payment_does_not_consume_funds(revenue):
    c=revenue;_,coins,asset,_=await fund(c)
    intent=payment(c,coins,asset)
    bundle=SpendBundle([*intent.operation(c.authority.inner_puzzle.get_tree_hash()).spends,*approvals(c,intent.action())],G2Element())
    c.sim.pass_time(uint64(intent.expires-int(c.sim.timestamp)+1));await c.sim.farm_block()
    assert (await c.client.push_tx(bundle))[0]==MempoolInclusionStatus.FAILED
    for coin in coins:
        assert not (await c.client.get_coin_record_by_name(coin.name())).spent


@pytest.mark.asyncio
@pytest.mark.parametrize('cat,backing',[(False,False),(True,False),(False,True),(True,True)])
async def test_consolidation_conserves_same_asset_and_custody_without_payment_authority(revenue,cat,backing):
    c=revenue;custody,coins,asset,lineages=await fund(c,cat=cat,backing=backing)
    op=merge_custody(custody,coins,asset=asset,lineages=lineages)
    for omitted in range(len(op.spends)):
        assert (await c.client.push_tx(SpendBundle(list(op.spends[:omitted]+op.spends[omitted+1:]),G2Element())))[0]==MempoolInclusionStatus.FAILED
    assert await c.client.push_tx(op.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    assert len(op.bundle().additions())==1
    assert op.bundle().additions()[0].amount==sum(c.amount for c in coins)
    assert op.bundle().additions()[0].puzzle_hash==coins[0].puzzle_hash


@pytest.mark.asyncio
async def test_company_approval_cannot_spend_backing_or_foreign_custody(revenue):
    c=revenue;backing,coins,asset,_=await fund(c,backing=True)
    intent=payment(c,coins,asset)
    with pytest.raises(ValueError,match='custody'):intent.action()
    with pytest.raises(ValueError):replace(intent,custody=backing).action()
    # Direct construction bypasses the Python guard: the native backing
    # contract still has no PAY branch even with company approvals attached.
    malicious=make_spend(coins[0],backing.inner(),Program.to([b'PAY',asset,coins[0].name(),int(coins[0].amount),
        [[coins[0].parent_coin_info,int(coins[0].amount)]]]))
    assert (await c.client.push_tx(SpendBundle([malicious],G2Element())))[0]==MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('cat',[False,True])
async def test_primary_fee_split_pays_only_company_and_sgt_then_company_approval_cannot_take_rewards(revenue,cat):
    from solslot_puzzles.generation_sgt import GenesisIssuancePlan
    from solslot_puzzles.generation_rewards import RewardCustody
    c=revenue
    bindings=GenesisIssuancePlan(b32(40),c.custody.generation,b32(41),b32(42),b32(43),
        (b32(44),b32(45),b32(46)),b32(47)).bindings()
    splitter=PrimaryFeeSplitter(bindings,b32(48),c.custody)
    _,coins,asset,lineages=await fund(c,cat=cat,destination=splitter)
    split=[]
    for index,coin in enumerate(coins):
        split.extend(splitter.operation(coin,asset,lineage=lineages[index] if cat else None).spends)
    bundle=SpendBundle(split,G2Element())
    assert await c.client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    company_ph=asset_puzzle(c.custody.inner(),asset).get_tree_hash()
    reward_ph=RewardCustody(bindings,b32(48),asset).full().get_tree_hash()
    additions=bundle.additions()
    company=tuple(coin for coin in additions if coin.puzzle_hash==company_ph)
    rewards=tuple(coin for coin in additions if coin.puzzle_hash==reward_ph)
    assert sum(coin.amount for coin in company)==8_400_000_000
    assert sum(coin.amount for coin in rewards)==3_600_000_000
    assert len(company)==len(rewards)==2 and len(additions)==4
    with pytest.raises(ValueError,match='custody'):
        payment(c,rewards,asset).operation(c.authority.inner_puzzle.get_tree_hash())
    parents={coin.name():coin for coin in coins}
    company_lineages=tuple(LineageProof(parents[coin.parent_coin_info].parent_coin_info,
        splitter.inner().get_tree_hash(),parents[coin.parent_coin_info].amount) for coin in company) if cat else ()
    intent=payment(c,company,asset)
    expense=SpendBundle([*intent.operation(c.authority.inner_puzzle.get_tree_hash(),lineages=company_lineages).spends,
        *approvals(c,intent.action())],G2Element())
    assert await c.client.push_tx(expense)==(MempoolInclusionStatus.SUCCESS,None)
    await c.sim.farm_block()
    for coin in rewards:
        assert not (await c.client.get_coin_record_by_name(coin.name())).spent
