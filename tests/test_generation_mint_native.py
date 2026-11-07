"""Holder-governed 25-deed issuance; simulator funds and metadata only.

Uses real governance, holdings, registry and mint kernels. Administrator
publication in this fixture is synthetic; its real signatures/recovery have
separate native tests. No live property packet is read or published.
"""
from dataclasses import replace
from copy import deepcopy

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import SpendBundle, G2Element
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_mint import TestMintEdition, MintRow
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles import load_puzzle
from tests.test_generation_governance_native import generation, open_vote, anchor, vote, finalize, push, perform_upgrade, unlock_all
from tests.test_generation_registry_native import b32


def edition_for(c):
    return TestMintEdition(c['bindings'].generation,b32(101),b32(102),b32(103),b32(104),b32(105),100,1,b'US-IL',
        tuple(MintRow(coin.name(),40000,300000,1_500_000_000_000_000) for coin in c['mint_funding']))


def mint_spends(c,edition,proposal,*,policy=None):
    mint,coin=c['mint'],c['mint_coin']
    gov,govcoin=c['gov'],c['gov_coin']
    registry,regcoin=c['registry'],c['registry_coin']
    from solslot_puzzles.generation_transactions import mint_collection,SingletonTip
    inventories=mint.inventories(edition);funding=[]
    for origin,output in zip(c['mint_funding'],inventories):
        funding.append(make_spend(origin,Program.to(1),Program.to([
            [51,output.launcher_spend.coin.puzzle_hash,1],
            [51,Program.to(1).get_tree_hash(),int(origin.amount)-1]])))
    tip=lambda c:SingletonTip(c.launcher,c.inner,c.coin,c.parent)
    operation,_,_,inventories=mint_collection(gov,tip(govcoin),registry,tip(regcoin),mint,tip(coin),
        proposal,edition,tuple(funding),policy=policy)
    return list(operation.spends),inventories



async def approve(c,edition):
    proposal=await open_vote(c,edition.bill())
    await anchor(c);await vote(c,[1])
    assert c['gov'].active.required_votes==15000
    c['sim'].pass_time(uint64(3601));await c['sim'].farm_block()
    await finalize(c)
    return proposal


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['mint'],indirect=True)
async def test_holder_vote_mints_exactly_25_unique_smartdeeds_and_cannot_mint_again(generation):
    c=generation
    await perform_upgrade(c)
    assert c['gov'].version==2
    edition=edition_for(c);proposal=await approve(c,edition)
    spends,inventory=mint_spends(c,edition,proposal)
    # All 25 are required, not just the authority update or a subset of launchers.
    for omitted in (0,1,2,4,len(spends)-1):
        status,_=await c['client'].push_tx(SpendBundle(spends[:omitted]+spends[omitted+1:],G2Element()))
        assert status==MempoolInclusionStatus.FAILED
    await push(c,spends)
    assert len({item.coin.name() for item in inventory})==25
    assert len({item.terms.deed_launcher_id for item in inventory})==25
    for item in inventory:
        record=await c['client'].get_coin_record_by_name(item.coin.name())
        assert record and not record.spent and record.coin.amount==1
        assert item.terms.metadata_root==edition.metadata_root
        assert item.terms.metadata_anchor_id==edition.commitment
        assert item.terms.share_ppm==40000 and item.terms.base_amount_minor==300000
        assert item.terms.technology_fee_bps==100 and item.terms.technology_fee_minor==3000
        assert item.terms.protocol_treasury_puzzle_hash==c['mint'].treasury_puzzle_hash
        assert item.terms.validator_pubkeys==c['mint'].validator_pubkeys
        from solslot_puzzles.generation_deed_custody import HeldSmartDeedTip
        actual=HeldSmartDeedTip(c['mint'].launcher_id,item.terms.deed_launcher_id,
            item.inner,item.coin,item.launcher_spend).validate()
        assert actual.full().get_tree_hash()==item.coin.puzzle_hash
        assert actual.launcher_puzzle.get_tree_hash()==item.terms.deed_launcher_puzzle_hash
        with pytest.raises(ValueError):replace(actual,mint_launcher_id=b32(99)).validate()
    assert sum(item.terms.base_amount_minor for item in inventory)==7_500_000
    assert sum(item.terms.share_ppm for item in inventory)==1_000_000
    after=c['mint'].minted(edition)
    c['mint_coin'].advance(spends[2],after.inner())
    c['gov']=c['gov'].executed(proposal,edition.bill())
    c['gov_coin'].advance(spends[0],c['gov'].inner())
    c['registry_coin'].advance(spends[1],c['registry'].inner())
    assert after.issued_count==25 and edition.collection in after.issued.keys
    with pytest.raises(ValueError,match='already minted'):after.inventories(edition)
    with pytest.raises(ValueError):
        c['mint_coin'].inner.run(c['mint'].mint_solution(edition,c['gov_coin'].inner.get_tree_hash()))
    assert (await c['client'].push_tx(SpendBundle(spends,G2Element())))[0]==MempoolInclusionStatus.FAILED
    # SGT remains conserved and eligible supply is still 30,000 after issuance.
    assert c['tree'].root.total==1_000_000 and c['tree'].root.eligible==30_000
    await unlock_all(c,proposal)
    assert all(int(h.kind)!=2 for h in c['tree'].holdings.values())


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['mint'],indirect=True)
async def test_native_mint_kernel_rejects_invalid_test_economics_and_generation(generation):
    c=generation;mint=c['mint'];edition=edition_for(c)
    valid=list(mint.mint_solution(edition,c['gov_coin'].inner.get_tree_hash()).as_iter())
    # Positive execution proves subsequent failures are not missing witnesses.
    assert list(mint.inner().run(Program.to(valid)).as_iter())
    for fault in ('production','generation','duplicate-parent','shares','fee','zero-price','zero-par','count','policy',
                  'zero-collection','zero-metadata','zero-preview','zero-property','zero-pricing','zero-parent'):
        raw=deepcopy(edition.program());policy=load_puzzle('generation_mint_logic_v1.clsp')
        if fault=='production':raw[0]=b'PRODUCTION'
        if fault=='generation':raw[1]=b32(99)
        if fault=='duplicate-parent':raw[10][1][0]=raw[10][0][0]
        if fault=='shares':raw[10][0][1]+=1
        if fault=='fee':raw[7]=1001
        if fault=='zero-price':raw[10][0][2]=0
        if fault=='zero-par':raw[10][0][3]=0
        if fault=='count':raw[10]=[]
        if fault=='policy':policy=Program.to(1)
        if fault.startswith('zero-') and fault[5:] in ('collection','metadata','preview','property','pricing'):
            raw[2+('collection','metadata','preview','property','pricing').index(fault[5:])]=b32(0)
        if fault=='zero-parent':raw[10][0][0]=b32(0)
        malformed=Program.to([b'MINT',[c['gov_coin'].inner.get_tree_hash(),raw,mint.issued.proof(edition.collection),policy]])
        with pytest.raises(ValueError):mint.inner().run(malformed)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['mint'],indirect=True)
async def test_approved_mint_cannot_substitute_economics_metadata_or_treasury(generation):
    c=generation;edition=edition_for(c);proposal=await approve(c,edition)
    valid,inventory=mint_spends(c,edition,proposal)
    for substitute in (replace(edition,metadata_root=b32(110)),replace(edition,preview_hash=b32(111)),
                       replace(edition,technology_fee_bps=200),replace(edition,pricing_round=b32(112))):
        with pytest.raises(ValueError):mint_spends(c,substitute,proposal)
    # Keep the approved bill but redirect one actual output. The fixed authority
    # must reject it even when all other 24 outputs match the approval.
    altered=list(valid);launcher=inventory[0].launcher_spend
    args=list(Program.from_bytes(bytes(launcher.solution)).as_iter());args[1]=Program.to(b32(113))
    altered[4]=make_spend(launcher.coin,Program.from_bytes(bytes(launcher.puzzle_reveal)),Program.to(args))
    assert (await c['client'].push_tx(SpendBundle(altered,G2Element())))[0]==MempoolInclusionStatus.FAILED
    await push(c,valid)
