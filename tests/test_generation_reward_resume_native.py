"""Bounded native/CAT processing of an authenticated, arbitrarily large snapshot."""
from dataclasses import replace
from copy import deepcopy

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia_rs import SpendBundle,G2Element
from chia_rs.sized_ints import uint64
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.generation_rewards import start_reward_epoch,close_reward_epoch
from solslot_puzzles.generation_sgt import transition_witness,ledger_inner
from solslot_puzzles.holdings import HoldingKind
from tests.test_generation_governance_native import generation,push
from tests.test_generation_holdings_native import cat_spend
from tests.test_generation_rewards_native import fee_inputs,holdings,tip


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['statutes'],indirect=True)
@pytest.mark.parametrize('native',[True,False])
async def test_resumable_rewards_authenticate_pages_and_preserve_all_claims(generation,native):
    c=generation;custody,fees=await fee_inputs(c,(101,),native=native)
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    epoch=start_reward_epoch(custody,c['gov'],c['registry'],holdings(c),c['parameters'],tip(c['parameters_coin']),fees)
    assert epoch.continuation and not epoch.claims
    for i in range(len(epoch.operation.spends)):
        assert (await c['client'].push_tx(SpendBundle([s for j,s in enumerate(epoch.operation.spends) if j!=i],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
    await push(c,list(epoch.operation.spends))
    progress=epoch.continuation;claims=[];seen=[]
    from solslot_api.generation_reward_evidence import verified_reward_progress,verify_reward_claim_source
    from tests.test_generation_primary_batch_api_native import NativeProvider
    snapshots={epoch.epoch_id:(holdings(c).tree,holdings(c).sequence)}
    # Deliberately process out of order. A keeper cannot skip a lower key and
    # thereby strand the epoch. Authenticated removal prevents duplicate rows.
    while progress:
        old=progress
        recovered,_=await verified_reward_progress(old.source.coin.name(),custody=custody,snapshots=snapshots,provider=NativeProvider(c))
        assert recovered.inner()==old.inner() and recovered.source==old.source
        available=old.remaining.holdings if old.phase==0 else old.owners.holdings
        keys=sorted((k for k,h in available.items() if old.phase==1 or h.kind in (HoldingKind.HOLDER,HoldingKind.LOCKED_HOLDER)),reverse=True)
        operation,progress,page=old.advance(keys[:1],limit=1)
        spend=operation.spends[0]
        raw=Program.from_bytes(bytes(spend.solution));inner=raw if native else raw.first()
        altered=deepcopy(inner.as_python());altered[3].append(altered[3][0])
        invalid=Program.to(altered) if native else Program.to([Program.to(altered),*list(raw.as_iter())[1:]])
        assert (await c['client'].push_tx(SpendBundle([make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),invalid)],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
        await push(c,list(operation.spends));seen.append(operation)
        assert (await c['client'].push_tx(operation.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
        claims.extend(page)
        for claim,source in page:
            verify_reward_claim_source(claim,source,custody)
            with pytest.raises(ValueError):verify_reward_claim_source(replace(claim,epoch_id=bytes32.zeros),source,custody)
    assert len(seen)==6 and len(claims)==3
    assert [claim.amount for claim,_ in claims]==[33]*3
    dust=[coin for coin in seen[-1].bundle().additions() if coin.puzzle_hash==custody.full().get_tree_hash()]
    assert len(dust)==1 and dust[0].amount==2
    assert sum(claim.amount for claim,_ in claims)+sum(coin.amount for coin in dust)==101


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['statutes'],indirect=True)
async def test_129_confirmed_eligible_holdings_do_not_block_rewards(generation):
    c=generation;coin=c['issue'].coins[0];descriptor=c['issue'].outputs[0];lineage=c['lineage']
    # Sequential valid two-output transfers establish the attack precondition
    # using consensus, rather than inventing an indexer root.
    for i in range(127):
        outputs=(replace(descriptor,amount=1),replace(descriptor,amount=descriptor.amount-1))
        witness,tree=transition_witness(c['bindings'],c['tree'],coin,descriptor,'TRANSFER',outputs)
        cat=cat_spend(c['bindings'],c['issue'],c['owners'],c['ledger_coin'],0,'TRANSFER',outputs,
            coin=coin,descriptor=descriptor,lineage=lineage)
        bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat])
        ledger=c['ledger_coin'].spend(Program.to([b'UPDATE',[witness]]))
        await push(c,[*bundle.coin_spends,ledger])
        c['sequence']+=1;c['tree']=tree
        c['ledger_coin'].advance(ledger,ledger_inner(c['bindings'],tree,c['sequence']))
        lineage=LineageProof(coin.parent_coin_info,descriptor.inner(c['bindings']).get_tree_hash(),coin.amount)
        coin=outputs[1].coin(c['bindings'],coin.name());descriptor=outputs[1]
    assert sum(h.kind==HoldingKind.HOLDER for h in c['tree'].holdings.values())==130
    custody,fees=await fee_inputs(c,(90,),native=True)
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    result=close_reward_epoch(custody,c['gov'],c['registry'],holdings(c),c['parameters'],tip(c['parameters_coin']),fees)
    assert result.continuation is not None
    await push(c,list(result.operation.spends));progress=result.continuation;claims=[];pages=0
    while progress:
        operation,progress,page=progress.advance(limit=8)
        await push(c,list(operation.spends));claims.extend(page);pages+=1
    assert pages==18 and len(claims)==3
    # All 128 split outputs aggregate to the unchanged owner before rounding.
    assert sorted(claim.amount for claim,_ in claims)==[30,30,30]
