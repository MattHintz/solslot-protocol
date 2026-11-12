"""Native ID ancestry and exact-input recipient consent, using synthetic keys."""
from dataclasses import replace
import pytest
from chia._tests.util.spend_sim import SpendSim,SimClient
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH,SINGLETON_MOD,launch_conditions_and_coinsol
from chia_rs import Coin,SpendBundle,G2Element,AugSchemeMPL
from chia_rs.sized_ints import uint64
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.generation_vault_migration import verified_deed_transfer,review_verified_deed_transfer
from solslot_puzzles.generation_deed_custody import HeldSmartDeedTip
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from tests.test_generation_registry_native import Singleton,b32


def signed(spends,keys):
    signatures=[]
    for spend in spends:
        conditions=conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,11_000_000_000)
        for key,message in pkm_pairs_for_conditions_dict(conditions,spend.coin,DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA):
            signatures.append(AugSchemeMPL.sign(next(sk for sk in keys if sk.get_g1()==key),message))
    return SpendBundle(spends,AugSchemeMPL.aggregate(signatures))


def tip(v):return SingletonTip(v.launcher,v.inner,v.coin,v.parent)


def changed_action(spend,change):
    outer=list(Program.from_bytes(bytes(spend.solution)).as_iter())
    action=list(outer[2].as_iter());params=list(action[4].as_iter())
    change(params);action[4]=Program.to(params);outer[2]=Program.to(action)
    return make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),Program.to(outer))


@pytest.mark.asyncio
@pytest.mark.parametrize("auth",[1,3])
async def test_empty_start_real_stamp_and_recipient_cosign_preserve_verified_custody(auth):
    async with SpendSim.managed(None,defaults=DEFAULT_CONSTANTS) as sim:
        client=SimClient(sim);acs=Program.to(1)
        for _ in range(5):await sim.farm_block(acs.get_tree_hash())
        origins=[r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False)]
        keys=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (41,42)]
        from eth_keys import keys as evm_keys
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend
        evm=[evm_keys.PrivateKey(bytes([n])*32) for n in (41,42)]
        public=[bytes(k.get_g1()) for k in keys] if auth==1 else [k.public_key.to_compressed_bytes() for k in evm]
        validator_keys=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (111,112,113)]
        validator_public=tuple(bytes(k.get_g1()) for k in validator_keys)
        from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash
        bridge_policy=make_bridge_policy_hash(validator_public,2)
        def owner_signature(index,action,operation,coin):
            return b'' if auth==1 else evm[index].sign_msg_hash(signing_message_for_vault_spend(action,operation,coin)).to_bytes()[:64]
        def transfer_args(recipient,deed,timestamp):
            args=dict(generation=b32(1),sender=tip(vaults[0]),recipient=recipient,deed=deed,timestamp=timestamp)
            review=review_verified_deed_transfer(**args)
            return {**args,'sender_signature':owner_signature(0,b'm',review['operationHash'],args['sender'].coin.name()),
                'recipient_signature':owner_signature(1,b't',review['operationHash'],recipient.coin.name())}

        vaults=[];launches=[];empty_args=[]
        for i in range(2):
            origin=origins[i];launcher=Coin(origin.name(),SINGLETON_LAUNCHER_HASH,uint64(1)).name()
            params=dict(vault_launcher_id=launcher,owner_pubkey=public[i],auth_type=auth,
                members_merkle_root=Program.to(public[i]).get_tree_hash(),pool_launcher_id=b32(15),
                zkpassport_bridge_policy_hash=bridge_policy)
            empty_args.append(params);inner=vault_inner(**params)
            conditions,launch=launch_conditions_and_coinsol(origin,inner,[],uint64(1))
            conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
            launches.extend([make_spend(origin,acs,Program.to(conditions)),launch]);vaults.append(Singleton(inner,launch))
        assert (await client.push_tx(SpendBundle(launches,G2Element())))[0]==MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        # A malformed initially-stamped vault may exist as an output, but no
        # first spend can authenticate it or launder it into a successor.
        origin=origins[2];launcher=Coin(origin.name(),SINGLETON_LAUNCHER_HASH,uint64(1)).name()
        fake=vault_inner(**{**empty_args[0],'vault_launcher_id':launcher,'identity_attest_root':b32(22)})
        conditions,launch=launch_conditions_and_coinsol(origin,fake,[],uint64(1))
        conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
        assert (await client.push_tx(SpendBundle([make_spend(origin,acs,Program.to(conditions)),launch],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
        await sim.farm_block();forged=Singleton(fake,launch)
        attempted=forged.spend(Program.to([forged.coin.name(),fake.get_tree_hash(),1,b't',
            [vaults[0].coin.puzzle_hash,vaults[0].coin.name(),b32(24),b32(25),int(sim.timestamp),b'']]))
        with pytest.raises(ValueError):signed([attempted],keys)
        from solslot_puzzles.generation_vault_identity import build_generation_identity_bundle
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
        for i,vault in enumerate(vaults):
            root=b32(30+i);origin=origins[3+i]
            bridge=Coin(origin.name(),bridge_policy,uint64(2))
            fund=make_spend(origin,acs,Program.to([[51,bridge_policy,2],[51,acs.get_tree_hash(),int(origin.amount)-2]]))
            assert (await client.push_tx(SpendBundle([fund],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
            await sim.farm_block()
            built=build_generation_identity_bundle(bridge_parent_id=origin.name(),bridge_amount=2,
                validator_pubkeys=validator_public,threshold=2,signer_indices=(0,1),vault_coin=vault.coin,
                vault_launcher_id=vault.launcher,owner_pubkey_bytes=public[i],auth_type=auth,
                members_merkle_root=Program.to(public[i]).get_tree_hash(),pool_launcher_id=b32(15),
                new_identity_attest_root=root,attestation_leaf_hash=root,scoped_nullifier=b32(60+i),
                nullifier_type=1,service_scope_hash=b32(62),service_subscope_hash=b32(63),
                proof_timestamp=int(sim.timestamp),current_timestamp=int(sim.timestamp),
                lineage_proof=lineage_proof_for_coinsol(vault.parent),signature_data=owner_signature(i,b'z',root,vault.coin.name()))
            assert built.bridge.coin_spend.coin==bridge
            vault_spend=built.vault_spend
            assert (await client.push_tx(signed(list(built.spend_bundle.coin_spends),[*keys,*validator_keys])))[0]==MempoolInclusionStatus.SUCCESS
            await sim.farm_block();vault.advance(vault_spend,vault_inner(**empty_args[i],identity_attest_root=root))
        # Use the actual DID-curried SmartDeed launcher ABI. The authority
        # itself is synthetic ACS here; this is not a complete genesis/mint.
        from hashlib import sha256
        available=[r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False) if r.coin.amount>2]
        origin,deed_origin=available[-2:]
        conditions,mint_launch=launch_conditions_and_coinsol(origin,acs,[],uint64(1))
        conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
        assert (await client.push_tx(SpendBundle([make_spend(origin,acs,Program.to(conditions)),mint_launch],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
        await sim.farm_block();mint_authority=Singleton(acs,mint_launch)
        held=puzzle_for_p2_vault(vaults[0].launcher)
        launcher_puzzle=load_puzzle('singleton_launcher_with_did.clsp').curry(singleton_struct(mint_authority.launcher))
        launcher_coin=Coin(deed_origin.name(),launcher_puzzle.get_tree_hash(),uint64(1))
        structure=Program.to((singleton_struct(mint_authority.launcher).first(),(launcher_coin.name(),launcher_puzzle.get_tree_hash())))
        full=SINGLETON_MOD.curry(structure,held)
        solution=Program.to([acs.get_tree_hash(),full.get_tree_hash(),1,[]])
        launch=make_spend(launcher_coin,launcher_puzzle,solution)
        funding=make_spend(deed_origin,acs,Program.to([[51,launcher_coin.puzzle_hash,1],
            [51,acs.get_tree_hash(),int(deed_origin.amount)-1],[61,sha256(launcher_coin.name()+solution.get_tree_hash()).digest()]]))
        consent=mint_authority.spend(Program.to([[62,full.get_tree_hash()],[51,acs.get_tree_hash(),1]]))
        assert (await client.push_tx(SpendBundle([funding,launch,consent],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        deed=HeldSmartDeedTip(mint_authority.launcher,launcher_coin.name(),held,
            Coin(launcher_coin.name(),full.get_tree_hash(),uint64(1)),launch).validate()
        with pytest.raises(ValueError):
            SingletonTip(deed.launcher_id,deed.inner,deed.coin,deed.parent).validate()
        sim.pass_time(uint64(600));await sim.farm_block()
        operation,_=verified_deed_transfer(**transfer_args(tip(vaults[1]),deed,int(sim.timestamp)))
        for index in range(3):
            omitted=signed([s for j,s in enumerate(operation.spends) if j!=index],keys)
            assert (await client.push_tx(omitted))[0]!=MempoolInclusionStatus.SUCCESS
        # BLS mutations receive valid network owner signatures, testing native
        # bindings. EVM mutations must also fail their exact signed commitment.
        mutations=[(0,1,b32(80)),(0,4,b32(81)),(1,0,b32(82)),(1,1,b32(83)),
            (1,2,b32(84)),(1,3,b32(85)),(1,4,int(sim.timestamp)+1)]
        for leg,field,value in mutations:
            spends=list(operation.spends)
            spends[leg]=changed_action(spends[leg],lambda p,f=field,v=value:p.__setitem__(f,Program.to(v)))
            try:malicious=signed(spends,keys)
            except ValueError:continue # The exact CLVM boundary rejected it.
            assert (await client.push_tx(malicious))[0]!=MempoolInclusionStatus.SUCCESS
        for field in (3,4,5,6):
            spends=list(operation.spends)
            def recipient_edit(p,field=field):
                recipient=list(p[5].as_iter());recipient[field]=Program.to(b32(88));p[5]=Program.to(recipient)
            spends[0]=changed_action(spends[0],recipient_edit)
            try:malicious=signed(spends,keys)
            except ValueError:continue
            assert (await client.push_tx(malicious))[0]!=MempoolInclusionStatus.SUCCESS
        if auth==1:
            assert (await client.push_tx(SpendBundle(list(operation.spends),G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
        for timestamp in (int(sim.timestamp)-121,int(sim.timestamp)+121):
            stale,_=verified_deed_transfer(**transfer_args(tip(vaults[1]),deed,timestamp))
            assert (await client.push_tx(signed(list(stale.spends),keys)))[0]!=MempoolInclusionStatus.SUCCESS
        # Legacy arbitrary destination shape no longer authorizes release.
        legacy=vaults[0].spend(Program.to([vaults[0].coin.name(),vaults[0].inner.get_tree_hash(),1,b'm',
            [deed.launcher,b32(77),int(sim.timestamp),b'']]))
        with pytest.raises(ValueError):signed([legacy],keys)
        bundle=signed(list(operation.spends),keys)
        assert await client.push_tx(bundle)==(MempoolInclusionStatus.SUCCESS,None)
        await sim.farm_block()
        assert (await client.get_coin_record_by_name(operation.successors[2].coin.name())).coin.puzzle_hash==operation.successors[2].coin.puzzle_hash
        assert operation.successors[2].inner==puzzle_for_p2_vault(vaults[1].launcher)
        assert (await client.push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
        # The transferred custom-launcher deed can still exercise its earned
        # claim. A real CAT funds the original immutable redemption leaf.
        from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,construct_cat_puzzle,unsigned_spend_bundle_for_spendable_cats
        from chia.wallet.lineage_proof import LineageProof
        from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
        from chia.wallet.trading.offer import Offer
        from solslot_puzzles.funded_redemption_v1 import (
            FundedRedemptionAllocation,FundedRedemptionPlanV1,redemption_funding_puzzle,build_permanent_redemption_offer)
        from solslot_puzzles.generation_vault_redemption import accept_funded_redemption,review_funded_redemption
        recipient=operation.successors[1];owned=operation.successors[2]
        origin=next(r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False) if r.coin.amount>500)
        tail=GENESIS_BY_ID_MOD.curry(origin.name());asset=tail.get_tree_hash()
        allocation=FundedRedemptionAllocation(owned.launcher_id,b32(95),1_000_000,500)
        plan=FundedRedemptionPlanV1(b32(96),b32(97),asset,500,(allocation,))
        leaf=redemption_funding_puzzle(payment_asset_id=asset,collection_id=plan.collection_id,
            settlement_id=plan.settlement_id,allocation=allocation,deed_launcher_puzzle_hash=owned.launcher_puzzle.get_tree_hash())
        eve=Coin(origin.name(),construct_cat_puzzle(CAT_MOD,asset,acs).get_tree_hash(),uint64(500))
        funding=make_spend(origin,acs,Program.to([[51,eve.puzzle_hash,500],[51,acs.get_tree_hash(),int(origin.amount)-500]]))
        issue=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(eve,asset,acs,
            Program.to([[51,leaf.uncurry()[1].at('rrf').get_tree_hash(),500],[51,[], -113,tail,[]]]),limitations_program_reveal=tail)])
        assert (await client.push_tx(SpendBundle([funding,*issue.coin_spends],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        leaf_coin=Coin(eve.name(),leaf.get_tree_hash(),uint64(500))
        maker,_=build_permanent_redemption_offer(funding_coin=leaf_coin,
            funding_lineage_proof=LineageProof(eve.parent_coin_info,acs.get_tree_hash(),uint64(500)),
            plan=plan,allocation=allocation,deed_singleton_struct=owned.structure)
        claim_args=dict(vault=recipient,deed=owned,leaf_coin=leaf_coin,
            plan=plan,allocation=allocation,payment_destination=acs.get_tree_hash())
        review=review_funded_redemption(**claim_args)
        acceptance=accept_funded_redemption(**claim_args,signature=owner_signature(1,b'd',review.operation_hash,recipient.coin.name()))
        claim=Offer.aggregate([maker,acceptance.taker_offer]).to_valid_spend()
        for removed in (leaf_coin.name(),owned.coin.name(),recipient.coin.name()):
            partial=signed([s for s in claim.coin_spends if s.coin.name()!=removed],keys)
            assert (await client.push_tx(partial))[0]!=MempoolInclusionStatus.SUCCESS
        for field in (0,1,2,3,4):
            def proof_edit(p,field=field):
                proof=list(p[3].as_iter());proof[field]=Program.to(999999 if field==4 else b32(99));p[3]=Program.to(proof)
            bad=changed_action(acceptance.vault_spend,proof_edit)
            spends=[bad if s.coin==bad.coin else s for s in claim.coin_spends]
            try:malicious=signed(spends,keys)
            except ValueError:continue
            assert (await client.push_tx(malicious))[0]!=MempoolInclusionStatus.SUCCESS
        assert (await client.push_tx(signed(list(claim.coin_spends),keys)))[0]==MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        from chia.wallet.util.curry_and_treehash import curry_and_treehash,calculate_hash_of_quoted_mod_hash
        sink_hash=curry_and_treehash(calculate_hash_of_quoted_mod_hash(SINGLETON_MOD.get_tree_hash()),
            owned.structure.get_tree_hash(),b32(0))
        # Standard Offer is ephemeral; the final sink's parent is its exact NFT
        # settlement spend, not the source p2_vault spend.
        additions=claim.additions()
        sinks=[c for c in additions if c.puzzle_hash==sink_hash and c.amount==1]
        assert len(sinks)==1 and (await client.get_coin_record_by_name(sinks[0].name())).coin==sinks[0]
