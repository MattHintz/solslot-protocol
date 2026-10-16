"""Full holder vote -> ratification -> delayed governance code activation.

Synthetic admin authority and owner keys isolate the new consensus kernels.
This suite does not replace the existing three-admin recovery/signature suite
or the mandatory live Testnet11 rehearsal with actual waiting periods.
"""
from dataclasses import replace
from copy import copy

import pytest
import pytest_asyncio
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol
from chia_rs import Coin, G2Element, SpendBundle, AugSchemeMPL
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import Governance, ballot_witnesses
from solslot_puzzles.generation_registry import Component, CodeChange, Registry, UpgradePlan, inner_solution
from solslot_puzzles.generation_sgt import GenesisIssuancePlan, build_initial_issuance, ledger_inner, transition_digest, transition_witness
from solslot_puzzles.holdings import HoldingKind
from solslot_puzzles.generation_vault import vault_inner, sgt_owner, authorization_solution, authorization_hash, owner_solution, signing_digest
from solslot_puzzles.vault_driver import one_leaf_merkle_root
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_mint import GenerationMint
from solslot_puzzles.generation_pool import GenerationPool
from tests.test_admin_authority_v3 import _compressed_pubkey
from tests.test_generation_registry_native import Singleton, b32, authorize


@pytest_asyncio.fixture
async def generation(request):
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client = SimClient(sim)
        acs = Program.to(1)
        for _ in range(18 if getattr(request,'param',False) in ('mint','batch','batch-revenue') else 6 if getattr(request,'param',False)=='rewards' else 4): await sim.farm_block(acs.get_tree_hash())
        origins = [r.coin for r in await client.get_coin_records_by_puzzle_hash(
            acs.get_tree_hash(), include_spent_coins=False)]
        ids = [Coin(c.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name() for c in origins]
        owners = [acs, Program.to([2, (1, 1), 1]), Program.to([2, (1, [2, (1, 1), 1]), 1])]
        vaults, custody_keys, custody_types = [], [], []
        if getattr(request,'param',False) is True or getattr(request,'param',False)=='rewards':
            custody_keys = [AugSchemeMPL.key_gen(bytes([61])*32), keys.PrivateKey(bytes([62])*32),
                            AugSchemeMPL.key_gen(bytes([63])*32)]
            custody_types = [1,3,1]
            vault_spends=[]; owners=[]
            vault_origins=origins[8:11] if request.param=='rewards' else origins[5:8]
            vault_ids=ids[8:11] if request.param=='rewards' else ids[5:8]
            for origin,launcher,sk,kind in zip(vault_origins,vault_ids,custody_keys,custody_types):
                pubkey=bytes(sk.get_g1()) if kind==1 else _compressed_pubkey(sk)
                inner=vault_inner(vault_launcher_id=launcher,owner_pubkey=pubkey,auth_type=kind,
                    members_merkle_root=one_leaf_merkle_root(pubkey),pool_launcher_id=b32(9))
                conditions,launch=launch_conditions_and_coinsol(origin,inner,[],uint64(1))
                conditions.append(Program.to([51,acs.get_tree_hash(),int(origin.amount)-1]))
                vault_spends.extend([make_spend(origin,acs,Program.to(conditions)),launch])
                vaults.append(Singleton(inner,launch)); owners.append(sgt_owner(b32(1),launcher))
            assert (await client.push_tx(SpendBundle(vault_spends,G2Element())))[0]==MempoolInclusionStatus.SUCCESS
            await sim.farm_block()
        plan = GenesisIssuancePlan(origins[0].name(), b32(1), ids[1], ids[2], b32(3),
                                  tuple(p.get_tree_hash() for p in owners), b32(88))
        bindings, issue = plan.bindings(), build_initial_issuance(plan)
        old = load_puzzle("generation_extension_v1.clsp").get_tree_hash()
        mint = GenerationMint(bindings.generation,ids[3],ids[2],ids[5],b32(12),b32(9),b32(81),b32(82),
            tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (71,72,73)),b32(83)) if getattr(request,'param',False)=='mint' else None
        governance = Governance(bindings, ids[3], ids[4], mint.launcher_id if mint else b32(9), b32(10), old)
        component = Component(b32(10), ids[2], load_puzzle("generation_governance_v1.clsp").get_tree_hash(), old, 1, 1)
        parameters = GenerationParameters(bindings.generation,ids[3],ids[2],ids[5],b32(11)) if getattr(request,'param',False)=='parameters' else None
        if getattr(request,'param',False) in ('statutes','rewards'):
            from solslot_puzzles.generation_statutes import GenerationStatutes
            from tests.test_sols_swap_v4_driver import RULES
            from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
            parameters=GenerationStatutes(bindings.generation,ids[3],ids[2],ids[5],b32(11),
                pool_id=b32(9),permanent_rules=replace(RULES,sgt_tail_hash=bindings.tail_hash,
                    sols_tail_hash=pool_token_tail_hash(b32(9)),network_id=bindings.generation))
        pool = None
        if getattr(request, 'param', False) in ('pool','pool-reserve'):
            from tests.test_sols_swap_v4_driver import CONFIG, EMPTY_POOL
            from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
            from solslot_puzzles.generation_registry import singleton_struct
            permanent = replace(CONFIG, pool_launcher_id=ids[5], governance_singleton_struct=singleton_struct(ids[2]),
                permanent_rules=replace(CONFIG.permanent_rules, sgt_tail_hash=bindings.tail_hash,
                    sols_tail_hash=pool_token_tail_hash(ids[5]), network_id=bindings.generation))
            pool = GenerationPool(bindings.generation, ids[3], b32(13), permanent, EMPTY_POOL)
            if request.param=='pool-reserve':
                from solslot_puzzles.generation_sols_reserve import reserve_inner
                custody=reserve_inner(generation=bindings.generation,registry_id=ids[3],
                    pool_id=ids[5],component_id=pool.component_id)
                pool=replace(pool,permanent=replace(permanent,reserve_puzzle_hash=custody.get_tree_hash()))
        if getattr(request,'param',False) in ('batch','batch-revenue'):
            from solslot_puzzles.generation_statutes import GenerationStatutes
            from solslot_puzzles.generation_primary_inventory import batch_bindings
            from solslot_puzzles.generation_sols_reserve import reserve_inner
            from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
            from solslot_puzzles.generation_registry import singleton_struct
            from tests.test_sols_swap_v4_driver import CONFIG,EMPTY_POOL,RULES
            parameters=GenerationStatutes(bindings.generation,ids[3],ids[2],ids[5],b32(11),
                pool_id=ids[7],permanent_rules=replace(RULES,sgt_tail_hash=bindings.tail_hash,
                    sols_tail_hash=pool_token_tail_hash(ids[7]),network_id=bindings.generation))
            mint=GenerationMint(bindings.generation,ids[3],ids[2],ids[6],b32(12),ids[7],b32(81),b32(82),
                tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (71,72,73)),b32(83),
                primary_batch_bindings=batch_bindings(generation=bindings.generation,pool_id=ids[7],
                    sgt=bindings,statutes_id=ids[5],treasury=parameters.permanent_rules.protocol_treasury_puzzle_hash,
                    oracle_pubkeys=tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (81,82,83))))
            restricted = request.param == 'batch-revenue'
            revenue = None
            if restricted:
                from solslot_puzzles.generation_revenue import CompanyRevenue, BackingCustody
                revenue = CompanyRevenue(bindings.generation, ids[4]).inner().get_tree_hash()
                parameters = replace(parameters, permanent_rules=replace(parameters.permanent_rules,
                    protocol_treasury_puzzle_hash=BackingCustody(bindings.generation).inner().get_tree_hash()))
                mint = replace(mint, treasury_puzzle_hash=revenue, primary_batch_bindings=batch_bindings(
                    generation=bindings.generation, pool_id=ids[7], sgt=bindings, statutes_id=ids[5],
                    treasury=revenue, pool_kernel_version=2,
                    oracle_pubkeys=tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1()) for n in (81,82,83))))
            custody=reserve_inner(generation=bindings.generation,registry_id=ids[3],pool_id=ids[7],component_id=b32(13),
                pool_kernel_version=2 if restricted else 1)
            launcher=load_puzzle('singleton_launcher_with_did.clsp').curry(singleton_struct(mint.launcher_id))
            permanent=replace(CONFIG,pool_launcher_id=ids[7],governance_singleton_struct=singleton_struct(ids[2]),
                statutes_inner_mod_hash=load_puzzle('generation_statutes_v1.clsp').get_tree_hash(),
                statutes_singleton_struct=singleton_struct(ids[5]),permanent_rules=parameters.permanent_rules,
                reserve_puzzle_hash=custody.get_tree_hash(),deed_launcher_puzzle_hash=launcher.get_tree_hash(),
                vault_v2_mod_hash=load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash())
            pool=GenerationPool(bindings.generation,ids[3],b32(13),permanent,EMPTY_POOL,
                company_revenue_puzzle_hash=revenue)
            governance=replace(governance,mint_id=mint.launcher_id)
        registry = Registry(bindings.generation, ids[3], ids[2], ids[4],
                            (component,parameters.component(),mint.component(),pool.component()) if parameters and mint and pool else (component,parameters.component()) if parameters else (component,mint.component()) if mint
                            else (component,pool.component()) if pool else (component,))
        li = ledger_inner(bindings, issue.holdings, 0)
        inners = [li, governance.inner(), registry.inner(), acs]
        if parameters:inners.append(parameters.inner())
        if mint:inners.append(mint.inner())
        if pool:inners.append(pool.inner())
        spends = [make_spend(origins[0], acs, Program.to([
            [51, issue.eve_coin.puzzle_hash, 1_000_000],
            [51, acs.get_tree_hash(), int(origins[0].amount) - 1_000_000]])), issue.eve_spend]
        objects = []
        for origin, inner in zip(origins[1:], inners):
            conditions, launch = launch_conditions_and_coinsol(origin, inner, [], uint64(1))
            conditions.append(Program.to([51, acs.get_tree_hash(), int(origin.amount) - 1]))
            spends.extend([make_spend(origin, acs, Program.to(conditions)), launch])
            objects.append(Singleton(inner, launch))
        initialization = objects[0].spend(issue.ledger_initialization())
        spends.append(initialization)
        assert await client.push_tx(SpendBundle(spends, G2Element())) == (MempoolInclusionStatus.SUCCESS, None)
        await sim.farm_block()
        objects[0].advance(initialization, li)
        eve_inner = list(Program.from_bytes(bytes(issue.eve_spend.puzzle_reveal)).uncurry()[1].as_iter())[2]
        lineage = LineageProof(issue.eve_coin.parent_coin_info, eve_inner.get_tree_hash(), issue.eve_coin.amount)
        yield dict(sim=sim, client=client, bindings=bindings, issue=issue, owners=owners,
                   gov=governance, registry=registry, ledger_coin=objects[0], gov_coin=objects[1],
                   registry_coin=objects[2], admin_coin=objects[3], tree=issue.holdings,
                   snapshot=issue.holdings, sequence=0, lineage=lineage, locked={},
                   vaults=vaults,custody_keys=custody_keys,custody_types=custody_types,pending_custody=[],
                   parameters=parameters,parameters_coin=objects[4] if parameters else None,
                   pool=pool,pool_coin=objects[6] if getattr(request,'param',False) in ('batch','batch-revenue') else objects[4] if pool else None,
                   mint=mint,mint_coin=objects[5] if getattr(request,'param',False) in ('batch','batch-revenue') else objects[4] if mint else None,mint_funding=origins[8:33] if getattr(request,'param',False) in ('batch','batch-revenue') else origins[6:31] if mint else [])


def upgrade_plan(c):
    component = c["registry"].components[0]
    return UpgradePlan(b32(50), (CodeChange(component.component_id, component.module_hash,
        load_puzzle("generation_extension_v2.clsp").get_tree_hash(), 2, 1),))


def source_holding(c, index):
    return c["locked"].get(index, (c["issue"].coins[index], c["issue"].outputs[index], c["lineage"]))


def lock_spends(c, proposal, indices, ledger_coin):
    tree, witnesses, cats, locked, paired_vaults = c["tree"], [], [], {}, []
    for index in indices:
        coin, descriptor, lineage = source_holding(c, index)
        output = replace(descriptor, kind=HoldingKind.LOCKED_HOLDER, lock_id=proposal)
        witness, tree = transition_witness(c["bindings"], tree, coin, descriptor, "LOCK", (output,))
        digest = transition_digest(c["bindings"], coin, "LOCK", (output,))
        owner_authorization=Program.to([[1,b'SGT_AUTHORIZE',digest]])
        if c.get('vaults'):
            vault=c['vaults'][index];expires=int(c['sim'].timestamp)+600;gen=c['bindings'].generation
            owner_authorization=owner_solution(vault.coin,vault.inner,coin.name(),'LOCK',(output,),expires)
            key=c['custody_keys'][index]
            if c['custody_types'][index]==1:
                signature=b''
                operation=authorization_hash(gen,vault.coin.name(),coin.name(),digest,expires)
                aggregate=AugSchemeMPL.sign(key,bytes(operation)+vault.coin.name()+DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
            else:
                signature=key.sign_msg_hash(signing_digest(gen,vault.coin.name(),coin.name(),digest,expires)).to_bytes()[:64]
                aggregate=G2Element()
            custody_spend=vault.spend(authorization_solution(gen,vault.coin,vault.inner,coin.name(),digest,expires,signature))
            paired_vaults.append(custody_spend)
            c['pending_custody'].append((vault,custody_spend,aggregate))
        witnesses.append(witness)
        cats.append(SpendableCAT(coin=coin, limitations_program_hash=c["bindings"].tail_hash,
            inner_puzzle=descriptor.inner(c["bindings"]), lineage_proof=lineage,
            inner_solution=Program.to([b"LOCK", coin.name(), coin.amount, ledger_coin.inner.get_tree_hash(),
                c["owners"][index], owner_authorization, c["gov_coin"].inner.get_tree_hash(),
                [output.descriptor()]])))
        locked[index] = (output.coin(c["bindings"], coin.name()), output,
                         LineageProof(coin.parent_coin_info, descriptor.inner(c["bindings"]).get_tree_hash(), coin.amount))
    cat_bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, cats)
    ledger_spend = ledger_coin.spend(Program.to([b"UPDATE", witnesses]))
    return [*cat_bundle.coin_spends,*paired_vaults], ledger_spend, tree, locked


async def push(c, spends):
    pending=c.get('pending_custody',[])
    result = await c["client"].push_tx(SpendBundle(spends, AugSchemeMPL.aggregate([s[2] for s in pending])))
    assert result == (MempoolInclusionStatus.SUCCESS, None), result
    await c["sim"].farm_block()
    for vault,spend,_ in pending:vault.advance(spend,vault.inner)
    c['pending_custody']=[]


async def open_vote(c, bill, sponsors=(0,)):
    gov, coin, registry, regcoin = c["gov"], c["gov_coin"], c["registry"], c["registry_coin"]
    proposal = gov.proposal_id(bill, c["tree"])
    c["snapshot"] = c["tree"]
    # Snapshot and mutation are separate, atomic spends of the same lineage.
    # Taking a snapshot cannot itself reserve input coins or trigger a wallet.
    ledger = c["ledger_coin"]
    snapshot_spend = ledger.spend(Program.to([b"SNAPSHOT", [coin.inner.get_tree_hash(), proposal]]))
    snapshot_coin = copy(ledger)
    snapshot_coin.advance(snapshot_spend, ledger.inner)
    cats, update, tree, locked = lock_spends(c, proposal, sponsors, snapshot_coin)
    issued = int(c["sim"].timestamp) - 1
    expires = issued + 86_400
    admin = c["admin_coin"]
    admin_spend = authorize(admin, coin, Program.to([
        b"PUBLICATION_APPROVAL", gov.sgt.generation, proposal, issued, expires]).get_tree_hash())
    reg_spend = regcoin.spend(inner_solution("AUTHORIZE_NEW", regcoin.coin,
        [1, coin.coin.puzzle_hash, proposal, bill]))
    gov_spend = coin.spend(inner_solution("OPEN", coin.coin, [admin.inner.get_tree_hash(), issued, expires,
        regcoin.inner.get_tree_hash(), ledger.inner.get_tree_hash(), c["tree"].root.program(), c["sequence"],
        bill, ballot_witnesses(c["snapshot"], [source_holding(c, i)[0].name() for i in sponsors], gov.closed)]))
    opened, clock = gov.opened(coin.coin, bill, c["tree"], c["sequence"], [source_holding(c, i)[0].name() for i in sponsors])
    await push(c, [admin_spend, reg_spend, gov_spend, snapshot_spend, update, *cats])
    coin.advance(gov_spend, opened.inner())
    admin.advance(admin_spend, admin.inner)
    regcoin.advance(reg_spend, registry.inner())
    c["sequence"] += 1
    ledger.advance(update, ledger_inner(c["bindings"], tree, c["sequence"]))
    c.update(gov=opened, tree=tree, clock=clock)
    c["locked"].update(locked)
    return proposal


async def anchor(c):
    coin, gov = c["gov_coin"], c["gov"]
    born = int((await c["client"].get_coin_record_by_name(c["clock"].name())).timestamp)
    anchor = coin.spend(inner_solution("ANCHOR", coin.coin, [born]))
    clock_spend = make_spend(c["clock"], gov.clock_puzzle(gov.active.proposal_id),
                            Program.to([coin.inner.get_tree_hash(), born]))
    await push(c, [anchor, clock_spend])
    c["gov"] = gov.anchored(born)
    coin.advance(anchor, c["gov"].inner())
    return born


async def vote(c, indices):
    coin, gov = c["gov_coin"], c["gov"]
    cats, update, tree, locked = lock_spends(c, gov.active.proposal_id, indices, c["ledger_coin"])
    ballots = ballot_witnesses(c["snapshot"], [source_holding(c, i)[0].name() for i in indices], gov.closed)
    spend = coin.spend(inner_solution("VOTE", coin.coin, ballots))
    await push(c, [spend, update, *cats])
    c["gov"] = gov.voted(sum(source_holding(c, i)[0].amount for i in indices))
    c["sequence"] += 1
    coin.advance(spend, c["gov"].inner())
    c["ledger_coin"].advance(update, ledger_inner(c["bindings"], tree, c["sequence"]))
    c["tree"] = tree
    c["locked"].update(locked)


def finalize_spend(c):
    gov, coin = c["gov"], c["gov_coin"]
    return coin.spend(inner_solution("FINALIZE", coin.coin, [gov.closed.proof(gov.active.proposal_id),
        gov.approved.proof(gov.action_key(gov.active.proposal_id, gov.active.bill))]))


async def finalize(c):
    spend = finalize_spend(c)
    await push(c, [spend])
    c["gov"] = c["gov"].finalized()
    c["gov_coin"].advance(spend, c["gov"].inner())


async def perform_upgrade(c):
    plan = upgrade_plan(c)
    bill = Program.to([b"UPGRADE", 0, plan.program()])
    proposal = await open_vote(c, bill)
    assert c["gov"].active.yes_weight == 10_000 and c["gov"].active.required_votes == 15_000
    born = await anchor(c)
    c["sim"].pass_time(uint64(120))
    await c["sim"].farm_block()
    await vote(c, [1])
    assert c["gov"].active.opened_at == born
    assert c["gov"].active.voting_closes_at == born + 3600
    result = await c["client"].push_tx(SpendBundle([finalize_spend(c)], G2Element()))
    assert result[0] != MempoolInclusionStatus.SUCCESS and "SECONDS_ABSOLUTE" in result[1].name
    c["sim"].pass_time(uint64(3601))
    await c["sim"].farm_block()
    await finalize(c)
    assert c["gov"].active is None and c["gov"].upgrade_reserved
    # Finalized approval is durable. Only execution consumes it, together with
    # registry ratification and its newly-created consensus delay ticket.
    gov, govcoin, reg, regcoin = c["gov"], c["gov_coin"], c["registry"], c["registry_coin"]
    execute = govcoin.spend(inner_solution("EXECUTE", govcoin.coin, [proposal, bill,
        gov.approved.proof(gov.action_key(proposal, bill)), regcoin.inner.get_tree_hash(), b32(0)]))
    ratification = regcoin.spend(inner_solution("RATIFY_UPGRADE", regcoin.coin,
        [govcoin.inner.get_tree_hash(), plan.program()]))
    pending, ticket = reg.ratified(regcoin.coin, plan)
    await push(c, [execute, ratification])
    executed = gov.executed(proposal, bill)
    c.update(gov=executed, registry=pending)
    govcoin.advance(execute, executed.inner())
    regcoin.advance(ratification, pending.inner())
    state_before = executed.state()
    regactivate = regcoin.spend(inner_solution("ACTIVATE", regcoin.coin,
        [plan.program(), [[executed.component_id, state_before]],govcoin.inner.get_tree_hash()]))
    govactivate = govcoin.spend(inner_solution("UPGRADE", govcoin.coin, [regcoin.inner.get_tree_hash(),
        pending.pending[0], plan.changes[0].new_module_hash, 2, 1]))
    delay = make_spend(ticket, pending.ticket_puzzle(pending.pending[0]), Program.to([regcoin.inner.get_tree_hash()]))
    activation = [regactivate, govactivate, delay]
    result = await c["client"].push_tx(SpendBundle(activation, G2Element()))
    assert result[0] != MempoolInclusionStatus.SUCCESS and "SECONDS_RELATIVE" in result[1].name
    c["sim"].pass_time(uint64(86_401))
    await c["sim"].farm_block()
    await push(c, activation)
    updated = replace(executed, module_hash=plan.changes[0].new_module_hash, version=2)
    assert updated.state() == state_before
    govcoin.advance(govactivate, updated.inner())
    regcoin.advance(regactivate, pending.activated(plan).inner())
    c.update(gov=updated, registry=pending.activated(plan))
    read = govcoin.spend(inner_solution("READ", govcoin.coin,
        [load_puzzle("generation_extension_v2.clsp"), b"PROVE_STATE"]))
    await push(c, [read])
    govcoin.advance(read, updated.inner())
    assert c["tree"].root.total == 1_000_000 and c["tree"].root.eligible == 30_000
    return proposal


async def unlock_all(c, proposal):
    updated,govcoin=c['gov'],c['gov_coin']
    # Unlock both whole input stakes after upgrade; owners and amounts survive.
    witnesses, cat_inputs, claims, tree = [], [], [], c["tree"]
    for coin, output, lineage in c["locked"].values():
        successor = replace(output, kind=HoldingKind.HOLDER, lock_id=None)
        witness, tree = transition_witness(c["bindings"], tree, coin, output, "UNLOCK", (successor,))
        witnesses.append(witness)
        claims.append([coin.name(), output.holding(c["bindings"]).program(), updated.closed.proof(proposal)])
        cat_inputs.append(SpendableCAT(coin=coin, limitations_program_hash=c["bindings"].tail_hash,
            inner_puzzle=output.inner(c["bindings"]), lineage_proof=lineage,
            inner_solution=Program.to([b"UNLOCK", coin.name(), coin.amount, c["ledger_coin"].inner.get_tree_hash(),
                [], [], govcoin.inner.get_tree_hash(), [successor.descriptor()]])))
    unlock = govcoin.spend(inner_solution("UNLOCK", govcoin.coin, claims))
    ledger = c["ledger_coin"].spend(Program.to([b"UPDATE", witnesses]))
    cats = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, cat_inputs)
    await push(c, [unlock, ledger, *cats.coin_spends])
    assert tree.root.eligible == 30_000 and tree.root.total == 1_000_000
    assert all(h.kind != HoldingKind.LOCKED_HOLDER for h in tree.holdings.values())
    govcoin.advance(unlock,updated.inner())
    c['sequence']+=1
    c['ledger_coin'].advance(ledger,ledger_inner(c['bindings'],tree,c['sequence']))
    c['tree']=tree
    c['locked']={index:(replace(output,kind=HoldingKind.HOLDER,lock_id=None).coin(c['bindings'],coin.name()),
        replace(output,kind=HoldingKind.HOLDER,lock_id=None),
        LineageProof(coin.parent_coin_info,output.inner(c['bindings']).get_tree_hash(),coin.amount))
        for index,(coin,output,lineage) in c['locked'].items()}


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',[False,True],indirect=True,ids=['kernel-fixture','bls-and-evm-custody'])
async def test_holder_governance_real_upgrade_wait_and_unlock(generation):
    proposal=await perform_upgrade(generation)
    await unlock_all(generation,proposal)


@pytest.mark.asyncio
async def test_consensus_birth_time_cannot_be_forged(generation):
    c = generation
    await open_vote(c, Program.to([b"REOPEN", 0, 2]))
    coin, gov = c["gov_coin"], c["gov"]
    actual = int((await c["client"].get_coin_record_by_name(c["clock"].name())).timestamp)
    wrong = actual + 100
    anchor_spend = coin.spend(inner_solution("ANCHOR", coin.coin, [wrong]))
    clock = make_spend(c["clock"], gov.clock_puzzle(gov.active.proposal_id), Program.to([coin.inner.get_tree_hash(), wrong]))
    result = await c["client"].push_tx(SpendBundle([anchor_spend, clock], G2Element()))
    assert result[0] == MempoolInclusionStatus.FAILED and "BIRTH_SECONDS" in result[1].name


@pytest.mark.asyncio
async def test_late_votes_fail_and_nonquorate_finalization_releases_receipts(generation):
    c = generation
    await open_vote(c, Program.to([b"REOPEN", 0, 2]))
    await anchor(c)
    c["sim"].pass_time(uint64(3601))
    await c["sim"].farm_block()
    proposal = c["gov"].active.proposal_id
    cats, ledger, _, _ = lock_spends(c, proposal, [1], c["ledger_coin"])
    gov = c["gov_coin"].spend(inner_solution("VOTE", c["gov_coin"].coin,
        ballot_witnesses(c["snapshot"], [c["issue"].coins[1].name()])))
    result = await c["client"].push_tx(SpendBundle([gov, ledger, *cats], G2Element()))
    assert result[0] == MempoolInclusionStatus.FAILED and "BEFORE_SECONDS" in result[1].name
    await finalize(c)
    assert proposal in c["gov"].closed.keys and not c["gov"].approved.keys


@pytest.mark.asyncio
async def test_co_sponsors_and_duplicate_ballot_rejection(generation):
    c = generation
    await open_vote(c, Program.to([b"REOPEN", 0, 2]), sponsors=(0, 1))
    await anchor(c)
    assert c["gov"].active.yes_weight == 20_000
    ballot = ballot_witnesses(c["snapshot"], [c["issue"].coins[2].name()])[0]
    with pytest.raises(ValueError):
        c["gov_coin"].inner.run(inner_solution("VOTE", c["gov_coin"].coin, [ballot, ballot]))
    # An input recreated by sponsorship is absent from the opening root.
    locked_coin, locked_output, _ = c["locked"][0]
    with pytest.raises(ValueError, match="opening snapshot"):
        ballot_witnesses(c["snapshot"], [locked_coin.name()])


@pytest.mark.asyncio
async def test_closed_snapshot_stakes_vote_again_without_unlocking_or_double_counting(generation):
    c = generation
    first = await open_vote(c, Program.to([b"REOPEN", 0, 2]), sponsors=(0, 1))
    await anchor(c)
    c["sim"].pass_time(uint64(3601))
    await c["sim"].farm_block()
    await finalize(c)
    old_stake = source_holding(c, 0)[0]
    # A closed stake can also co-sponsor directly from the next opening root.
    await open_vote(c, Program.to([b"REOPEN", 0, 4]), sponsors=(1,))
    await anchor(c)
    assert c["gov"].active.required_votes == 15_000
    assert c["gov"].active.snapshot.eligible == 30_000
    ballot = ballot_witnesses(c["snapshot"], [old_stake.name()], c["gov"].closed)[0]
    forged = [*ballot[:3], c["gov"].approved.proof(first)]
    with pytest.raises(ValueError):
        c["gov_coin"].inner.run(inner_solution("VOTE", c["gov_coin"].coin, [forged]))
    await vote(c, [0])
    assert c["gov"].active.yes_weight == 20_000
    assert (await c["client"].get_coin_record_by_name(old_stake.name())).spent
    # Newly recreated stake is never eligible against that same snapshot.
    with pytest.raises(ValueError, match="opening snapshot"):
        ballot_witnesses(c["snapshot"], [source_holding(c, 0)[0].name()], c["gov"].closed)
    # A fabricated closure cannot authorize an active lock.
    current_id = source_holding(c, 0)[0].name()
    with pytest.raises(ValueError, match="prior proposal"):
        ballot_witnesses(c["tree"], [current_id], c["gov"].closed)
    c["sim"].pass_time(uint64(3601))
    await c["sim"].farm_block()
    await finalize(c)
    assert c["tree"].root.eligible == 30_000 and c["tree"].root.total == 1_000_000
