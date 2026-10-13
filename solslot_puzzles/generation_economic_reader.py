"""Replay supported economic components from their frozen initial state.

No provider-selected child state, arbitrary replacement reveal or coordinator
counter is trusted. Native execution must create the independently projected
successor. The caller must additionally prove inclusion on the primary chain.
"""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_mint import GenerationMint, TestMintEdition, MintRow
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_statutes import GenerationStatutes, RECORDS
from solslot_puzzles.generation_pool import GenerationPool, decode_pool_state, replay_pool_swap
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_registry_reader import exact_list, uint

EconomicComponent = GenerationParameters | GenerationMint | GenerationPool
MAX_ECONOMIC_READ_COST = 11_000_000_000


def decode_initial_economic_inner(inner:Program, *, generation:bytes32, registry_id:bytes32,
                                  governance_id:bytes32, launcher_id:bytes32) -> EconomicComponent:
    module,args=inner.uncurry()
    self_hash,gen,registry,identity,logic,version,compatibility,state=exact_list(args,8)
    if (self_hash.as_atom()!=module.get_tree_hash() or gen.as_atom()!=generation
            or registry!=singleton_struct(registry_id) or uint(version)!=1 or uint(compatibility)!=1):
        raise ValueError('economic anchor differs from the frozen initial generation')
    common=dict(generation=generation,registry_id=registry_id,governance_id=governance_id,
        launcher_id=launcher_id,component_id=bytes32(identity.as_atom()),module_hash=bytes32(logic.as_atom()))
    if module==load_puzzle('generation_parameters_v1.clsp'):
        mine,gov,revision,values=exact_list(state,4)
        if mine!=singleton_struct(launcher_id) or gov!=singleton_struct(governance_id) or uint(revision)!=0:
            raise ValueError('parameter anchor must be the initial authority')
        result=GenerationParameters(**common,values=tuple(uint(v) for v in exact_list(values,6)))
    elif module==load_puzzle('generation_statutes_v1.clsp'):
        from solslot_puzzles.protocol_statutes_v1 import PermanentRules
        mine,gov,pool,rules,revision,values,collections,oracles,routes,liquidity=exact_list(state,10)
        permanent=exact_list(rules,15)
        if (mine!=singleton_struct(launcher_id) or gov!=singleton_struct(governance_id) or uint(revision)!=0
                or any(v.as_atom()!=Program.to([]).get_tree_hash() for v in (collections,oracles,routes,liquidity))):
            raise ValueError('statutes anchor must be the initial canonical authority')
        result=GenerationStatutes(**common,pool_id=bytes32(pool.rest().first().as_atom()),
            permanent_rules=PermanentRules(bytes32(permanent[0].as_atom()),uint(permanent[1]),
                *(bytes32(v.as_atom()) for v in permanent[2:6])),
            values=tuple(uint(v) for v in exact_list(values,6)))
    elif module==load_puzzle('generation_mint_v1.clsp'):
        bindings,issued,count=exact_list(state,3)
        mine,gov,pool,treasury,protocol,keys,provider,modules,primary=exact_list(bindings,9)
        _,pool_pair=pool.as_pair();pool_launcher=bytes32(pool_pair.first().as_atom())
        result=GenerationMint(**common,pool_id=pool_launcher,treasury_puzzle_hash=bytes32(treasury.as_atom()),
            protocol_puzzle_hash=bytes32(protocol.as_atom()),
            validator_pubkeys=tuple(v.as_atom() for v in exact_list(keys,3)),provider_id=bytes32(provider.as_atom()),primary_batch_bindings=primary)
        # Reproduction below verifies all module pins, singleton structures,
        # empty issued-set root and counter, not just the descriptive fields.
    elif module==load_puzzle('generation_pool_v1.clsp'):
        result=decode_pool_state(state, **common)
        e=result.economics.economics
        if (e.bootstrap_complete or e.inventory_nav_micro_usd or e.treasury_assets_micro_usd
                or e.proven_liabilities_micro_usd or e.deed_count or e.total_sols_mojos!=1
                or e.reserve_sols_mojos!=1 or result.economics.state_version!=1
                or result.economics.inventory_root!=Program.to([]).get_tree_hash()):
            raise ValueError('initial pool must contain only its conserved Sols anchor')
    else:raise ValueError('unsupported economic kernel')
    if result.inner()!=inner:raise ValueError('economic anchor cannot be reproduced exactly')
    expected=load_puzzle('generation_statutes_logic_v1.clsp' if isinstance(result,GenerationStatutes)
                         else 'generation_parameter_logic_v1.clsp' if isinstance(result,GenerationParameters)
                         else 'generation_pool_logic_v1.clsp' if isinstance(result,GenerationPool)
                         else 'generation_mint_logic_v1.clsp').get_tree_hash()
    if result.logic_hash()!=expected:raise ValueError('initial economic policy differs from the reviewed source')
    return result


def parse_test_edition(raw:Program) -> TestMintEdition:
    purpose,gen,collection,metadata,preview,property_id,pricing,fee,asset,jurisdiction,rows=exact_list(raw,11)
    if purpose.as_atom()!=b'TEST_ONLY':raise ValueError('mint evidence must be explicitly test-only')
    entries=list(rows.as_iter())
    if not 0<len(entries)<=100 or Program.to(entries)!=rows:raise ValueError('mint rows exceed the canonical bound')
    parsed=[]
    for row in entries:
        parent,share,base,par=exact_list(row,4)
        parsed.append(MintRow(bytes32(parent.as_atom()),uint(share),uint(base),uint(par)))
    edition=TestMintEdition(*(bytes32(v.as_atom()) for v in (gen,collection,metadata,preview,property_id,pricing)),
        uint(fee),uint(asset),jurisdiction.as_atom(),tuple(parsed))
    if Program.to(edition.program())!=raw:raise ValueError('mint edition is noncanonical')
    return edition


@dataclass(frozen=True)
class EconomicTransition:
    action:str
    before:EconomicComponent
    after:EconomicComponent
    successor:Coin
    edition:TestMintEdition|None=None
    statute_kind:str|None=None
    statute_records:tuple=()
    inventory:tuple|None=None


def reconstruct_economic_successor(spend:CoinSpend, expected:EconomicComponent) -> EconomicTransition:
    if not isinstance(expected,(GenerationParameters,GenerationMint,GenerationPool)):
        raise ValueError('unsupported economic authority')
    full=Program.from_bytes(bytes(spend.puzzle_reveal));module,args=full.uncurry()
    if module.get_tree_hash()!=SINGLETON_MOD_HASH or full.get_tree_hash()!=spend.coin.puzzle_hash or spend.coin.amount!=1:
        raise ValueError('economic evidence differs from the confirmed singleton input')
    structure,inner=exact_list(args,2)
    if structure!=singleton_struct(expected.launcher_id) or inner!=expected.inner():
        raise ValueError('economic evidence does not continue the last verified state')
    _,amount,solution=exact_list(Program.from_bytes(bytes(spend.solution)),3)
    if uint(amount)!=1:raise ValueError('economic singleton amount changed')
    if isinstance(expected,GenerationPool):
        identity,inner_hash,pool_amount,action,values,policy,statutes_inner_hash=exact_list(solution,7)
        if (identity.as_atom()!=spend.coin.name() or inner_hash.as_atom()!=expected.inner().get_tree_hash()
                or uint(pool_amount)!=1):
            raise ValueError('pool evidence changes the confirmed identity or inner hash')
    else:
        action,values=exact_list(solution,2)
    tag=action.as_atom();edition=None;after=expected;statute_kind=None;statute_records=();inventory=None
    if tag==b'UPGRADE':
        _,_,logic,version,compatibility=exact_list(values,5)
        after=replace(expected,module_hash=bytes32(logic.as_atom()),version=uint(version),compatibility=uint(compatibility))
    elif tag==b'READ':
        if not isinstance(expected,GenerationPool):exact_list(values,2)
    elif tag==b'SEED_SOLS' and isinstance(expected,GenerationPool):
        exact_list(values,2)
        after=replace(expected,economics=replace(expected.economics,state_version=2))
    elif tag==b'UPDATE' and isinstance(expected,GenerationParameters):
        _,_,_,values,_=exact_list(values,5)
        after=expected.updated(tuple(uint(v) for v in exact_list(values,6)))
    elif tag==b'MUTATE' and isinstance(expected,GenerationStatutes):
        _,_,kind,key,replacement,records,_=exact_list(values,7)
        label=kind.as_atom().decode('ascii')
        record=parse_statute_record(label,replacement)
        entries=[parse_statute_record(label,v) for v in records.as_iter()]
        _,after,statute_records=expected.record_change(label,entries,record)
        statute_kind=label
    elif tag==b'SOLS_EVIDENCE' and isinstance(expected,GenerationStatutes):
        exact_list(values,5)
    elif tag==b'PRIMARY_EVIDENCE' and isinstance(expected,GenerationStatutes):
        exact_list(values,16)
    elif tag==b'REWARD_EVIDENCE' and isinstance(expected,GenerationStatutes):
        exact_list(values,2)
    elif tag==b'MINT' and isinstance(expected,GenerationMint):
        _,raw,_,_=exact_list(values,4)
        edition=parse_test_edition(raw);after=expected.minted(edition)
    elif tag in (b'\x01',b'\x02',b'\x03') and isinstance(expected,GenerationPool):
        after=replay_pool_swap(expected,action.as_int(),values)
        from solslot_puzzles.sols_pool_v4 import PoolInventoryRecord,canonical_inventory
        def record(raw):
            fields=exact_list(raw,9)
            return PoolInventoryRecord(*(bytes32(v.as_atom()) for v in fields[:4]),
                *(uint(v) for v in fields[4:])).validate()
        params=list(values.as_iter())
        previous=canonical_inventory(tuple(record(raw) for raw in params[0].as_iter()))
        expected.economics.validate(previous)
        if tag in (b'\x01',b'\x03'):
            inventory=canonical_inventory((*previous,record(params[30])))
        else:
            removed=bytes32(params[11].as_atom())
            inventory=canonical_inventory(tuple(row for row in previous if row.deed_launcher_id!=removed))
        after.economics.validate(inventory)
    else:raise ValueError('unsupported economic transition')
    additions,_=compute_additions_with_cost(spend,max_cost=MAX_ECONOMIC_READ_COST)
    successor=Coin(spend.coin.name(),puzzle_for_singleton(expected.launcher_id,after.inner()).get_tree_hash(),uint64(1))
    expected_outputs=[successor]
    if tag==b'\x03' and isinstance(expected,GenerationPool):
        params=exact_list(values,41);plan=list(params[40].as_iter())
        if plan[0].first().as_atom()==spend.coin.name():
            mod=load_puzzle('generation_batch_payout_v1.clsp');cfg=expected.config()
            payout=mod.curry(mod.get_tree_hash(),expected.generation,cfg.cat_mod_hash,
                cfg.permanent_rules.sols_tail_hash,cfg.offer_mod_hash,spend.coin.name(),params[40],params[39])
            expected_outputs.append(Coin(spend.coin.name(),payout.get_tree_hash(),uint64(0)))
    if sorted(additions,key=lambda c:c.name())!=sorted(expected_outputs,key=lambda c:c.name()):
        raise ValueError('economic reconstruction differs from its actual output')
    label={b'\x01':'DEED_TO_SOLS',b'\x02':'SOLS_TO_DEED',b'\x03':'PRIMARY_SOLS_BATCH'}.get(tag,tag.decode('ascii'))
    return EconomicTransition(label,expected,after,successor,edition,statute_kind,statute_records,inventory)


def parse_statute_record(kind,raw):
    shapes={'COLLECTION':(7,{0}),'ORACLE':(10,{0,5}),
            'ROUTE':(7,{0,1,2,3,4}),'LIQUIDITY':(9,{0,1,2,3,4,5,6,7})}
    if kind not in shapes:raise ValueError('unsupported statutes record')
    length,hashes=shapes[kind]
    record=RECORDS[kind][1](*(bytes32(v.as_atom()) if i in hashes else uint(v)
        for i,v in enumerate(exact_list(raw,length)))).validate()
    if Program.to(record.as_program_value())!=raw:raise ValueError('statutes record is noncanonical')
    return record
