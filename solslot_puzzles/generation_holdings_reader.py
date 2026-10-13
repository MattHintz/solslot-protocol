"""Rebuild the holder index from confirmed ledger spends and exact outputs.

The API cannot set eligible supply: replay must reproduce the full immutable
ledger puzzle and both consensus-authenticated sums at every transition.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_registry_reader import exact_list, uint
from solslot_puzzles.generation_sgt import SGTBindings, SGTOutput, ledger_inner
from solslot_puzzles.holdings import Holding, HoldingKind, HoldingsTree

MAX_HOLDINGS_READ_COST = 11_000_000_000


@dataclass(frozen=True)
class HoldingsTransition:
    action: str
    tree: HoldingsTree
    sequence: int
    successor: Coin
    consumed: tuple[bytes32,...]
    created: tuple[bytes32,...]


def reconstruct_holdings_successor(spend: CoinSpend, bindings: SGTBindings,
                                   tree: HoldingsTree, sequence: int) -> HoldingsTransition:
    # Detach the mutable index before executing evidence supplied by a provider.
    tree=HoldingsTree(dict(tree.holdings))
    full=Program.from_bytes(bytes(spend.puzzle_reveal))
    module,raw=full.uncurry()
    if module.get_tree_hash()!=SINGLETON_MOD_HASH or full.get_tree_hash()!=spend.coin.puzzle_hash:
        raise ValueError('holdings evidence does not match the canonical confirmed singleton')
    structure,inner=exact_list(raw,2)
    if (structure!=singleton_struct(bindings.ledger_launcher_id)
            or inner!=ledger_inner(bindings,tree,sequence) or spend.coin.amount!=1):
        raise ValueError('holdings index does not reproduce the last confirmed state')
    _,amount,solution=exact_list(Program.from_bytes(bytes(spend.solution)),3)
    action,args=exact_list(solution,2)
    if uint(amount)!=1:raise ValueError('holdings evidence changed the singleton amount')
    tag=action.as_atom();consumed=[];created=[]
    if tag==b'UPDATE':
        requests=list(args.as_iter())
        if not 0<len(requests)<=256 or Program.to(requests)!=args:
            raise ValueError('holdings update exceeds the bounded canonical request list')
        for request in requests:
            parent,description,operation,outputs,_,_=exact_list(request,6)
            ph,quantity,kind,owner,lock=exact_list(description,5)
            lock_id=bytes32(lock.as_atom()) if lock!=Program.to([]) else None
            before=Holding(bytes32(ph.as_atom()),uint(quantity),HoldingKind(uint(kind)),bytes32(owner.as_atom()),lock_id)
            before.program()
            coin=Coin(bytes32(parent.as_atom()),before.puzzle_hash,uint64(before.amount))
            descriptor=SGTOutput(before.kind,before.owner_hash,before.amount,before.lock_id)
            if descriptor.holding(bindings)!=before:
                raise ValueError('holding descriptor does not match the fixed generation kernel')
            tree=tree.replace(coin.name(),before,None);consumed.append(coin.name())
            children=list(outputs.as_iter())
            if len(children)>256 or Program.to(children)!=outputs:
                raise ValueError('holdings output list exceeds the canonical bound')
            for child in children:
                next_kind,next_owner,next_lock,next_amount=exact_list(child,4)
                output=SGTOutput(HoldingKind(uint(next_kind)),bytes32(next_owner.as_atom()),uint(next_amount),
                    bytes32(next_lock.as_atom()) if next_lock!=Program.to([]) else None)
                next_coin=output.coin(bindings,coin.name())
                tree=tree.replace(next_coin.name(),None,output.holding(bindings));created.append(next_coin.name())
        sequence+=1
    elif tag==b'SNAPSHOT':exact_list(args,2)
    elif tag==b'REWARD_SNAPSHOT':exact_list(args,2)
    elif tag==b'INITIALIZE':exact_list(args,2)
    else:raise ValueError('unsupported holdings transition')
    # Native evaluation checks every sparse proof and conservation rule. Exact
    # output matching prevents a friendly-looking indexed sum hiding other state.
    additions,_=compute_additions_with_cost(spend,max_cost=MAX_HOLDINGS_READ_COST)
    expected=Coin(spend.coin.name(),puzzle_for_singleton(bindings.ledger_launcher_id,
        ledger_inner(bindings,tree,sequence)).get_tree_hash(),uint64(1))
    if additions!=[expected]:
        raise ValueError('holdings reconstruction differs from the consensus successor')
    return HoldingsTransition(tag.decode('ascii'),tree,sequence,expected,tuple(consumed),tuple(created))
