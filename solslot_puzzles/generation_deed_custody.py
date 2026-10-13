"""Current SmartDeed custody with its frozen, DID-curried mint launcher.

Protocol authority singletons use a standard launcher. SmartDeeds do not;
preserve their actual outer structure when constructing any custody spend.
Callers must obtain the mint launcher and parent from verified chain evidence.
"""
from dataclasses import dataclass,replace
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD,SINGLETON_MOD_HASH,lineage_proof_for_coinsol,solution_for_singleton)
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia.wallet.lineage_proof import LineageProof
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_transactions import MAX_NATIVE_COST


@dataclass(frozen=True)
class HeldSmartDeedTip:
    mint_launcher_id:bytes32
    launcher_id:bytes32
    inner:Program
    coin:Coin
    parent:object

    @property
    def launcher(self):return self.launcher_id

    @property
    def launcher_puzzle(self):
        return load_puzzle('singleton_launcher_with_did.clsp').curry(singleton_struct(self.mint_launcher_id))

    @property
    def structure(self):
        return Program.to((SINGLETON_MOD_HASH,(self.launcher_id,self.launcher_puzzle.get_tree_hash())))

    def full(self,inner=None):return SINGLETON_MOD.curry(self.structure,self.inner if inner is None else inner)

    def validate(self):
        if self.mint_launcher_id==bytes32.zeros or self.launcher_id==bytes32.zeros:
            raise ValueError('SmartDeed requires its actual nonzero mint and deed identities')
        reveal=Program.from_bytes(bytes(self.parent.puzzle_reveal))
        if (self.coin.amount!=1 or self.coin.puzzle_hash!=self.full().get_tree_hash()
                or self.coin.parent_coin_info!=self.parent.coin.name()
                or reveal.get_tree_hash()!=self.parent.coin.puzzle_hash):
            raise ValueError('SmartDeed current output differs from its exact parent and custody')
        if self.parent.coin.name()==self.launcher_id:
            if reveal!=self.launcher_puzzle or self.parent.coin.amount!=1:
                raise ValueError('SmartDeed launcher differs from its frozen mint authority')
        else:
            mod,args=reveal.uncurry();values=list(args.as_iter())
            if mod!=SINGLETON_MOD or len(values)!=2 or Program.to(values)!=args or values[0]!=self.structure:
                raise ValueError('SmartDeed parent belongs to another outer singleton identity')
        additions,_=compute_additions_with_cost(self.parent,max_cost=MAX_NATIVE_COST)
        if [coin for coin in additions if coin.amount%2]!=[self.coin]:
            raise ValueError('SmartDeed parent does not create this exact current output')
        return self

    def spend(self,solution):
        self.validate()
        lineage=(LineageProof(self.parent.coin.parent_coin_info,None,uint64(1))
            if self.parent.coin.name()==self.launcher_id else lineage_proof_for_coinsol(self.parent))
        return make_spend(self.coin,self.full(),solution_for_singleton(
            lineage,uint64(1),solution))

    def advanced(self,spend,inner):
        if spend.coin!=self.coin:raise ValueError('SmartDeed continuation consumes another input')
        return replace(self,inner=inner,parent=spend,
            coin=Coin(self.coin.name(),self.full(inner).get_tree_hash(),uint64(1))).validate()
