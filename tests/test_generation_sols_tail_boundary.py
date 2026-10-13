"""Real CAT2 invocation: arbitrary issuance cannot claim to be a transfer."""
import pytest
from chia.types.blockchain_format.program import Program
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,construct_cat_puzzle,unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_sols_tail import pool_token_tail
from solslot_puzzles import load_puzzle
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH,SINGLETON_LAUNCHER_HASH


def legacy_tail(launcher):
    return load_puzzle('pool_token_tail.clsp').curry(SINGLETON_MOD_HASH,launcher,SINGLETON_LAUNCHER_HASH)


def h(n):return bytes32(bytes([n])*32)


def execute(tail,*,flag=0,delta=0,eve=False,amount=100):
    inner=Program.to(1);parent=Coin(h(1),construct_cat_puzzle(CAT_MOD,tail.get_tree_hash(),inner).get_tree_hash(),100)
    coin=Coin(parent.name(),parent.puzzle_hash,uint64(100))
    payload=Program.to([h(2),h(3),h(4),coin.name(),flag,amount])
    bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(coin,tail.get_tree_hash(),inner,
        Program.to([[51,inner.get_tree_hash(),100+delta],[51,[], -113,tail,payload]]),
        lineage_proof=LineageProof() if eve else LineageProof(parent.parent_coin_info,inner.get_tree_hash(),parent.amount),
        extra_delta=delta,limitations_program_reveal=tail,limitations_solution=payload)])
    spend=bundle.coin_spends[0]
    return conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,11_000_000_000)


def test_historical_positive_control_and_generation_cat_transfer_boundary():
    # Historical evidence is deliberately unchanged. These calls evaluate the
    # real CAT2 wrapper, not a fabricated direct tail argument list.
    assert execute(legacy_tail(h(7)),flag=0,delta=100)
    strict=pool_token_tail(h(7))
    assert execute(strict,flag=0,delta=0)
    with pytest.raises(ValueError):execute(strict,flag=0,delta=100)
    with pytest.raises(ValueError):execute(strict,flag=0,delta=-10)
    with pytest.raises(ValueError):execute(strict,flag=0,delta=0,eve=True)
    for flag,delta,amount in [(2,100,100),(1,100,101),(-1,-10,11),(1,0,0)]:
        with pytest.raises(ValueError):execute(strict,flag=flag,delta=delta,amount=amount)
