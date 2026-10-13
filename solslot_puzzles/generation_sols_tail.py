"""Generation-only issuance identity; historical pool tails remain intact."""
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH,SINGLETON_LAUNCHER_HASH
from solslot_puzzles import load_puzzle


def pool_token_tail(launcher):
    return load_puzzle('generation_sols_tail_v1.clsp').curry(SINGLETON_MOD_HASH,launcher,SINGLETON_LAUNCHER_HASH)


def pool_token_tail_hash(launcher):
    return pool_token_tail(launcher).get_tree_hash()
