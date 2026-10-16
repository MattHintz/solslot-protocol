"""Additive primary inventory: original direct delivery plus pool-only batching.

The immutable bindings are created at genesis, never taken from an order.
Historical AVAILABLE V3 and RESERVED V6 program bytes remain unchanged.
"""
from chia.types.blockchain_format.program import Program
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.stripe_settlement_v1_driver import _mint_immutable_args

PAYMENT_MODULES = ('generation_primary_payment_v1.clsp',
    'generation_reward_custody_v1.clsp', 'generation_reward_epoch_v1.clsp',
    'generation_sgt_coin_v1.clsp', 'generation_reward_leaf_v1.clsp',
    'generation_sgt_vault_owner_v1.clsp', 'p2_vault.clsp')


def batch_bindings(*, generation, pool_id, sgt, statutes_id, treasury, oracle_pubkeys=(), pool_kernel_version=1):
    if sgt.generation != generation:
        raise ValueError('primary bindings require the same issued SGT generation')
    if type(pool_kernel_version) is not int or pool_kernel_version not in (1, 2):
        raise ValueError('primary route requires an exact supported pool kernel')
    return Program.to([generation, singleton_struct(pool_id),
        load_puzzle(f'generation_pool_v{pool_kernel_version}.clsp').get_tree_hash(), sgt.program(),
        singleton_struct(statutes_id), treasury,
        [load_puzzle(n).get_tree_hash() for n in PAYMENT_MODULES], list(oracle_pubkeys)])


def inventory_inner(terms, bindings):
    module = inventory_module(bindings)
    return module.curry(module.get_tree_hash(),
        load_puzzle('mint_offer_delegate_v6.clsp').get_tree_hash(),
        *_mint_immutable_args(terms), bindings)


def inventory_module(bindings):
    values = list(bindings.as_iter())
    if values and len(values) != 8:
        raise ValueError('primary bindings require the exact eight-field contract')
    restricted = bool(values) and values[2].as_atom() == load_puzzle('generation_pool_v2.clsp').get_tree_hash()
    return load_puzzle('generation_primary_inventory_v2.clsp' if restricted else 'generation_primary_inventory_v1.clsp')
