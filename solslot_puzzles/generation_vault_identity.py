"""Reuse the existing identity bridge, binding z to the generation vault.

Bridge/permit validators and owner authorization remain unchanged. The custody
module is fixed here, never selected by a request or used to upgrade an old coin.
"""
from dataclasses import replace
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton,solution_for_singleton
from chia_rs import SpendBundle,G2Element
from chia_rs.sized_ints import uint64
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import DEFAULT_IDENTITY_ATTEST_ROOT
from solslot_puzzles.zkpassport_bridge_driver import build_bridge_and_vault_update_identity_bundle as legacy_bridge_bundle


def build_generation_identity_bundle(**kwargs):
    built=legacy_bridge_bundle(**kwargs)
    inner=vault_inner(vault_launcher_id=kwargs['vault_launcher_id'],owner_pubkey=kwargs['owner_pubkey_bytes'],
        auth_type=kwargs['auth_type'],members_merkle_root=kwargs['members_merkle_root'],
        pool_launcher_id=kwargs['pool_launcher_id'],identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=built.bridge.bridge_policy_hash)
    full=puzzle_for_singleton(kwargs['vault_launcher_id'],inner);coin=kwargs['vault_coin']
    if coin.amount!=1 or coin.puzzle_hash!=full.get_tree_hash():
        raise ValueError('identity stamp input does not match the fixed empty generation vault')
    root=kwargs['new_identity_attest_root']
    if root==bytes(32) or root==DEFAULT_IDENTITY_ATTEST_ROOT:raise ValueError('identity stamp requires a nonempty verified root')
    solution=Program.to([coin.name(),inner.get_tree_hash(),1,b'z',
        [load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash(),root,
            kwargs['bridge_parent_id'],kwargs['bridge_amount'],kwargs['current_timestamp'],kwargs.get('signature_data') or b'']])
    spend=make_spend(coin,full,solution_for_singleton(kwargs['lineage_proof'],uint64(1),solution))
    return replace(built,vault_spend=spend,spend_bundle=SpendBundle([built.bridge.coin_spend,spend],G2Element()))
