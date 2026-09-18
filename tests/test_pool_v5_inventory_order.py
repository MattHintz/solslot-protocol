"""Raw launcher IDs sort as bytes, including the signed-integer boundary."""
from dataclasses import replace
import pytest
from tests.test_pool_v4_driver import (
    CONFIG,EMPTY_POOL,COLLECTION,SHARE_PPM,PARAMETERS,STATUTES_STATE,
    POOL_COIN,VAULT_LAUNCHER,VAULT_COIN,SELLER_PUZZLE,QUOTE_EXPIRES,
    PAR_VALUE,ASSET_CLASS,PROPERTY_ID,MINT_TOKEN_COIN,OWNER_PUBKEY,
    AUTH_TYPE_BLS,MEMBERS_ROOT,IDENTITY_ROOT,RULES,b32,
    Program,bytes32,prepare_deed_to_sols,prepare_sols_to_deed,
    deterministic_custody_coin_id,make_pool_v4_inner,deed_to_sols_inner_solution,
    sols_to_deed_inner_solution,puzzle_hash_for_p2_vault,
)


@pytest.mark.parametrize('launchers',[(0x80,1,0xff),(1,0xff,0x7f),(0xff,0x80,1)])
def test_mixed_high_bit_inventory_deposits_and_withdrawal_execute(launchers):
    config=replace(CONFIG,pool_puzzle_version=5)
    state,inventory=EMPTY_POOL,()
    for index,seed in enumerate(launchers):
        launcher,parent=b32(seed),b32(70+index)
        commitment=bytes32(Program.to([launcher,PAR_VALUE,ASSET_CLASS,PROPERTY_ID,
            COLLECTION.collection_id,SHARE_PPM]).get_tree_hash())
        custody=deterministic_custody_coin_id(config=config,deed_parent_coin_id=parent,
            deed_launcher_id=launcher,deed_commitment=commitment)
        receipt=prepare_deed_to_sols(pool_coin_id=POOL_COIN,state=state,inventory=inventory,
            deed_launcher_id=launcher,custody_coin_id=custody,deed_commitment=commitment,
            collection=COLLECTION,share_ppm=SHARE_PPM,parameters=PARAMETERS,statutes_state=STATUTES_STATE,
            pause=None,vault_launcher_id=VAULT_LAUNCHER,vault_coin_id=VAULT_COIN,
            seller_sols_puzzle_hash=SELLER_PUZZLE,quote_expires_at=QUOTE_EXPIRES)
        inner=make_pool_v4_inner(config,state)
        solution=deed_to_sols_inner_solution(config=config,pool_coin_id=POOL_COIN,
            pool_inner_puzzle_hash=inner.get_tree_hash(),pool_amount=1,receipt=receipt,
            parameters=PARAMETERS,collection=COLLECTION,pause=None,statutes_state=STATUTES_STATE,
            deed_parent_coin_id=parent,par_value=PAR_VALUE,asset_class=ASSET_CLASS,property_id=PROPERTY_ID,
            seller_sols_puzzle_hash=SELLER_PUZZLE,mint_token_coin_id=MINT_TOKEN_COIN,
            vault_launcher_id=VAULT_LAUNCHER,vault_coin_id=VAULT_COIN,owner_pubkey=OWNER_PUBKEY,
            auth_type=AUTH_TYPE_BLS,members_root=MEMBERS_ROOT,identity_root=IDENTITY_ROOT,
            bridge_policy=RULES.zkpassport_policy_hash,quote_expires_at=QUOTE_EXPIRES)
        conditions=inner.run(solution).as_python()
        assert any(c[0]==b'3' and c[1]==make_pool_v4_inner(config,receipt.next_state).get_tree_hash() for c in conditions)
        state,inventory=receipt.next_state,receipt.next_inventory
    assert [r.deed_launcher_id for r in inventory]==sorted(b32(n) for n in launchers)
    destination=puzzle_hash_for_p2_vault(VAULT_LAUNCHER)
    receipt=prepare_sols_to_deed(pool_coin_id=POOL_COIN,state=state,inventory=inventory,
        deed_launcher_id=b32(launchers[0]),collection=COLLECTION,parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,pause=None,vault_launcher_id=VAULT_LAUNCHER,vault_coin_id=VAULT_COIN,
        sols_payment_coin_id=b32(79),destination_p2_vault_hash=destination,quote_expires_at=QUOTE_EXPIRES)
    inner=make_pool_v4_inner(config,state)
    solution=sols_to_deed_inner_solution(pool_coin_id=POOL_COIN,pool_inner_puzzle_hash=inner.get_tree_hash(),
        pool_amount=1,receipt=receipt,parameters=PARAMETERS,collection=COLLECTION,pause=None,
        statutes_state=STATUTES_STATE,vault_launcher_id=VAULT_LAUNCHER,vault_coin_id=VAULT_COIN,
        owner_pubkey=OWNER_PUBKEY,auth_type=AUTH_TYPE_BLS,members_root=MEMBERS_ROOT,
        identity_root=IDENTITY_ROOT,bridge_policy=RULES.zkpassport_policy_hash,
        quote_expires_at=QUOTE_EXPIRES,destination_p2_vault_hash=destination)
    assert inner.run(solution).as_python()


def test_legacy_pool_module_remains_exact_and_unknown_versions_reject():
    from solslot_puzzles.pool_v4_driver import pool_v4_inner_mod_hash,pool_puzzle_version_for_hash
    assert pool_v4_inner_mod_hash(4).hex()=='e01e8cb71b9612ba01ac9678e45e6cae6915cebffff6795f6809c081d973e27d'
    assert pool_puzzle_version_for_hash(pool_v4_inner_mod_hash(5))==5
    for invalid in (True,'5',3,6):
        with pytest.raises(ValueError,match='unsupported'):
            pool_v4_inner_mod_hash(invalid)
    with pytest.raises(ValueError,match='unsupported'):
        pool_puzzle_version_for_hash(b32(99))
