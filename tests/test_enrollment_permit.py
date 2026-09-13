from dataclasses import replace
import json
from pathlib import Path
import pytest
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs import (AugSchemeMPL, Coin, CoinRecord, SpendBundle, check_time_locks,
    validate_clvm_and_signature, get_flags_for_height_and_constants, MEMPOOL_MODE)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32, uint64
from solslot_puzzles.enrollment_permit import EnrollmentPermit, EnrollmentPermitContext, owner_key_hash
from solslot_puzzles.enrollment_permit_driver import make_permit_bridge_puzzle, build_permit_bridge_spend
from solslot_puzzles.zkpassport_bridge_driver import make_bridge_policy_hash

B = lambda i: bytes32(bytes([i])*32)
KEYS = [AugSchemeMPL.key_gen(bytes([i])*32) for i in (7,8,9)]
PUBKEYS = [bytes(k.get_g1()) for k in KEYS]
HEIGHT = uint32(10_000_000)
FLAGS = get_flags_for_height_and_constants(HEIGHT, DEFAULT_CONSTANTS) | MEMPOOL_MODE


def case():
    # The companion is deliberately a synthetic coin, not a customer vault.
    companion = Coin(B(20), Program.to(1).get_tree_hash(), 1)
    puzzle = make_permit_bridge_puzzle(PUBKEYS, B(7))
    coin = Coin(B(1), puzzle.get_tree_hash(), 1)
    permit = EnrollmentPermit(B(2), B(7), B(3), companion.name(), 1,
        owner_key_hash(1, PUBKEYS[0]), coin.name(), 1_900_000_000, 1_900_003_600)
    fields = dict(bridge_coin=coin, validator_pubkeys=PUBKEYS, signer_indices=[0,2],
        new_identity_attest_root=B(4), attestation_leaf_hash=B(4), scoped_nullifier=B(5),
        nullifier_type=1, service_scope_hash=B(6), service_subscope_hash=B(8), proof_timestamp=permit.issued_at)
    return permit, fields, companion


def signed(permit, fields, companion, *, original_signature=None):
    bridge = build_permit_bridge_spend(permit=permit, **fields)
    message = bytes(bridge.validator_message) + bytes(bridge.bridge_coin_id) + bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    sig = original_signature or AugSchemeMPL.aggregate([AugSchemeMPL.sign(KEYS[i], message) for i in (0,2)])
    spend = make_spend(companion, Program.to(1), Program.to([[51, B(42), 1]]))
    return SpendBundle([bridge.coin_spend, spend], sig), bridge


def test_actual_rust_consensus_exclusive_deadline_and_signed_outcome():
    permit, fields, companion = case()
    bundle, bridge = signed(permit, fields, companion)
    conds, _, _ = validate_clvm_and_signature(bundle, 11_000_000_000, DEFAULT_CONSTANTS, FLAGS)
    records = {cs.coin.name(): CoinRecord(cs.coin, uint32(1), uint32(0), False, uint64(permit.issued_at-1)) for cs in bundle.coin_spends}
    assert check_time_locks(records, conds, HEIGHT, uint64(permit.issued_at), True) is None
    assert check_time_locks(records, conds, HEIGHT, uint64(permit.expires_at-1), True) is None
    assert check_time_locks(records, conds, HEIGHT, uint64(permit.issued_at-1), True) is not None
    assert check_time_locks(records, conds, HEIGHT, uint64(permit.expires_at), True) is not None
    assert check_time_locks(records, conds, HEIGHT, uint64(permit.expires_at+7200), True) is not None
    assert Coin(companion.name(), B(42), 1) in bundle.additions()
    emitted = bridge.puzzle.run(bridge.solution).as_python()
    assert [b'\x55', permit.expires_at.to_bytes(4, 'big')] in emitted
    assert [b'\x40', bytes(companion.name())] in emitted


@pytest.mark.parametrize('indices', [(0,1), (0,2), (1,2)])
def test_actual_vault_successor_and_refreshed_timestamp_cannot_revive_expired_signature(indices):
    from chia.wallet.lineage_proof import LineageProof
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
    from solslot_puzzles.vault_driver import (puzzle_for_vault_full, one_leaf_merkle_root,
        DEFAULT_IDENTITY_ATTEST_ROOT, build_vault_update_identity_spend)
    owner = AugSchemeMPL.key_gen(b'o'*32)
    owner_key = bytes(owner.get_g1())
    launcher = Coin(B(15), SINGLETON_LAUNCHER_HASH, 1)
    policy = make_permit_bridge_puzzle(PUBKEYS, B(7)).get_tree_hash()
    bridge_coin = Coin(B(1), policy, 1)
    members = one_leaf_merkle_root(owner_key)
    initial = puzzle_for_vault_full(launcher.name(), owner_key, 1, members, B(9),
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT, zkpassport_bridge_policy_hash=policy)
    vault_coin = Coin(launcher.name(), initial.get_tree_hash(), 1)
    permit = EnrollmentPermit(B(2), B(7), launcher.name(), vault_coin.name(), 1,
        owner_key_hash(1, owner_key), bridge_coin.name(), 1_900_000_000, 1_900_003_600)
    _, fields, _ = case()
    fields.update(bridge_coin=bridge_coin, signer_indices=indices)
    bridge = build_permit_bridge_spend(permit=permit, **fields)
    vm = bytes(bridge.validator_message)+bytes(bridge_coin.name())+bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    om = bytes(Program.to([b'z', B(4), vault_coin.name()]).get_tree_hash())+bytes(vault_coin.name())+bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    sig = AugSchemeMPL.aggregate([AugSchemeMPL.sign(owner,om)] + [AugSchemeMPL.sign(KEYS[i],vm) for i in indices])
    def bundle(timestamp):
        vault = build_vault_update_identity_spend(vault_coin, launcher.name(), owner_key, 1, members,
            B(9), B(4), bridge_coin.parent_coin_info, 1, timestamp,
            LineageProof(parent_name=launcher.parent_coin_info, amount=uint64(1)),
            zkpassport_bridge_policy_hash=policy)
        return SpendBundle([bridge.coin_spend, vault], sig)
    original = bundle(permit.issued_at+30)
    refreshed = bundle(permit.expires_at+30)
    records = {c.name(): CoinRecord(c, uint32(1), uint32(0), False, uint64(permit.issued_at-1)) for c in (bridge_coin,vault_coin)}
    first,_,_ = validate_clvm_and_signature(original,11_000_000_000,DEFAULT_CONSTANTS,FLAGS)
    later,_,_ = validate_clvm_and_signature(refreshed,11_000_000_000,DEFAULT_CONSTANTS,FLAGS)
    assert check_time_locks(records,first,HEIGHT,uint64(permit.issued_at+30),True) is None
    assert check_time_locks(records,later,HEIGHT,uint64(permit.expires_at+30),True) is not None
    assert original.aggregated_signature == refreshed.aggregated_signature
    successor = puzzle_for_vault_full(launcher.name(), owner_key, 1, members, B(9),
        identity_attest_root=B(4), zkpassport_bridge_policy_hash=policy)
    assert Coin(vault_coin.name(),successor.get_tree_hash(),1) in original.additions()


@pytest.mark.parametrize('field,value', [('permit_id', B(55)), ('current_vault_coin_id', B(56)),
    ('owner_key_hash', B(57)), ('owner_auth_type', 2), ('issued_at', 1_900_000_001), ('expires_at', 1_900_003_599)])
def test_collected_signature_cannot_authorize_changed_permit(field, value):
    permit, fields, companion = case()
    original, _ = signed(permit, fields, companion)
    changed, _ = signed(replace(permit, **{field:value}), fields, companion, original_signature=original.aggregated_signature)
    with pytest.raises(ValueError):
        validate_clvm_and_signature(changed, 11_000_000_000, DEFAULT_CONSTANTS, FLAGS)


def test_public_solution_cannot_extend_deadline_or_omit_concurrent_vault():
    permit, fields, companion = case()
    original, bridge = signed(permit, fields, companion)
    solution = bridge.solution.as_python()
    solution[-1] = permit.expires_at + 1
    changed = SpendBundle([make_spend(fields['bridge_coin'], bridge.puzzle, Program.to(solution)), original.coin_spends[1]], original.aggregated_signature)
    with pytest.raises(ValueError):
        validate_clvm_and_signature(changed, 11_000_000_000, DEFAULT_CONSTANTS, FLAGS)
    with pytest.raises(ValueError):
        validate_clvm_and_signature(SpendBundle([bridge.coin_spend], original.aggregated_signature), 11_000_000_000, DEFAULT_CONSTANTS, FLAGS)


@pytest.mark.parametrize('indices', [[0], [0,0], [2,1], [0,3]])
def test_direct_clvm_rejects_wrong_quorum(indices):
    permit, fields, _ = case()
    bridge = build_permit_bridge_spend(permit=permit, **fields)
    solution = bridge.solution.as_python(); solution[11] = indices
    with pytest.raises(ValueError):
        bridge.puzzle.run(Program.to(solution))


def test_new_policy_is_explicit_and_legacy_hash_is_unchanged():
    permit, fields, _ = case()
    assert fields['bridge_coin'].puzzle_hash != make_bridge_policy_hash(PUBKEYS, 2)
    with pytest.raises(ValueError, match='exact authorized coin'):
        build_permit_bridge_spend(permit=replace(permit, context_hash=B(8)), **fields)


@pytest.mark.parametrize('field,value', [('issued_at', True), ('expires_at', 1_900_003_601),
    ('expires_at', 1_900_000_000), ('owner_auth_type', True), ('permit_id', bytes(32)), ('context_hash', b'bad')])
def test_malformed_permits_fail_closed(field, value):
    permit, _, _ = case()
    with pytest.raises(ValueError): replace(permit, **{field:value})


def test_context_isolates_environment_network_emitter_issuer_deployment_and_release():
    ctx = EnrollmentPermitContext('staging-alpha', 'testnet11', 84532, b'e'*20, b'i'*20, B(8), B(9))
    for field, value in [('environment','production-alpha'), ('emitter',b'f'*20), ('issuer',b'j'*20),
                         ('deployment_id',B(10)), ('release_identity',B(11))]:
        assert replace(ctx, **{field:value}).context_hash != ctx.context_hash
    for field, value in [('environment','staging-beta'), ('network','mainnet'), ('evm_chain_id',8453)]:
        with pytest.raises(ValueError): replace(ctx, **{field:value})


def test_evm_python_clvm_wire_vector():
    vector = json.loads((Path(__file__).parents[1]/'fixtures/enrollment-permit-v1.json').read_text())
    p = vector['permit']
    permit = EnrollmentPermit(bytes32.fromhex(p['permitId'][2:]), bytes32.fromhex(p['contextHash'][2:]),
        bytes32.fromhex(p['vaultLauncherId'][2:]), bytes32.fromhex(p['currentVaultCoinId'][2:]), p['ownerAuthType'],
        bytes32.fromhex(p['ownerKeyHash'][2:]), bytes32.fromhex(p['bridgeCoinId'][2:]), p['issuedAt'], p['expiresAt'])
    assert '0x'+permit.permit_hash.hex() == vector['permitHash']
    assert '0x'+permit.validator_message(bytes32.fromhex(vector['legacyValidatorMessage'][2:])).hex() == vector['validatorMessage']


@pytest.mark.parametrize("auth_type", [1, 3])
def test_combined_permit_builder_binds_real_owner_and_current_vault(auth_type):
    from chia.wallet.lineage_proof import LineageProof
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
    from solslot_puzzles.zkpassport_bridge_driver import build_bridge_and_vault_update_identity_bundle
    from solslot_puzzles.vault_driver import (puzzle_for_vault_full, one_leaf_merkle_root,
        DEFAULT_IDENTITY_ATTEST_ROOT, eip712_typed_data_for_vault_spend)
    from solslot_puzzles.enrollment_permit import permit_owner_from_native
    owner = AugSchemeMPL.key_gen(b'o'*32)
    if auth_type == 1:
        key = bytes(owner.get_g1()); permit_key = key
    else:
        from eth_keys import keys
        private = keys.PrivateKey(b'e'*32)
        key = private.public_key.to_compressed_bytes(); permit_key = private.public_key.to_canonical_address()
    launcher = Coin(B(15), SINGLETON_LAUNCHER_HASH, 1)
    policy = make_permit_bridge_puzzle(PUBKEYS, B(7)).get_tree_hash()
    bridge_coin = Coin(B(1), policy, 1)
    members = one_leaf_merkle_root(key)
    initial = puzzle_for_vault_full(launcher.name(), key, auth_type, members, B(9),
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT, zkpassport_bridge_policy_hash=policy)
    vault = Coin(launcher.name(), initial.get_tree_hash(), 1)
    kind, digest = permit_owner_from_native(auth_type, permit_key)
    permit = EnrollmentPermit(B(2), B(7), launcher.name(), vault.name(), kind,
        digest, bridge_coin.name(), 1_900_000_000, 1_900_003_600)
    signature_data = None
    if auth_type == 3:
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend
        sig = private.sign_msg_hash(signing_message_for_vault_spend(b'z', B(4), vault.name()))
        signature_data = sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
    kwargs = dict(bridge_parent_id=B(1), bridge_amount=1, validator_pubkeys=PUBKEYS, threshold=2,
        signer_indices=[0,2], vault_coin=vault, vault_launcher_id=launcher.name(), owner_pubkey_bytes=key,
        auth_type=auth_type, members_merkle_root=members, pool_launcher_id=B(9), new_identity_attest_root=B(4),
        attestation_leaf_hash=B(4), scoped_nullifier=B(5), nullifier_type=1, service_scope_hash=B(6),
        service_subscope_hash=B(8), proof_timestamp=permit.issued_at, current_timestamp=permit.issued_at+30,
        lineage_proof=LineageProof(parent_name=launcher.parent_coin_info, amount=uint64(1)),
        signature_data=signature_data, enrollment_permit=permit)
    built = build_bridge_and_vault_update_identity_bundle(**kwargs)
    vm = bytes(built.bridge.validator_message)+bytes(bridge_coin.name())+bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    sigs = [AugSchemeMPL.sign(KEYS[i], vm) for i in (0,2)]
    if auth_type == 1:
        om = bytes(Program.to([b'z', B(4), vault.name()]).get_tree_hash())+bytes(vault.name())+bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
        sigs.append(AugSchemeMPL.sign(owner, om))
    signed_bundle = SpendBundle(built.spend_bundle.coin_spends, AugSchemeMPL.aggregate(sigs))
    conditions, _, _ = validate_clvm_and_signature(signed_bundle, 11_000_000_000, DEFAULT_CONSTANTS, FLAGS)
    records = {c.name(): CoinRecord(c, uint32(1), uint32(0), False, uint64(permit.issued_at-1)) for c in (bridge_coin,vault)}
    assert check_time_locks(records, conditions, HEIGHT, uint64(permit.issued_at+30), True) is None
    assert check_time_locks(records, conditions, HEIGHT, uint64(permit.expires_at), True) is not None
    successor = puzzle_for_vault_full(launcher.name(), key, auth_type, members, B(9),
        identity_attest_root=B(4), zkpassport_bridge_policy_hash=policy)
    assert Coin(vault.name(), successor.get_tree_hash(), 1) in signed_bundle.additions()
    for field, value in [("current_vault_coin_id",B(55)), ("owner_key_hash",B(56)), ("vault_launcher_id",B(57))]:
        with pytest.raises(ValueError):build_bridge_and_vault_update_identity_bundle(**{**kwargs,"enrollment_permit":replace(permit,**{field:value})})
    with pytest.raises(ValueError):build_bridge_and_vault_update_identity_bundle(**{**kwargs,"current_timestamp":permit.expires_at})
