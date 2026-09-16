"""Full signed local bundles for the vault/custody boundary (synthetic ancestry).

The pool here is a fixture singleton which emits the required operation
announcements. Actual Pool V4 economic transitions are covered separately by
test_sols_swap_v4_driver. No node, provider, live key or chain is used.
"""
import hashlib

import chia_rs
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton, solution_for_singleton
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from eth_keys import keys
import pytest

from solslot_puzzles.vault_driver import one_leaf_merkle_root, puzzle_for_p2_vault
from solslot_puzzles.vault_v2_driver import (
    build_vault_sols_swap_spend, puzzle_for_vault_v2_inner,
    signing_digest_for_sols_swap, sols_swap_authorization_hash,
)

FLAGS = chia_rs.MEMPOOL_MODE | chia_rs.ENABLE_SECP_OPS | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD


def b(n):
    return bytes32(bytes([n]) * 32)


def child(launcher, inner, seed):
    full = puzzle_for_singleton(launcher, inner)
    parent = Coin(b(seed), full.get_tree_hash(), 1)
    coin = Coin(parent.name(), full.get_tree_hash(), 1)
    lineage = LineageProof(parent.parent_coin_info, inner.get_tree_hash(), uint64(1))
    return coin, full, lineage


def validate(bundle):
    return chia_rs.validate_clvm_and_signature(bundle, 11_000_000_000, DEFAULT_CONSTANTS, FLAGS)


def fixture(auth_type, *, transfer=True):
    bls = AugSchemeMPL.key_gen(bytes([91]) * 32)
    evm = keys.PrivateKey(bytes([92]) * 32)
    passkey = ec.derive_private_key(93, ec.SECP256R1())
    owner = {
        1: bytes(bls.get_g1()), 3: evm.public_key.to_compressed_bytes(),
        2: passkey.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint),
    }[auth_type]
    params = dict(vault_launcher_id=b(1), owner_pubkey=owner, auth_type=auth_type,
                  members_merkle_root=one_leaf_merkle_root(owner), pool_launcher_id=b(2),
                  identity_attest_root=b(3), zkpassport_bridge_policy_hash=b(4))
    inner = puzzle_for_vault_v2_inner(**params)
    vault, full, lineage = child(b(1), inner, 5)
    holding = puzzle_for_p2_vault(b(1))
    deed, deed_full, deed_lineage = child(b(6), holding, 7)
    op = b(8)
    message = b"S" + bytes(Program.to([b"PSOL", op]).get_tree_hash())
    pool_inner = Program.to((1, [[62, message], [60, message], [51, b(9), 1]]))
    pool, pool_full, pool_lineage = child(b(2), pool_inner, 10)
    intent = dict(pool_coin_id=pool.name(), pool_inner_puzzle_hash=pool_inner.get_tree_hash(),
                  quote_expires_at=1_900_000_000)
    if transfer:
        intent.update(deed_launcher_id=b(6), p2_vault_coin_id=deed.name(), smart_deed_inner_puzzle_hash=b(11))
    commitment = sols_swap_authorization_hash(op, vault.name(), **intent)
    signature = None
    aggregate = G2Element()
    if auth_type == 1:
        aggregate = AugSchemeMPL.sign(bls, bytes(commitment) + bytes(vault.name()) + bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA))
    elif auth_type == 3:
        signature = evm.sign_msg_hash(signing_digest_for_sols_swap(op, vault.name(), **intent)).to_bytes()[:64]
    else:
        digest = hashlib.sha256(b"s".ljust(32, b"\0") + bytes(commitment) + bytes(vault.name())).digest()
        der = passkey.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    vs = build_vault_sols_swap_spend(vault_coin=vault, **params, operation_hash=op,
                                    lineage_proof=lineage, signature_data=signature, **intent)
    ps = make_spend(pool, pool_full, solution_for_singleton(pool_lineage, uint64(1), Program.to([])))
    spends = [vs, ps]
    if transfer:
        ds = make_spend(deed, deed_full, solution_for_singleton(deed_lineage, uint64(1), Program.to([
            inner.get_tree_hash(), vault.name(), b(6), holding.get_tree_hash(), 1, b(11), deed.name(),
        ])))
        spends.append(ds)
    return SpendBundle(spends, aggregate)


def mutate_vault(bundle, change):
    cs = bundle.coin_spends[0]
    solution = Program.from_bytes(bytes(cs.solution)).as_python()
    change(solution[2][4])
    mutated = make_spend(cs.coin, Program.from_bytes(bytes(cs.puzzle_reveal)), Program.to(solution))
    return SpendBundle([mutated, *bundle.coin_spends[1:]], bundle.aggregated_signature)


@pytest.mark.parametrize("auth_type", [1, 2, 3])
@pytest.mark.parametrize("transfer", [False, True])
def test_complete_signed_swap_boundary_accepts_owner_intent(auth_type, transfer):
    validate(fixture(auth_type, transfer=transfer))


@pytest.mark.parametrize("auth_type", [1, 2, 3])
@pytest.mark.parametrize("field", ["operation", "expiry", "pool_coin", "pool_inner", "deed", "held_coin", "destination", "remove_transfer", "extra_field"])
def test_same_signature_rejects_every_modified_intent_field(auth_type, field):
    bundle = fixture(auth_type)
    def change(p):
        if field == "operation": p[0] = b(20)
        elif field == "expiry": p[1] = 1_900_000_001
        elif field == "pool_coin": p[4][0] = b(21)
        elif field == "pool_inner": p[4][1] = b(22)
        elif field == "deed": p[3][0] = b(23)
        elif field == "held_coin": p[3][1] = b(24)
        elif field == "destination": p[3][2] = Program.to(1).get_tree_hash()
        elif field == "remove_transfer": p[3] = []
        elif field == "extra_field": p.append(b(25))
    with pytest.raises(Exception): validate(mutate_vault(bundle, change))


@pytest.mark.parametrize("auth_type", [1, 2, 3])
def test_no_transfer_signature_cannot_authorize_a_transfer(auth_type):
    bundle = fixture(auth_type, transfer=False)
    with pytest.raises(Exception):
        validate(mutate_vault(bundle, lambda p: p.__setitem__(3, [b(6), b(26), b(11)])))


@pytest.mark.parametrize("index", [1, 2])
def test_pool_and_exact_held_input_are_required(index):
    bundle = fixture(3)
    with pytest.raises(Exception):
        validate(SpendBundle([s for i, s in enumerate(bundle.coin_spends) if i != index], bundle.aggregated_signature))


@pytest.mark.parametrize("mode", ["copy_input", "own_input", "legacy_announcement"])
def test_second_held_singleton_cannot_reuse_first_transfer_authorization(mode):
    bundle = fixture(3)
    holding = puzzle_for_p2_vault(b(1))
    other, full, lineage = child(b(30), holding, 31)
    original = Program.from_bytes(bytes(bundle.coin_spends[2].solution)).as_python()[2]
    if mode == "own_input": original[6] = other.name()
    elif mode == "legacy_announcement": original = original[:6]
    extra = make_spend(other, full, solution_for_singleton(lineage, uint64(1), Program.to(original)))
    with pytest.raises(Exception):
        validate(SpendBundle([*bundle.coin_spends, extra], bundle.aggregated_signature))


def test_wrong_bls_network_and_invalid_owner_signature_fail():
    bundle = fixture(1)
    with pytest.raises(Exception): validate(SpendBundle(bundle.coin_spends, G2Element()))
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=b(42))
    with pytest.raises(Exception): chia_rs.validate_clvm_and_signature(bundle, 11_000_000_000, constants, FLAGS)


def test_stale_owner_signature_cannot_authorize_successor_coin():
    bundle = fixture(3)
    original = bundle.coin_spends[0]
    successor = Coin(original.coin.name(), original.coin.puzzle_hash, original.coin.amount)
    full = Program.from_bytes(bytes(original.puzzle_reveal))
    inner = list(full.uncurry()[1].as_iter())[1]
    solution = Program.from_bytes(bytes(original.solution)).as_python()[2]
    solution[0] = successor.name()
    spend = make_spend(successor, full, solution_for_singleton(
        LineageProof(original.coin.parent_coin_info, inner.get_tree_hash(), uint64(1)), uint64(1), Program.to(solution)))
    with pytest.raises(Exception): validate(SpendBundle([spend, *bundle.coin_spends[1:]], bundle.aggregated_signature))
