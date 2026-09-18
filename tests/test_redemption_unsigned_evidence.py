"""Full unsigned/signed redemption controls; synthetic inputs, no live chain."""
from dataclasses import replace

import chia_rs
import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles.funded_redemption_v1 import (
    aggregate_direct_redemption, build_direct_redemption_acceptance, prepare_unsigned_direct_redemption,
)
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1, one_leaf_merkle_root, puzzle_for_p2_vault
from solslot_puzzles.vault_v2_driver import puzzle_for_vault_v2_inner, signing_digest_for_redemption_accept
from tests.test_funded_redemption_v1 import _funded_maker_offer, _holder_acceptance_kwargs

CONSTANTS = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"))
FLAGS = chia_rs.MEMPOOL_MODE | chia_rs.ENABLE_SECP_OPS | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD


def redemption_case(evm=False):
    args = _holder_acceptance_kwargs()
    bls = AugSchemeMPL.key_gen(b"synthetic-redemption-test-seed-000")
    secp = keys.PrivateKey(bytes.fromhex("42" * 32))
    owner = secp.public_key.to_compressed_bytes() if evm else bytes(bls.get_g1())
    args.update(vault_owner_pubkey=owner, vault_auth_type=AUTH_TYPE_SECP256K1 if evm else AUTH_TYPE_BLS,
                vault_members_merkle_root=one_leaf_merkle_root(owner),
                payment_recipient_inner_puzzle_hash=bytes32(puzzle_for_p2_vault(args["vault_launcher_id"]).get_tree_hash()))
    inner = puzzle_for_vault_v2_inner(vault_launcher_id=args["vault_launcher_id"], owner_pubkey=owner,
        auth_type=args["vault_auth_type"], members_merkle_root=args["vault_members_merkle_root"],
        pool_launcher_id=args["pool_launcher_id"], identity_attest_root=args["identity_attest_root"],
        zkpassport_bridge_policy_hash=args["zkpassport_bridge_policy_hash"])
    full = puzzle_for_singleton(args["vault_launcher_id"], inner)
    parent = Coin(bytes32(b"\x81" * 32), full.get_tree_hash(), uint64(1))
    args.update(vault_coin=Coin(parent.name(), full.get_tree_hash(), uint64(1)),
                vault_lineage_proof=LineageProof(parent.parent_coin_info, inner.get_tree_hash(), uint64(1)))
    maker = _funded_maker_offer()
    pending = build_direct_redemption_acceptance(**args)
    evidence = prepare_unsigned_direct_redemption(maker_offer=maker, acceptance=pending)
    return args, maker, pending, evidence, bls, secp


@pytest.mark.parametrize("evm", [False, True], ids=["bls", "evm"])
def test_exact_unsigned_redemption_becomes_complete_signed_consensus(evm):
    args, maker, pending, evidence, bls, secp = redemption_case(evm)
    assert len(evidence.coin_spends) == 5 and len(evidence.outputs) == 3
    assert len(set(evidence.roles)) == 5
    assert evidence.to_json()["consensusValidated"] is False
    assert evidence.required_backing_mojos == 0
    with pytest.raises(Exception):
        chia_rs.validate_clvm_and_signature(SpendBundle(list(evidence.coin_spends), G2Element()),
            11_000_000_000, CONSTANTS, FLAGS)
    signature = secp.sign_msg_hash(signing_digest_for_redemption_accept(
        pending.operation_hash, evidence.vault_coin_id)).to_bytes()[:64] if evm else None
    acceptance = build_direct_redemption_acceptance(**args, signature_data=signature)
    bundle = aggregate_direct_redemption(maker_offer=maker, acceptance=acceptance).to_valid_spend()
    signatures = []
    for spend in bundle.coin_spends:
        conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 11_000_000_000)
        for public_key, message in pkm_pairs_for_conditions_dict(conditions, spend.coin, CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA):
            assert bytes(public_key) == bytes(bls.get_g1())
            signatures.append(AugSchemeMPL.sign(bls, message))
    signed = SpendBundle(list(bundle.coin_spends), AugSchemeMPL.aggregate(signatures))
    chia_rs.validate_clvm_and_signature(signed, 11_000_000_000, CONSTANTS, FLAGS)
    expected = {bytes(spend) for spend in evidence.coin_spends if spend.coin.name() != evidence.vault_coin_id}
    assert expected == {bytes(spend) for spend in signed.coin_spends if spend.coin.name() != evidence.vault_coin_id}
    terminal = {coin for coin in signed.additions() if coin.name() not in {s.coin.name() for s in signed.coin_spends}}
    assert terminal == set(evidence.outputs)
    assert sum(c.amount for c in signed.removals()) == sum(c.amount for c in signed.additions())
    assert redemption_case(evm)[3].candidate_hash == evidence.candidate_hash


@pytest.mark.parametrize("evm", [False, True], ids=["bls", "evm"])
def test_unsigned_redemption_candidate_commits_every_serialized_spend(evm):
    _, _, _, evidence, _, _ = redemption_case(evm)
    for index in range(len(evidence.coin_spends)):
        changed = list(evidence.coin_spends)
        spend = changed[index]
        changed[index] = chia_rs.CoinSpend(spend.coin, spend.puzzle_reveal, chia_rs.Program.from_bytes(b"\x80"))
        assert replace(evidence, coin_spends=tuple(changed)).candidate_hash != evidence.candidate_hash
