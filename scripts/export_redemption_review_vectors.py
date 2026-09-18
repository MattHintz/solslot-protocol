"""Export synthetic public redemption vectors, without any private keys."""
import argparse
from dataclasses import fields, is_dataclass
import json
from pathlib import Path

from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia_rs import AugSchemeMPL, Coin, SpendBundle
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from solslot_puzzles.funded_redemption_v1 import aggregate_direct_redemption, build_direct_redemption_acceptance, p2_deed_redemption_v1_mod
from solslot_puzzles.vault_v2_driver import signing_digest_for_redemption_accept
from tests.test_redemption_unsigned_evidence import CONSTANTS, redemption_case


def encode(value):
    if isinstance(value, Coin): return {"kind": "coin", "value": value.to_json_dict()}
    if isinstance(value, LineageProof): return {"kind": "lineage", "value": [encode(value.parent_name), encode(value.inner_puzzle_hash), int(value.amount)]}
    if isinstance(value, Program): return {"kind": "program", "value": "0x" + bytes(value).hex()}
    if isinstance(value, bytes): return "0x" + value.hex()
    if is_dataclass(value): return {"kind": type(value).__name__, "value": {f.name: encode(getattr(value, f.name)) for f in fields(value)}}
    if isinstance(value, (list, tuple)): return [encode(item) for item in value]
    if isinstance(value, dict): return {key: encode(item) for key, item in value.items()}
    return value


def vectors():
    result = []
    for evm in (False, True):
        args, maker, pending, evidence, bls, secp = redemption_case(evm)
        auth = secp.sign_msg_hash(signing_digest_for_redemption_accept(pending.operation_hash, evidence.vault_coin_id)).to_bytes() if evm else None
        acceptance = build_direct_redemption_acceptance(**args, signature_data=auth[:64] if auth else None)
        bundle = aggregate_direct_redemption(maker_offer=maker, acceptance=acceptance).to_valid_spend()
        signatures = []
        for spend in bundle.coin_spends:
            conditions = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 11_000_000_000)
            for key, message in pkm_pairs_for_conditions_dict(conditions, spend.coin, CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA):
                assert key == bls.get_g1()
                signatures.append(AugSchemeMPL.sign(bls, message))
        signed = SpendBundle(list(bundle.coin_spends), AugSchemeMPL.aggregate(signatures))
        result.append({"name": "evm" if evm else "bls", "args": encode(args),
            "ownerAddress": secp.public_key.to_checksum_address().lower() if evm else "0x" + bytes(bls.get_g1()).hex(),
            "makerOffer": "0x" + bytes(maker).hex(), "evidence": evidence.to_json(),
            "signedBundle": signed.to_json_dict(),
            "authorization": {"vaultOwnerAuthorization": "0x" + auth.hex()} if auth else
                {"aggregatedSignature": "0x" + bytes(signed.aggregated_signature).hex()}})
    return {"synthetic": True, "network": "testnet11", "redemptionLeafModule": "0x" + p2_deed_redemption_v1_mod().get_tree_hash().hex(), "vectors": result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    options = parser.parse_args()
    options.output.write_text(json.dumps(vectors(), indent=2) + "\n")
