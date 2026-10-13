"""Reuse the existing H-system price fact; never authorize an asset by price.

Delivery separately binds the exact generation, primary NFT and buyer batch.
The old read-only price signature domain is retained so live price updates do
not require governance votes or a new paid service.
"""
from dataclasses import dataclass
from chia_rs import AugSchemeMPL, G1Element, G2Element
from solslot_puzzles.payment_artifacts_v2 import OracleRoundV1, oracle_operator_set_root, oracle_round_signature_message


@dataclass(frozen=True)
class SignedPrimaryPrice:
    round: OracleRoundV1
    signatures: tuple[tuple[int, bytes], ...]

    def verify(self, pubkeys, *, asset, decimals, expires_at, maximum_age):
        r = self.round
        if (r.network != 'testnet11' or r.asset_id != asset or r.asset_decimals != decimals
                or r.operator_set_root != oracle_operator_set_root(pubkeys)
                or not r.valid_from < expires_at <= r.valid_until
                or r.valid_until-r.valid_from > maximum_age
                or len(self.signatures) != 2 or tuple(sorted(i for i,_ in self.signatures)) != tuple(i for i,_ in self.signatures)
                or len({i for i,_ in self.signatures}) != 2):
            raise ValueError('live price differs from the immutable asset, operator, freshness or quorum policy')
        message = oracle_round_signature_message(r.round_hash)
        for index, signature in self.signatures:
            if (type(index) is not int or not 0 <= index < 3
                    or not AugSchemeMPL.verify(G1Element.from_bytes(pubkeys[index]), message, G2Element.from_bytes(signature))):
                raise ValueError('live price signature is not an authorized operator attestation')
        return self

    def aggregate(self):
        return AugSchemeMPL.aggregate([G2Element.from_bytes(raw) for _,raw in self.signatures])

