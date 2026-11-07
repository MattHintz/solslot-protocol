"""Unsigned, exact Testnet issuer-wallet forwarding companion.

Compatibility assessment only, not a signer or live authorization. The issuer
must separately authorize this one gross proceeds coin. No existing deed,
metadata, token identity or generation is replaced. A live integration must
reconstruct terms and the buyer offer from native evidence, apply a finite
issuer signing policy and include this companion in the saved purchase bundle.
This is not permanent on-chain fee enforcement for a wallet-bound old mint.
"""
from dataclasses import dataclass
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD,solution_for_conditions
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin,G1Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_primary_proceeds import PrimaryProceedsSplitter
from solslot_puzzles.generation_transactions import NativeOperation
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.stripe_settlement_v1_driver import assert_artifact_matches_terms


@dataclass(frozen=True)
class TestnetPrimaryForwarding:
    operation: NativeOperation
    proceeds: PrimaryProceedsSplitter
    gross_coin: Coin

    @property
    def issuer_signature_spend(self):return self.operation.spends[0]

    def review(self):
        return {**self.proceeds.review(),'scope':'ONE_EXACT_TESTNET_PRIMARY_PAYOUT',
            'grossCoinId':'0x'+self.gross_coin.name().hex(),'grossMojos':str(self.gross_coin.amount),
            'issuerSignatureRequired':True,'serverSigningAuthorityGranted':False,
            'contractEnforcedFromOriginalPrimaryDestination':False,
            'existingDeedOrMetadataChanged':False,'createsNewGeneration':False}


def build_testnet_primary_forwarding(*,bundle,artifact,terms,issuer_public_key,fees):
    assert_artifact_matches_terms(artifact,terms)
    if (terms.network!='testnet11' or artifact.rail!=PaymentRail.CHIA_XCH
            or terms.inventory_version!=4 or terms.technology_fee_bps!=100):
        raise ValueError('forwarding is limited to the reviewed Testnet native primary route')
    bindings=list(Program.from_bytes(terms.generation_batch_bindings).as_iter())
    if (len(bindings)!=8 or bindings[0].as_atom()!=bytes(fees.bindings.generation)
            or fees.inner().get_tree_hash()!=terms.protocol_treasury_puzzle_hash):
        raise ValueError('forwarding fee custody differs from the native mint')
    key=G1Element.from_bytes(issuer_public_key)
    if key==G1Element():raise ValueError('issuer public key must not be identity')
    # Exact public key curried into the existing standard-p2 reveal. Do not
    # derive a different synthetic key and thereby substitute its destination.
    wallet=Program.from_bytes(bytes(MOD)).curry(key)
    if wallet.get_tree_hash()!=terms.protocol_puzhash:
        raise ValueError('the issuer cannot authorize the existing primary proceeds destination')
    spent={spend.coin.name() for spend in bundle.coin_spends}
    candidates=[]
    for spend in bundle.coin_spends:
        if spend.puzzle_reveal.get_tree_hash()!=OFFER_MOD_HASH:continue
        # Equal-price batch payouts are distinguished by their exact child
        # commitment as well as amount/destination. Memos do not change coin
        # identity, so native completion must also give them distinct parents.
        _,conditions=Program.from_bytes(bytes(spend.puzzle_reveal)).run_with_cost(
            100_000_000,Program.from_bytes(bytes(spend.solution)))
        for condition in conditions.as_iter():
            fields=list(condition.as_iter())
            if (len(fields)==4 and fields[0].as_int()==51
                    and fields[1].as_atom()==terms.protocol_puzhash
                    and fields[2].as_int()==artifact.rail_amount
                    and [m.as_atom()for m in fields[3].as_iter()]==[artifact.purchase_id,artifact.artifact_hash]):
                coin=Coin(spend.coin.name(),terms.protocol_puzhash,artifact.rail_amount)
                if coin.name() not in spent:candidates.append(coin)
    if len(candidates)!=1:
        raise ValueError('forwarding requires one exact newly delivered offer proceeds coin')
    gross,=candidates
    proceeds=PrimaryProceedsSplitter.for_terms(terms.protocol_puzhash,fees,
        terms.base_amount_minor,terms.technology_fee_minor)
    conditions=[[51,proceeds.inner().get_tree_hash(),int(gross.amount),[proceeds.inner().get_tree_hash()]]]
    issuer_spend=make_spend(gross,wallet,solution_for_conditions(conditions))
    routed=compute_additions(issuer_spend)
    if len(routed)!=1 or routed[0].amount!=gross.amount:
        raise ValueError('forwarding must preserve the exact primary subtotal')
    split=proceeds.operation(routed[0])
    operation=NativeOperation(fees.bindings.generation,'FORWARD_TESTNET_PRIMARY_PROCEEDS',
        (issuer_spend,*split.spends),())
    return TestnetPrimaryForwarding(operation,proceeds,gross)
