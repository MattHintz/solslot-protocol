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
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD,solution_for_conditions
from chia.wallet.trading.offer import OFFER_MOD, OFFER_MOD_HASH
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin,G1Element
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_primary_proceeds import PrimaryProceedsSplitter
from solslot_puzzles.generation_revenue import asset_puzzle, single_asset_spend
from solslot_puzzles.generation_transactions import NativeOperation
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.stripe_settlement_v1_driver import assert_artifact_matches_terms


@dataclass(frozen=True)
class TestnetPrimaryForwarding:
    operation: NativeOperation
    proceeds: PrimaryProceedsSplitter
    gross_coin: Coin
    payment_asset: bytes32 = bytes32.zeros

    @property
    def issuer_signature_spend(self):return self.operation.spends[0]

    def review(self):
        amount = ({'grossMojos':str(self.gross_coin.amount)} if self.payment_asset == bytes32.zeros
                  else {'assetId':'0x'+self.payment_asset.hex(), 'grossAtomicUnits':str(self.gross_coin.amount)})
        return {**self.proceeds.review(),**amount,'scope':'ONE_EXACT_TESTNET_PRIMARY_PAYOUT',
            'grossCoinId':'0x'+self.gross_coin.name().hex(),
            'issuerSignatureRequired':True,'serverSigningAuthorityGranted':False,
            'contractEnforcedFromOriginalPrimaryDestination':False,
            'existingDeedOrMetadataChanged':False,'createsNewGeneration':False}


def build_testnet_primary_forwarding(*,bundle,artifact,terms,issuer_public_key,fees,approved_cat_asset=None):
    assert_artifact_matches_terms(artifact,terms)
    asset = artifact.rail_asset_id
    native = artifact.rail == PaymentRail.CHIA_XCH and asset == bytes32.zeros and approved_cat_asset is None
    approved_cat = (artifact.rail == PaymentRail.CHIA_CAT and isinstance(approved_cat_asset, bytes32)
                    and asset == approved_cat_asset and asset != bytes32.zeros)
    if (terms.network!='testnet11' or not (native or approved_cat)
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
    settlement_hash = asset_puzzle(OFFER_MOD, asset).get_tree_hash()
    wallet_hash = asset_puzzle(wallet, asset).get_tree_hash()
    for spend in bundle.coin_spends:
        if spend.puzzle_reveal.get_tree_hash()!=settlement_hash or spend.coin.puzzle_hash!=settlement_hash:continue
        # Equal-price batch payouts are distinguished by their exact child
        # commitment as well as amount/destination. Memos do not change coin
        # identity, so native completion must also give them distinct parents.
        solution = Program.from_bytes(bytes(spend.solution))
        _,conditions=OFFER_MOD.run_with_cost(100_000_000, solution if native else solution.first())
        for condition in conditions.as_iter():
            fields=list(condition.as_iter())
            if (len(fields)==4 and fields[0].as_int()==51
                    and fields[1].as_atom()==terms.protocol_puzhash
                    and fields[2].as_int()==artifact.rail_amount
                    and [m.as_atom()for m in fields[3].as_iter()]==[artifact.purchase_id,artifact.artifact_hash]):
                coin=Coin(spend.coin.name(),wallet_hash,artifact.rail_amount)
                if coin.name() not in spent and coin in compute_additions(spend):
                    candidates.append((coin, spend.coin))
    if len(candidates)!=1:
        raise ValueError('forwarding requires one exact newly delivered offer proceeds coin')
    (gross, parent),=candidates
    proceeds=PrimaryProceedsSplitter.for_terms(terms.protocol_puzhash,fees,
        terms.base_amount_minor,terms.technology_fee_minor)
    conditions=[[51,proceeds.inner().get_tree_hash(),int(gross.amount),[proceeds.inner().get_tree_hash()]]]
    gross_lineage = None if native else LineageProof(parent.parent_coin_info, OFFER_MOD_HASH, parent.amount)
    issuer_spend=single_asset_spend(gross,wallet,solution_for_conditions(conditions),asset,gross_lineage)
    routed=compute_additions(issuer_spend)
    if len(routed)!=1 or routed[0].amount!=gross.amount:
        raise ValueError('forwarding must preserve the exact primary subtotal')
    routed_lineage = None if native else LineageProof(gross.parent_coin_info, wallet.get_tree_hash(), gross.amount)
    split=proceeds.operation(routed[0], asset, lineage=routed_lineage)
    operation=NativeOperation(fees.bindings.generation,'FORWARD_TESTNET_PRIMARY_PROCEEDS',
        (issuer_spend,*split.spends),())
    return TestnetPrimaryForwarding(operation,proceeds,gross,asset)
