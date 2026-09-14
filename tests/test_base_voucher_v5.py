"""Current Base voucher binding and reserved-deed CLVM regression coverage."""
from dataclasses import replace
import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail, purchase_artifact_to_json
from solslot_puzzles.payment_artifacts_v3 import (
    build_evm_test_usd_purchase_artifact_v3, purchase_artifact_v3_to_json, PurchaseKind,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import VoucherSeriesState
from solslot_puzzles.voucher_presale_v2_driver import (
    VoucherSeriesStateV2, VoucherAction, build_base_voucher_terminal_spends,
    curry_series, curry_voucher_inner, curry_external_receipt,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    PrimaryMintTermsV3, InventoryReservationV1, make_mint_offer_v5_inner,
    deed_launcher_puzzle_hash_from_struct,
)
from solslot_puzzles.base_voucher_v5 import prepare_base_voucher_redemption_offer_v5, build_base_voucher_primary_offer_v5
from solslot_puzzles.voucher_purchase import voucher_purchase_from_json, validate_base_voucher_purchase
from tests.test_voucher_presale_v2_driver import base_voucher, terms, b32
from tests.test_voucher_presale_v3_driver import smart_deed_struct


def current_base():
    voucher, old = base_voucher()
    purchase = build_evm_test_usd_purchase_artifact_v3(network=old.network,
        collection_id=old.collection_id, deed_launcher_id=old.deed_launcher_id,
        metadata_root=old.metadata_root, metadata_anchor_id=old.metadata_anchor_id,
        share_ppm=old.share_ppm, vault_launcher_id=old.vault_launcher_id,
        vault_p2_puzzle_hash=old.vault_p2_puzzle_hash, authorization_nonce=old.authorization_nonce,
        authorization_expires_at=old.authorization_expires_at, quote_expires_at=old.quote_expires_at,
        chain_id=old.rail_chain_id, token_asset_id=old.rail_asset_id,
        base_usd_amount_minor=voucher.base_price_minor, technology_fee_bps=voucher.technology_fee_bps,
        protocol_treasury_puzzle_hash=voucher.trusted_protocol_treasury,
        zkpassport_root=b32(30), presale_terms_hash=voucher.series_terms_hash)
    # New synthetic purchase fixture, never migration of historical paid evidence.
    return replace(voucher, purchase_artifact_hash=purchase.artifact_hash), purchase


def test_historical_base_purchase_remains_byte_exact():
    voucher, purchase = base_voucher()
    encoded = purchase_artifact_to_json(purchase)
    assert voucher_purchase_from_json(encoded) == purchase
    assert purchase_artifact_to_json(voucher_purchase_from_json(encoded)) == encoded
    validate_base_voucher_purchase(voucher, purchase, terms())


def test_current_base_purchase_roundtrip():
    voucher, purchase = current_base()
    assert voucher_purchase_from_json(purchase_artifact_v3_to_json(purchase)) == purchase
    validate_base_voucher_purchase(voucher, purchase, terms())


@pytest.mark.parametrize("field,value", [("presale_terms_hash", b32(210)),
    ("protocol_treasury_puzzle_hash", b32(211)), ("technology_fee_bps", 249),
    ("base_amount_minor", 101), ("metadata_anchor_id", b32(212))])
def test_current_base_rejects_rebound_economics_and_terms(field, value):
    voucher, purchase = current_base()
    with pytest.raises(PaymentArtifactError):
        changed = replace(purchase, **{field:value})
        rebound = replace(voucher, purchase_artifact_hash=changed.artifact_hash)
        validate_base_voucher_purchase(rebound, changed, terms())


@pytest.mark.parametrize("field,value", [("rail_chain_id", 1),
    ("rail_asset_id", b32(213)), ("network", "mainnet")])
def test_current_base_parser_rejects_wrong_deployment(field, value):
    _, purchase = current_base()
    with pytest.raises(PaymentArtifactError):
        voucher_purchase_from_json(purchase_artifact_v3_to_json(replace(purchase, **{field:value})))


def test_current_base_parser_rejects_direct_purchase():
    _, purchase = current_base()
    direct = replace(purchase, purchase_kind=PurchaseKind.DIRECT, presale_terms_hash=bytes32.zeros)
    with pytest.raises(PaymentArtifactError):
        voucher_purchase_from_json(purchase_artifact_v3_to_json(direct))


@pytest.mark.parametrize("inventory_version", [1, 2])
def test_current_base_voucher_delivers_exact_reserved_deed(inventory_version):
    item, artifact = current_base()
    state = VoucherSeriesStateV2(
        sold_count=1,
        phase=VoucherSeriesState.LIVE,
        launched_at=220,
    )
    series_inner = curry_series(terms(), state)
    series_coin = Coin(
        b32(157),
        bytes32(
            puzzle_for_singleton(
                terms().series_singleton_id,
                series_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    voucher_launcher_id = b32(158)
    voucher_inner = curry_voucher_inner(
        terms=terms(),
        voucher=item,
        voucher_launcher_id=voucher_launcher_id,
    )
    voucher_coin = Coin(
        b32(159),
        bytes32(
            puzzle_for_singleton(
                voucher_launcher_id,
                voucher_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    receipt_puzzle = curry_external_receipt(terms=terms(), voucher=item)
    receipt_coin = Coin(
        b32(160),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(1),
    )
    terminal = build_base_voucher_terminal_spends(
        terms=terms(),
        state=state,
        series_coin=series_coin,
        series_lineage_proof=LineageProof(b32(161), b32(162), uint64(1)),
        voucher=item,
        purchase=artifact,
        voucher_launcher_id=voucher_launcher_id,
        voucher_coin=voucher_coin,
        voucher_lineage_proof=LineageProof(b32(163), b32(164), uint64(1)),
        receipt_coin=receipt_coin,
        vault_coin_id=bytes32.zeros,
        vault_inner_puzzle_hash=bytes32.zeros,
        action=VoucherAction.REDEEM,
        external_settlement_evidence_hash=b32(165),
        signer_indices=(0, 1),
    )
    singleton_struct = smart_deed_struct(artifact.deed_launcher_id)
    mint_terms = PrimaryMintTermsV3.for_artifact(artifact=artifact,
        inventory_version=inventory_version, smart_deed_inner_hash=item.smart_deed_inner_hash,
        deed_launcher_puzzle_hash=deed_launcher_puzzle_hash_from_struct(singleton_struct, artifact.deed_launcher_id),
        protocol_puzhash=terms().trusted_protocol_treasury, validator_pubkeys=terms().validator_pubkeys)
    reservation = InventoryReservationV1(artifact=artifact, expires_at=400)
    buyer_offer = prepare_base_voucher_redemption_offer_v5(terminal=terminal,
        receipt_coin=receipt_coin, artifact=artifact, terms=mint_terms, deed_singleton_struct=singleton_struct)
    inner = make_mint_offer_v5_inner(mint_terms, reservation)
    deed_coin = Coin(
        b32(167),
        bytes32(
            SINGLETON_MOD.curry(singleton_struct, inner).get_tree_hash()
        ),
        uint64(1),
    )
    purchase_offer = build_base_voucher_primary_offer_v5(voucher_offer=buyer_offer,
        terminal=terminal, receipt_coin=receipt_coin, artifact=artifact, deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(b32(168), bytes32(inner.get_tree_hash()), uint64(1)),
        signer_indices=(0, 1), terms=mint_terms, reservation=reservation)

    assert purchase_offer.aggregate_offer.is_valid()
    assert purchase_offer.aggregate_offer.arbitrage() == {
        artifact.deed_launcher_id: 0,
        None: 0,
    }
    valid_spend = purchase_offer.aggregate_offer.to_valid_spend()
    additions = [
        addition
        for spend in valid_spend.coin_spends
        for addition in compute_additions(spend)
    ]
    delivered_deed_puzzle_hash = bytes32(
        SINGLETON_MOD.curry(
            singleton_struct,
            puzzle_for_p2_vault(artifact.vault_launcher_id),
        ).get_tree_hash()
    )
    assert sum(
        addition.puzzle_hash == delivered_deed_puzzle_hash
        and int(addition.amount) == 1
        for addition in additions
    ) == 1
    assert sum(
        addition.puzzle_hash == terms().trusted_protocol_treasury
        and int(addition.amount) == 1
        for addition in additions
    ) == 1
    assert not any(
        addition.puzzle_hash == terms().trusted_protocol_treasury
        and int(addition.amount) == artifact.rail_amount
        for addition in additions
    )
