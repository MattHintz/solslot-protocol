from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.collection_nav_registry_driver import compute_nav_evidence_message
from solslot_puzzles.pool_economics_v2 import (
    DEED_SPEND_POOL_DEPOSIT,
    DEED_SPEND_POOL_REDEEM,
    MAX_POOL_V2_TOKEN_OUTPUTS,
    PROTOCOL_PREFIX,
    TOKEN_MELT,
    TOKEN_MINT,
    CollectionNavEvidence,
    PoolEconomicState,
    TokenOutput,
    build_reserve_acquisition_spec,
    build_specific_deed_swap_spec,
    build_true_redemption_spec,
    deed_nav_mojos,
    deed_metadata_commitment,
    deed_pool_deposit_message,
    deed_pool_redeem_message,
    fee_split_for_principal,
    principal_tokens_for_nav,
    quote_reserve_acquisition,
    quote_specific_deed_swap,
    quote_true_redemption,
    token_authorization_message,
    token_settlement_payment_message,
)


def b32(byte: int) -> bytes32:
    return bytes32(bytes([byte]) * 32)


def nav_evidence(collection_id: bytes32 = b32(0xA1)) -> CollectionNavEvidence:
    return CollectionNavEvidence(
        registry_coin_id=b32(0xC1),
        registry_puzzle_hash=b32(0xC2),
        collection_id_canon=collection_id,
        nav_value_mojos=1_000_000_000,
        collection_nav_root=b32(0xC3),
        registry_version=7,
    )


def test_deed_nav_uses_share_ppm_with_ceiling_rounding():
    assert deed_nav_mojos(1_000_000_000, 250_000) == 250_000_000
    assert deed_nav_mojos(10, 333_333) == 4


def test_principal_tokens_are_nav_pro_rata_against_circulating_supply():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    assert state.circulating_supply() == 600_000_000
    assert principal_tokens_for_nav(250_000_000, state) == 150_000_000


def test_fee_split_is_one_percent_with_protocol_and_governance_parts():
    split = fee_split_for_principal(100_000)
    assert split.total_fee_tokens == 1_000
    assert split.protocol_fee_tokens == 300
    assert split.governance_fee_tokens == 700


def test_specific_deed_swap_locks_principal_as_treasury_reserve():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    quote = quote_specific_deed_swap(
        state,
        collection_nav_mojos=1_000_000_000,
        share_ppm=250_000,
    )
    assert quote.deed_nav_mojos == 250_000_000
    assert quote.principal_tokens == 150_000_000
    assert quote.buyer_total_tokens == 151_500_000
    assert quote.next_total_nav_locked_mojos == 750_000_000
    assert quote.next_deed_count == 9
    assert quote.next_total_pool_token_supply == 800_000_000
    assert quote.next_treasury_reserve_tokens == 350_000_000
    assert quote.next_circulating_supply == 450_000_000


def test_true_redemption_melts_principal_supply():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    quote = quote_true_redemption(
        state,
        collection_nav_mojos=1_000_000_000,
        share_ppm=250_000,
    )
    assert quote.principal_tokens == 150_000_000
    assert quote.next_total_nav_locked_mojos == 750_000_000
    assert quote.next_deed_count == 9
    assert quote.next_total_pool_token_supply == 650_000_000
    assert quote.next_treasury_reserve_tokens == 200_000_000
    assert quote.next_circulating_supply == 450_000_000


def test_reserve_acquisition_uses_reserve_before_fresh_mint():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    quote = quote_reserve_acquisition(
        state,
        collection_nav_mojos=400_000_000,
        share_ppm=500_000,
        seller_token_price=200_000_000,
    )
    assert quote.deed_nav_mojos == 200_000_000
    assert quote.reserve_tokens_paid == 200_000_000
    assert quote.fresh_tokens_to_mint == 0
    assert quote.next_total_nav_locked_mojos == 1_200_000_000
    assert quote.next_deed_count == 11
    assert quote.next_total_pool_token_supply == 800_000_000
    assert quote.next_treasury_reserve_tokens == 0


def test_reserve_acquisition_rejects_seller_price_above_deed_nav():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    with pytest.raises(ValueError, match="cannot exceed deed NAV"):
        quote_reserve_acquisition(
            state,
            collection_nav_mojos=400_000_000,
            share_ppm=500_000,
            seller_token_price=200_000_001,
        )


def test_nav_evidence_message_is_registry_driver_compatible():
    evidence = nav_evidence()
    assert evidence.evidence_message == compute_nav_evidence_message(
        evidence.collection_id_canon,
        evidence.nav_value_mojos,
        evidence.collection_nav_root,
        evidence.registry_version,
    )
    assert evidence.announcement_message == PROTOCOL_PREFIX + evidence.evidence_message


def test_deed_and_token_messages_match_clvm_tree_shapes():
    deed_id = b32(0xD1)
    deed_launcher_id = b32(0xD3)
    p2_vault = b32(0xD2)
    collection_id = b32(0xA1)
    token_coin_id = b32(0xE1)
    property_id = b32(0xA2)

    commitment = deed_metadata_commitment(
        deed_launcher_id, 123_000, 1, property_id, collection_id, 250_000
    )
    assert deed_pool_redeem_message(commitment, p2_vault) == (
        PROTOCOL_PREFIX
        + Program.to([DEED_SPEND_POOL_REDEEM, commitment, p2_vault]).get_tree_hash()
    )
    assert deed_pool_deposit_message(
        deed_id,
        deed_launcher_id,
        123_000,
        1,
        property_id,
        collection_id,
        250_000,
    ) == (
        PROTOCOL_PREFIX
        + Program.to(
            [
                DEED_SPEND_POOL_DEPOSIT,
                deed_id,
                commitment,
                123_000,
                1,
                property_id,
                collection_id,
                250_000,
            ]
        ).get_tree_hash()
    )
    assert token_authorization_message(TOKEN_MELT, token_coin_id, 150) == (
        PROTOCOL_PREFIX + Program.to([TOKEN_MELT, token_coin_id, 150]).get_tree_hash()
    )
    assert token_authorization_message(TOKEN_MINT, token_coin_id, 25) == (
        PROTOCOL_PREFIX + Program.to([TOKEN_MINT, token_coin_id, 25]).get_tree_hash()
    )


def test_specific_deed_swap_spec_binds_nav_deed_reserve_and_fee_outputs():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    deed_id = b32(0xD1)
    deed_launcher_id = b32(0xD3)
    property_id = b32(0xA2)
    p2_vault = b32(0xD2)
    collection_id = b32(0xA1)
    evidence = nav_evidence(collection_id)

    spec = build_specific_deed_swap_spec(
        state,
        deed_id=deed_id,
        deed_launcher_id=deed_launcher_id,
        par_value_mojos=123_000,
        asset_class=1,
        property_id_canon=property_id,
        p2_vault_puzzle_hash=p2_vault,
        collection_id_canon=collection_id,
        share_ppm=250_000,
        nav_evidence=evidence,
        treasury_reserve_puzhash=b32(0xF1),
        protocol_treasury_puzhash=b32(0xF2),
        governance_rewards_puzhash=b32(0xF3),
        governance_rewards_root=b32(0xF4),
    )

    assert spec.quote.principal_tokens == 150_000_000
    assert spec.next_state == PoolEconomicState(
        total_nav_locked_mojos=750_000_000,
        deed_count=9,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=350_000_000,
    )
    assert spec.required_nav_evidence_message == evidence.announcement_message
    assert spec.deed_message == deed_pool_redeem_message(
        spec.deed_commitment,
        p2_vault,
    )
    assert [(o.role, o.amount) for o in spec.token_outputs] == [
        ("treasury_reserve_principal", 150_000_000),
        ("protocol_treasury_fee", 450_000),
        ("pgt_rewards_fee", 1_050_000),
    ]
    assert spec.token_outputs[2].memos == (b32(0xF3), b32(0xF4))
    assert token_settlement_payment_message(b32(0x11), spec.token_outputs) == bytes32(
        Program.to(b32(0x11))
        .cons(
            Program.to(
                [
                    [b32(0xF1), 150_000_000, [b32(0xF1)]],
                    [b32(0xF2), 450_000, [b32(0xF2)]],
                    [b32(0xF3), 1_050_000, [b32(0xF3), b32(0xF4)]],
                ]
            )
        )
        .get_tree_hash()
    )
    assert sum(o.amount for o in spec.token_outputs) == spec.quote.buyer_total_tokens
    assert spec.pool_action_message.startswith(PROTOCOL_PREFIX)


def test_token_settlement_payment_message_rejects_unbounded_or_empty_outputs():
    outputs = tuple(
        TokenOutput(b32(0xF0 + i), 1, f"out_{i}")
        for i in range(MAX_POOL_V2_TOKEN_OUTPUTS + 1)
    )
    with pytest.raises(ValueError, match="outputs cannot exceed"):
        token_settlement_payment_message(b32(0x11), outputs)
    with pytest.raises(ValueError, match="outputs must not be empty"):
        token_settlement_payment_message(b32(0x11), ())


def test_token_settlement_payment_message_rejects_zero_amount_output():
    with pytest.raises(ValueError, match="amount must be positive"):
        token_settlement_payment_message(
            b32(0x11),
            (TokenOutput(b32(0xF1), 0, "zero"),),
        )


def test_true_redemption_spec_melts_principal_tokens_and_releases_deed():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    deed_id = b32(0xD1)
    deed_launcher_id = b32(0xD3)
    property_id = b32(0xA2)
    p2_vault = b32(0xD2)
    collection_id = b32(0xA1)
    token_coin_id = b32(0xE1)

    spec = build_true_redemption_spec(
        state,
        deed_id=deed_id,
        deed_launcher_id=deed_launcher_id,
        par_value_mojos=123_000,
        asset_class=1,
        property_id_canon=property_id,
        p2_vault_puzzle_hash=p2_vault,
        collection_id_canon=collection_id,
        share_ppm=250_000,
        nav_evidence=nav_evidence(collection_id),
        token_coin_id=token_coin_id,
    )

    assert spec.quote.principal_tokens == 150_000_000
    assert spec.next_state.total_pool_token_supply == 650_000_000
    assert spec.next_state.treasury_reserve_tokens == 200_000_000
    assert spec.token_outputs == ()
    assert len(spec.token_authorizations) == 1
    assert spec.token_authorizations[0].mint_or_melt == TOKEN_MELT
    assert spec.token_authorizations[0].announcement_message == token_authorization_message(
        TOKEN_MELT,
        token_coin_id,
        150_000_000,
    )
    assert spec.deed_message == deed_pool_redeem_message(
        spec.deed_commitment,
        p2_vault,
    )


def test_reserve_acquisition_spec_uses_reserve_then_mints_shortfall():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    deed_id = b32(0xD1)
    deed_launcher_id = b32(0xD3)
    property_id = b32(0xA2)
    collection_id = b32(0xA1)
    seller = b32(0xB1)

    spec = build_reserve_acquisition_spec(
        state,
        deed_id=deed_id,
        deed_launcher_id=deed_launcher_id,
        property_id_canon=property_id,
        par_value_mojos=123_000,
        asset_class=1,
        collection_id_canon=collection_id,
        share_ppm=500_000,
        nav_evidence=CollectionNavEvidence(
            registry_coin_id=b32(0xC1),
            registry_puzzle_hash=b32(0xC2),
            collection_id_canon=collection_id,
            nav_value_mojos=400_000_000,
            collection_nav_root=b32(0xC3),
            registry_version=7,
        ),
        seller_puzhash=seller,
        seller_token_price=200_000_000,
    )

    assert spec.quote.reserve_tokens_paid == 200_000_000
    assert spec.quote.fresh_tokens_to_mint == 0
    assert spec.next_state == PoolEconomicState(
        total_nav_locked_mojos=1_200_000_000,
        deed_count=11,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=0,
    )
    assert [(o.role, o.amount, o.puzzle_hash) for o in spec.token_outputs] == [
        ("seller_reserve_payment", 200_000_000, seller),
    ]
    assert spec.token_authorizations == ()
    assert spec.deed_message == deed_pool_deposit_message(
        deed_id,
        deed_launcher_id,
        123_000,
        1,
        property_id,
        collection_id,
        500_000,
    )


def test_reserve_acquisition_requires_mint_coin_for_fresh_shortfall():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=0,
    )
    collection_id = b32(0xA1)
    with pytest.raises(ValueError, match="mint_token_coin_id"):
        build_reserve_acquisition_spec(
            state,
            deed_id=b32(0xD1),
            deed_launcher_id=b32(0xD3),
            property_id_canon=b32(0xA2),
            par_value_mojos=123_000,
            asset_class=1,
            collection_id_canon=collection_id,
            share_ppm=500_000,
            nav_evidence=CollectionNavEvidence(
                registry_coin_id=b32(0xC1),
                registry_puzzle_hash=b32(0xC2),
                collection_id_canon=collection_id,
                nav_value_mojos=400_000_000,
                collection_nav_root=b32(0xC3),
                registry_version=7,
            ),
            seller_puzhash=b32(0xB1),
            seller_token_price=200_000_000,
        )


def test_action_specs_reject_nav_evidence_for_wrong_collection():
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    with pytest.raises(ValueError, match="collection_id_canon mismatch"):
        build_true_redemption_spec(
            state,
            deed_id=b32(0xD1),
            deed_launcher_id=b32(0xD3),
            par_value_mojos=123_000,
            asset_class=1,
            property_id_canon=b32(0xA3),
            p2_vault_puzzle_hash=b32(0xD2),
            collection_id_canon=b32(0xA1),
            share_ppm=250_000,
            nav_evidence=nav_evidence(b32(0xA2)),
            token_coin_id=b32(0xE1),
        )


def test_rejects_empty_or_overdrawn_pool_state():
    state = PoolEconomicState(
        total_nav_locked_mojos=0,
        deed_count=0,
        total_pool_token_supply=0,
        treasury_reserve_tokens=0,
    )
    with pytest.raises(ValueError, match="total_nav_locked"):
        principal_tokens_for_nav(1, state)
