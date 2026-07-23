from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.types.coin_spend import make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk,
    solution_for_conditions,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from clvm.EvalError import EvalError

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentRail,
    PurchaseArtifactV2,
    XCH_ASSET_DECIMALS,
    build_evm_test_usd_purchase_artifact,
    xch_mojos_for_usd,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    PrimaryMintTermsV2,
    PrimaryPurchaseMode,
    build_chia_primary_offer,
    build_universal_primary_offer_v4,
    chia_offer_v3_solution,
    make_mint_offer_v3_inner,
    make_mint_offer_v4_inner,
    prepare_base_voucher_redemption_offer,
    prepare_xch_voucher_redemption_offer,
    universal_offer_v4_solution,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault, puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    VoucherCommitmentV2,
    VoucherPaymentRail,
    VoucherSeriesState,
    VoucherSeriesTermsV2,
    VoucherState,
)
from solslot_puzzles.voucher_presale_v2_driver import (
    BASE_SEPOLIA_USDC_ASSET_ID,
    SeriesTransition,
    VoucherAction,
    VoucherSeriesStateV2,
    VoucherTransitionContextV2,
    base_result_message,
    burn_inner_hash,
    build_base_voucher_terminal_spends,
    build_voucher_issuance_spends,
    build_voucher_series_phase_spend,
    build_xch_voucher_terminal_spends,
    curry_series,
    curry_external_receipt,
    curry_purchase_launcher,
    curry_voucher_inner,
    curry_xch_escrow,
    escrow_solution,
    external_receipt_evidence_message,
    external_receipt_solution,
    external_receipt_settlement_message,
    issuance_coin_ids,
    next_series_state,
    prepare_xch_voucher_offer,
    series_solution,
    transition_message,
    validate_xch_voucher_offer,
    purchase_launcher_solution,
    voucher_solution,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def validator_keys() -> tuple[bytes, bytes, bytes]:
    return tuple(
        bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
        for index in (1, 2, 3)
    )  # type: ignore[return-value]


def terms() -> VoucherSeriesTermsV2:
    return VoucherSeriesTermsV2(
        series_singleton_id=b32(1),
        collection_id=b32(2),
        metadata_root=b32(3),
        metadata_anchor_id=b32(4),
        allocation_root=b32(5),
        trusted_protocol_treasury=b32(6),
        base_return_puzzle_hash=b32(60),
        inventory_cap=2,
        sale_open=100,
        sale_close=200,
        refund_deadline=300,
        launch_deadline=400,
        validator_pubkeys=validator_keys(),
    )


def purchase(vault_launcher: bytes32, rail_amount: int) -> PurchaseArtifactV2:
    return PurchaseArtifactV2(
        network="testnet11",
        collection_id=terms().collection_id,
        deed_launcher_id=b32(20),
        metadata_root=terms().metadata_root,
        metadata_anchor_id=terms().metadata_anchor_id,
        share_ppm=500_000,
        usd_amount_minor=103,
        rail=PaymentRail.CHIA_XCH,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=XCH_ASSET_DECIMALS,
        rail_amount=rail_amount,
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=b32(21),
        authorization_expires_at=500,
        quote_expires_at=200,
        oracle_round_hash=b32(22),
        oracle_price_usd_minor_per_asset=2_500,
        source_evidence_root=b32(23),
    )


def voucher() -> tuple[VoucherCommitmentV2, PurchaseArtifactV2]:
    vault_launcher = b32(10)
    amount = xch_mojos_for_usd(103, 2_500)
    artifact = purchase(vault_launcher, amount)
    item = VoucherCommitmentV2(
        series_terms_hash=terms().terms_hash,
        series_singleton_id=terms().series_singleton_id,
        collection_id=terms().collection_id,
        metadata_root=terms().metadata_root,
        allocation_root=terms().allocation_root,
        serial=0,
        payment_rail=VoucherPaymentRail.CHIA_XCH,
        payment_chain_id=0,
        payment_asset_id=bytes32.zeros,
        payment_asset_decimals=12,
        external_escrow_contract=bytes32.zeros,
        base_price_minor=100,
        technology_fee_bps=250,
        technology_fee_minor=3,
        gross_price_minor=103,
        payment_principal=amount,
        original_payer=b32(11),
        approved_vault_launcher_id=vault_launcher,
        approved_vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        refund_deadline=terms().refund_deadline,
        delivery_window_seconds=DELIVERY_WINDOW_SECONDS,
        trusted_protocol_treasury=terms().trusted_protocol_treasury,
        deed_launcher_id=artifact.deed_launcher_id,
        smart_deed_inner_hash=bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        ),
        purchase_artifact_hash=artifact.artifact_hash,
        global_payment_id=b32(12),
        state=VoucherState.ESCROWED,
    )
    return item, artifact


def base_voucher() -> tuple[VoucherCommitmentV2, PurchaseArtifactV2]:
    vault_launcher = b32(10)
    artifact = build_evm_test_usd_purchase_artifact(
        network="testnet11",
        collection_id=terms().collection_id,
        deed_launcher_id=b32(20),
        metadata_root=terms().metadata_root,
        metadata_anchor_id=terms().metadata_anchor_id,
        share_ppm=500_000,
        usd_amount_minor=103,
        chain_id=84532,
        token_asset_id=BASE_SEPOLIA_USDC_ASSET_ID,
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=b32(121),
        authorization_expires_at=500,
        quote_expires_at=200,
    )
    item = VoucherCommitmentV2(
        series_terms_hash=terms().terms_hash,
        series_singleton_id=terms().series_singleton_id,
        collection_id=terms().collection_id,
        metadata_root=terms().metadata_root,
        allocation_root=terms().allocation_root,
        serial=0,
        payment_rail=VoucherPaymentRail.BASE_SEPOLIA_USDC,
        payment_chain_id=84532,
        payment_asset_id=artifact.rail_asset_id,
        payment_asset_decimals=6,
        external_escrow_contract=b32(122),
        base_price_minor=100,
        technology_fee_bps=250,
        technology_fee_minor=3,
        gross_price_minor=103,
        payment_principal=artifact.rail_amount,
        original_payer=b32(123),
        approved_vault_launcher_id=vault_launcher,
        approved_vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        refund_deadline=terms().refund_deadline,
        delivery_window_seconds=DELIVERY_WINDOW_SECONDS,
        trusted_protocol_treasury=terms().trusted_protocol_treasury,
        deed_launcher_id=artifact.deed_launcher_id,
        smart_deed_inner_hash=bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        ),
        purchase_artifact_hash=artifact.artifact_hash,
        global_payment_id=b32(124),
        state=VoucherState.ESCROWED,
    )
    return item, artifact


def condition(conditions: list, opcode: int) -> list:
    return next(item for item in conditions if int.from_bytes(item[0], "big") == opcode)


def test_series_self_recurry_matches_driver_and_transition_message() -> None:
    current = VoucherSeriesStateV2(sold_count=1)
    inner = curry_series(terms(), current)
    full = puzzle_for_singleton(terms().series_singleton_id, inner)
    coin = Coin(b32(40), bytes32(full.get_tree_hash()), uint64(1))
    context = VoucherTransitionContextV2(
        SeriesTransition.LAUNCH,
        VoucherAction.NONE,
        bytes32.zeros,
        bytes32.zeros,
        bytes32.zeros,
        launch_anchor=220,
    )
    conditions = inner.run(
        series_solution(
            coin=coin,
            inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            context=context,
            signer_indices=(0, 2),
        )
    ).as_python()
    next_state = next_series_state(terms(), current, context)
    create = condition(conditions, 51)
    assert create[1] == bytes(curry_series(terms(), next_state).get_tree_hash())
    announcement = condition(conditions, 60)
    assert announcement[1] == bytes(
        transition_message(
            terms=terms(), state=current, series_coin_id=coin.name(), context=context
        )
    )


@pytest.mark.parametrize(
    ("transition", "launch_anchor", "expected_phase"),
    (
        (SeriesTransition.LAUNCH, 220, VoucherSeriesState.LIVE),
        (SeriesTransition.CANCEL, 0, VoucherSeriesState.CANCELED),
    ),
)
def test_phase_builder_spends_exact_series_and_recurries_once(
    transition: SeriesTransition,
    launch_anchor: int,
    expected_phase: VoucherSeriesState,
) -> None:
    current = VoucherSeriesStateV2(sold_count=1)
    inner = curry_series(terms(), current)
    full = puzzle_for_singleton(terms().series_singleton_id, inner)
    coin = Coin(b32(41), bytes32(full.get_tree_hash()), uint64(1))

    phase = build_voucher_series_phase_spend(
        terms=terms(),
        state=current,
        series_coin=coin,
        series_lineage_proof=LineageProof(b32(42), b32(43), uint64(1)),
        transition=transition,
        launch_anchor=launch_anchor,
        signer_indices=(0, 2),
    )

    additions = compute_additions(phase.series_spend)
    assert additions == [phase.next_series_coin]
    assert phase.next_series_state.phase == expected_phase
    assert phase.next_series_state.launched_at == launch_anchor
    assert phase.next_series_state.sold_count == current.sold_count
    assert phase.validator_message == transition_message(
        terms=terms(),
        state=current,
        series_coin_id=coin.name(),
        context=phase.transition_context,
    )


def test_phase_builder_rejects_non_phase_and_cancel_anchor() -> None:
    current = VoucherSeriesStateV2()
    inner = curry_series(terms(), current)
    coin = Coin(
        b32(44),
        bytes32(
            puzzle_for_singleton(terms().series_singleton_id, inner).get_tree_hash()
        ),
        uint64(1),
    )
    common = {
        "terms": terms(),
        "state": current,
        "series_coin": coin,
        "series_lineage_proof": LineageProof(b32(45), b32(46), uint64(1)),
        "signer_indices": (0, 1),
    }
    with pytest.raises(Exception, match="launch or cancel"):
        build_voucher_series_phase_spend(
            **common,
            transition=SeriesTransition.SALE,
            launch_anchor=0,
        )
    with pytest.raises(Exception, match="cannot carry"):
        build_voucher_series_phase_spend(
            **common,
            transition=SeriesTransition.CANCEL,
            launch_anchor=220,
        )


def test_voucher_is_vault_authorized_and_can_only_move_to_burn() -> None:
    item, _artifact = voucher()
    launcher = b32(30)
    inner = curry_voucher_inner(
        terms=terms(), voucher=item, voucher_launcher_id=launcher
    )
    series_coin_id = b32(31)
    escrow_coin_id = item.global_payment_id
    conditions = inner.run(
        voucher_solution(
            action=VoucherAction.REFUND_PRESALE,
            delivery_deadline=0,
            series_coin_id=series_coin_id,
            escrow_coin_id=escrow_coin_id,
            vault_inner_puzzle_hash=b32(32),
            vault_coin_id=b32(33),
            voucher_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            signer_indices=(0, 1),
        )
    ).as_python()
    create = condition(conditions, 51)
    assert create[1] == bytes(burn_inner_hash())
    assert int.from_bytes(create[2], "big") == 1
    assert condition(conditions, 63) is not None
    assert condition(conditions, 60) is not None
    with pytest.raises((EvalError, ValueError)):
        inner.run(
            voucher_solution(
                action=VoucherAction.NONE,
                delivery_deadline=0,
                series_coin_id=series_coin_id,
                escrow_coin_id=escrow_coin_id,
                vault_inner_puzzle_hash=b32(32),
                vault_coin_id=b32(33),
                voucher_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
                signer_indices=(0, 1),
            )
        )


def test_xch_escrow_refund_is_exact_and_redeem_reuses_offer_path() -> None:
    item, artifact = voucher()
    puzzle = curry_xch_escrow(terms=terms(), voucher=item, purchase=artifact)
    coin = Coin(b32(50), bytes32(puzzle.get_tree_hash()), uint64(item.payment_principal))
    refund_conditions = puzzle.run(
        escrow_solution(
            escrow_coin=coin,
            action=VoucherAction.REFUND_PRESALE,
            delivery_deadline=0,
            series_coin_id=b32(51),
            voucher_coin_id=b32(52),
            signer_indices=(0, 2),
        )
    ).as_python()
    refund = condition(refund_conditions, 51)
    assert refund[1] == bytes(item.original_payer)
    assert int.from_bytes(refund[2], "big") == item.payment_principal

    delivery_deadline = 220 + DELIVERY_WINDOW_SECONDS
    redeem_conditions = puzzle.run(
        escrow_solution(
            escrow_coin=coin,
            action=VoucherAction.REDEEM,
            delivery_deadline=delivery_deadline,
            series_coin_id=b32(51),
            voucher_coin_id=b32(52),
            signer_indices=(0, 2),
        )
    ).as_python()
    settlement = condition(redeem_conditions, 51)
    assert settlement[1] == bytes(OFFER_MOD_HASH)
    assert int.from_bytes(settlement[2], "big") == item.payment_principal
    assert condition(redeem_conditions, 63) is not None


def test_series_phase_rules_reject_early_live_refund() -> None:
    current = VoucherSeriesStateV2(
        sold_count=1,
        phase=VoucherSeriesState.LIVE,
        launched_at=220,
    )
    wrong = VoucherTransitionContextV2(
        SeriesTransition.REFUND,
        VoucherAction.REFUND_PRESALE,
        b32(60),
        b32(61),
        b32(62),
    )
    with pytest.raises(Exception, match="phase"):
        next_series_state(terms(), current, wrong)


@pytest.mark.parametrize(
    ("current", "context"),
    (
        (
            VoucherSeriesStateV2(),
            VoucherTransitionContextV2(
                SeriesTransition.SALE,
                VoucherAction.NONE,
                b32(70),
                b32(71),
                b32(72),
                voucher_launcher_id=b32(68),
                voucher_full_puzzle_hash=b32(67),
                purchase_launcher_coin_id=b32(69),
            ),
        ),
        (
            VoucherSeriesStateV2(),
            VoucherTransitionContextV2(
                SeriesTransition.CANCEL,
                VoucherAction.NONE,
                bytes32.zeros,
                bytes32.zeros,
                bytes32.zeros,
            ),
        ),
        (
            VoucherSeriesStateV2(sold_count=1),
            VoucherTransitionContextV2(
                SeriesTransition.REFUND,
                VoucherAction.REFUND_PRESALE,
                b32(73),
                b32(74),
                b32(75),
            ),
        ),
        (
            VoucherSeriesStateV2(
                sold_count=1, phase=VoucherSeriesState.CANCELED
            ),
            VoucherTransitionContextV2(
                SeriesTransition.REFUND,
                VoucherAction.REFUND_CANCELED,
                b32(76),
                b32(77),
                b32(78),
            ),
        ),
        (
            VoucherSeriesStateV2(
                sold_count=1,
                phase=VoucherSeriesState.LIVE,
                launched_at=220,
            ),
            VoucherTransitionContextV2(
                SeriesTransition.REFUND,
                VoucherAction.REFUND_EXPIRED,
                b32(79),
                b32(80),
                b32(81),
            ),
        ),
        (
            VoucherSeriesStateV2(
                sold_count=1,
                phase=VoucherSeriesState.LIVE,
                launched_at=220,
            ),
            VoucherTransitionContextV2(
                SeriesTransition.REDEEM,
                VoucherAction.REDEEM,
                b32(82),
                b32(83),
                b32(84),
            ),
        ),
    ),
)
def test_every_series_transition_executes_and_recurries_exactly(
    current: VoucherSeriesStateV2,
    context: VoucherTransitionContextV2,
) -> None:
    inner = curry_series(terms(), current)
    full = puzzle_for_singleton(terms().series_singleton_id, inner)
    coin = Coin(b32(85), bytes32(full.get_tree_hash()), uint64(1))
    conditions = inner.run(
        series_solution(
            coin=coin,
            inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            context=context,
            signer_indices=(0, 2),
        )
    ).as_python()

    expected = curry_series(terms(), next_series_state(terms(), current, context))
    assert condition(conditions, 51)[1] == bytes(expected.get_tree_hash())
    assert condition(conditions, 60)[1] == bytes(
        transition_message(
            terms=terms(), state=current, series_coin_id=coin.name(), context=context
        )
    )
    assert sum(
        1 for item in conditions if int.from_bytes(item[0], "big") == 50
    ) == 2


@pytest.mark.parametrize(
    ("action", "deadline"),
    (
        (VoucherAction.REFUND_PRESALE, 0),
        (VoucherAction.REFUND_CANCELED, 0),
        (VoucherAction.REFUND_EXPIRED, 220 + DELIVERY_WINDOW_SECONDS),
        (VoucherAction.REDEEM, 220 + DELIVERY_WINDOW_SECONDS),
    ),
)
def test_every_voucher_terminal_action_is_burn_only(
    action: VoucherAction, deadline: int
) -> None:
    item, _artifact = voucher()
    inner = curry_voucher_inner(
        terms=terms(), voucher=item, voucher_launcher_id=b32(86)
    )
    automatic = action in {
        VoucherAction.REFUND_EXPIRED,
        VoucherAction.REDEEM,
    }
    conditions = inner.run(
        voucher_solution(
            action=action,
            delivery_deadline=deadline,
            series_coin_id=b32(87),
            escrow_coin_id=b32(88),
            vault_inner_puzzle_hash=(bytes32.zeros if automatic else b32(89)),
            vault_coin_id=(bytes32.zeros if automatic else b32(90)),
            voucher_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            signer_indices=(0, 1),
        )
    ).as_python()
    create = condition(conditions, 51)
    assert create[1] == bytes(burn_inner_hash())
    assert int.from_bytes(create[2], "big") == 1


@pytest.mark.parametrize(
    "action",
    (VoucherAction.REFUND_EXPIRED, VoucherAction.REDEEM),
)
def test_automatic_voucher_terminal_actions_reject_a_second_vault_spend(
    action: VoucherAction,
) -> None:
    item, _artifact = voucher()
    inner = curry_voucher_inner(
        terms=terms(), voucher=item, voucher_launcher_id=b32(86)
    )
    with pytest.raises(Exception):
        inner.run(
            voucher_solution(
                action=action,
                delivery_deadline=220 + DELIVERY_WINDOW_SECONDS,
                series_coin_id=b32(87),
                escrow_coin_id=b32(88),
                vault_inner_puzzle_hash=b32(89),
                vault_coin_id=b32(90),
                voucher_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
                signer_indices=(0, 1),
            )
        )


@pytest.mark.parametrize(
    "action",
    (VoucherAction.REFUND_PRESALE, VoucherAction.REFUND_CANCELED),
)
def test_owner_refund_actions_reject_missing_vault_authorization(
    action: VoucherAction,
) -> None:
    item, _artifact = voucher()
    inner = curry_voucher_inner(
        terms=terms(), voucher=item, voucher_launcher_id=b32(86)
    )
    with pytest.raises(Exception):
        inner.run(
            voucher_solution(
                action=action,
                delivery_deadline=0,
                series_coin_id=b32(87),
                escrow_coin_id=b32(88),
                vault_inner_puzzle_hash=bytes32.zeros,
                vault_coin_id=bytes32.zeros,
                voucher_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
                signer_indices=(0, 1),
            )
        )


@pytest.mark.parametrize(
    ("action", "deadline", "expected_puzzle_hash"),
    (
        (VoucherAction.REFUND_PRESALE, 0, b32(11)),
        (VoucherAction.REFUND_CANCELED, 0, b32(11)),
        (
            VoucherAction.REFUND_EXPIRED,
            220 + DELIVERY_WINDOW_SECONDS,
            b32(11),
        ),
        (
            VoucherAction.REDEEM,
            220 + DELIVERY_WINDOW_SECONDS,
            bytes32(OFFER_MOD_HASH),
        ),
    ),
)
def test_every_xch_escrow_terminal_action_has_one_immutable_destination(
    action: VoucherAction,
    deadline: int,
    expected_puzzle_hash: bytes32,
) -> None:
    item, artifact = voucher()
    puzzle = curry_xch_escrow(terms=terms(), voucher=item, purchase=artifact)
    coin = Coin(b32(91), bytes32(puzzle.get_tree_hash()), uint64(item.payment_principal))
    conditions = puzzle.run(
        escrow_solution(
            escrow_coin=coin,
            action=action,
            delivery_deadline=deadline,
            series_coin_id=b32(92),
            voucher_coin_id=b32(93),
            signer_indices=(1, 2),
        )
    ).as_python()
    create = condition(conditions, 51)
    assert create[1] == bytes(expected_puzzle_hash)
    assert int.from_bytes(create[2], "big") == item.payment_principal


def test_quorum_indices_reject_single_duplicate_unsorted_and_out_of_range() -> None:
    item, _artifact = voucher()
    for bad in ((0,), (0, 0), (2, 1), (0, 3)):
        with pytest.raises(Exception, match="signer indices"):
            voucher_solution(
                action=VoucherAction.REFUND_PRESALE,
                delivery_deadline=0,
                series_coin_id=b32(94),
                escrow_coin_id=item.global_payment_id,
                vault_inner_puzzle_hash=b32(95),
                vault_coin_id=b32(96),
                voucher_inner_puzzle_hash=b32(97),
                signer_indices=bad,
            )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("series_terms_hash", b32(101)),
        ("series_singleton_id", b32(102)),
        ("collection_id", b32(103)),
        ("metadata_root", b32(104)),
        ("allocation_root", b32(105)),
        ("serial", 1),
        ("base_price_minor", 200),
        ("payment_principal", 999),
        ("original_payer", b32(106)),
        ("approved_vault_launcher_id", b32(107)),
        ("refund_deadline", 301),
        ("trusted_protocol_treasury", b32(108)),
        ("deed_launcher_id", b32(109)),
        ("smart_deed_inner_hash", b32(110)),
        ("purchase_artifact_hash", b32(112)),
        ("global_payment_id", b32(111)),
    ),
)
def test_every_valid_immutable_voucher_mutation_changes_commitment(
    field: str, value: object
) -> None:
    item, _artifact = voucher()
    updates = {field: value}
    if field == "base_price_minor":
        updates.update(
            technology_fee_minor=5,
            gross_price_minor=205,
        )
    if field == "approved_vault_launcher_id":
        updates["approved_vault_p2_puzzle_hash"] = puzzle_hash_for_p2_vault(value)
    changed = replace(item, **updates)
    assert changed.commitment_hash != item.commitment_hash


def test_xch_purchase_launcher_atomically_pairs_series_voucher_and_escrow() -> None:
    item, artifact = voucher()
    payment = curry_xch_escrow(terms=terms(), voucher=item, purchase=artifact)
    launcher = curry_purchase_launcher(
        terms=terms(),
        voucher=item,
        payment_puzzle_hash=bytes32(payment.get_tree_hash()),
        payment_amount=item.payment_principal,
    )
    launcher_coin = Coin(
        b32(125),
        bytes32(launcher.get_tree_hash()),
        uint64(item.payment_principal + 1),
    )
    voucher_launcher_id, payment_coin_id = issuance_coin_ids(
        launcher_coin,
        payment_puzzle_hash=bytes32(payment.get_tree_hash()),
        payment_amount=item.payment_principal,
    )
    voucher_inner = curry_voucher_inner(
        terms=terms(), voucher=item, voucher_launcher_id=voucher_launcher_id
    )
    voucher_full_puzzle_hash = bytes32(
        puzzle_for_singleton(voucher_launcher_id, voucher_inner).get_tree_hash()
    )
    state = VoucherSeriesStateV2()
    series_inner = curry_series(terms(), state)
    series_full = puzzle_for_singleton(terms().series_singleton_id, series_inner)
    series_coin = Coin(b32(126), bytes32(series_full.get_tree_hash()), uint64(1))
    context = VoucherTransitionContextV2(
        SeriesTransition.SALE,
        VoucherAction.NONE,
        item.commitment_hash,
        item.global_payment_id,
        payment_coin_id,
        voucher_launcher_id=voucher_launcher_id,
        voucher_full_puzzle_hash=voucher_full_puzzle_hash,
        purchase_launcher_coin_id=launcher_coin.name(),
    )

    series_conditions = series_inner.run(
        series_solution(
            coin=series_coin,
            inner_puzzle_hash=bytes32(series_inner.get_tree_hash()),
            context=context,
            signer_indices=(0, 1),
        )
    ).as_python()
    launcher_conditions = launcher.run(
        purchase_launcher_solution(
            purchase_launcher_coin=launcher_coin,
            series_coin_id=series_coin.name(),
            voucher_full_puzzle_hash=voucher_full_puzzle_hash,
        )
    ).as_python()
    message = transition_message(
        terms=terms(), state=state, series_coin_id=series_coin.name(), context=context
    )
    assert condition(series_conditions, 60)[1] == bytes(message)
    assert condition(launcher_conditions, 60)[1] == bytes(message)
    assert condition(series_conditions, 61)[1] == bytes(
        bytes32(hashlib.sha256(bytes(launcher_coin.name()) + bytes(message)).digest())
    )
    outputs = [
        row for row in launcher_conditions if int.from_bytes(row[0], "big") == 51
    ]
    assert len(outputs) == 2
    assert {Coin(launcher_coin.name(), bytes32(row[1]), uint64(int.from_bytes(row[2], "big"))).name() for row in outputs} == {
        voucher_launcher_id,
        payment_coin_id,
    }


def test_xch_voucher_offer_is_one_signature_and_rejects_changed_outputs() -> None:
    item, artifact = voucher()
    state = VoucherSeriesStateV2()
    series_inner = curry_series(terms(), state)
    series_coin = Coin(
        terms().series_singleton_id,
        bytes32(
            puzzle_for_singleton(terms().series_singleton_id, series_inner).get_tree_hash()
        ),
        uint64(1),
    )
    payment_sk = AugSchemeMPL.key_gen(bytes([9]) * 32)
    payment_puzzle = puzzle_for_pk(payment_sk.get_g1())
    payment_coin = Coin(
        b32(150),
        bytes32(payment_puzzle.get_tree_hash()),
        uint64(item.payment_principal + 10),
    )
    prepared = prepare_xch_voucher_offer(
        terms=terms(),
        state=state,
        series_coin=series_coin,
        voucher=item,
        purchase=artifact,
        payment_coin=payment_coin,
        payment_public_key=bytes(payment_sk.get_g1()),
    )
    round_trip = Offer.from_bech32(prepared.offer.to_bech32())
    assert validate_xch_voucher_offer(
        buyer_offer=round_trip,
        terms=terms(),
        state=state,
        series_coin=series_coin,
        voucher=item,
        purchase=artifact,
    ) == prepared.purchase_launcher_coin
    assert len(round_trip.coin_spends()) == 1
    assert round_trip.requested_payments == {}

    changed_solution = solution_for_conditions(
        [
            Program.to(
                [
                    51,
                    prepared.purchase_launcher_coin.puzzle_hash,
                    int(prepared.purchase_launcher_coin.amount) - 1,
                    [
                        terms().terms_hash,
                        item.commitment_hash,
                        item.global_payment_id,
                    ],
                ]
            ).as_python(),
            Program.to(
                [
                    51,
                    payment_coin.puzzle_hash,
                    int(payment_coin.amount)
                    - int(prepared.purchase_launcher_coin.amount)
                    + 1,
                    [payment_coin.puzzle_hash],
                ]
            ).as_python(),
        ]
    )
    changed = Offer(
        {},
        WalletSpendBundle(
            [
                make_spend(
                    payment_coin,
                    payment_puzzle,
                    changed_solution,
                )
            ],
            G2Element(),
        ),
        {},
    )
    with pytest.raises(Exception, match="changes payment|atomically bound"):
        validate_xch_voucher_offer(
            buyer_offer=changed,
            terms=terms(),
            state=state,
            series_coin=series_coin,
            voucher=item,
            purchase=artifact,
        )


def test_issuance_builder_derives_every_spend_and_successor_coin() -> None:
    item, artifact = voucher()
    payment = curry_xch_escrow(terms=terms(), voucher=item, purchase=artifact)
    launcher = curry_purchase_launcher(
        terms=terms(),
        voucher=item,
        payment_puzzle_hash=bytes32(payment.get_tree_hash()),
        payment_amount=item.payment_principal,
    )
    launcher_coin = Coin(
        b32(140),
        bytes32(launcher.get_tree_hash()),
        uint64(item.payment_principal + 1),
    )
    current_state = VoucherSeriesStateV2()
    current_inner = curry_series(terms(), current_state)
    current_full = puzzle_for_singleton(terms().series_singleton_id, current_inner)
    series_coin = Coin(
        terms().series_singleton_id,
        bytes32(current_full.get_tree_hash()),
        uint64(1),
    )
    result = build_voucher_issuance_spends(
        terms=terms(),
        state=current_state,
        series_coin=series_coin,
        series_lineage_proof=LineageProof(b32(139), None, uint64(1)),
        voucher=item,
        purchase_launcher_coin=launcher_coin,
        payment_puzzle=payment,
        payment_amount=item.payment_principal,
        signer_indices=(0, 2),
    )

    assert len(result.coin_spends) == 3
    assert result.voucher_launcher_id == Coin(
        launcher_coin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)
    ).name()
    assert result.voucher_coin.parent_coin_info == result.voucher_launcher_id
    assert result.payment_coin.parent_coin_info == launcher_coin.name()
    assert int(result.payment_coin.amount) == item.payment_principal
    assert result.next_series_coin.parent_coin_info == series_coin.name()
    assert result.next_series_state.sold_count == 1
    assert result.validator_message == transition_message(
        terms=terms(),
        state=current_state,
        series_coin_id=series_coin.name(),
        context=result.transition_context,
    )


def _issued_xch_voucher():
    item, artifact = voucher()
    payment = curry_xch_escrow(terms=terms(), voucher=item, purchase=artifact)
    launcher = curry_purchase_launcher(
        terms=terms(),
        voucher=item,
        payment_puzzle_hash=bytes32(payment.get_tree_hash()),
        payment_amount=item.payment_principal,
    )
    launcher_coin = Coin(
        b32(141),
        bytes32(launcher.get_tree_hash()),
        uint64(item.payment_principal + 1),
    )
    state = VoucherSeriesStateV2()
    inner = curry_series(terms(), state)
    series_coin = Coin(
        terms().series_singleton_id,
        bytes32(
            puzzle_for_singleton(
                terms().series_singleton_id,
                inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    issuance = build_voucher_issuance_spends(
        terms=terms(),
        state=state,
        series_coin=series_coin,
        series_lineage_proof=LineageProof(b32(142), None, uint64(1)),
        voucher=item,
        purchase_launcher_coin=launcher_coin,
        payment_puzzle=payment,
        payment_amount=item.payment_principal,
        signer_indices=(0, 1),
    )
    return item, artifact, issuance


def test_xch_refund_builder_burns_voucher_and_returns_exact_principal() -> None:
    item, artifact, issuance = _issued_xch_voucher()
    result = build_xch_voucher_terminal_spends(
        terms=terms(),
        state=issuance.next_series_state,
        series_coin=issuance.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
        voucher=item,
        purchase=artifact,
        voucher_launcher_id=issuance.voucher_launcher_id,
        voucher_coin=issuance.voucher_coin,
        voucher_lineage_proof=lineage_proof_for_coinsol(
            issuance.voucher_launcher_spend
        ),
        payment_coin=issuance.payment_coin,
        vault_coin_id=b32(143),
        vault_inner_puzzle_hash=b32(144),
        action=VoucherAction.REFUND_PRESALE,
        signer_indices=(0, 2),
    )

    assert len(result.coin_spends) == 3
    assert result.next_series_state.sold_count == 1
    assert result.next_series_state.refunded_count == 1
    assert result.settlement_coin.parent_coin_info == issuance.payment_coin.name()
    assert result.settlement_coin.puzzle_hash == item.original_payer
    assert int(result.settlement_coin.amount) == item.payment_principal
    assert result.terminal_voucher_coin.parent_coin_info == issuance.voucher_coin.name()
    assert result.terminal_voucher_coin.puzzle_hash == puzzle_for_singleton(
        issuance.voucher_launcher_id,
        load_puzzle("voucher_burn_v2.clsp"),
    ).get_tree_hash()
    assert result.validator_message == transition_message(
        terms=terms(),
        state=issuance.next_series_state,
        series_coin_id=issuance.next_series_coin.name(),
        context=result.transition_context,
    )


def test_xch_refund_builder_rejects_a_changed_escrow_coin() -> None:
    item, artifact, issuance = _issued_xch_voucher()
    changed = Coin(
        issuance.payment_coin.parent_coin_info,
        issuance.payment_coin.puzzle_hash,
        uint64(item.payment_principal - 1),
    )

    with pytest.raises(Exception, match="escrow coin"):
        build_xch_voucher_terminal_spends(
            terms=terms(),
            state=issuance.next_series_state,
            series_coin=issuance.next_series_coin,
            series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
            voucher=item,
            purchase=artifact,
            voucher_launcher_id=issuance.voucher_launcher_id,
            voucher_coin=issuance.voucher_coin,
            voucher_lineage_proof=LineageProof(
                issuance.voucher_launcher_id,
                None,
                uint64(1),
            ),
            payment_coin=changed,
            vault_coin_id=b32(143),
            vault_inner_puzzle_hash=b32(144),
            action=VoucherAction.REFUND_PRESALE,
            signer_indices=(0, 2),
        )


def test_live_xch_voucher_redeems_expired_quote_into_exact_governed_deed() -> None:
    item, artifact, issuance = _issued_xch_voucher()
    phase = build_voucher_series_phase_spend(
        terms=terms(),
        state=issuance.next_series_state,
        series_coin=issuance.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
        transition=SeriesTransition.LAUNCH,
        launch_anchor=220,
        signer_indices=(0, 1),
    )
    assert artifact.quote_expires_at < phase.next_series_state.launched_at

    terminal = build_xch_voucher_terminal_spends(
        terms=terms(),
        state=phase.next_series_state,
        series_coin=phase.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(phase.series_spend),
        voucher=item,
        purchase=artifact,
        voucher_launcher_id=issuance.voucher_launcher_id,
        voucher_coin=issuance.voucher_coin,
        voucher_lineage_proof=lineage_proof_for_coinsol(
            issuance.voucher_launcher_spend
        ),
        payment_coin=issuance.payment_coin,
        vault_coin_id=bytes32.zeros,
        vault_inner_puzzle_hash=bytes32.zeros,
        action=VoucherAction.REDEEM,
        signer_indices=(0, 1),
    )
    mint_terms = PrimaryMintTermsV2(
        network=artifact.network,
        smart_deed_inner_hash=item.smart_deed_inner_hash,
        deed_launcher_id=artifact.deed_launcher_id,
        collection_id=artifact.collection_id,
        metadata_root=artifact.metadata_root,
        metadata_anchor_id=artifact.metadata_anchor_id,
        share_ppm=artifact.share_ppm,
        usd_amount_minor=artifact.usd_amount_minor,
        protocol_puzhash=terms().trusted_protocol_treasury,
        validator_pubkeys=terms().validator_pubkeys,
        provider_id=b32(150),
    )
    buyer_offer = prepare_xch_voucher_redemption_offer(
        terminal_coin_spends=terminal.coin_spends,
        payment_coin=issuance.payment_coin,
        artifact=artifact,
        terms=mint_terms,
    )
    inner = make_mint_offer_v3_inner(mint_terms)
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    deed_coin = Coin(
        b32(151),
        bytes32(SINGLETON_MOD.curry(singleton_struct, inner).get_tree_hash()),
        uint64(1),
    )
    purchase_offer = build_chia_primary_offer(
        buyer_offer=buyer_offer,
        deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            b32(152),
            bytes32(inner.get_tree_hash()),
            uint64(1),
        ),
        artifact=artifact,
        signer_indices=(0, 1),
        terms=mint_terms,
        purchase_mode=PrimaryPurchaseMode.VOUCHER,
        voucher_coin_id=issuance.voucher_coin.name(),
        voucher_transition_message=terminal.validator_message,
    )

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
        addition.puzzle_hash == terms().trusted_protocol_treasury
        and int(addition.amount) == artifact.rail_amount
        for addition in additions
    ) == 1
    assert sum(
        addition.puzzle_hash == delivered_deed_puzzle_hash
        and int(addition.amount) == 1
        for addition in additions
    ) == 1
    assert terminal.settlement_coin.puzzle_hash == OFFER_MOD_HASH
    assert int(terminal.settlement_coin.amount) == item.payment_principal

    buyer_nonce = next(iter(buyer_offer.requested_payments.values()))[0].nonce
    voucher_conditions = inner.run(
        chia_offer_v3_solution(
            deed_coin=deed_coin,
            artifact=artifact,
            buyer_offer_nonce=bytes32(buyer_nonce),
            signer_indices=(0, 1),
            terms=mint_terms,
            purchase_mode=PrimaryPurchaseMode.VOUCHER,
            voucher_coin_id=issuance.voucher_coin.name(),
            voucher_transition_message=terminal.validator_message,
        )
    ).as_python()
    voucher_opcodes = {int.from_bytes(row[0], "big") for row in voucher_conditions}
    assert 61 in voucher_opcodes  # ASSERT_COIN_ANNOUNCEMENT
    assert 85 not in voucher_opcodes  # no stale quote deadline
    assert hashlib.sha256(
        bytes(issuance.voucher_coin.name()) + bytes(terminal.validator_message)
    ).digest() in {row[1] for row in voucher_conditions if row[0] == bytes([61])}

    direct_conditions = inner.run(
        chia_offer_v3_solution(
            deed_coin=deed_coin,
            artifact=artifact,
            buyer_offer_nonce=bytes32(buyer_nonce),
            signer_indices=(0, 1),
            terms=mint_terms,
        )
    ).as_python()
    assert 85 in {int.from_bytes(row[0], "big") for row in direct_conditions}


def test_base_receipt_binds_external_escrow_and_burns_without_moving_chia_value() -> None:
    item, _artifact = base_voucher()
    receipt = curry_external_receipt(terms=terms(), voucher=item)
    coin = Coin(b32(127), bytes32(receipt.get_tree_hash()), uint64(1))
    evidence_hash = b32(130)
    conditions = receipt.run(
        external_receipt_solution(
            receipt_coin=coin,
            action=VoucherAction.REFUND_PRESALE,
            delivery_deadline=0,
            series_coin_id=b32(128),
            voucher_coin_id=b32(129),
            external_settlement_evidence_hash=evidence_hash,
            signer_indices=(0, 2),
        )
    ).as_python()
    assert not any(int.from_bytes(row[0], "big") == 51 for row in conditions)
    signatures = [
        row for row in conditions if int.from_bytes(row[0], "big") == 50
    ]
    assert len(signatures) == 2
    assert {row[2] for row in signatures} == {
        bytes(
            external_receipt_evidence_message(
                voucher=item,
                action=VoucherAction.REFUND_PRESALE,
                external_settlement_evidence_hash=evidence_hash,
            )
        )
    }
    remark = condition(conditions, 1)
    assert bytes(item.global_payment_id) in remark
    assert bytes(item.original_payer) in remark


def test_base_receipt_redeem_exposes_only_its_offer_mojo_and_announcement() -> None:
    item, _artifact = base_voucher()
    receipt = curry_external_receipt(terms=terms(), voucher=item)
    coin = Coin(b32(131), bytes32(receipt.get_tree_hash()), uint64(1))
    evidence_hash = b32(132)
    series_coin_id = b32(133)
    voucher_coin_id = b32(134)
    transition = VoucherTransitionContextV2(
        transition=SeriesTransition.REDEEM,
        action=VoucherAction.REDEEM,
        voucher_commitment_hash=item.commitment_hash,
        global_payment_id=item.global_payment_id,
        escrow_coin_id=coin.name(),
    )
    voucher_message = transition_message(
        terms=terms(),
        state=VoucherSeriesStateV2(
            sold_count=1,
            phase=VoucherSeriesState.LIVE,
            launched_at=220,
        ),
        series_coin_id=series_coin_id,
        context=transition,
    )
    conditions = receipt.run(
        external_receipt_solution(
            receipt_coin=coin,
            action=VoucherAction.REDEEM,
            delivery_deadline=220 + DELIVERY_WINDOW_SECONDS,
            series_coin_id=series_coin_id,
            voucher_coin_id=voucher_coin_id,
            external_settlement_evidence_hash=evidence_hash,
            signer_indices=(0, 2),
        )
    ).as_python()
    creates = [
        row for row in conditions if int.from_bytes(row[0], "big") == 51
    ]
    assert creates == [
        [
            bytes([51]),
            bytes(OFFER_MOD_HASH),
            bytes([1]),
            [
                bytes(item.purchase_artifact_hash),
                bytes(item.deed_launcher_id),
                bytes(item.approved_vault_p2_puzzle_hash),
            ],
        ]
    ]
    assert condition(conditions, 60)[1] == bytes(
        external_receipt_settlement_message(
            voucher=item,
            action=VoucherAction.REDEEM,
            external_settlement_evidence_hash=evidence_hash,
            voucher_transition_message=voucher_message,
        )
    )


def test_base_terminal_builder_binds_receipt_and_automatic_delivery() -> None:
    item, artifact = base_voucher()
    state = VoucherSeriesStateV2(
        sold_count=1,
        phase=VoucherSeriesState.LIVE,
        launched_at=220,
    )
    series_inner = curry_series(terms(), state)
    series_coin = Coin(
        b32(135),
        bytes32(
            puzzle_for_singleton(
                terms().series_singleton_id,
                series_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    voucher_launcher_id = b32(136)
    voucher_inner = curry_voucher_inner(
        terms=terms(),
        voucher=item,
        voucher_launcher_id=voucher_launcher_id,
    )
    voucher_coin = Coin(
        b32(137),
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
        b32(138),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(1),
    )
    terminal = build_base_voucher_terminal_spends(
        terms=terms(),
        state=state,
        series_coin=series_coin,
        series_lineage_proof=LineageProof(b32(139), b32(140), uint64(1)),
        voucher=item,
        purchase=artifact,
        voucher_launcher_id=voucher_launcher_id,
        voucher_coin=voucher_coin,
        voucher_lineage_proof=LineageProof(b32(141), b32(142), uint64(1)),
        receipt_coin=receipt_coin,
        vault_coin_id=bytes32.zeros,
        vault_inner_puzzle_hash=bytes32.zeros,
        action=VoucherAction.REDEEM,
        external_settlement_evidence_hash=b32(143),
        signer_indices=(0, 2),
    )

    assert len(terminal.coin_spends) == 3
    assert terminal.next_series_state.redeemed_count == 1
    assert terminal.offer_coin == Coin(
        receipt_coin.name(),
        bytes32(OFFER_MOD_HASH),
        uint64(1),
    )
    assert compute_additions(terminal.receipt_spend) == [terminal.offer_coin]
    assert terminal.receipt_settlement_message == (
        external_receipt_settlement_message(
            voucher=item,
            action=VoucherAction.REDEEM,
            external_settlement_evidence_hash=b32(143),
            voucher_transition_message=terminal.validator_message,
        )
    )
    assert terminal.terminal_voucher_coin.puzzle_hash == bytes32(
        puzzle_for_singleton(
            voucher_launcher_id,
            terminal.result_authorization_inner_puzzle,
        ).get_tree_hash()
    )
    result_conditions = terminal.result_authorization_inner_puzzle.run(
        Program.to([[]])
    ).as_python()
    result_message = bytes(base_result_message(voucher=item, succeeded=True))
    assert [bytes([51]), bytes(burn_inner_hash()), bytes([1])] in result_conditions
    assert [bytes([60]), result_message] in result_conditions
    assert [
        bytes([63]),
        hashlib.sha256(
            bytes(terms().base_return_puzzle_hash) + result_message
        ).digest(),
    ] in result_conditions


def test_live_base_voucher_atomically_delivers_exact_governed_deed() -> None:
    item, artifact = base_voucher()
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
    mint_terms = PrimaryMintTermsV2(
        network=artifact.network,
        smart_deed_inner_hash=item.smart_deed_inner_hash,
        deed_launcher_id=artifact.deed_launcher_id,
        collection_id=artifact.collection_id,
        metadata_root=artifact.metadata_root,
        metadata_anchor_id=artifact.metadata_anchor_id,
        share_ppm=artifact.share_ppm,
        usd_amount_minor=artifact.usd_amount_minor,
        protocol_puzhash=terms().trusted_protocol_treasury,
        validator_pubkeys=terms().validator_pubkeys,
        provider_id=b32(166),
    )
    buyer_offer = prepare_base_voucher_redemption_offer(
        terminal_coin_spends=terminal.coin_spends,
        receipt_coin=receipt_coin,
        artifact=artifact,
        terms=mint_terms,
    )
    inner = make_mint_offer_v4_inner(mint_terms)
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    deed_coin = Coin(
        b32(167),
        bytes32(
            SINGLETON_MOD.curry(singleton_struct, inner).get_tree_hash()
        ),
        uint64(1),
    )
    purchase_offer = build_universal_primary_offer_v4(
        buyer_offer=buyer_offer,
        deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            b32(168),
            bytes32(inner.get_tree_hash()),
            uint64(1),
        ),
        artifact=artifact,
        signer_indices=(0, 1),
        terms=mint_terms,
        purchase_mode=PrimaryPurchaseMode.VOUCHER,
        voucher_coin_id=voucher_coin.name(),
        voucher_transition_message=terminal.validator_message,
        external_receipt_coin=receipt_coin,
        external_settlement_evidence_hash=(
            terminal.external_settlement_evidence_hash
        ),
    )

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

    buyer_nonce = next(iter(buyer_offer.requested_payments.values()))[0].nonce
    conditions = inner.run(
        universal_offer_v4_solution(
            deed_coin=deed_coin,
            artifact=artifact,
            buyer_offer_nonce=bytes32(buyer_nonce),
            signer_indices=(0, 1),
            terms=mint_terms,
            purchase_mode=PrimaryPurchaseMode.VOUCHER,
            voucher_coin_id=voucher_coin.name(),
            voucher_transition_message=terminal.validator_message,
            external_receipt_coin_id=receipt_coin.name(),
            external_settlement_evidence_hash=(
                terminal.external_settlement_evidence_hash
            ),
        )
    ).as_python()
    announcement_ids = {
        row[1]
        for row in conditions
        if int.from_bytes(row[0], "big") == 61
    }
    assert {
        row[2]
        for row in conditions
        if int.from_bytes(row[0], "big") == 50
    } == {bytes(artifact.artifact_hash)}
    assert hashlib.sha256(
        bytes(voucher_coin.name()) + bytes(terminal.validator_message)
    ).digest() in announcement_ids
    receipt_conditions = conditions_dict_for_solution(
        terminal.receipt_spend.puzzle_reveal,
        terminal.receipt_spend.solution,
        INFINITE_COST,
    )
    receipt_message = bytes(
        receipt_conditions[ConditionOpcode.CREATE_COIN_ANNOUNCEMENT][0].vars[0]
    )
    assert receipt_message == bytes(terminal.receipt_settlement_message)
    binding_remark = next(
        row
        for row in conditions
        if int.from_bytes(row[0], "big") == 1
        and b"BASE_RECEIPT_BINDING_V2" in row
    )
    assert binding_remark[3:-1] == [
        bytes(artifact.artifact_hash),
        bytes(artifact.deed_launcher_id),
        bytes(artifact.vault_p2_puzzle_hash),
        bytes(terminal.external_settlement_evidence_hash),
        bytes(terminal.validator_message),
    ]
    assert binding_remark[-1] == receipt_message
    assert hashlib.sha256(
        bytes(receipt_coin.name())
        + receipt_message
    ).digest() in announcement_ids
    assert 85 not in {
        int.from_bytes(row[0], "big") for row in conditions
    }


def test_base_terminal_rejects_noncanonical_usdc() -> None:
    item, artifact = base_voucher()
    changed = replace(item, payment_asset_id=b32(144))
    with pytest.raises(Exception, match="official"):
        build_base_voucher_terminal_spends(
            terms=terms(),
            state=VoucherSeriesStateV2(
                sold_count=1,
                phase=VoucherSeriesState.LIVE,
                launched_at=220,
            ),
            series_coin=Coin(b32(145), b32(146), uint64(1)),
            series_lineage_proof=LineageProof(b32(147), b32(148), uint64(1)),
            voucher=changed,
            purchase=artifact,
            voucher_launcher_id=b32(149),
            voucher_coin=Coin(b32(150), b32(151), uint64(1)),
            voucher_lineage_proof=LineageProof(b32(152), b32(153), uint64(1)),
            receipt_coin=Coin(b32(154), b32(155), uint64(1)),
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REDEEM,
            external_settlement_evidence_hash=b32(156),
            signer_indices=(0, 2),
        )


def test_purchase_launcher_rejects_any_amount_other_than_exact_outputs() -> None:
    item, artifact = voucher()
    payment = curry_xch_escrow(terms=terms(), voucher=item, purchase=artifact)
    launcher = curry_purchase_launcher(
        terms=terms(),
        voucher=item,
        payment_puzzle_hash=bytes32(payment.get_tree_hash()),
        payment_amount=item.payment_principal,
    )
    wrong_coin = Coin(
        b32(131), bytes32(launcher.get_tree_hash()), uint64(item.payment_principal + 2)
    )
    with pytest.raises((EvalError, ValueError)):
        launcher.run(
            purchase_launcher_solution(
                purchase_launcher_coin=wrong_coin,
                series_coin_id=b32(132),
                voucher_full_puzzle_hash=b32(133),
            )
        )
