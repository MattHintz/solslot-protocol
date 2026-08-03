"""Atomic RC22 SmartDeed/Sols offer construction.

This module only orchestrates existing reviewed puzzles. The wallet offers the
exact quoted Sols CAT amount and requests one pool-custodied SmartDeed. The
protocol half proves the statutes snapshot, zkPassport vault authorization,
pool transition, and custody release before the two standard Chia Offers can
balance.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.conditions import (
    AssertAnnouncement,
    AssertPuzzleAnnouncement,
    CreateCoin,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk,
    solution_for_conditions,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
    deed_to_sols_inner_solution,
    make_pool_v4_full,
    make_pool_v4_inner,
    sols_to_deed_inner_solution,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    chia_cat_driver,
)
from solslot_puzzles.protocol_statutes_driver import (
    build_sols_evidence_spend,
    make_inner_puzzle as make_statutes_inner,
    protocol_statutes_inner_mod_hash,
)
from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    ProtocolParameters,
    ScopedPause,
    StatutesState,
)
from solslot_puzzles.sols_pool_v4 import (
    DEED_TO_SOLS,
    SOLS_TO_DEED,
    SWAP_OPERATION_TAG,
    SwapReceipt,
)
from solslot_puzzles.vault_driver import (
    puzzle_for_p2_vault,
    puzzle_hash_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import (
    build_vault_sols_swap_spend,
    puzzle_for_vault_v2_full,
    vault_v2_inner_mod_hash,
)
from solslot_puzzles.vault_sols_v1 import (
    puzzle_for_vault_sols_cat,
    puzzle_for_vault_sols_inner,
    vault_sols_inner_solution_for_swap,
)


class SolsSwapOfferError(ValueError):
    """Raised when a Sols swap offer does not match the governed operation."""


@dataclass(frozen=True)
class PreparedSolsBuyerOffer:
    offer: Offer
    coin_spend: CoinSpend
    payment_puzzle: Program


@dataclass(frozen=True)
class SolsToDeedProtocolOffer:
    offer: Offer
    statutes_spend: CoinSpend
    vault_spend: CoinSpend
    pool_spend: CoinSpend
    custody_spend: CoinSpend


@dataclass(frozen=True)
class AtomicSolsToDeedSwap:
    buyer_offer: Offer
    protocol_offer: Offer
    aggregate_offer: Offer


@dataclass(frozen=True)
class DeedToSolsProtocolOffer:
    offer: Offer
    statutes_spend: CoinSpend
    vault_spend: CoinSpend
    p2_vault_spend: CoinSpend
    smart_deed_spend: CoinSpend
    pool_spend: CoinSpend
    reserve_cat_spend: CoinSpend
    reserve_signing_conditions: Program


def _complete_lineage(lineage: LineageProof, label: str) -> None:
    if (
        lineage.parent_name is None
        or lineage.inner_puzzle_hash is None
        or lineage.amount is None
    ):
        raise SolsSwapOfferError(f"{label} requires a complete lineage proof")


def _quote(receipt: SwapReceipt):
    if receipt.direction != SOLS_TO_DEED:
        raise SolsSwapOfferError("receipt is not a Sols-to-deed operation")
    quote = receipt.sols_to_deed_quote
    if quote is None:
        raise SolsSwapOfferError("receipt is not a Sols-to-deed quote")
    return quote


def _reverse_quote(receipt: SwapReceipt):
    if receipt.direction != DEED_TO_SOLS:
        raise SolsSwapOfferError("receipt is not a deed-to-Sols operation")
    quote = receipt.deed_to_sols_quote
    if quote is None:
        raise SolsSwapOfferError("receipt is not a deed-to-Sols quote")
    return quote


def _deed_singleton_struct(
    config: PoolV4Config,
    deed_launcher_id: bytes32,
) -> Program:
    return Program.to(
        (
            SINGLETON_MOD_HASH,
            (deed_launcher_id, config.deed_launcher_puzzle_hash),
        )
    )


def _deed_full_puzzle(
    config: PoolV4Config,
    deed_launcher_id: bytes32,
    inner_puzzle: Program,
) -> Program:
    return SINGLETON_MOD.curry(
        _deed_singleton_struct(config, deed_launcher_id),
        inner_puzzle,
    )


def _validate_smart_deed_inner(
    *,
    smart_deed_inner: Program,
    receipt: SwapReceipt,
    config: PoolV4Config,
    par_value: int,
    asset_class: int,
    property_id: bytes32,
) -> None:
    uncurried = smart_deed_inner.uncurry()
    if uncurried is None:
        raise SolsSwapOfferError("SmartDeed inner puzzle is not curried")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != bytes32(
        load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
    ):
        raise SolsSwapOfferError("SmartDeed uses an unexpected inner module")
    values = list(args.as_iter())
    if len(values) != 15:
        raise SolsSwapOfferError("SmartDeed inner puzzle has unexpected terms")
    expected_struct = _deed_singleton_struct(
        config,
        receipt.record.deed_launcher_id,
    )
    expected = {
        "singleton": bytes32(expected_struct.get_tree_hash()),
        "par value": par_value,
        "asset class": asset_class,
        "property": property_id,
        "collection": receipt.record.collection_id,
        "share": receipt.record.share_ppm,
        "singleton module": SINGLETON_MOD_HASH,
        "pool launcher": config.pool_launcher_id,
        "pool launcher puzzle": SINGLETON_LAUNCHER_HASH,
        "p2 pool": config.p2_pool_v2_mod_hash,
        "p2 vault": config.p2_vault_mod_hash,
    }
    actual = {
        "singleton": bytes32(values[0].get_tree_hash()),
        "par value": values[2].as_int(),
        "asset class": values[3].as_int(),
        "property": bytes32(values[4].as_atom()),
        "collection": bytes32(values[5].as_atom()),
        "share": values[6].as_int(),
        "singleton module": bytes32(values[10].as_atom()),
        "pool launcher": bytes32(values[11].as_atom()),
        "pool launcher puzzle": bytes32(values[12].as_atom()),
        "p2 pool": bytes32(values[13].as_atom()),
        "p2 vault": bytes32(values[14].as_atom()),
    }
    mismatched = [
        label for label, value in expected.items() if actual[label] != value
    ]
    if mismatched:
        raise SolsSwapOfferError(
            "SmartDeed terms do not match the quote: "
            + ", ".join(mismatched)
        )
    commitment = bytes32(
        Program.to(
            [
                receipt.record.deed_launcher_id,
                par_value,
                asset_class,
                property_id,
                receipt.record.collection_id,
                receipt.record.share_ppm,
            ]
        ).get_tree_hash()
    )
    if commitment != receipt.record.deed_commitment:
        raise SolsSwapOfferError("SmartDeed commitment does not match the quote")


def _assert_driver_config(config: PoolV4Config) -> None:
    config.permanent_rules.validate()
    expected = {
        "CAT": bytes32(CAT_MOD.get_tree_hash()),
        "offer": OFFER_MOD_HASH,
        "p2_vault": bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
        "vault": vault_v2_inner_mod_hash(),
        "p2_pool": bytes32(load_puzzle("p2_pool_v2.clsp").get_tree_hash()),
        "statutes": protocol_statutes_inner_mod_hash(),
    }
    actual = {
        "CAT": config.cat_mod_hash,
        "offer": config.offer_mod_hash,
        "p2_vault": config.p2_vault_mod_hash,
        "vault": config.vault_v2_mod_hash,
        "p2_pool": config.p2_pool_v2_mod_hash,
        "statutes": config.statutes_inner_mod_hash,
    }
    mismatched = [name for name in expected if actual[name] != expected[name]]
    if mismatched:
        raise SolsSwapOfferError(
            "swap configuration uses unexpected modules: "
            + ", ".join(mismatched)
        )


def _assert_vault_binding(
    receipt: SwapReceipt,
    *,
    vault_launcher_id: bytes32,
    vault_coin_id: bytes32 | None = None,
) -> bytes32:
    destination = puzzle_hash_for_p2_vault(vault_launcher_id)
    if (
        receipt.vault_launcher_id != vault_launcher_id
        or receipt.counterparty_puzzle_hash != destination
    ):
        raise SolsSwapOfferError("quote is bound to a different vault")
    if vault_coin_id is not None and receipt.vault_coin_id != vault_coin_id:
        raise SolsSwapOfferError("quote is bound to a different vault coin")
    return destination


def pool_operation_announcement(operation_hash: bytes32) -> bytes:
    return b"\x53" + bytes(
        Program.to([SWAP_OPERATION_TAG, operation_hash]).get_tree_hash()
    )


def _sols_payments(
    *,
    receipt: SwapReceipt,
    config: PoolV4Config,
) -> dict:
    quote = _quote(receipt)
    payments = [
        CreateCoin(
            config.reserve_puzzle_hash,
            uint64(quote.principal_sols_mojos),
            [config.reserve_puzzle_hash],
        )
    ]
    if quote.fee_split.protocol_fee_sols_mojos:
        payments.append(
            CreateCoin(
                config.permanent_rules.protocol_treasury_puzzle_hash,
                uint64(quote.fee_split.protocol_fee_sols_mojos),
                [config.permanent_rules.protocol_treasury_puzzle_hash],
            )
        )
    if quote.fee_split.sgt_rewards_fee_sols_mojos:
        payments.append(
            CreateCoin(
                config.sgt_rewards_puzzle_hash,
                uint64(quote.fee_split.sgt_rewards_fee_sols_mojos),
                [config.sgt_rewards_puzzle_hash],
            )
        )
    return {config.permanent_rules.sols_tail_hash: payments}


def prepare_sols_buyer_offer(
    *,
    payment_coin: Coin,
    payment_public_key: bytes,
    payment_lineage_proof: LineageProof,
    receipt: SwapReceipt,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
) -> PreparedSolsBuyerOffer:
    """Create the exact unsigned Sols CAT half that a Chia wallet signs."""
    _assert_driver_config(config)
    quote = _quote(receipt)
    if len(payment_public_key) != 48:
        raise SolsSwapOfferError("payment_public_key must be 48 bytes")
    try:
        public_key = G1Element.from_bytes(payment_public_key)
    except ValueError as exc:
        raise SolsSwapOfferError("payment_public_key is not valid BLS") from exc
    _complete_lineage(payment_lineage_proof, "Sols payment coin")
    if int(payment_coin.amount) < quote.buyer_total_sols_mojos:
        raise SolsSwapOfferError("Sols payment coin is smaller than the quote")

    _assert_vault_binding(
        receipt,
        vault_launcher_id=vault_launcher_id,
    )
    payment_puzzle = puzzle_for_pk(public_key)
    expected_cat = construct_cat_puzzle(
        CAT_MOD,
        config.permanent_rules.sols_tail_hash,
        payment_puzzle,
    )
    if payment_coin.puzzle_hash != expected_cat.get_tree_hash():
        raise SolsSwapOfferError(
            "Sols payment coin does not belong to the selected BLS key"
        )

    drivers = {
        config.permanent_rules.sols_tail_hash: chia_cat_driver(
            config.permanent_rules.sols_tail_hash
        ),
    }
    pool_puzzle_hash = bytes32(
        make_pool_v4_full(config, receipt.current_state).get_tree_hash()
    )
    conditions = [
        CreateCoin(
            OFFER_MOD_HASH,
            uint64(quote.buyer_total_sols_mojos),
            [OFFER_MOD_HASH],
        ).to_program(),
        AssertPuzzleAnnouncement(
            asserted_ph=pool_puzzle_hash,
            asserted_msg=pool_operation_announcement(
                receipt.operation_hash
            ),
        ).to_program(),
    ]
    change = int(payment_coin.amount) - quote.buyer_total_sols_mojos
    if change:
        payment_inner_hash = bytes32(payment_puzzle.get_tree_hash())
        conditions.append(
            CreateCoin(
                payment_inner_hash,
                uint64(change),
                [payment_inner_hash],
            ).to_program()
        )
    inner_solution = solution_for_conditions(
        [condition.as_python() for condition in conditions]
    )
    bundle = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [
            SpendableCAT(
                payment_coin,
                config.permanent_rules.sols_tail_hash,
                payment_puzzle,
                inner_solution,
                lineage_proof=payment_lineage_proof,
            )
        ],
    )
    offer = Offer({}, bundle, drivers)
    validate_sols_buyer_offer(
        buyer_offer=offer,
        receipt=receipt,
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    return PreparedSolsBuyerOffer(
        offer=offer,
        coin_spend=bundle.coin_spends[0],
        payment_puzzle=payment_puzzle,
    )


def prepare_vault_sols_buyer_offer(
    *,
    payment_coin: Coin,
    payment_lineage_proof: LineageProof,
    receipt: SwapReceipt,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
) -> PreparedSolsBuyerOffer:
    """Create an unsigned Sols offer controlled by the vault singleton.

    No independent BLS payment key exists. Pool V4 commits to the complete
    economic operation and emits its one-time announcement only after the
    registered vault owner authorizes it. This custody puzzle separately binds
    the selected input coin, exact payment, expiry, and same-vault change.
    """
    _assert_driver_config(config)
    quote = _quote(receipt)
    _complete_lineage(payment_lineage_proof, "vault Sols payment coin")
    if int(payment_coin.amount) < quote.buyer_total_sols_mojos:
        raise SolsSwapOfferError("Sols payment coin is smaller than the quote")
    if receipt.sols_payment_coin_id != payment_coin.name():
        raise SolsSwapOfferError(
            "Sols payment coin does not match the governed operation"
        )
    _assert_vault_binding(
        receipt,
        vault_launcher_id=vault_launcher_id,
    )
    payment_puzzle = puzzle_for_vault_sols_inner(
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    expected_cat = puzzle_for_vault_sols_cat(
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    if payment_coin.puzzle_hash != expected_cat.get_tree_hash():
        raise SolsSwapOfferError(
            "Sols payment coin is not controlled by this vault"
        )
    inner_solution = vault_sols_inner_solution_for_swap(
        payment_coin=payment_coin,
        payment_amount=quote.buyer_total_sols_mojos,
        operation_hash=receipt.operation_hash,
        quote_expires_at=receipt.quote_expires_at,
        pool_state=receipt.current_state,
        pool_inventory=receipt.inventory,
    )
    bundle = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [
            SpendableCAT(
                payment_coin,
                config.permanent_rules.sols_tail_hash,
                payment_puzzle,
                inner_solution,
                lineage_proof=payment_lineage_proof,
            )
        ],
    )
    offer = Offer(
        {},
        bundle,
        {
            config.permanent_rules.sols_tail_hash: chia_cat_driver(
                config.permanent_rules.sols_tail_hash
            )
        },
    )
    validate_sols_buyer_offer(
        buyer_offer=offer,
        receipt=receipt,
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    return PreparedSolsBuyerOffer(
        offer=offer,
        coin_spend=bundle.coin_spends[0],
        payment_puzzle=payment_puzzle,
    )


def validate_sols_buyer_offer(
    *,
    buyer_offer: Offer,
    receipt: SwapReceipt,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
) -> None:
    """Reject any wallet offer that changes the deed, vault, or Sols total."""
    _assert_driver_config(config)
    quote = _quote(receipt)
    _assert_vault_binding(
        receipt,
        vault_launcher_id=vault_launcher_id,
    )
    if buyer_offer.requested_payments:
        raise SolsSwapOfferError(
            "buyer offer cannot add settlement outputs"
        )
    offered = buyer_offer.get_offered_amounts()
    sols_tail = config.permanent_rules.sols_tail_hash
    if set(offered) != {sols_tail}:
        raise SolsSwapOfferError("buyer must offer only Sols")
    if int(offered[sols_tail]) != quote.buyer_total_sols_mojos:
        raise SolsSwapOfferError("buyer Sols amount does not match the quote")
    expected_sols = chia_cat_driver(sols_tail)
    actual_sols = buyer_offer.driver_dict.get(sols_tail)
    if actual_sols is None or actual_sols.info != expected_sols.info:
        raise SolsSwapOfferError("buyer uses an unexpected Sols CAT driver")
    if receipt.sols_payment_coin_id == bytes32.zeros:
        raise SolsSwapOfferError("buyer operation is missing its Sols input coin")
    coin_spends = tuple(buyer_offer.coin_spends())
    if len(coin_spends) != 1:
        raise SolsSwapOfferError("buyer offer must spend one Sols coin")
    selected = coin_spends[0].coin
    if selected.name() != receipt.sols_payment_coin_id:
        raise SolsSwapOfferError("buyer offer spends a different Sols coin")
    expected_cat = puzzle_for_vault_sols_cat(
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    if selected.puzzle_hash != expected_cat.get_tree_hash():
        raise SolsSwapOfferError("buyer Sols coin is not vault controlled")
    expected_pool_announcement = AssertPuzzleAnnouncement(
        asserted_ph=bytes32(
            make_pool_v4_full(
                config,
                receipt.current_state,
            ).get_tree_hash()
        ),
        asserted_msg=pool_operation_announcement(receipt.operation_hash),
    )
    assertions = [
        condition
        for conditions in buyer_offer.conditions().values()
        for condition in conditions
        if isinstance(condition, AssertAnnouncement)
        and not condition.coin_not_puzzle
    ]
    if not any(
        assertion.msg_calc == expected_pool_announcement.msg_calc
        for assertion in assertions
    ):
        raise SolsSwapOfferError(
            "buyer signature is not bound to the quoted pool operation"
        )
    unexpected_drivers = set(buyer_offer.driver_dict) - {
        sols_tail,
    }
    if unexpected_drivers:
        raise SolsSwapOfferError(
            "buyer offer contains unexpected asset drivers"
        )
def build_sols_to_deed_protocol_offer(
    *,
    receipt: SwapReceipt,
    config: PoolV4Config,
    parameters: ProtocolParameters,
    collection: CollectionStatute,
    pause: ScopedPause | None,
    statutes_state: StatutesState,
    statutes_coin: Coin,
    statutes_launcher_id: bytes32,
    statutes_lineage_proof: LineageProof,
    collections: Sequence[CollectionStatute],
    pauses: Sequence[ScopedPause],
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    vault_lineage_proof: LineageProof,
    vault_owner_pubkey: bytes,
    vault_auth_type: int,
    vault_members_merkle_root: bytes32,
    identity_attest_root: bytes32,
    zkpassport_bridge_policy_hash: bytes32,
    vault_signature_data: bytes | None,
    pool_coin: Coin,
    pool_lineage_proof: LineageProof,
    custody_coin: Coin,
    custody_lineage_proof: LineageProof,
    quote_expires_at: int,
) -> SolsToDeedProtocolOffer:
    """Build the protocol half from live singleton coins and reviewed state."""
    _assert_driver_config(config)
    quote = _quote(receipt)
    for lineage, label in (
        (statutes_lineage_proof, "statutes singleton"),
        (vault_lineage_proof, "vault singleton"),
        (pool_lineage_proof, "pool singleton"),
        (custody_lineage_proof, "SmartDeed custody singleton"),
    ):
        _complete_lineage(lineage, label)
    if pool_coin.name() != receipt.pool_coin_id:
        raise SolsSwapOfferError("pool coin does not match the quoted operation")
    if quote_expires_at != receipt.quote_expires_at:
        raise SolsSwapOfferError("quote expiry does not match the operation")
    if collection.collection_id != receipt.record.collection_id:
        raise SolsSwapOfferError("collection does not match the quoted deed")

    destination = _assert_vault_binding(
        receipt,
        vault_launcher_id=vault_launcher_id,
        vault_coin_id=vault_coin.name(),
    )
    statutes_inner = make_statutes_inner(
        singleton_struct=config.statutes_singleton_struct,
        governance_singleton_struct=config.governance_singleton_struct,
        permanent_rules=config.permanent_rules,
        state=statutes_state,
    )
    statutes_full = puzzle_for_singleton(
        statutes_launcher_id,
        statutes_inner,
    )
    if statutes_coin.puzzle_hash != statutes_full.get_tree_hash():
        raise SolsSwapOfferError(
            "statutes coin does not match the governed statutes state"
        )
    evidence = build_sols_evidence_spend(
        my_id=statutes_coin.name(),
        my_inner_puzzle_hash=bytes32(statutes_inner.get_tree_hash()),
        my_amount=int(statutes_coin.amount),
        consumer_coin_id=pool_coin.name(),
        collection_id=collection.collection_id,
        parameters=parameters,
        collections=collections,
        pauses=pauses,
        state=statutes_state,
    )
    statutes_spend = make_spend(
        statutes_coin,
        statutes_full,
        solution_for_singleton(
            statutes_lineage_proof,
            uint64(statutes_coin.amount),
            evidence.inner_solution,
        ),
    )

    vault_spend = build_vault_sols_swap_spend(
        vault_coin=vault_coin,
        vault_launcher_id=vault_launcher_id,
        owner_pubkey=vault_owner_pubkey,
        auth_type=vault_auth_type,
        members_merkle_root=vault_members_merkle_root,
        pool_launcher_id=config.pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
        operation_hash=receipt.operation_hash,
        quote_expires_at=quote_expires_at,
        lineage_proof=vault_lineage_proof,
        signature_data=vault_signature_data,
    )

    pool_inner = make_pool_v4_inner(config, receipt.current_state)
    pool_full = make_pool_v4_full(config, receipt.current_state)
    if pool_coin.puzzle_hash != pool_full.get_tree_hash():
        raise SolsSwapOfferError("pool coin does not match the quoted state")
    pool_inner_solution = sols_to_deed_inner_solution(
        pool_coin_id=pool_coin.name(),
        pool_inner_puzzle_hash=bytes32(pool_inner.get_tree_hash()),
        pool_amount=int(pool_coin.amount),
        receipt=receipt,
        parameters=parameters,
        collection=collection,
        pause=pause,
        statutes_state=statutes_state,
        vault_launcher_id=vault_launcher_id,
        vault_coin_id=vault_coin.name(),
        owner_pubkey=vault_owner_pubkey,
        auth_type=vault_auth_type,
        members_root=vault_members_merkle_root,
        identity_root=identity_attest_root,
        bridge_policy=zkpassport_bridge_policy_hash,
        quote_expires_at=quote_expires_at,
        destination_p2_vault_hash=destination,
    )
    pool_spend = make_spend(
        pool_coin,
        pool_full,
        solution_for_singleton(
            pool_lineage_proof,
            uint64(pool_coin.amount),
            pool_inner_solution,
        ),
    )

    custody_inner = load_puzzle("p2_pool_v2.clsp").curry(
        config.p2_pool_v2_mod_hash,
        SINGLETON_MOD_HASH,
        config.pool_launcher_id,
        SINGLETON_LAUNCHER_HASH,
        receipt.record.deed_commitment,
    )
    deed_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (
                receipt.record.deed_launcher_id,
                config.deed_launcher_puzzle_hash,
            ),
        )
    )
    custody_full = SINGLETON_MOD.curry(
        deed_struct,
        custody_inner,
    )
    if (
        custody_coin.name() != receipt.record.custody_coin_id
        or custody_coin.puzzle_hash != custody_full.get_tree_hash()
        or int(custody_coin.amount) != 1
    ):
        raise SolsSwapOfferError(
            "custody coin does not match the quoted SmartDeed"
        )
    custody_inner_solution = Program.to(
        [
            bytes32(pool_inner.get_tree_hash()),
            pool_coin.name(),
            custody_coin.name(),
            receipt.record.deed_launcher_id,
            int(custody_coin.amount),
            destination,
        ]
    )
    custody_spend = make_spend(
        custody_coin,
        custody_full,
        solution_for_singleton(
            custody_lineage_proof,
            uint64(custody_coin.amount),
            custody_inner_solution,
        ),
    )

    requested = _sols_payments(receipt=receipt, config=config)
    drivers = {
        config.permanent_rules.sols_tail_hash: chia_cat_driver(
            config.permanent_rules.sols_tail_hash
        ),
    }
    notarized = Offer.notarize_payments(requested, [pool_coin])
    offer = Offer(
        notarized,
        WalletSpendBundle(
            [
                statutes_spend,
                vault_spend,
                pool_spend,
                custody_spend,
            ],
            G2Element(),
        ),
        drivers,
    )
    if sum(int(item.amount) for item in requested[
        config.permanent_rules.sols_tail_hash
    ]) != quote.buyer_total_sols_mojos:
        raise SolsSwapOfferError("protocol payment split does not balance")
    return SolsToDeedProtocolOffer(
        offer=offer,
        statutes_spend=statutes_spend,
        vault_spend=vault_spend,
        pool_spend=pool_spend,
        custody_spend=custody_spend,
    )


def build_deed_to_sols_protocol_offer(
    *,
    receipt: SwapReceipt,
    config: PoolV4Config,
    parameters: ProtocolParameters,
    collection: CollectionStatute,
    pause: ScopedPause | None,
    statutes_state: StatutesState,
    statutes_coin: Coin,
    statutes_launcher_id: bytes32,
    statutes_lineage_proof: LineageProof,
    collections: Sequence[CollectionStatute],
    pauses: Sequence[ScopedPause],
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    vault_lineage_proof: LineageProof,
    vault_owner_pubkey: bytes,
    vault_auth_type: int,
    vault_members_merkle_root: bytes32,
    identity_attest_root: bytes32,
    zkpassport_bridge_policy_hash: bytes32,
    vault_signature_data: bytes | None,
    pool_coin: Coin,
    pool_lineage_proof: LineageProof,
    p2_vault_deed_coin: Coin,
    p2_vault_deed_lineage_proof: LineageProof,
    smart_deed_inner: Program,
    par_value: int,
    asset_class: int,
    property_id: bytes32,
    reserve_cat_coin: Coin,
    reserve_cat_lineage_proof: LineageProof,
    reserve_inner_puzzle: Program,
    quote_expires_at: int,
) -> DeedToSolsProtocolOffer:
    """Build one self-balancing protocol Offer for a deed deposit and Sols payout."""
    _assert_driver_config(config)
    quote = _reverse_quote(receipt)
    for lineage, label in (
        (statutes_lineage_proof, "statutes singleton"),
        (vault_lineage_proof, "vault singleton"),
        (pool_lineage_proof, "pool singleton"),
        (p2_vault_deed_lineage_proof, "SmartDeed vault singleton"),
    ):
        _complete_lineage(lineage, label)
    if pool_coin.name() != receipt.pool_coin_id:
        raise SolsSwapOfferError("pool coin does not match the quoted operation")
    if quote_expires_at != receipt.quote_expires_at:
        raise SolsSwapOfferError("quote expiry does not match the operation")
    if collection.collection_id != receipt.record.collection_id:
        raise SolsSwapOfferError("collection does not match the quoted deed")
    if int(reserve_cat_coin.amount) != (
        receipt.current_state.economics.reserve_sols_mojos
    ):
        raise SolsSwapOfferError(
            "Sols reserve must be one consolidated CAT coin"
        )

    seller_puzzle_hash = receipt.counterparty_puzzle_hash
    if (
        receipt.vault_launcher_id != vault_launcher_id
        or receipt.vault_coin_id != vault_coin.name()
    ):
        raise SolsSwapOfferError("quote is bound to a different vault")
    _validate_smart_deed_inner(
        smart_deed_inner=smart_deed_inner,
        receipt=receipt,
        config=config,
        par_value=par_value,
        asset_class=asset_class,
        property_id=property_id,
    )

    statutes_inner = make_statutes_inner(
        singleton_struct=config.statutes_singleton_struct,
        governance_singleton_struct=config.governance_singleton_struct,
        permanent_rules=config.permanent_rules,
        state=statutes_state,
    )
    statutes_full = puzzle_for_singleton(
        statutes_launcher_id,
        statutes_inner,
    )
    if statutes_coin.puzzle_hash != statutes_full.get_tree_hash():
        raise SolsSwapOfferError(
            "statutes coin does not match the governed statutes state"
        )
    evidence = build_sols_evidence_spend(
        my_id=statutes_coin.name(),
        my_inner_puzzle_hash=bytes32(statutes_inner.get_tree_hash()),
        my_amount=int(statutes_coin.amount),
        consumer_coin_id=pool_coin.name(),
        collection_id=collection.collection_id,
        parameters=parameters,
        collections=collections,
        pauses=pauses,
        state=statutes_state,
    )
    statutes_spend = make_spend(
        statutes_coin,
        statutes_full,
        solution_for_singleton(
            statutes_lineage_proof,
            uint64(statutes_coin.amount),
            evidence.inner_solution,
        ),
    )

    p2_vault_inner = puzzle_for_p2_vault(vault_launcher_id)
    p2_vault_full = _deed_full_puzzle(
        config,
        receipt.record.deed_launcher_id,
        p2_vault_inner,
    )
    if (
        p2_vault_deed_coin.puzzle_hash != p2_vault_full.get_tree_hash()
        or int(p2_vault_deed_coin.amount) != 1
    ):
        raise SolsSwapOfferError(
            "SmartDeed is not held by the approved vault"
        )
    smart_deed_hash = bytes32(smart_deed_inner.get_tree_hash())
    vault_inner = puzzle_for_vault_v2_full(
        vault_launcher_id=vault_launcher_id,
        owner_pubkey=vault_owner_pubkey,
        auth_type=vault_auth_type,
        members_merkle_root=vault_members_merkle_root,
        pool_launcher_id=config.pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    ).uncurry()
    if vault_inner is None:
        raise SolsSwapOfferError("vault puzzle cannot be reconstructed")
    _, vault_args = vault_inner
    vault_inner_puzzle = list(vault_args.as_iter())[1]
    p2_vault_solution = Program.to(
        [
            bytes32(vault_inner_puzzle.get_tree_hash()),
            vault_coin.name(),
            receipt.record.deed_launcher_id,
            bytes32(p2_vault_inner.get_tree_hash()),
            int(p2_vault_deed_coin.amount),
            smart_deed_hash,
        ]
    )
    p2_vault_spend = make_spend(
        p2_vault_deed_coin,
        p2_vault_full,
        solution_for_singleton(
            p2_vault_deed_lineage_proof,
            uint64(p2_vault_deed_coin.amount),
            p2_vault_solution,
        ),
    )
    ephemeral_deed_coin = Coin(
        p2_vault_deed_coin.name(),
        bytes32(
            _deed_full_puzzle(
                config,
                receipt.record.deed_launcher_id,
                smart_deed_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    if ephemeral_deed_coin.name() != receipt.record.custody_coin_id:
        # The receipt stores the next custody coin, not the ephemeral deed.
        expected_custody = Coin(
            ephemeral_deed_coin.name(),
            bytes32(
                _deed_full_puzzle(
                    config,
                    receipt.record.deed_launcher_id,
                    load_puzzle("p2_pool_v2.clsp").curry(
                        config.p2_pool_v2_mod_hash,
                        SINGLETON_MOD_HASH,
                        config.pool_launcher_id,
                        SINGLETON_LAUNCHER_HASH,
                        receipt.record.deed_commitment,
                    ),
                ).get_tree_hash()
            ),
            uint64(1),
        ).name()
        if expected_custody != receipt.record.custody_coin_id:
            raise SolsSwapOfferError(
                "quoted custody coin is not the deterministic SmartDeed output"
            )

    pool_inner = make_pool_v4_inner(config, receipt.current_state)
    pool_full = make_pool_v4_full(config, receipt.current_state)
    if pool_coin.puzzle_hash != pool_full.get_tree_hash():
        raise SolsSwapOfferError("pool coin does not match the quoted state")
    smart_deed_solution = Program.to(
        [
            ephemeral_deed_coin.name(),
            smart_deed_hash,
            int(ephemeral_deed_coin.amount),
            0x64,
            [bytes32(pool_inner.get_tree_hash())],
        ]
    )
    smart_deed_spend = make_spend(
        ephemeral_deed_coin,
        _deed_full_puzzle(
            config,
            receipt.record.deed_launcher_id,
            smart_deed_inner,
        ),
        solution_for_singleton(
            LineageProof(
                parent_name=p2_vault_deed_coin.parent_coin_info,
                inner_puzzle_hash=bytes32(p2_vault_inner.get_tree_hash()),
                amount=p2_vault_deed_coin.amount,
            ),
            uint64(ephemeral_deed_coin.amount),
            smart_deed_solution,
        ),
    )

    vault_spend = build_vault_sols_swap_spend(
        vault_coin=vault_coin,
        vault_launcher_id=vault_launcher_id,
        owner_pubkey=vault_owner_pubkey,
        auth_type=vault_auth_type,
        members_merkle_root=vault_members_merkle_root,
        pool_launcher_id=config.pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
        operation_hash=receipt.operation_hash,
        quote_expires_at=quote_expires_at,
        lineage_proof=vault_lineage_proof,
        signature_data=vault_signature_data,
        deed_launcher_id=receipt.record.deed_launcher_id,
        p2_vault_coin_id=p2_vault_deed_coin.name(),
        smart_deed_inner_puzzle_hash=smart_deed_hash,
    )

    mint_token_coin_id = (
        reserve_cat_coin.name()
        if quote.fresh_sols_mojos_minted
        else None
    )
    pool_inner_solution = deed_to_sols_inner_solution(
        config=config,
        pool_coin_id=pool_coin.name(),
        pool_inner_puzzle_hash=bytes32(pool_inner.get_tree_hash()),
        pool_amount=int(pool_coin.amount),
        receipt=receipt,
        parameters=parameters,
        collection=collection,
        pause=pause,
        statutes_state=statutes_state,
        deed_parent_coin_id=ephemeral_deed_coin.name(),
        par_value=par_value,
        asset_class=asset_class,
        property_id=property_id,
        seller_sols_puzzle_hash=seller_puzzle_hash,
        mint_token_coin_id=mint_token_coin_id,
        vault_launcher_id=vault_launcher_id,
        vault_coin_id=vault_coin.name(),
        owner_pubkey=vault_owner_pubkey,
        auth_type=vault_auth_type,
        members_root=vault_members_merkle_root,
        identity_root=identity_attest_root,
        bridge_policy=zkpassport_bridge_policy_hash,
        quote_expires_at=quote_expires_at,
    )
    pool_spend = make_spend(
        pool_coin,
        pool_full,
        solution_for_singleton(
            pool_lineage_proof,
            uint64(pool_coin.amount),
            pool_inner_solution,
        ),
    )

    pool_token_tail = load_puzzle("pool_token_tail.clsp").curry(
        SINGLETON_MOD_HASH,
        config.pool_launcher_id,
        SINGLETON_LAUNCHER_HASH,
    )
    if bytes32(pool_token_tail.get_tree_hash()) != (
        config.permanent_rules.sols_tail_hash
    ):
        raise SolsSwapOfferError("Sols CAT tail does not match Pool V4")
    reserve_inner_hash = bytes32(reserve_inner_puzzle.get_tree_hash())
    if reserve_inner_hash != config.reserve_puzzle_hash:
        raise SolsSwapOfferError("reserve inner puzzle is not the trusted reserve")
    expected_reserve_cat = construct_cat_puzzle(
        CAT_MOD,
        config.permanent_rules.sols_tail_hash,
        reserve_inner_puzzle,
    )
    if reserve_cat_coin.puzzle_hash != expected_reserve_cat.get_tree_hash():
        raise SolsSwapOfferError("reserve coin is not a Sols CAT")
    reserve_change = (
        int(reserve_cat_coin.amount)
        + quote.fresh_sols_mojos_minted
        - quote.seller_sols_mojos
    )
    if reserve_change != receipt.next_state.economics.reserve_sols_mojos:
        raise SolsSwapOfferError("reserve CAT change does not match next state")
    tail_solution = Program.to(
        [
            bytes32(pool_full.get_tree_hash()),
            bytes32(pool_inner.get_tree_hash()),
            pool_coin.name(),
            reserve_cat_coin.name(),
            1,
            quote.fresh_sols_mojos_minted,
        ]
    )
    reserve_condition_list = [
        CreateCoin(
            OFFER_MOD_HASH,
            uint64(quote.seller_sols_mojos),
            [OFFER_MOD_HASH],
        ).to_program().as_python(),
        CreateCoin(
            reserve_inner_hash,
            uint64(reserve_change),
            [reserve_inner_hash],
        ).to_program().as_python(),
        AssertPuzzleAnnouncement(
            asserted_ph=bytes32(pool_full.get_tree_hash()),
            asserted_msg=pool_operation_announcement(
                receipt.operation_hash
            ),
        ).to_program().as_python(),
    ]
    if quote.fresh_sols_mojos_minted:
        reserve_condition_list.append(
            Program.to(
                [51, 0, -113, pool_token_tail, tail_solution]
            ).as_python()
        )
    reserve_conditions = Program.to(reserve_condition_list)
    reserve_inner_solution = solution_for_conditions(
        reserve_conditions.as_python()
    )
    spendable = SpendableCAT(
        reserve_cat_coin,
        config.permanent_rules.sols_tail_hash,
        reserve_inner_puzzle,
        reserve_inner_solution,
        limitations_solution=(
            tail_solution if quote.fresh_sols_mojos_minted else Program.to(0)
        ),
        lineage_proof=reserve_cat_lineage_proof,
        extra_delta=quote.fresh_sols_mojos_minted,
        limitations_program_reveal=(
            pool_token_tail if quote.fresh_sols_mojos_minted else Program.to(0)
        ),
    )
    reserve_bundle = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [spendable],
    )
    if len(reserve_bundle.coin_spends) != 1:
        raise SolsSwapOfferError("reserve CAT assembly produced extra spends")

    requested = {
        config.permanent_rules.sols_tail_hash: [
            CreateCoin(
                seller_puzzle_hash,
                uint64(quote.seller_sols_mojos),
                [seller_puzzle_hash],
            )
        ]
    }
    drivers = {
        config.permanent_rules.sols_tail_hash: chia_cat_driver(
            config.permanent_rules.sols_tail_hash
        ),
    }
    offer = Offer(
        Offer.notarize_payments(requested, [pool_coin]),
        WalletSpendBundle(
            [
                statutes_spend,
                vault_spend,
                p2_vault_spend,
                smart_deed_spend,
                pool_spend,
                *reserve_bundle.coin_spends,
            ],
            G2Element(),
        ),
        drivers,
    )
    if not offer.is_valid():
        raise SolsSwapOfferError(
            "deed-to-Sols protocol offer does not balance"
        )
    return DeedToSolsProtocolOffer(
        offer=offer,
        statutes_spend=statutes_spend,
        vault_spend=vault_spend,
        p2_vault_spend=p2_vault_spend,
        smart_deed_spend=smart_deed_spend,
        pool_spend=pool_spend,
        reserve_cat_spend=reserve_bundle.coin_spends[0],
        reserve_signing_conditions=reserve_conditions,
    )


def aggregate_sols_to_deed_swap(
    *,
    buyer_offer: Offer,
    protocol_offer: SolsToDeedProtocolOffer,
    receipt: SwapReceipt,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
) -> AtomicSolsToDeedSwap:
    validate_sols_buyer_offer(
        buyer_offer=buyer_offer,
        receipt=receipt,
        config=config,
        vault_launcher_id=vault_launcher_id,
    )
    aggregate = Offer.aggregate([buyer_offer, protocol_offer.offer])
    if not aggregate.is_valid():
        raise SolsSwapOfferError("buyer and protocol offers do not balance")
    return AtomicSolsToDeedSwap(
        buyer_offer=buyer_offer,
        protocol_offer=protocol_offer.offer,
        aggregate_offer=aggregate,
    )


__all__ = [
    "SolsSwapOfferError",
    "PreparedSolsBuyerOffer",
    "SolsToDeedProtocolOffer",
    "AtomicSolsToDeedSwap",
    "DeedToSolsProtocolOffer",
    "pool_operation_announcement",
    "prepare_sols_buyer_offer",
    "prepare_vault_sols_buyer_offer",
    "validate_sols_buyer_offer",
    "build_sols_to_deed_protocol_offer",
    "build_deed_to_sols_protocol_offer",
    "aggregate_sols_to_deed_swap",
]
