"""Drivers for governed SGT reserve allocations and native Chia sales."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.outer_puzzles import AssetType
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.vault_driver import P2_VAULT_MOD_HASH, puzzle_hash_for_p2_vault
from solslot_puzzles.sgt_driver import (
    BILL_SGT_GRANT,
    BILL_SGT_SALE,
    SGT_RELEASE_EXEC,
    SGT_TRANSFER,
    bill_sgt_grant,
    bill_sgt_sale,
    build_sgt_lock_coin_spend,
    proposal_hash_from_bill,
    sgt_free_inner_mod,
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
    sgt_locked_inner_puzzle,
)


class SGTAllocationRail(IntEnum):
    XCH = 1
    CAT = 2
    STRIPE = 3
    BASE_USDC = 4


class SGTReserveMode(IntEnum):
    LOCK = 1
    SALE = 2
    GRANT = 3


class SGTSaleMode(IntEnum):
    TAKE = 1
    RETURN = 2
    EXTERNAL_TAKE = 3


@dataclass(frozen=True)
class SGTSaleTermsV1:
    sale_id: bytes32
    proposal_hash: bytes32
    sgt_amount: int
    recipient_vault_launcher_id: bytes32
    payment_rail: SGTAllocationRail
    payment_asset_id: bytes32
    payment_amount: int
    company_treasury_puzzle_hash: bytes32
    expires_at: int
    reserve_owner_inner_puzzle_hash: bytes32
    purchase_artifact_hash: bytes32 = bytes32.zeros

    def __post_init__(self) -> None:
        bill = bill_sgt_sale(
            sale_id=self.sale_id,
            sgt_amount=self.sgt_amount,
            recipient_vault_launcher_id=self.recipient_vault_launcher_id,
            payment_rail=int(self.payment_rail),
            payment_asset_id=self.payment_asset_id,
            payment_amount=self.payment_amount,
            company_treasury_puzzle_hash=self.company_treasury_puzzle_hash,
            expires_at=self.expires_at,
            reserve_owner_inner_puzzle_hash=self.reserve_owner_inner_puzzle_hash,
            purchase_artifact_hash=self.purchase_artifact_hash,
        )
        if proposal_hash_from_bill(bill) != self.proposal_hash:
            raise ValueError("proposal_hash does not match the SGT sale bill")


def sgt_sale_terms_from_bill(
    bill: Program,
    *,
    reserve_owner_inner_hash: bytes32,
) -> SGTSaleTermsV1:
    """Parse and validate one complete governed SGT sale bill."""

    values = list(bill.as_iter())
    if len(values) != 11 or values[0].as_atom() != BILL_SGT_SALE:
        raise ValueError("bill is not an exact SGT sale")
    if bytes32(values[9].as_atom()) != reserve_owner_inner_hash:
        raise ValueError("SGT sale is not bound to the canonical reserve")
    return SGTSaleTermsV1(
        sale_id=bytes32(values[1].as_atom()),
        proposal_hash=proposal_hash_from_bill(bill),
        sgt_amount=values[2].as_int(),
        recipient_vault_launcher_id=bytes32(values[3].as_atom()),
        payment_rail=SGTAllocationRail(values[4].as_int()),
        payment_asset_id=bytes32(values[5].as_atom()),
        payment_amount=values[6].as_int(),
        company_treasury_puzzle_hash=bytes32(values[7].as_atom()),
        expires_at=values[8].as_int(),
        reserve_owner_inner_puzzle_hash=reserve_owner_inner_hash,
        purchase_artifact_hash=bytes32(values[10].as_atom()),
    )


def sgt_reserve_inner_mod() -> Program:
    return load_puzzle("sgt_reserve_inner_v1.clsp")


def sgt_sale_inner_mod() -> Program:
    return load_puzzle("sgt_sale_inner_v1.clsp")


def sgt_reserve_inner_puzzle(
    *,
    proposal_tracker_struct: Program,
    admin_authority_struct: Program,
    sgt_tail_hash: bytes32,
    wusdc_b_asset_id: bytes32,
    company_treasury_puzzle_hash: bytes32,
) -> Program:
    mod = sgt_reserve_inner_mod()
    return mod.curry(
        mod.get_tree_hash(),
        sgt_free_inner_mod().get_tree_hash(),
        sgt_locked_inner_mod().get_tree_hash(),
        proposal_tracker_struct,
        admin_authority_struct,
        sgt_sale_inner_mod().get_tree_hash(),
        CAT_MOD.get_tree_hash(),
        sgt_tail_hash,
        OFFER_MOD_HASH,
        P2_VAULT_MOD_HASH,
        SINGLETON_MOD_HASH,
        SINGLETON_LAUNCHER_HASH,
        wusdc_b_asset_id,
        company_treasury_puzzle_hash,
    )


def sgt_reserve_owner_inner_hash(**kwargs) -> bytes32:
    return bytes32(sgt_reserve_inner_puzzle(**kwargs).get_tree_hash())


def sgt_sale_inner_puzzle(
    *,
    reserve_owner_inner_hash: bytes32,
    sgt_tail_hash: bytes32,
    terms: SGTSaleTermsV1,
) -> Program:
    if reserve_owner_inner_hash != terms.reserve_owner_inner_puzzle_hash:
        raise ValueError("sale terms do not match the governed reserve owner")
    mod = sgt_sale_inner_mod()
    return mod.curry(
        mod.get_tree_hash(),
        reserve_owner_inner_hash,
        CAT_MOD.get_tree_hash(),
        sgt_tail_hash,
        OFFER_MOD_HASH,
        terms.sale_id,
        terms.proposal_hash,
        terms.sgt_amount,
        puzzle_hash_for_p2_vault(terms.recipient_vault_launcher_id),
        int(terms.payment_rail),
        terms.payment_asset_id,
        terms.payment_amount,
        terms.company_treasury_puzzle_hash,
        terms.expires_at,
        terms.purchase_artifact_hash,
    )


def sgt_sale_owner_inner_hash(**kwargs) -> bytes32:
    return bytes32(sgt_sale_inner_puzzle(**kwargs).get_tree_hash())


def sgt_cat_puzzle(
    *,
    proposal_tracker_struct: Program,
    sgt_tail_hash: bytes32,
    owner_inner_puzzle: Program,
) -> Program:
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        proposal_tracker_struct,
        bytes32(owner_inner_puzzle.get_tree_hash()),
    )
    return construct_cat_puzzle(CAT_MOD, sgt_tail_hash, free_inner)


def build_reserve_lock_coin_spend(
    *,
    reserve_coin: Coin,
    reserve_lineage_proof: LineageProof,
    proposal_tracker_struct: Program,
    admin_authority_struct: Program,
    sgt_tail_hash: bytes32,
    wusdc_b_asset_id: bytes32,
    company_treasury_puzzle_hash: bytes32,
    bill: Program,
    deadline: int,
    admin_authority_inner_puzzle_hash: bytes32,
) -> CoinSpend:
    """Lock the complete reserve coin as the first vote for one queued bill."""
    values = list(bill.as_iter())
    if not values or values[0].as_atom() not in (BILL_SGT_SALE, BILL_SGT_GRANT):
        raise ValueError("reserve can sponsor only SGT_SALE or SGT_GRANT")
    reserve_inner = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=proposal_tracker_struct,
        admin_authority_struct=admin_authority_struct,
        sgt_tail_hash=sgt_tail_hash,
        wusdc_b_asset_id=wusdc_b_asset_id,
        company_treasury_puzzle_hash=company_treasury_puzzle_hash,
    )
    proposal_hash = proposal_hash_from_bill(bill)
    reserve_solution = Program.to(
        [
            int(SGTReserveMode.LOCK),
            reserve_coin.amount,
            [
                proposal_hash,
                bill,
                deadline,
                admin_authority_inner_puzzle_hash,
            ],
        ]
    )
    return build_sgt_lock_coin_spend(
        sgt_coin=reserve_coin,
        voter_inner_puzzle=reserve_inner,
        voter_inner_solution=reserve_solution,
        proposal_tracker_struct=proposal_tracker_struct,
        sgt_tail_hash=sgt_tail_hash,
        lineage_proof=reserve_lineage_proof,
        proposal_hash=proposal_hash,
        deadline=deadline,
    )


def _one_cat_spend(spendable: SpendableCAT) -> CoinSpend:
    bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [spendable])
    if len(bundle.coin_spends) != 1:
        raise RuntimeError("expected exactly one CAT coin spend")
    return bundle.coin_spends[0]


def build_reserve_allocation_spend(
    *,
    reserve_coin: Coin,
    reserve_lineage_proof: LineageProof,
    proposal_tracker_struct: Program,
    admin_authority_struct: Program,
    sgt_tail_hash: bytes32,
    wusdc_b_asset_id: bytes32,
    company_treasury_puzzle_hash: bytes32,
    bill: Program,
    tracker_inner_puzzle_hash: bytes32,
) -> CoinSpend:
    """Split a free reserve coin after the exact tracker execution."""
    values = list(bill.as_iter())
    if not values:
        raise ValueError("bill cannot be empty")
    tag = values[0].as_atom()
    if tag == BILL_SGT_SALE:
        mode = SGTReserveMode.SALE
    elif tag == BILL_SGT_GRANT:
        mode = SGTReserveMode.GRANT
    else:
        raise ValueError("reserve allocation requires SGT_SALE or SGT_GRANT")
    reserve_inner = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=proposal_tracker_struct,
        admin_authority_struct=admin_authority_struct,
        sgt_tail_hash=sgt_tail_hash,
        wusdc_b_asset_id=wusdc_b_asset_id,
        company_treasury_puzzle_hash=company_treasury_puzzle_hash,
    )
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        proposal_tracker_struct,
        bytes32(reserve_inner.get_tree_hash()),
    )
    reserve_solution = Program.to(
        [int(mode), reserve_coin.amount, [bill, tracker_inner_puzzle_hash]]
    )
    free_solution = Program.to(
        [SGT_TRANSFER, reserve_inner, reserve_solution, []]
    )
    return _one_cat_spend(
        SpendableCAT(
            coin=reserve_coin,
            limitations_program_hash=sgt_tail_hash,
            inner_puzzle=free_inner,
            inner_solution=free_solution,
            lineage_proof=reserve_lineage_proof,
            extra_delta=0,
        )
    )


def build_reserve_execute_spends(
    *,
    locked_reserve_coin: Coin,
    locked_reserve_lineage_proof: LineageProof,
    proposal_tracker_struct: Program,
    admin_authority_struct: Program,
    sgt_tail_hash: bytes32,
    wusdc_b_asset_id: bytes32,
    company_treasury_puzzle_hash: bytes32,
    bill: Program,
    voting_deadline: int,
    tracker_inner_puzzle_hash: bytes32,
) -> tuple[CoinSpend, CoinSpend]:
    """Release and allocate the governed reserve in one CAT spend ring.

    The tracker EXEC announcement exists only in the transaction that executes
    the proposal. The reserve therefore cannot be released in one transaction
    and allocated in a later transaction. This helper spends the locked reserve
    and its ephemeral free child together; callers aggregate both spends with
    the matching tracker EXECUTE spend.
    """
    proposal_hash = proposal_hash_from_bill(bill)
    reserve_inner = sgt_reserve_inner_puzzle(
        proposal_tracker_struct=proposal_tracker_struct,
        admin_authority_struct=admin_authority_struct,
        sgt_tail_hash=sgt_tail_hash,
        wusdc_b_asset_id=wusdc_b_asset_id,
        company_treasury_puzzle_hash=company_treasury_puzzle_hash,
    )
    free_mod_hash = bytes32(sgt_free_inner_mod().get_tree_hash())
    locked_inner = sgt_locked_inner_puzzle(
        free_mod_hash,
        proposal_tracker_struct,
        bytes32(reserve_inner.get_tree_hash()),
        proposal_hash,
        voting_deadline,
    )
    expected_locked_puzzle = construct_cat_puzzle(
        CAT_MOD,
        sgt_tail_hash,
        locked_inner,
    )
    if locked_reserve_coin.puzzle_hash != expected_locked_puzzle.get_tree_hash():
        raise ValueError("locked reserve coin does not match the proposal bill")

    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        proposal_tracker_struct,
        bytes32(reserve_inner.get_tree_hash()),
    )
    free_full_puzzle = construct_cat_puzzle(CAT_MOD, sgt_tail_hash, free_inner)
    ephemeral_free_coin = Coin(
        locked_reserve_coin.name(),
        bytes32(free_full_puzzle.get_tree_hash()),
        uint64(locked_reserve_coin.amount),
    )
    ephemeral_lineage = LineageProof(
        locked_reserve_coin.parent_coin_info,
        bytes32(locked_inner.get_tree_hash()),
        uint64(locked_reserve_coin.amount),
    )

    values = list(bill.as_iter())
    if not values:
        raise ValueError("bill cannot be empty")
    tag = values[0].as_atom()
    if tag == BILL_SGT_SALE:
        mode = SGTReserveMode.SALE
    elif tag == BILL_SGT_GRANT:
        mode = SGTReserveMode.GRANT
    else:
        raise ValueError("reserve execution requires SGT_SALE or SGT_GRANT")

    bundle = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [
            SpendableCAT(
                coin=locked_reserve_coin,
                limitations_program_hash=sgt_tail_hash,
                inner_puzzle=locked_inner,
                inner_solution=Program.to(
                    [
                        SGT_RELEASE_EXEC,
                        tracker_inner_puzzle_hash,
                        locked_reserve_coin.amount,
                    ]
                ),
                lineage_proof=locked_reserve_lineage_proof,
                extra_delta=0,
            ),
            SpendableCAT(
                coin=ephemeral_free_coin,
                limitations_program_hash=sgt_tail_hash,
                inner_puzzle=free_inner,
                inner_solution=Program.to(
                    [
                        SGT_TRANSFER,
                        reserve_inner,
                        [
                            int(mode),
                            ephemeral_free_coin.amount,
                            [bill, tracker_inner_puzzle_hash],
                        ],
                        [],
                    ]
                ),
                lineage_proof=ephemeral_lineage,
                extra_delta=0,
            ),
        ],
    )
    if len(bundle.coin_spends) != 2:
        raise RuntimeError("reserve execution must produce exactly two CAT spends")
    by_coin_id = {bytes32(spend.coin.name()): spend for spend in bundle.coin_spends}
    return (
        by_coin_id[bytes32(locked_reserve_coin.name())],
        by_coin_id[bytes32(ephemeral_free_coin.name())],
    )


def _payment_driver(asset_id: bytes32) -> PuzzleInfo:
    return PuzzleInfo(
        {"type": AssetType.CAT.value, "tail": f"0x{asset_id.hex()}"}
    )


def prepare_sgt_sale_offer(
    *,
    sale_coin: Coin,
    sale_lineage_proof: LineageProof,
    proposal_tracker_struct: Program,
    reserve_owner_inner_hash: bytes32,
    sgt_tail_hash: bytes32,
    terms: SGTSaleTermsV1,
) -> Offer:
    """Create the governed seller half of an exact native Chia sale.

    SGT delivery is a committed side effect of the sale coin spend. The Offer
    requests only the exact XCH/CAT proceeds, so the buyer cannot redirect the
    SGT output or alter the company treasury.
    """
    if terms.payment_rail not in {
        SGTAllocationRail.XCH,
        SGTAllocationRail.CAT,
    }:
        raise ValueError("external SGT sales use the receipt fulfillment path")
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=reserve_owner_inner_hash,
        sgt_tail_hash=sgt_tail_hash,
        terms=terms,
    )
    expected_puzzle = sgt_cat_puzzle(
        proposal_tracker_struct=proposal_tracker_struct,
        sgt_tail_hash=sgt_tail_hash,
        owner_inner_puzzle=sale_inner,
    )
    if sale_coin.puzzle_hash != expected_puzzle.get_tree_hash():
        raise ValueError("sale coin does not match the governed sale terms")
    sale_solution = Program.to(
        [
            int(SGTSaleMode.TAKE),
            sale_coin.parent_coin_info,
            sale_coin.puzzle_hash,
            sale_coin.amount,
            bytes32.zeros,
            bytes32.zeros,
        ]
    )
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        proposal_tracker_struct,
        bytes32(sale_inner.get_tree_hash()),
    )
    spend = _one_cat_spend(
        SpendableCAT(
            coin=sale_coin,
            limitations_program_hash=sgt_tail_hash,
            inner_puzzle=free_inner,
            inner_solution=Program.to(
                [SGT_TRANSFER, sale_inner, sale_solution, []]
            ),
            lineage_proof=sale_lineage_proof,
            extra_delta=0,
        )
    )
    asset_id: bytes32 | None = None
    drivers: dict[bytes32, PuzzleInfo] = {}
    if terms.payment_rail is SGTAllocationRail.CAT:
        asset_id = terms.payment_asset_id
        drivers[terms.payment_asset_id] = _payment_driver(
            terms.payment_asset_id
        )
    requested = {
        asset_id: [
            CreateCoin(
                terms.company_treasury_puzzle_hash,
                uint64(terms.payment_amount),
                [terms.sale_id, terms.proposal_hash],
            )
        ]
    }
    return Offer(
        Offer.notarize_payments(requested, [sale_coin]),
        WalletSpendBundle([spend], G2Element()),
        drivers,
    )


def build_sgt_external_sale_spend(
    *,
    sale_coin: Coin,
    sale_lineage_proof: LineageProof,
    proposal_tracker_struct: Program,
    reserve_owner_inner_hash: bytes32,
    sgt_tail_hash: bytes32,
    terms: SGTSaleTermsV1,
    external_receipt_coin_id: bytes32,
    external_receipt_hash: bytes32,
) -> CoinSpend:
    """Deliver one governed SGT allocation with an exact external receipt.

    The receipt spend is supplied by the existing Stripe/Base fulfillment
    worker. This spend only consumes its coin announcement and cannot alter
    the governed recipient, amount, asset, sale id, or purchase artifact.
    """
    if terms.payment_rail not in {
        SGTAllocationRail.STRIPE,
        SGTAllocationRail.BASE_USDC,
    }:
        raise ValueError("external settlement requires Stripe or Base USDC")
    if external_receipt_coin_id == bytes32.zeros:
        raise ValueError("external_receipt_coin_id must be non-zero")
    if external_receipt_hash == bytes32.zeros:
        raise ValueError("external_receipt_hash must be non-zero")
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=reserve_owner_inner_hash,
        sgt_tail_hash=sgt_tail_hash,
        terms=terms,
    )
    expected_puzzle = sgt_cat_puzzle(
        proposal_tracker_struct=proposal_tracker_struct,
        sgt_tail_hash=sgt_tail_hash,
        owner_inner_puzzle=sale_inner,
    )
    if sale_coin.puzzle_hash != expected_puzzle.get_tree_hash():
        raise ValueError("sale coin does not match the governed sale terms")
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        proposal_tracker_struct,
        bytes32(sale_inner.get_tree_hash()),
    )
    return _one_cat_spend(
        SpendableCAT(
            coin=sale_coin,
            limitations_program_hash=sgt_tail_hash,
            inner_puzzle=free_inner,
            inner_solution=Program.to(
                [
                    SGT_TRANSFER,
                    sale_inner,
                    [
                        int(SGTSaleMode.EXTERNAL_TAKE),
                        sale_coin.parent_coin_info,
                        sale_coin.puzzle_hash,
                        sale_coin.amount,
                        external_receipt_coin_id,
                        external_receipt_hash,
                    ],
                    [],
                ]
            ),
            lineage_proof=sale_lineage_proof,
            extra_delta=0,
        )
    )


def build_sgt_sale_return_spend(
    *,
    sale_coin: Coin,
    sale_lineage_proof: LineageProof,
    proposal_tracker_struct: Program,
    reserve_owner_inner_hash: bytes32,
    sgt_tail_hash: bytes32,
    terms: SGTSaleTermsV1,
) -> CoinSpend:
    """Return an untaken allocation to the reserve after its expiry."""
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=reserve_owner_inner_hash,
        sgt_tail_hash=sgt_tail_hash,
        terms=terms,
    )
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        proposal_tracker_struct,
        bytes32(sale_inner.get_tree_hash()),
    )
    return _one_cat_spend(
        SpendableCAT(
            coin=sale_coin,
            limitations_program_hash=sgt_tail_hash,
            inner_puzzle=free_inner,
            inner_solution=Program.to(
                [
                    SGT_TRANSFER,
                    sale_inner,
                    [
                        int(SGTSaleMode.RETURN),
                        sale_coin.parent_coin_info,
                        sale_coin.puzzle_hash,
                        sale_coin.amount,
                        bytes32.zeros,
                        bytes32.zeros,
                    ],
                    [],
                ]
            ),
            lineage_proof=sale_lineage_proof,
            extra_delta=0,
        )
    )


__all__ = [
    "SGTAllocationRail",
    "SGTReserveMode",
    "SGTSaleMode",
    "SGTSaleTermsV1",
    "bill_sgt_grant",
    "bill_sgt_sale",
    "build_reserve_allocation_spend",
    "build_reserve_execute_spends",
    "build_reserve_lock_coin_spend",
    "build_sgt_external_sale_spend",
    "build_sgt_sale_return_spend",
    "prepare_sgt_sale_offer",
    "sgt_reserve_inner_mod",
    "sgt_reserve_inner_puzzle",
    "sgt_reserve_owner_inner_hash",
    "sgt_sale_terms_from_bill",
    "sgt_sale_inner_mod",
    "sgt_sale_inner_puzzle",
    "sgt_sale_owner_inner_hash",
]
