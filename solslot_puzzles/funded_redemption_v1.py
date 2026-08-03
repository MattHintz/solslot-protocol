"""Governed, permanently funded wUSDC.b SmartDeed redemption offers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    solution_for_singleton,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.primary_purchase_v2_driver import (
    chia_cat_driver,
    smart_deed_singleton_driver,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    deed_launcher_puzzle_hash_from_struct,
)
from solslot_puzzles.sols_economics_v3 import (
    SHARE_PPM_DENOMINATOR,
    SettlementShare,
    allocate_settlement,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from solslot_puzzles.vault_v2_driver import (
    build_vault_redemption_accept_spend,
    puzzle_for_vault_v2_inner,
    redemption_accept_operation_hash,
)


CANONICAL_DEED_SETTLEMENT_INNER = bytes32.zeros
REDEMPTION_OFFER_TAG = b"RDM1"

_MOD: Program | None = None


def p2_deed_redemption_v1_mod() -> Program:
    global _MOD
    if _MOD is None:
        _MOD = load_puzzle("p2_deed_redemption_v1.clsp")
    return _MOD


@dataclass(frozen=True)
class FundedRedemptionAllocation:
    deed_launcher_id: bytes32
    deed_commitment: bytes32
    share_ppm: int
    payment_amount: int

    def validate(self) -> "FundedRedemptionAllocation":
        if len(self.deed_launcher_id) != 32:
            raise ValueError("deed_launcher_id must be bytes32")
        if len(self.deed_commitment) != 32:
            raise ValueError("deed_commitment must be bytes32")
        if not 0 < self.share_ppm <= SHARE_PPM_DENOMINATOR:
            raise ValueError("share_ppm must be between 1 and 1,000,000")
        if not 0 < self.payment_amount < 2**64:
            raise ValueError("payment_amount must be a positive uint64")
        return self

    def as_program_value(self) -> list[object]:
        self.validate()
        return [
            self.deed_launcher_id,
            self.deed_commitment,
            self.share_ppm,
            self.payment_amount,
        ]


def canonical_redemption_allocations(
    allocations: Sequence[FundedRedemptionAllocation],
) -> tuple[FundedRedemptionAllocation, ...]:
    normalized = tuple(
        sorted(allocations, key=lambda item: bytes(item.deed_launcher_id))
    )
    if not normalized:
        raise ValueError("redemption requires at least one SmartDeed")
    for allocation in normalized:
        allocation.validate()
    ids = [item.deed_launcher_id for item in normalized]
    commitments = [item.deed_commitment for item in normalized]
    if len(ids) != len(set(ids)):
        raise ValueError("redemption deed launcher IDs must be unique")
    if len(commitments) != len(set(commitments)):
        raise ValueError("redemption deed commitments must be unique")
    if sum(item.share_ppm for item in normalized) != SHARE_PPM_DENOMINATOR:
        raise ValueError("redemption shares must total exactly 1,000,000 ppm")
    return normalized


def redemption_allocations_root(
    allocations: Sequence[FundedRedemptionAllocation],
) -> bytes32:
    normalized = canonical_redemption_allocations(allocations)
    return bytes32(
        Program.to(
            [allocation.as_program_value() for allocation in normalized]
        ).get_tree_hash()
    )


@dataclass(frozen=True)
class FundedRedemptionPlanV1:
    collection_id: bytes32
    settlement_id: bytes32
    payment_asset_id: bytes32
    total_payment_amount: int
    allocations: tuple[FundedRedemptionAllocation, ...]

    def validate(self) -> "FundedRedemptionPlanV1":
        for label, value in (
            ("collection_id", self.collection_id),
            ("settlement_id", self.settlement_id),
            ("payment_asset_id", self.payment_asset_id),
        ):
            if len(value) != 32:
                raise ValueError(f"{label} must be bytes32")
        if not 0 < self.total_payment_amount < 2**64:
            raise ValueError("total_payment_amount must be a positive uint64")
        normalized = canonical_redemption_allocations(self.allocations)
        if sum(item.payment_amount for item in normalized) != (
            self.total_payment_amount
        ):
            raise ValueError("redemption allocations must equal the funded total")
        return self

    @property
    def allocations_root(self) -> bytes32:
        return redemption_allocations_root(self.allocations)

    @property
    def deed_count(self) -> int:
        return len(self.allocations)


def build_funded_redemption_plan(
    *,
    collection_id: bytes32,
    settlement_id: bytes32,
    payment_asset_id: bytes32,
    total_payment_amount: int,
    deed_shares_ppm: Mapping[bytes32, int],
    deed_commitments: Mapping[bytes32, bytes32],
) -> FundedRedemptionPlanV1:
    if set(deed_shares_ppm) != set(deed_commitments):
        raise ValueError("deed shares and commitments must cover the same deeds")
    shares = [
        SettlementShare(deed_id=deed.hex(), share_ppm=share_ppm)
        for deed, share_ppm in deed_shares_ppm.items()
    ]
    amounts = {
        bytes32.fromhex(item.deed_id): item.amount_micro_usd
        for item in allocate_settlement(total_payment_amount, shares)
    }
    allocations = tuple(
        FundedRedemptionAllocation(
            deed_launcher_id=deed,
            deed_commitment=deed_commitments[deed],
            share_ppm=share_ppm,
            payment_amount=amounts[deed],
        )
        for deed, share_ppm in deed_shares_ppm.items()
    )
    return FundedRedemptionPlanV1(
        collection_id=collection_id,
        settlement_id=settlement_id,
        payment_asset_id=payment_asset_id,
        total_payment_amount=total_payment_amount,
        allocations=canonical_redemption_allocations(allocations),
    ).validate()


def redemption_payment_memos(
    *,
    collection_id: bytes32,
    settlement_id: bytes32,
    allocation: FundedRedemptionAllocation,
) -> list[bytes]:
    allocation.validate()
    return [
        collection_id,
        settlement_id,
        allocation.deed_launcher_id,
        allocation.deed_commitment,
        Program.to(allocation.share_ppm).as_atom(),
    ]


def puzzle_for_deed_redemption_v1(
    *,
    payment_asset_id: bytes32,
    collection_id: bytes32,
    settlement_id: bytes32,
    allocation: FundedRedemptionAllocation,
    deed_launcher_puzzle_hash: bytes32,
) -> Program:
    allocation.validate()
    mod = p2_deed_redemption_v1_mod()
    return mod.curry(
        mod.get_tree_hash(),
        CAT_MOD.get_tree_hash(),
        payment_asset_id,
        OFFER_MOD_HASH,
        SINGLETON_MOD_HASH,
        deed_launcher_puzzle_hash,
        collection_id,
        settlement_id,
        allocation.deed_launcher_id,
        allocation.deed_commitment,
        allocation.share_ppm,
        allocation.payment_amount,
    )


def redemption_funding_puzzle(
    *,
    payment_asset_id: bytes32,
    collection_id: bytes32,
    settlement_id: bytes32,
    allocation: FundedRedemptionAllocation,
    deed_launcher_puzzle_hash: bytes32,
) -> Program:
    return construct_cat_puzzle(
        CAT_MOD,
        payment_asset_id,
        puzzle_for_deed_redemption_v1(
            payment_asset_id=payment_asset_id,
            collection_id=collection_id,
            settlement_id=settlement_id,
            allocation=allocation,
            deed_launcher_puzzle_hash=deed_launcher_puzzle_hash,
        ),
    )


def redemption_leaf_solution(funding_coin: Coin) -> Program:
    return Program.to(
        [
            funding_coin.parent_coin_info,
            funding_coin.puzzle_hash,
            int(funding_coin.amount),
        ]
    )


def build_permanent_redemption_offer(
    *,
    funding_coin: Coin,
    funding_lineage_proof: LineageProof,
    plan: FundedRedemptionPlanV1,
    allocation: FundedRedemptionAllocation,
    deed_singleton_struct: Program,
) -> tuple[Offer, CoinSpend]:
    plan.validate()
    allocation.validate()
    if allocation not in plan.allocations:
        raise ValueError("allocation is not part of the governed redemption plan")
    deed_launcher_puzzle_hash = deed_launcher_puzzle_hash_from_struct(
        deed_singleton_struct,
        allocation.deed_launcher_id,
    )
    inner = puzzle_for_deed_redemption_v1(
        payment_asset_id=plan.payment_asset_id,
        collection_id=plan.collection_id,
        settlement_id=plan.settlement_id,
        allocation=allocation,
        deed_launcher_puzzle_hash=deed_launcher_puzzle_hash,
    )
    full = construct_cat_puzzle(CAT_MOD, plan.payment_asset_id, inner)
    if funding_coin.puzzle_hash != full.get_tree_hash():
        raise ValueError("funding coin is not the governed redemption leaf")
    if int(funding_coin.amount) != allocation.payment_amount:
        raise ValueError("funding coin amount does not match the governed payout")
    if (
        funding_lineage_proof.parent_name is None
        or funding_lineage_proof.inner_puzzle_hash is None
        or funding_lineage_proof.amount is None
    ):
        raise ValueError("funding CAT requires a complete lineage proof")

    requested = {
        allocation.deed_launcher_id: [
            CreateCoin(
                CANONICAL_DEED_SETTLEMENT_INNER,
                uint64(1),
                redemption_payment_memos(
                    collection_id=plan.collection_id,
                    settlement_id=plan.settlement_id,
                    allocation=allocation,
                ),
            )
        ]
    }
    notarized = Offer.notarize_payments(requested, [funding_coin])
    bundle = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [
            SpendableCAT(
                funding_coin,
                plan.payment_asset_id,
                inner,
                redemption_leaf_solution(funding_coin),
                lineage_proof=funding_lineage_proof,
            )
        ],
    )
    drivers = {
        plan.payment_asset_id: chia_cat_driver(plan.payment_asset_id),
        allocation.deed_launcher_id: smart_deed_singleton_driver(
            allocation.deed_launcher_id,
            deed_launcher_puzzle_hash,
        ),
    }
    offer = Offer(notarized, bundle, drivers)
    return offer, bundle.coin_spends[0]


@dataclass(frozen=True)
class DirectRedemptionAcceptance:
    taker_offer: Offer
    vault_spend: CoinSpend
    deed_spend: CoinSpend
    operation_hash: bytes32
    payment_nonce: bytes32
    payment_announcement_id: bytes32


def build_direct_redemption_acceptance(
    *,
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    vault_lineage_proof: LineageProof,
    vault_owner_pubkey: bytes,
    vault_auth_type: int,
    vault_members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    identity_attest_root: bytes32,
    zkpassport_bridge_policy_hash: bytes32,
    deed_coin: Coin,
    deed_lineage_proof: LineageProof,
    deed_current_inner_puzzle_hash: bytes32,
    deed_singleton_struct: Program,
    payment_recipient_inner_puzzle_hash: bytes32,
    plan: FundedRedemptionPlanV1,
    allocation: FundedRedemptionAllocation,
    signature_data: bytes | None = None,
) -> DirectRedemptionAcceptance:
    """Build the vault-signed holder half of a permanent redemption offer."""
    plan.validate()
    allocation.validate()
    if allocation not in plan.allocations:
        raise ValueError("allocation is not part of the governed redemption plan")
    if allocation.deed_launcher_id == bytes32.zeros:
        raise ValueError("deed launcher ID cannot be zero")

    vault_inner = puzzle_for_vault_v2_inner(
        vault_launcher_id=vault_launcher_id,
        owner_pubkey=vault_owner_pubkey,
        auth_type=vault_auth_type,
        members_merkle_root=vault_members_merkle_root,
        pool_launcher_id=pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    p2_vault = puzzle_for_p2_vault(vault_launcher_id)
    deed_launcher_puzzle_hash = deed_launcher_puzzle_hash_from_struct(
        deed_singleton_struct,
        allocation.deed_launcher_id,
    )
    expected_deed_puzzle = SINGLETON_MOD.curry(
        deed_singleton_struct,
        p2_vault,
    )
    if deed_coin.puzzle_hash != expected_deed_puzzle.get_tree_hash():
        raise ValueError("SmartDeed is not held by the reviewed vault")
    if int(deed_coin.amount) != 1:
        raise ValueError("SmartDeed singleton amount must be one mojo")

    payment_memos = [
        plan.collection_id,
        plan.settlement_id,
        allocation.deed_launcher_id,
        allocation.deed_commitment,
    ]
    requested = {
        plan.payment_asset_id: [
            CreateCoin(
                payment_recipient_inner_puzzle_hash,
                uint64(allocation.payment_amount),
                payment_memos,
            )
        ]
    }
    notarized = Offer.notarize_payments(requested, [deed_coin])
    payment = notarized[plan.payment_asset_id][0]
    payment_announcements = Offer.calculate_announcements(
        notarized,
        {plan.payment_asset_id: chia_cat_driver(plan.payment_asset_id)},
    )
    if len(payment_announcements) != 1:
        raise ValueError("redemption must produce one payment announcement")
    payment_announcement_id = bytes32(
        payment_announcements[0].to_program().rest().first().as_atom()
    )
    operation_hash = redemption_accept_operation_hash(
        vault_coin_id=vault_coin.name(),
        deed_launcher_id=allocation.deed_launcher_id,
        deed_commitment=allocation.deed_commitment,
        collection_id=plan.collection_id,
        settlement_id=plan.settlement_id,
        payment_asset_id=plan.payment_asset_id,
        payment_amount=allocation.payment_amount,
        payment_recipient_inner_puzzle_hash=(
            payment_recipient_inner_puzzle_hash
        ),
        payment_nonce=payment.nonce,
        payment_announcement_id=payment_announcement_id,
    )
    vault_spend = build_vault_redemption_accept_spend(
        vault_coin=vault_coin,
        vault_launcher_id=vault_launcher_id,
        owner_pubkey=vault_owner_pubkey,
        auth_type=vault_auth_type,
        members_merkle_root=vault_members_merkle_root,
        pool_launcher_id=pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
        deed_launcher_id=allocation.deed_launcher_id,
        deed_commitment=allocation.deed_commitment,
        collection_id=plan.collection_id,
        settlement_id=plan.settlement_id,
        payment_asset_id=plan.payment_asset_id,
        payment_amount=allocation.payment_amount,
        payment_recipient_inner_puzzle_hash=(
            payment_recipient_inner_puzzle_hash
        ),
        payment_nonce=payment.nonce,
        payment_announcement_id=payment_announcement_id,
        lineage_proof=vault_lineage_proof,
        signature_data=signature_data,
    )
    deed_inner_solution = Program.to(
        [
            vault_inner.get_tree_hash(),
            vault_coin.name(),
            allocation.deed_launcher_id,
            deed_current_inner_puzzle_hash,
            int(deed_coin.amount),
            OFFER_MOD_HASH,
        ]
    )
    deed_spend = make_spend(
        deed_coin,
        expected_deed_puzzle,
        solution_for_singleton(
            deed_lineage_proof,
            uint64(deed_coin.amount),
            deed_inner_solution,
        ),
    )
    drivers = {
        plan.payment_asset_id: chia_cat_driver(plan.payment_asset_id),
        allocation.deed_launcher_id: smart_deed_singleton_driver(
            allocation.deed_launcher_id,
            deed_launcher_puzzle_hash,
        ),
    }
    taker_offer = Offer(
        notarized,
        WalletSpendBundle([vault_spend, deed_spend], G2Element()),
        drivers,
    )
    return DirectRedemptionAcceptance(
        taker_offer=taker_offer,
        vault_spend=vault_spend,
        deed_spend=deed_spend,
        operation_hash=operation_hash,
        payment_nonce=payment.nonce,
        payment_announcement_id=payment_announcement_id,
    )


def aggregate_direct_redemption(
    *,
    maker_offer: Offer,
    acceptance: DirectRedemptionAcceptance,
) -> Offer:
    aggregate = Offer.aggregate([maker_offer, acceptance.taker_offer])
    if not aggregate.is_valid():
        raise ValueError("redemption maker and holder offers do not balance")
    return aggregate


def redemption_leaf_conditions(
    *,
    funding_coin: Coin,
    plan: FundedRedemptionPlanV1,
    allocation: FundedRedemptionAllocation,
    deed_singleton_struct: Program,
) -> list[list[object]]:
    """Run the inner puzzle for focused consensus fixtures."""
    return puzzle_for_deed_redemption_v1(
        payment_asset_id=plan.payment_asset_id,
        collection_id=plan.collection_id,
        settlement_id=plan.settlement_id,
        allocation=allocation,
        deed_launcher_puzzle_hash=deed_launcher_puzzle_hash_from_struct(
            deed_singleton_struct,
            allocation.deed_launcher_id,
        ),
    ).run(redemption_leaf_solution(funding_coin)).as_python()


__all__ = [
    "CANONICAL_DEED_SETTLEMENT_INNER",
    "REDEMPTION_OFFER_TAG",
    "FundedRedemptionAllocation",
    "FundedRedemptionPlanV1",
    "canonical_redemption_allocations",
    "redemption_allocations_root",
    "build_funded_redemption_plan",
    "redemption_payment_memos",
    "p2_deed_redemption_v1_mod",
    "puzzle_for_deed_redemption_v1",
    "redemption_funding_puzzle",
    "redemption_leaf_solution",
    "build_permanent_redemption_offer",
    "DirectRedemptionAcceptance",
    "build_direct_redemption_acceptance",
    "aggregate_direct_redemption",
    "redemption_leaf_conditions",
]
