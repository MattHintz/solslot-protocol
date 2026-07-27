"""Driver for the governed non-withdrawable wUSDC.b redemption treasury."""
from __future__ import annotations

from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.funded_redemption_v1 import (
    FundedRedemptionPlanV1,
    p2_deed_redemption_v1_mod,
    redemption_funding_puzzle,
)


_MOD: Program | None = None


def redemption_treasury_v1_mod() -> Program:
    global _MOD
    if _MOD is None:
        _MOD = load_puzzle("redemption_treasury_v1.clsp")
    return _MOD


def redemption_treasury_inner_puzzle(
    *,
    governance_singleton_struct: Program,
    payment_asset_id: bytes32,
) -> Program:
    mod = redemption_treasury_v1_mod()
    return mod.curry(
        mod.get_tree_hash(),
        governance_singleton_struct,
        CAT_MOD.get_tree_hash(),
        payment_asset_id,
        OFFER_MOD_HASH,
        p2_deed_redemption_v1_mod().get_tree_hash(),
        SINGLETON_MOD_HASH,
        SINGLETON_LAUNCHER_HASH,
    )


def redemption_treasury_puzzle(
    *,
    governance_singleton_struct: Program,
    payment_asset_id: bytes32,
) -> Program:
    return construct_cat_puzzle(
        CAT_MOD,
        payment_asset_id,
        redemption_treasury_inner_puzzle(
            governance_singleton_struct=governance_singleton_struct,
            payment_asset_id=payment_asset_id,
        ),
    )


def redemption_treasury_solution(
    *,
    treasury_coin: Coin,
    governance_inner_puzzle_hash: bytes32,
    plan: FundedRedemptionPlanV1,
) -> Program:
    plan.validate()
    return Program.to(
        [
            treasury_coin.name(),
            int(treasury_coin.amount),
            governance_inner_puzzle_hash,
            plan.collection_id,
            plan.settlement_id,
            plan.total_payment_amount,
            [
                allocation.as_program_value()
                for allocation in plan.allocations
            ],
            plan.allocations_root,
        ]
    )


@dataclass(frozen=True)
class FundedRedemptionLeaves:
    spend_bundle: WalletSpendBundle
    treasury_coin_spend_index: int
    leaf_coins: tuple[Coin, ...]
    leaf_lineage_proof: LineageProof


def fund_redemption_leaves(
    *,
    treasury_coin: Coin,
    treasury_lineage_proof: LineageProof,
    governance_singleton_struct: Program,
    governance_inner_puzzle_hash: bytes32,
    plan: FundedRedemptionPlanV1,
) -> FundedRedemptionLeaves:
    plan.validate()
    inner = redemption_treasury_inner_puzzle(
        governance_singleton_struct=governance_singleton_struct,
        payment_asset_id=plan.payment_asset_id,
    )
    full = construct_cat_puzzle(CAT_MOD, plan.payment_asset_id, inner)
    if treasury_coin.puzzle_hash != full.get_tree_hash():
        raise ValueError("treasury coin does not belong to the governed treasury")
    if int(treasury_coin.amount) != plan.total_payment_amount:
        raise ValueError("treasury funding must equal the governed settlement total")
    if (
        treasury_lineage_proof.parent_name is None
        or treasury_lineage_proof.inner_puzzle_hash is None
        or treasury_lineage_proof.amount is None
    ):
        raise ValueError("treasury CAT requires a complete lineage proof")

    bundle = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [
            SpendableCAT(
                treasury_coin,
                plan.payment_asset_id,
                inner,
                redemption_treasury_solution(
                    treasury_coin=treasury_coin,
                    governance_inner_puzzle_hash=governance_inner_puzzle_hash,
                    plan=plan,
                ),
                lineage_proof=treasury_lineage_proof,
            )
        ],
    )
    leaves = tuple(
        Coin(
            treasury_coin.name(),
            bytes32(
                redemption_funding_puzzle(
                    payment_asset_id=plan.payment_asset_id,
                    collection_id=plan.collection_id,
                    settlement_id=plan.settlement_id,
                    allocation=allocation,
                ).get_tree_hash()
            ),
            uint64(allocation.payment_amount),
        )
        for allocation in plan.allocations
    )
    return FundedRedemptionLeaves(
        spend_bundle=bundle,
        treasury_coin_spend_index=0,
        leaf_coins=leaves,
        leaf_lineage_proof=LineageProof(
            treasury_coin.parent_coin_info,
            bytes32(inner.get_tree_hash()),
            uint64(treasury_coin.amount),
        ),
    )


__all__ = [
    "FundedRedemptionLeaves",
    "redemption_treasury_v1_mod",
    "redemption_treasury_inner_puzzle",
    "redemption_treasury_puzzle",
    "redemption_treasury_solution",
    "fund_redemption_leaves",
]
