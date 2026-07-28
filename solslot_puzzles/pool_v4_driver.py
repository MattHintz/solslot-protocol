"""Driver for the RC22 protocol-only SmartDeed/Sols pool."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    PermanentRules,
    ProtocolParameters,
    ScopedPause,
    StatutesState,
)
from solslot_puzzles.sols_pool_v4 import (
    DEED_TO_SOLS,
    SOLS_TO_DEED,
    PoolInventoryRecord,
    SolsPoolStateV4,
    SwapReceipt,
)


_MOD: Program | None = None


def pool_v4_inner_mod() -> Program:
    global _MOD
    if _MOD is None:
        _MOD = load_puzzle("pool_singleton_inner_v4.clsp")
    return _MOD


def pool_v4_inner_mod_hash() -> bytes32:
    return bytes32(pool_v4_inner_mod().get_tree_hash())


@dataclass(frozen=True)
class PoolV4Config:
    pool_launcher_id: bytes32
    statutes_inner_mod_hash: bytes32
    statutes_singleton_struct: Program
    governance_singleton_struct: Program
    permanent_rules: PermanentRules
    cat_mod_hash: bytes32
    offer_mod_hash: bytes32
    p2_vault_mod_hash: bytes32
    vault_v2_mod_hash: bytes32
    p2_pool_v2_mod_hash: bytes32
    reserve_puzzle_hash: bytes32
    sgt_rewards_puzzle_hash: bytes32

    @property
    def pool_singleton_struct(self) -> Program:
        return Program.to(
            (
                SINGLETON_MOD_HASH,
                (self.pool_launcher_id, SINGLETON_LAUNCHER_HASH),
            )
        )

    @property
    def statutes_config(self) -> Program:
        rules = self.permanent_rules.validate()
        return Program.to(
            [
                self.statutes_inner_mod_hash,
                self.statutes_singleton_struct,
                self.governance_singleton_struct,
                rules.sgt_tail_hash,
                rules.sgt_total_supply,
                rules.sols_tail_hash,
                rules.zkpassport_policy_hash,
                rules.protocol_treasury_puzzle_hash,
                rules.network_id,
            ]
        )

    @property
    def market_config(self) -> Program:
        return Program.to(
            [
                self.cat_mod_hash,
                self.offer_mod_hash,
                self.p2_vault_mod_hash,
                self.vault_v2_mod_hash,
                self.p2_pool_v2_mod_hash,
                self.reserve_puzzle_hash,
                self.sgt_rewards_puzzle_hash,
            ]
        )


def make_pool_v4_inner(
    config: PoolV4Config,
    state: SolsPoolStateV4,
) -> Program:
    state.economics.validate()
    return pool_v4_inner_mod().curry(
        pool_v4_inner_mod_hash(),
        config.pool_singleton_struct,
        config.statutes_config,
        config.market_config,
        state.inventory_root,
        int(state.economics.bootstrap_complete),
        state.economics.inventory_nav_micro_usd,
        state.economics.treasury_assets_micro_usd,
        state.economics.proven_liabilities_micro_usd,
        state.economics.deed_count,
        state.economics.total_sols_mojos,
        state.economics.reserve_sols_mojos,
        state.state_version,
    )


def make_pool_v4_full(
    config: PoolV4Config,
    state: SolsPoolStateV4,
) -> Program:
    return puzzle_for_singleton(
        config.pool_launcher_id,
        make_pool_v4_inner(config, state),
    )


def p2_pool_v2_inner_hash(
    *,
    config: PoolV4Config,
    deed_commitment: bytes32,
) -> bytes32:
    inner = load_puzzle("p2_pool_v2.clsp").curry(
        config.p2_pool_v2_mod_hash,
        SINGLETON_MOD_HASH,
        config.pool_launcher_id,
        SINGLETON_LAUNCHER_HASH,
        deed_commitment,
    )
    return bytes32(inner.get_tree_hash())


def deterministic_custody_coin_id(
    *,
    config: PoolV4Config,
    deed_parent_coin_id: bytes32,
    deed_launcher_id: bytes32,
    deed_commitment: bytes32,
) -> bytes32:
    full = puzzle_for_singleton(
        deed_launcher_id,
        load_puzzle("p2_pool_v2.clsp").curry(
            config.p2_pool_v2_mod_hash,
            SINGLETON_MOD_HASH,
            config.pool_launcher_id,
            SINGLETON_LAUNCHER_HASH,
            deed_commitment,
        ),
    )
    return Coin(
        deed_parent_coin_id,
        bytes32(full.get_tree_hash()),
        1,
    ).name()


def _inventory_values(
    inventory: Sequence[PoolInventoryRecord],
) -> list[object]:
    return [record.as_program_value() for record in inventory]


def _pause_value(pause: ScopedPause | None) -> list[object]:
    return [1, pause.as_program_value()] if pause is not None else [0, []]


def _statutes_values(
    *,
    parameters: ProtocolParameters,
    collection: CollectionStatute,
    pause: ScopedPause | None,
    statutes_state: StatutesState,
) -> list[object]:
    return [
        list(parameters.as_tuple()),
        collection.as_program_value(),
        _pause_value(pause),
        statutes_state.parameters_root,
        statutes_state.collections_root,
        statutes_state.oracle_root,
        statutes_state.routes_root,
        statutes_state.liquidity_root,
        statutes_state.pauses_root,
        statutes_state.registry_version,
    ]


def deed_to_sols_inner_solution(
    *,
    config: PoolV4Config,
    pool_coin_id: bytes32,
    pool_inner_puzzle_hash: bytes32,
    pool_amount: int,
    receipt: SwapReceipt,
    parameters: ProtocolParameters,
    collection: CollectionStatute,
    pause: ScopedPause | None,
    statutes_state: StatutesState,
    deed_parent_coin_id: bytes32,
    par_value: int,
    asset_class: int,
    property_id: bytes32,
    seller_sols_puzzle_hash: bytes32,
    mint_token_coin_id: bytes32 | None,
    vault_launcher_id: bytes32,
    vault_coin_id: bytes32,
    owner_pubkey: bytes,
    auth_type: int,
    members_root: bytes32,
    identity_root: bytes32,
    bridge_policy: bytes32,
    quote_expires_at: int,
) -> Program:
    if receipt.direction != DEED_TO_SOLS:
        raise ValueError("receipt is not a deed-to-Sols quote")
    quote = receipt.deed_to_sols_quote
    if quote is None:
        raise ValueError("deed-to-Sols quote is missing")
    expected_custody = deterministic_custody_coin_id(
        config=config,
        deed_parent_coin_id=deed_parent_coin_id,
        deed_launcher_id=receipt.record.deed_launcher_id,
        deed_commitment=receipt.record.deed_commitment,
    )
    if expected_custody != receipt.record.custody_coin_id:
        raise ValueError("receipt custody coin is not deterministic")
    statutes = _statutes_values(
        parameters=parameters,
        collection=collection,
        pause=pause,
        statutes_state=statutes_state,
    )
    params: list[object] = [
        _inventory_values(receipt.inventory),
        *statutes,
        deed_parent_coin_id,
        receipt.record.deed_launcher_id,
        receipt.record.custody_coin_id,
        receipt.record.deed_commitment,
        par_value,
        asset_class,
        property_id,
        receipt.record.share_ppm,
        seller_sols_puzzle_hash,
        mint_token_coin_id or b"",
        vault_launcher_id,
        vault_coin_id,
        owner_pubkey,
        auth_type,
        members_root,
        identity_root,
        bridge_policy,
        quote_expires_at,
        receipt.record.deed_value_micro_usd,
        receipt.record.as_program_value(),
        quote.seller_sols_mojos,
        quote.reserve_sols_mojos_paid,
        quote.fresh_sols_mojos_minted,
        receipt.next_state.inventory_root,
        receipt.current_state.commitment_hash,
        receipt.next_state.commitment_hash,
        statutes_state.content_hash,
        receipt.operation_hash,
    ]
    return Program.to(
        [
            pool_coin_id,
            pool_inner_puzzle_hash,
            pool_amount,
            DEED_TO_SOLS,
            params,
        ]
    )


def sols_to_deed_inner_solution(
    *,
    pool_coin_id: bytes32,
    pool_inner_puzzle_hash: bytes32,
    pool_amount: int,
    receipt: SwapReceipt,
    parameters: ProtocolParameters,
    collection: CollectionStatute,
    pause: ScopedPause | None,
    statutes_state: StatutesState,
    vault_launcher_id: bytes32,
    vault_coin_id: bytes32,
    owner_pubkey: bytes,
    auth_type: int,
    members_root: bytes32,
    identity_root: bytes32,
    bridge_policy: bytes32,
    quote_expires_at: int,
    destination_p2_vault_hash: bytes32,
) -> Program:
    if receipt.direction != SOLS_TO_DEED:
        raise ValueError("receipt is not a Sols-to-deed quote")
    quote = receipt.sols_to_deed_quote
    if quote is None:
        raise ValueError("Sols-to-deed quote is missing")
    statutes = _statutes_values(
        parameters=parameters,
        collection=collection,
        pause=pause,
        statutes_state=statutes_state,
    )
    params: list[object] = [
        _inventory_values(receipt.inventory),
        *statutes,
        receipt.record.deed_launcher_id,
        vault_launcher_id,
        vault_coin_id,
        owner_pubkey,
        auth_type,
        members_root,
        identity_root,
        bridge_policy,
        quote_expires_at,
        receipt.record.as_program_value(),
        receipt.record.custody_coin_id,
        receipt.record.deed_commitment,
        receipt.record.deed_value_micro_usd,
        destination_p2_vault_hash,
        quote.principal_sols_mojos,
        quote.fee_split.protocol_fee_sols_mojos,
        quote.fee_split.sgt_rewards_fee_sols_mojos,
        receipt.next_state.inventory_root,
        receipt.current_state.commitment_hash,
        receipt.next_state.commitment_hash,
        statutes_state.content_hash,
        receipt.operation_hash,
    ]
    return Program.to(
        [
            pool_coin_id,
            pool_inner_puzzle_hash,
            pool_amount,
            SOLS_TO_DEED,
            params,
        ]
    )


__all__ = [
    "PoolV4Config",
    "pool_v4_inner_mod",
    "pool_v4_inner_mod_hash",
    "make_pool_v4_inner",
    "make_pool_v4_full",
    "p2_pool_v2_inner_hash",
    "deterministic_custody_coin_id",
    "deed_to_sols_inner_solution",
    "sols_to_deed_inner_solution",
]
