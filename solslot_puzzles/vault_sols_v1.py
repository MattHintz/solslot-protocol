"""Vault-bound Sols CAT custody for BLS and EVM-authorized vaults."""
from __future__ import annotations

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.pool_v4_driver import PoolV4Config, pool_v4_inner_mod_hash
from solslot_puzzles.sols_pool_v4 import PoolInventoryRecord, SolsPoolStateV4


_MOD: Program | None = None


def vault_sols_inner_mod() -> Program:
    global _MOD
    if _MOD is None:
        _MOD = load_puzzle("vault_sols_inner_v1.clsp")
    return _MOD


def vault_sols_inner_mod_hash() -> bytes32:
    return bytes32(vault_sols_inner_mod().get_tree_hash())


def puzzle_for_vault_sols_inner(
    *,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
) -> Program:
    if vault_launcher_id == bytes32.zeros:
        raise ValueError("vault_launcher_id must be non-zero")
    return vault_sols_inner_mod().curry(
        vault_sols_inner_mod_hash(),
        pool_v4_inner_mod_hash(),
        config.pool_singleton_struct,
        config.statutes_config,
        config.market_config,
        vault_launcher_id,
    )


def puzzle_for_vault_sols_cat(
    *,
    config: PoolV4Config,
    vault_launcher_id: bytes32,
) -> Program:
    return construct_cat_puzzle(
        CAT_MOD,
        config.permanent_rules.sols_tail_hash,
        puzzle_for_vault_sols_inner(
            config=config,
            vault_launcher_id=vault_launcher_id,
        ),
    )


def vault_sols_inner_solution_for_swap(
    *,
    payment_coin: Coin,
    payment_amount: int,
    operation_hash: bytes32,
    quote_expires_at: int,
    pool_state: SolsPoolStateV4,
    pool_inventory: tuple[PoolInventoryRecord, ...],
) -> Program:
    if payment_coin.name() == bytes32.zeros:
        raise ValueError("payment coin must be non-zero")
    if operation_hash == bytes32.zeros:
        raise ValueError("operation hash must be non-zero")
    if not 0 < payment_amount <= int(payment_coin.amount):
        raise ValueError("payment amount must fit the selected Sols coin")
    if not 0 < quote_expires_at < 2**64:
        raise ValueError("quote expiry must be a positive uint64")
    state = pool_state.validate(pool_inventory)
    economics = state.economics
    return Program.to(
        [
            payment_coin.name(),
            int(payment_coin.amount),
            operation_hash,
            payment_amount,
            quote_expires_at,
            state.inventory_root,
            int(economics.bootstrap_complete),
            economics.inventory_nav_micro_usd,
            economics.treasury_assets_micro_usd,
            economics.proven_liabilities_micro_usd,
            economics.deed_count,
            economics.total_sols_mojos,
            economics.reserve_sols_mojos,
            state.state_version,
        ]
    )


__all__ = [
    "puzzle_for_vault_sols_cat",
    "puzzle_for_vault_sols_inner",
    "vault_sols_inner_mod",
    "vault_sols_inner_mod_hash",
    "vault_sols_inner_solution_for_swap",
]
