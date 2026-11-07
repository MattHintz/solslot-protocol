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
    if config.pool_puzzle_version in (6, 7):
        from solslot_puzzles.generation_pool import GenerationPoolConfig
        from solslot_puzzles.generation_registry import singleton_struct
        if not isinstance(config, GenerationPoolConfig):
            raise ValueError('generation Sols custody requires the pinned stable pool')
        config.market_config
        module = load_puzzle('vault_sols_generation_v1.clsp')
        # Current policy/version are deliberately absent from this permanent
        # custody puzzle. Already-held Sols remain spendable after activation.
        market = Program.to([*list(config.market_config.as_iter())[:8],
            [config.generation, singleton_struct(config.registry_id), config.component_id,
             load_puzzle('generation_sols_eve_v1.clsp').get_tree_hash()]])
        return module.curry(module.get_tree_hash(), pool_v4_inner_mod_hash(config.pool_puzzle_version),
            config.pool_singleton_struct, config.statutes_config, market, vault_launcher_id)
    return vault_sols_inner_mod().curry(
        vault_sols_inner_mod_hash(),
        pool_v4_inner_mod_hash(config.pool_puzzle_version),
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
    config: PoolV4Config | None = None,
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
    result = Program.to(
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
    if config is not None and config.pool_puzzle_version in (6, 7):
        from solslot_puzzles.generation_pool import GenerationPoolConfig
        if not isinstance(config, GenerationPoolConfig):
            raise ValueError('generation Sols spend requires exact pool policy evidence')
        config.market_config
        result = Program.to([*result.as_iter(), config.module_hash, config.version, config.compatibility])
    return result


__all__ = [
    "puzzle_for_vault_sols_cat",
    "puzzle_for_vault_sols_inner",
    "vault_sols_inner_mod",
    "vault_sols_inner_mod_hash",
    "vault_sols_inner_solution_for_swap",
]
