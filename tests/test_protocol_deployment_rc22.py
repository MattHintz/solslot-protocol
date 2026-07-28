from __future__ import annotations

from dataclasses import replace

from chia.types.blockchain_format.coin import Coin
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.protocol_deployment import (
    ProtocolDeploymentPlan,
    singleton_full_puzzle_hash,
)
from solslot_puzzles.protocol_deployment_rc22 import (
    RC22ProtocolDeploymentPlan,
    build_rc22_protocol_deployment_plan,
)
from solslot_puzzles.protocol_statutes_v1 import ProtocolParameters
from solslot_puzzles.sgt_driver import TEST_KOS_MINT_EXECUTE_PUBKEY


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def plan(
    *,
    parameters: ProtocolParameters | None = None,
    statutes_coin_id: bytes32 | None = None,
) -> RC22ProtocolDeploymentPlan:
    return build_rc22_protocol_deployment_plan(
        network="testnet11",
        parameters=parameters or ProtocolParameters(),
        faucet_inner_puzzle_hash=b32(0x10),
        sgt_genesis_coin_id=b32(0x11),
        pool_genesis_coin_id=b32(0x12),
        did_genesis_coin_id=b32(0x13),
        governance_genesis_coin_id=b32(0x14),
        statutes_genesis_coin_id=statutes_coin_id or b32(0x15),
        admin_authority_genesis_coin_id=b32(0x16),
        governance_bls_pubkey=b"\x17" * 48,
        kos_mint_execute_pubkey=TEST_KOS_MINT_EXECUTE_PUBKEY,
        trusted_treasury_reserve_puzzle_hash=b32(0x18),
        trusted_protocol_treasury_puzzle_hash=b32(0x19),
        trusted_governance_rewards_puzzle_hash=b32(0x1A),
        trusted_governance_rewards_root=b32(0x1B),
        trusted_zkpassport_bridge_policy_hash=b32(0x1C),
    )


def test_rc22_plan_launches_only_current_protocol_modules() -> None:
    built = plan()
    assert built.pool_puzzle_version == 4
    assert built.governance_puzzle_version == 2
    assert built.statutes_puzzle_version == 1
    assert built.vault_puzzle_version == 2
    assert built.pool_inner_mod_hash == load_puzzle(
        "pool_singleton_inner_v4.clsp"
    ).get_tree_hash()
    assert built.vault_inner_mod_hash == load_puzzle(
        "vault_singleton_inner_v2.clsp"
    ).get_tree_hash()
    assert built.statutes_inner_mod_hash == load_puzzle(
        "protocol_statutes_inner_v1.clsp"
    ).get_tree_hash()
    assert built.pool_state.state_version == 1
    assert built.pool_state.economics.bootstrap_complete is False
    assert built.pool_state.economics.total_sols_mojos == 1
    assert built.pool_state.economics.reserve_sols_mojos == 1
    assert built.pool_state.economics.circulating_sols_mojos == 0
    assert built.sols_reserve_seed_coin_id == Coin(
        built.pool_genesis_coin_id,
        built.sols_reserve_seed_puzzle_hash,
        1,
    ).name()


def test_rc22_plan_derives_each_singleton_from_its_reserved_coin() -> None:
    built = plan()
    expected_statutes = Coin(
        b32(0x15),
        bytes32(SINGLETON_LAUNCHER_HASH),
        1,
    ).name()
    assert built.statutes_launcher_id == expected_statutes
    assert built.statutes_full_puzzle_hash == singleton_full_puzzle_hash(
        built.statutes_launcher_id,
        built.statutes_inner_puzzle_hash,
    )
    assert built.governance_full_puzzle_hash == singleton_full_puzzle_hash(
        built.governance_launcher_id,
        built.governance_inner_puzzle_hash,
    )
    assert built.pool_full_puzzle_hash == singleton_full_puzzle_hash(
        built.pool_launcher_id,
        built.pool_inner_puzzle_hash,
    )


def test_statutes_launcher_is_bound_into_pool_and_governance() -> None:
    first = plan()
    second = plan(statutes_coin_id=b32(0x2A))
    assert first.statutes_launcher_id != second.statutes_launcher_id
    assert first.statutes_inner_puzzle_hash != second.statutes_inner_puzzle_hash
    assert first.pool_inner_puzzle_hash != second.pool_inner_puzzle_hash
    assert (
        first.governance_inner_puzzle_hash
        != second.governance_inner_puzzle_hash
    )


def test_governed_parameters_are_bound_to_statutes_and_tracker() -> None:
    first = plan()
    second = plan(
        parameters=replace(
            ProtocolParameters(),
            voting_window_seconds=900,
            quorum_bps=6_000,
            min_proposal_stake=20_000,
        )
    )
    assert first.statutes_inner_puzzle_hash != second.statutes_inner_puzzle_hash
    assert (
        first.governance_inner_puzzle_hash
        != second.governance_inner_puzzle_hash
    )
    # Pool V4 trusts the statutes singleton and reads current values by proof.
    assert first.pool_inner_puzzle_hash == second.pool_inner_puzzle_hash


def test_archived_protocol_plan_remains_pool_v3() -> None:
    assert ProtocolDeploymentPlan.pool_puzzle_version == 3
