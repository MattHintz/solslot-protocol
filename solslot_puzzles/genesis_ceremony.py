"""Deterministic Solslot V2 testnet genesis planner and bundle builder."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs import AugSchemeMPL, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import admin_authority_v2_driver as admin_authority
from solslot_puzzles import collection_nav_registry_driver as nav_registry
from solslot_puzzles import protocol_config_driver as protocol_config
from solslot_puzzles import property_registry_driver as property_registry
from solslot_puzzles import vault_version_registry_driver as vault_registry
from solslot_puzzles.protocol_deployment import (
    PROTOCOL_VERSION,
    ProtocolDeploymentParams,
    ProtocolDeploymentPlan,
    singleton_full_puzzle_hash,
)
from solslot_puzzles.vault_driver import VAULT_INNER_MOD
from solslot_puzzles.zkpassport_bridge_driver import require_genesis_validator_set
from solslot_puzzles.genesis_constants import GENESIS_EVM_CHAIN_ID, GENESIS_NETWORK


GENESIS_PLAN_SCHEMA = "solslot-genesis-plan-v2"
GENESIS_ADMIN_THRESHOLD = 2
GENESIS_VALIDATOR_THRESHOLD = 2
GENESIS_BRIDGE_BATCH_SIZE = 32
GENESIS_BRIDGE_LOW_WATER_MARK = 8
GENESIS_VAULT_VERSION = 2
REQUIRED_SOURCE_SHAS = (
    "protocol",
    "evm",
    "api",
    "customerWeb",
    "adminPortal",
)
REQUIRED_EVM_ADDRESSES = (
    "forwarder",
    "verifierAdapter",
    "attestationEmitter",
)


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _nonzero_b32(value: bytes32, label: str) -> bytes32:
    if len(value) != 32 or value == bytes32.zeros:
        raise ValueError(f"{label} must be a nonzero 32-byte value")
    return bytes32(value)


def _normalize_source_shas(values: Mapping[str, str]) -> dict[str, str]:
    if set(values) != set(REQUIRED_SOURCE_SHAS):
        raise ValueError(
            "source_shas must contain exactly " + ", ".join(REQUIRED_SOURCE_SHAS)
        )
    normalized: dict[str, str] = {}
    for name in REQUIRED_SOURCE_SHAS:
        value = values[name].lower()
        if len(value) != 40:
            raise ValueError(f"source_shas.{name} must be a 40-character Git SHA")
        int(value, 16)
        normalized[name] = value
    return normalized


def _normalize_evm_addresses(values: Mapping[str, str]) -> dict[str, str]:
    if set(values) != set(REQUIRED_EVM_ADDRESSES):
        raise ValueError(
            "evm_addresses must contain exactly " + ", ".join(REQUIRED_EVM_ADDRESSES)
        )
    normalized: dict[str, str] = {}
    for name in REQUIRED_EVM_ADDRESSES:
        value = values[name].lower()
        if not value.startswith("0x") or len(value) != 42:
            raise ValueError(f"evm_addresses.{name} must be a 0x-prefixed address")
        int(value[2:], 16)
        if value == "0x" + "00" * 20:
            raise ValueError(f"evm_addresses.{name} must be nonzero")
        normalized[name] = value
    if len(set(normalized.values())) != len(normalized):
        raise ValueError("fresh EVM contract addresses must be distinct")
    return normalized


def _launcher_id(parent_coin_id: bytes32) -> bytes32:
    return bytes32(
        Coin(parent_coin_id, bytes32(SINGLETON_LAUNCHER_HASH), uint64(1)).name()
    )


@dataclass(frozen=True)
class GenesisFundingCoinIds:
    sgt: bytes32
    pool: bytes32
    did: bytes32
    governance: bytes32
    nav_registry: bytes32
    protocol_config: bytes32
    admin_authority: bytes32
    vault_version_registry: bytes32
    bridge_batch: bytes32

    def values(self) -> tuple[bytes32, ...]:
        return (
            self.sgt,
            self.pool,
            self.did,
            self.governance,
            self.nav_registry,
            self.protocol_config,
            self.admin_authority,
            self.vault_version_registry,
            self.bridge_batch,
        )

    def validate(self) -> None:
        values = self.values()
        for index, value in enumerate(values):
            _nonzero_b32(value, f"funding coin {index}")
        if len(set(values)) != len(values):
            raise ValueError("all nine genesis funding coin ids must be distinct")


@dataclass(frozen=True)
class GenesisFundingCoins:
    sgt: Coin
    pool: Coin
    did: Coin
    governance: Coin
    nav_registry: Coin
    protocol_config: Coin
    admin_authority: Coin
    vault_version_registry: Coin
    bridge_batch: Coin

    def values(self) -> tuple[Coin, ...]:
        return (
            self.sgt,
            self.pool,
            self.did,
            self.governance,
            self.nav_registry,
            self.protocol_config,
            self.admin_authority,
            self.vault_version_registry,
            self.bridge_batch,
        )

    def ids(self) -> GenesisFundingCoinIds:
        return GenesisFundingCoinIds(
            sgt=bytes32(self.sgt.name()),
            pool=bytes32(self.pool.name()),
            did=bytes32(self.did.name()),
            governance=bytes32(self.governance.name()),
            nav_registry=bytes32(self.nav_registry.name()),
            protocol_config=bytes32(self.protocol_config.name()),
            admin_authority=bytes32(self.admin_authority.name()),
            vault_version_registry=bytes32(self.vault_version_registry.name()),
            bridge_batch=bytes32(self.bridge_batch.name()),
        )


@dataclass(frozen=True)
class SingletonSurface:
    launcher_id: bytes32
    inner_puzzle_hash: bytes32
    full_puzzle_hash: bytes32


@dataclass(frozen=True)
class BridgeBatchPlan:
    policy_hash: bytes32
    parent_coins: tuple[Coin, ...]
    bridge_coins: tuple[Coin, ...]
    low_water_mark: int = GENESIS_BRIDGE_LOW_WATER_MARK


@dataclass(frozen=True)
class GenesisCeremonyPlan:
    ceremony_id: bytes32
    network: str
    evm_chain_id: int
    expires_at: int
    source_shas: Mapping[str, str]
    evm_addresses: Mapping[str, str]
    funding: GenesisFundingCoinIds
    base_protocol: ProtocolDeploymentPlan
    nav_registry: SingletonSurface
    protocol_config: SingletonSurface
    admin_authority: SingletonSurface
    vault_version_registry: SingletonSurface
    property_registry: SingletonSurface
    admin_quorum: admin_authority.GenesisAdminQuorum
    validator_pubkeys: tuple[bytes, bytes, bytes]
    validator_threshold: int
    bridge_batch: BridgeBatchPlan
    trusted_treasury_reserve_puzzle_hash: bytes32
    trusted_protocol_treasury_puzzle_hash: bytes32
    trusted_governance_rewards_puzzle_hash: bytes32
    trusted_governance_rewards_root: bytes32
    retired_coordinates: tuple[bytes32, ...]
    nav_registry_version: int
    protocol_config_version: int
    admin_authority_version: int
    vault_version: int
    property_registry_version: int
    canonical_params_hash: bytes32
    plan_hash: bytes32

    def canonical_payload(self) -> dict[str, Any]:
        return _plan_payload(self, include_hash=True)


@dataclass(frozen=True)
class GenesisCeremonyBundle:
    plan: GenesisCeremonyPlan
    spend_bundle: SpendBundle

    @property
    def spend_bundle_id(self) -> str:
        return _hex(bytes32(self.spend_bundle.name()))


def _plan_payload(
    plan: GenesisCeremonyPlan,
    *,
    include_hash: bool,
) -> dict[str, Any]:
    base = plan.base_protocol
    payload: dict[str, Any] = {
        "schema": GENESIS_PLAN_SCHEMA,
        "protocolVersion": PROTOCOL_VERSION,
        "ceremonyId": _hex(plan.ceremony_id),
        "network": plan.network,
        "evmChainId": plan.evm_chain_id,
        "expiresAt": plan.expires_at,
        "sourceShas": dict(plan.source_shas),
        "evmAddresses": dict(plan.evm_addresses),
        "kosMintExecutePubkey": _hex(plan.base_protocol.kos_mint_execute_pubkey),
        "fundingCoinIds": {
            key: _hex(value)
            for key, value in asdict(plan.funding).items()
        },
        "launcherIds": {
            "pool": _hex(base.pool_launcher_id),
            "did": _hex(base.did_launcher_id),
            "governance": _hex(base.tracker_launcher_id),
            "navRegistry": _hex(plan.nav_registry.launcher_id),
            "protocolConfig": _hex(plan.protocol_config.launcher_id),
            "adminAuthority": _hex(plan.admin_authority.launcher_id),
            "vaultVersionRegistry": _hex(plan.vault_version_registry.launcher_id),
            "propertyRegistry": _hex(plan.property_registry.launcher_id),
        },
        "puzzleHashes": {
            "poolInner": _hex(base.pool_inner_puzhash),
            "poolFull": _hex(base.pool_full_puzhash),
            "didInner": _hex(base.did_inner_puzhash),
            "didFull": _hex(base.did_full_puzhash),
            "governanceInner": _hex(base.tracker_inner_puzhash),
            "governanceFull": _hex(base.tracker_full_puzhash),
            "navRegistryInner": _hex(plan.nav_registry.inner_puzzle_hash),
            "navRegistryFull": _hex(plan.nav_registry.full_puzzle_hash),
            "protocolConfigInner": _hex(plan.protocol_config.inner_puzzle_hash),
            "protocolConfigFull": _hex(plan.protocol_config.full_puzzle_hash),
            "adminAuthorityInner": _hex(plan.admin_authority.inner_puzzle_hash),
            "adminAuthorityFull": _hex(plan.admin_authority.full_puzzle_hash),
            "vaultVersionRegistryInner": _hex(
                plan.vault_version_registry.inner_puzzle_hash
            ),
            "vaultVersionRegistryFull": _hex(
                plan.vault_version_registry.full_puzzle_hash
            ),
            "propertyRegistryInner": _hex(
                plan.property_registry.inner_puzzle_hash
            ),
            "propertyRegistryFull": _hex(
                plan.property_registry.full_puzzle_hash
            ),
            "sgtTail": _hex(base.sgt_tail_hash),
            "bridgePolicy": _hex(plan.bridge_batch.policy_hash),
        },
        "protocolParameters": asdict(base.params),
        "stateVersions": {
            "navRegistry": plan.nav_registry_version,
            "protocolConfig": plan.protocol_config_version,
            "adminAuthority": plan.admin_authority_version,
            "vault": plan.vault_version,
            "propertyRegistry": plan.property_registry_version,
        },
        "adminAuthority": {
            "threshold": plan.admin_quorum.threshold,
            "compressedPubkeys": [
                _hex(pubkey) for pubkey in plan.admin_quorum.compressed_pubkeys
            ],
            "adminsHash": _hex(plan.admin_quorum.admins_hash),
            "mipsRootHash": _hex(plan.admin_quorum.mips_root_hash),
        },
        "validatorSet": {
            "threshold": plan.validator_threshold,
            "pubkeys": [_hex(pubkey) for pubkey in plan.validator_pubkeys],
        },
        "bridgeBatch": {
            "count": len(plan.bridge_batch.bridge_coins),
            "lowWaterMark": plan.bridge_batch.low_water_mark,
            "parentCoinIds": [
                _hex(bytes32(coin.name())) for coin in plan.bridge_batch.parent_coins
            ],
            "bridgeCoinIds": [
                _hex(bytes32(coin.name())) for coin in plan.bridge_batch.bridge_coins
            ],
        },
        "trustedDestinations": {
            "treasuryReservePuzzleHash": _hex(
                plan.trusted_treasury_reserve_puzzle_hash
            ),
            "protocolTreasuryPuzzleHash": _hex(
                plan.trusted_protocol_treasury_puzzle_hash
            ),
            "governanceRewardsPuzzleHash": _hex(
                plan.trusted_governance_rewards_puzzle_hash
            ),
            "governanceRewardsRoot": _hex(plan.trusted_governance_rewards_root),
        },
        "canonicalVaultParamsHash": _hex(plan.canonical_params_hash),
        "retiredCoordinates": [_hex(value) for value in plan.retired_coordinates],
    }
    if include_hash:
        payload["planHash"] = _hex(plan.plan_hash)
    return payload


def _compute_plan_hash(plan: GenesisCeremonyPlan) -> bytes32:
    payload = _plan_payload(plan, include_hash=False)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return bytes32(hashlib.sha256(encoded).digest())


def build_genesis_ceremony_plan(
    *,
    ceremony_id: bytes32,
    expires_at: int,
    source_shas: Mapping[str, str],
    evm_addresses: Mapping[str, str],
    funding: GenesisFundingCoinIds,
    faucet_puzzle_hash: bytes32,
    governance_bls_pubkey: bytes,
    kos_mint_execute_pubkey: bytes,
    admin_compressed_pubkeys: Sequence[bytes],
    validator_pubkeys: Sequence[bytes],
    trusted_treasury_reserve_puzzle_hash: bytes32,
    trusted_protocol_treasury_puzzle_hash: bytes32,
    trusted_governance_rewards_puzzle_hash: bytes32,
    trusted_governance_rewards_root: bytes32,
    retired_coordinates: Sequence[bytes32],
    params: ProtocolDeploymentParams | None = None,
    network: str = GENESIS_NETWORK,
    evm_chain_id: int = GENESIS_EVM_CHAIN_ID,
    nav_registry_version: int = 1,
    protocol_config_version: int = 1,
    admin_authority_version: int = 1,
    vault_version: int = GENESIS_VAULT_VERSION,
    property_registry_version: int = 0,
) -> GenesisCeremonyPlan:
    """Build a complete, immutable dry-run plan without touching a node."""
    if network != GENESIS_NETWORK:
        raise ValueError("fresh Alpha genesis is restricted to testnet11")
    if evm_chain_id != GENESIS_EVM_CHAIN_ID:
        raise ValueError("fresh Alpha genesis is restricted to Sepolia")
    _nonzero_b32(ceremony_id, "ceremony_id")
    _nonzero_b32(faucet_puzzle_hash, "faucet_puzzle_hash")
    if expires_at <= 0:
        raise ValueError("expires_at must be a positive Unix timestamp")
    if len(governance_bls_pubkey) != 48:
        raise ValueError("governance_bls_pubkey must be 48 bytes")
    if len(kos_mint_execute_pubkey) != 48 or kos_mint_execute_pubkey == b"\x00" * 48:
        raise ValueError("kos_mint_execute_pubkey must be a nonzero 48-byte BLS key")
    funding.validate()
    normalized_sources = _normalize_source_shas(source_shas)
    normalized_evm = _normalize_evm_addresses(evm_addresses)
    for label, value in (
        ("trusted_treasury_reserve_puzzle_hash", trusted_treasury_reserve_puzzle_hash),
        ("trusted_protocol_treasury_puzzle_hash", trusted_protocol_treasury_puzzle_hash),
        ("trusted_governance_rewards_puzzle_hash", trusted_governance_rewards_puzzle_hash),
        ("trusted_governance_rewards_root", trusted_governance_rewards_root),
    ):
        _nonzero_b32(value, label)
    retired = tuple(_nonzero_b32(value, "retired coordinate") for value in retired_coordinates)
    if len(set(retired)) != len(retired):
        raise ValueError("retired coordinates must be distinct")
    if nav_registry_version < 1:
        raise ValueError("nav_registry_version must be at least one")
    if protocol_config_version < 1 or admin_authority_version < 1:
        raise ValueError("config and authority versions must be at least one")
    if vault_version != GENESIS_VAULT_VERSION:
        raise ValueError(f"fresh V2 genesis requires vault version {GENESIS_VAULT_VERSION}")
    if property_registry_version != 0:
        raise ValueError("fresh V2 genesis requires an empty property registry")

    resolved_params = params or ProtocolDeploymentParams(
        min_nav_registry_version=nav_registry_version
    )
    if resolved_params.min_nav_registry_version != nav_registry_version:
        raise ValueError("pool NAV floor must equal the launched NAV registry version")

    admin_quorum = admin_authority.build_genesis_eip712_admin_quorum(
        network=network,
        compressed_pubkeys=admin_compressed_pubkeys,
    )
    validator_set = require_genesis_validator_set(
        validator_pubkeys, GENESIS_VALIDATOR_THRESHOLD
    )
    validator_tuple = tuple(validator_set.pubkeys)

    bridge_policy_hash = validator_set.policy_hash
    nav_launcher_id = _launcher_id(funding.nav_registry)
    base = ProtocolDeploymentPlan(
        network=network,
        params=resolved_params,
        faucet_inner_puzhash=faucet_puzzle_hash,
        sgt_genesis_coin_id=funding.sgt,
        pool_genesis_coin_id=funding.pool,
        did_genesis_coin_id=funding.did,
        gov_genesis_coin_id=funding.governance,
        trusted_nav_registry_gov_pubkey=bytes(governance_bls_pubkey),
        kos_mint_execute_pubkey=bytes(kos_mint_execute_pubkey),
        trusted_nav_registry_launcher_id=nav_launcher_id,
        trusted_treasury_reserve_puzhash=trusted_treasury_reserve_puzzle_hash,
        trusted_protocol_treasury_puzhash=trusted_protocol_treasury_puzzle_hash,
        trusted_governance_rewards_puzhash=trusted_governance_rewards_puzzle_hash,
        trusted_governance_rewards_root=trusted_governance_rewards_root,
        trusted_zkpassport_bridge_policy_hash=bridge_policy_hash,
    )

    nav_inner = nav_registry.make_inner_puzzle_hash(
        governance_bls_pubkey,
        nav_registry_version,
        nav_registry.EMPTY_COLLECTION_NAV_ROOT,
    )
    nav_surface = SingletonSurface(
        launcher_id=nav_launcher_id,
        inner_puzzle_hash=nav_inner,
        full_puzzle_hash=singleton_full_puzzle_hash(nav_launcher_id, nav_inner),
    )

    config_launcher_id = _launcher_id(funding.protocol_config)
    config_inner = protocol_config.make_inner_puzzle_hash(
        governance_bls_pubkey,
        base.pool_launcher_id,
        base.tracker_launcher_id,
        protocol_config.NETWORK_ID_TESTNET11,
        protocol_config_version,
    )
    config_surface = SingletonSurface(
        launcher_id=config_launcher_id,
        inner_puzzle_hash=config_inner,
        full_puzzle_hash=singleton_full_puzzle_hash(config_launcher_id, config_inner),
    )

    admin_launcher_id = _launcher_id(funding.admin_authority)
    admin_inner = admin_authority.make_inner_puzzle_hash(
        mips_root_hash=admin_quorum.mips_root_hash,
        admins_hash=admin_quorum.admins_hash,
        pending_ops_hash=admin_authority.EMPTY_LIST_HASH,
        authority_version=admin_authority_version,
        sgt_governance_puzzle_hash=base.tracker_full_puzhash,
    )
    admin_surface = SingletonSurface(
        launcher_id=admin_launcher_id,
        inner_puzzle_hash=admin_inner,
        full_puzzle_hash=singleton_full_puzzle_hash(admin_launcher_id, admin_inner),
    )

    canonical_params_hash = vault_registry.compute_canonical_params_hash(
        pool_singleton_mod_hash=bytes32(SINGLETON_MOD_HASH),
        pool_launcher_id=base.pool_launcher_id,
        pool_singleton_launcher_puzzle_hash=bytes32(SINGLETON_LAUNCHER_HASH),
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    vault_registry_launcher_id = _launcher_id(funding.vault_version_registry)
    vault_registry_inner = vault_registry.make_inner_puzzle_hash(
        admin_authority_launcher_id=admin_launcher_id,
        governance_launcher_id=base.tracker_launcher_id,
        vault_inner_mod_hash=bytes32(VAULT_INNER_MOD.get_tree_hash()),
        canonical_params_hash=canonical_params_hash,
        vault_version=vault_version,
    )
    vault_registry_surface = SingletonSurface(
        launcher_id=vault_registry_launcher_id,
        inner_puzzle_hash=vault_registry_inner,
        full_puzzle_hash=singleton_full_puzzle_hash(
            vault_registry_launcher_id, vault_registry_inner
        ),
    )

    property_registry_launcher_id = _launcher_id(funding.bridge_batch)
    property_registry_inner = property_registry.make_inner_puzzle_hash(
        governance_bls_pubkey,
        property_registry_version,
        property_registry.EMPTY_REGISTERED_IDS_ROOT,
    )
    property_registry_surface = SingletonSurface(
        launcher_id=property_registry_launcher_id,
        inner_puzzle_hash=property_registry_inner,
        full_puzzle_hash=singleton_full_puzzle_hash(
            property_registry_launcher_id, property_registry_inner
        ),
    )

    bridge_parents = tuple(
        Coin(
            funding.bridge_batch,
            faucet_puzzle_hash,
            uint64(amount),
        )
        for amount in range(1, GENESIS_BRIDGE_BATCH_SIZE + 1)
    )
    bridge_coins = tuple(
        Coin(parent.name(), bridge_policy_hash, uint64(1))
        for parent in bridge_parents
    )

    placeholder_hash = bytes32.zeros
    plan = GenesisCeremonyPlan(
        ceremony_id=ceremony_id,
        network=network,
        evm_chain_id=evm_chain_id,
        expires_at=expires_at,
        source_shas=normalized_sources,
        evm_addresses=normalized_evm,
        funding=funding,
        base_protocol=base,
        nav_registry=nav_surface,
        protocol_config=config_surface,
        admin_authority=admin_surface,
        vault_version_registry=vault_registry_surface,
        property_registry=property_registry_surface,
        admin_quorum=admin_quorum,
        validator_pubkeys=validator_tuple,  # type: ignore[arg-type]
        validator_threshold=validator_set.threshold,
        bridge_batch=BridgeBatchPlan(
            policy_hash=bridge_policy_hash,
            parent_coins=bridge_parents,
            bridge_coins=bridge_coins,
        ),
        trusted_treasury_reserve_puzzle_hash=trusted_treasury_reserve_puzzle_hash,
        trusted_protocol_treasury_puzzle_hash=trusted_protocol_treasury_puzzle_hash,
        trusted_governance_rewards_puzzle_hash=trusted_governance_rewards_puzzle_hash,
        trusted_governance_rewards_root=trusted_governance_rewards_root,
        retired_coordinates=retired,
        nav_registry_version=nav_registry_version,
        protocol_config_version=protocol_config_version,
        admin_authority_version=admin_authority_version,
        vault_version=vault_version,
        property_registry_version=property_registry_version,
        canonical_params_hash=canonical_params_hash,
        plan_hash=placeholder_hash,
    )
    object.__setattr__(plan, "plan_hash", _compute_plan_hash(plan))
    return plan


def verify_genesis_ceremony_plan(plan: GenesisCeremonyPlan) -> None:
    """Recompute all deterministic commitments before signatures or broadcast."""
    if plan.network != GENESIS_NETWORK:
        raise ValueError("ceremony plan network is not testnet11")
    if plan.evm_chain_id != GENESIS_EVM_CHAIN_ID:
        raise ValueError("ceremony plan EVM chain is not Sepolia")
    plan.funding.validate()
    if plan.admin_quorum.threshold != GENESIS_ADMIN_THRESHOLD:
        raise ValueError("ceremony plan admin authority is not 2-of-3")
    if plan.validator_threshold != GENESIS_VALIDATOR_THRESHOLD:
        raise ValueError("ceremony plan validator authority is not 2-of-3")
    if len(plan.validator_pubkeys) != 3 or len(set(plan.validator_pubkeys)) != 3:
        raise ValueError("ceremony plan validator set is not three distinct keys")
    if len(plan.bridge_batch.bridge_coins) != GENESIS_BRIDGE_BATCH_SIZE:
        raise ValueError("ceremony plan does not contain 32 bridge coins")
    if plan.plan_hash != _compute_plan_hash(plan):
        raise ValueError("ceremony plan hash does not match canonical content")


def _signed_faucet_spend(
    *,
    faucet: Any,
    coin: Coin,
    conditions: Sequence[Program],
) -> tuple[CoinSpend, Any]:
    delegated_puzzle = Program.to((1, Program.to(list(conditions))))
    solution = Program.to([0, delegated_puzzle, Program.to(0)])
    coin_spend = make_spend(coin, faucet.key.puzzle, solution)
    message = (
        bytes(delegated_puzzle.get_tree_hash())
        + bytes(coin.name())
        + bytes(faucet.agg_sig_me_data)
    )
    return coin_spend, AugSchemeMPL.sign(faucet.key.wallet_sk, message)


def _funding_spend(
    *,
    faucet: Any,
    coin: Coin,
    target_puzzle_hash: bytes32,
    target_amount: int,
    fee: int,
) -> tuple[CoinSpend, Any]:
    if int(coin.amount) < target_amount + fee:
        raise ValueError("genesis funding coin is too small")
    conditions = [Program.to([51, target_puzzle_hash, target_amount])]
    change = int(coin.amount) - target_amount - fee
    if change:
        conditions.append(Program.to([51, faucet.address_puzzle_hash, change]))
    if fee:
        conditions.append(Program.to([52, fee]))
    return _signed_faucet_spend(faucet=faucet, coin=coin, conditions=conditions)


def _singleton_spends(
    *,
    faucet: Any,
    funding_coin: Coin,
    surface: SingletonSurface,
    fee: int,
) -> tuple[list[CoinSpend], Any]:
    parent_spend, signature = _funding_spend(
        faucet=faucet,
        coin=funding_coin,
        target_puzzle_hash=bytes32(SINGLETON_LAUNCHER_HASH),
        target_amount=1,
        fee=fee,
    )
    launcher_coin = Coin(
        funding_coin.name(), bytes32(SINGLETON_LAUNCHER_HASH), uint64(1)
    )
    if bytes32(launcher_coin.name()) != surface.launcher_id:
        raise ValueError("derived launcher id does not match ceremony plan")
    launcher_spend = make_spend(
        launcher_coin,
        SINGLETON_LAUNCHER,
        Program.to([surface.inner_puzzle_hash, 1, []]),
    )
    return [parent_spend, launcher_spend], signature


def build_genesis_ceremony_bundle(
    *,
    plan: GenesisCeremonyPlan,
    faucet: Any,
    funding_coins: GenesisFundingCoins,
    fee_per_funding_spend: int = 0,
) -> GenesisCeremonyBundle:
    """Build the one-shot bundle after rechecking all nine live inputs."""
    verify_genesis_ceremony_plan(plan)
    if fee_per_funding_spend < 0:
        raise ValueError("fee_per_funding_spend must be non-negative")
    actual_ids = funding_coins.ids()
    actual_ids.validate()
    if actual_ids != plan.funding:
        raise ValueError("live funding coins do not match the signed ceremony plan")
    for coin in funding_coins.values():
        if coin.puzzle_hash != faucet.address_puzzle_hash:
            raise ValueError("every genesis funding coin must belong to the ceremony faucet")

    spends: list[CoinSpend] = []
    signatures: list[Any] = []
    sgt_spend, sgt_signature = _funding_spend(
        faucet=faucet,
        coin=funding_coins.sgt,
        target_puzzle_hash=plan.base_protocol.sgt_full_puzhash,
        target_amount=plan.base_protocol.params.sgt_total_supply,
        fee=fee_per_funding_spend,
    )
    spends.append(sgt_spend)
    signatures.append(sgt_signature)

    singleton_inputs = (
        (funding_coins.pool, SingletonSurface(
            plan.base_protocol.pool_launcher_id,
            plan.base_protocol.pool_inner_puzhash,
            plan.base_protocol.pool_full_puzhash,
        )),
        (funding_coins.did, SingletonSurface(
            plan.base_protocol.did_launcher_id,
            plan.base_protocol.did_inner_puzhash,
            plan.base_protocol.did_full_puzhash,
        )),
        (funding_coins.governance, SingletonSurface(
            plan.base_protocol.tracker_launcher_id,
            plan.base_protocol.tracker_inner_puzhash,
            plan.base_protocol.tracker_full_puzhash,
        )),
        (funding_coins.nav_registry, plan.nav_registry),
        (funding_coins.protocol_config, plan.protocol_config),
        (funding_coins.admin_authority, plan.admin_authority),
        (funding_coins.vault_version_registry, plan.vault_version_registry),
    )
    for funding_coin, surface in singleton_inputs:
        surface_spends, signature = _singleton_spends(
            faucet=faucet,
            funding_coin=funding_coin,
            surface=surface,
            fee=fee_per_funding_spend,
        )
        spends.extend(surface_spends)
        signatures.append(signature)

    bridge_total = sum(int(coin.amount) for coin in plan.bridge_batch.parent_coins)
    property_registry_launcher_amount = 1
    if int(funding_coins.bridge_batch.amount) < (
        bridge_total + property_registry_launcher_amount + fee_per_funding_spend
    ):
        raise ValueError("bridge batch funding coin is too small")
    batch_conditions = [
        Program.to([51, faucet.address_puzzle_hash, int(parent.amount)])
        for parent in plan.bridge_batch.parent_coins
    ]
    batch_conditions.append(
        Program.to([51, bytes32(SINGLETON_LAUNCHER_HASH), 1])
    )
    bridge_change = (
        int(funding_coins.bridge_batch.amount)
        - bridge_total
        - property_registry_launcher_amount
        - fee_per_funding_spend
    )
    if bridge_change:
        batch_conditions.append(
            Program.to([51, faucet.address_puzzle_hash, bridge_change])
        )
    if fee_per_funding_spend:
        batch_conditions.append(Program.to([52, fee_per_funding_spend]))
    batch_spend, batch_signature = _signed_faucet_spend(
        faucet=faucet,
        coin=funding_coins.bridge_batch,
        conditions=batch_conditions,
    )
    spends.append(batch_spend)
    signatures.append(batch_signature)

    property_registry_launcher_coin = Coin(
        funding_coins.bridge_batch.name(),
        bytes32(SINGLETON_LAUNCHER_HASH),
        uint64(1),
    )
    if bytes32(property_registry_launcher_coin.name()) != plan.property_registry.launcher_id:
        raise ValueError("derived property registry launcher id does not match plan")
    spends.append(
        make_spend(
            property_registry_launcher_coin,
            SINGLETON_LAUNCHER,
            Program.to([plan.property_registry.inner_puzzle_hash, 1, []]),
        )
    )

    for parent, bridge_coin in zip(
        plan.bridge_batch.parent_coins,
        plan.bridge_batch.bridge_coins,
        strict=True,
    ):
        if parent.parent_coin_info != funding_coins.bridge_batch.name():
            raise ValueError("bridge parent lineage does not match batch input")
        if bridge_coin.parent_coin_info != parent.name():
            raise ValueError("bridge coin lineage does not match predicted parent")
        conditions = [Program.to([51, plan.bridge_batch.policy_hash, 1])]
        if int(parent.amount) > 1:
            conditions.append(
                Program.to([51, faucet.address_puzzle_hash, int(parent.amount) - 1])
            )
        parent_spend, signature = _signed_faucet_spend(
            faucet=faucet,
            coin=parent,
            conditions=conditions,
        )
        spends.append(parent_spend)
        signatures.append(signature)

    if len(spends) != 49:
        raise ValueError(f"ceremony bundle must contain 49 spends, got {len(spends)}")
    return GenesisCeremonyBundle(
        plan=plan,
        spend_bundle=SpendBundle(
            spends,
            AugSchemeMPL.aggregate(signatures),
        ),
    )


__all__ = [
    "GENESIS_PLAN_SCHEMA",
    "GENESIS_NETWORK",
    "GENESIS_EVM_CHAIN_ID",
    "GENESIS_BRIDGE_BATCH_SIZE",
    "GenesisFundingCoinIds",
    "GenesisFundingCoins",
    "SingletonSurface",
    "BridgeBatchPlan",
    "GenesisCeremonyPlan",
    "GenesisCeremonyBundle",
    "build_genesis_ceremony_plan",
    "verify_genesis_ceremony_plan",
    "build_genesis_ceremony_bundle",
]
