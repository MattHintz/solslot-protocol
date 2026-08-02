"""Fresh RC23 testnet genesis plan and atomic ceremony bundle."""
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
from chia_rs import AugSchemeMPL, G1Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import admin_authority_v3_driver as admin_authority
from solslot_puzzles import protocol_config_driver as protocol_config
from solslot_puzzles import property_registry_driver as property_registry
from solslot_puzzles import vault_version_registry_driver as vault_registry
from solslot_puzzles.admin_authority_v2_driver import (
    build_genesis_eip712_admin_quorum,
)
from solslot_puzzles.genesis_ceremony import (
    GENESIS_ADMIN_COADMIN_INDICES,
    GENESIS_ADMIN_COADMIN_THRESHOLD,
    GENESIS_ADMIN_OWNER_INDEX,
    GENESIS_ADMIN_POLICY,
    GENESIS_ADMIN_THRESHOLD,
    GENESIS_BRIDGE_BATCH_SIZE,
    GENESIS_BRIDGE_LOW_WATER_MARK,
    GENESIS_EVM_CHAIN_ID,
    GENESIS_NETWORK,
    GENESIS_VALIDATOR_THRESHOLD,
    BridgeBatchPlan,
    SingletonSurface,
    _funding_spend,
    _normalize_evm_addresses,
    _normalize_source_shas,
    _signed_faucet_spend,
    _singleton_spends,
)
from solslot_puzzles.recovery_dependencies import (
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)
from solslot_puzzles.eip712_helpers import keccak256
from solslot_puzzles.protocol_deployment import singleton_full_puzzle_hash
from solslot_puzzles.protocol_deployment_rc22 import (
    RC22ProtocolDeploymentPlan,
    build_rc22_protocol_deployment_plan,
)
from solslot_puzzles.protocol_statutes_v1 import (
    MAX_EXCHANGE_FEE_BPS,
    UPGRADE_DELAY_SECONDS,
    ProtocolParameters,
)
from solslot_puzzles.zkpassport_bridge_driver import (
    require_genesis_validator_set,
)


RC23_GENESIS_PLAN_SCHEMA = "solslot-genesis-plan-v4"
RC23_PROTOCOL_VERSION = "solslot-v2-rc23"
RC23_SOURCE_MANIFEST_VERSION = 4
RC23_BRIDGE_PARENT_TOTAL = sum(range(1, GENESIS_BRIDGE_BATCH_SIZE + 1))
RC23_PROPERTY_REGISTRY_LAUNCHER_AMOUNT = 1
RC23_BRIDGE_BATCH_BUFFER_AMOUNT = 1
RC23_SOLS_RESERVE_SEED_AMOUNT = 1
RC23_POOL_FUNDING_AMOUNT = (
    RC23_PROPERTY_REGISTRY_LAUNCHER_AMOUNT
    + RC23_SOLS_RESERVE_SEED_AMOUNT
)
RC23_BRIDGE_BATCH_FUNDING_AMOUNT = (
    RC23_BRIDGE_PARENT_TOTAL
    + RC23_PROPERTY_REGISTRY_LAUNCHER_AMOUNT
    + RC23_BRIDGE_BATCH_BUFFER_AMOUNT
)
RC23_VAULT_VERSION = 2
RC23_ADMIN_AUTHORITY_FUNDING_AMOUNT = (
    admin_authority.ADMIN_AUTHORITY_FUNDING_AMOUNT
)


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _nonzero(value: bytes32, label: str) -> bytes32:
    if value == bytes32.zeros:
        raise ValueError(f"{label} must be a nonzero 32-byte value")
    return value


def _launcher_id(parent_coin_id: bytes32) -> bytes32:
    return bytes32(
        Coin(
            parent_coin_id,
            bytes32(SINGLETON_LAUNCHER_HASH),
            uint64(1),
        ).name()
    )


@dataclass(frozen=True)
class RC23GenesisFundingCoinIds:
    sgt: bytes32
    pool: bytes32
    did: bytes32
    governance: bytes32
    statutes: bytes32
    protocol_config: bytes32
    admin_authority: bytes32
    vault_version_registry: bytes32
    bridge_batch: bytes32

    def values(self) -> tuple[bytes32, ...]:
        return tuple(asdict(self).values())

    def validate(self) -> None:
        for label, value in asdict(self).items():
            _nonzero(value, f"funding coin {label}")
        if len(set(self.values())) != 9:
            raise ValueError("all nine RC23 funding coin IDs must be distinct")


@dataclass(frozen=True)
class RC23GenesisFundingCoins:
    sgt: Coin
    pool: Coin
    did: Coin
    governance: Coin
    statutes: Coin
    protocol_config: Coin
    admin_authority: Coin
    vault_version_registry: Coin
    bridge_batch: Coin

    def values(self) -> tuple[Coin, ...]:
        return tuple(asdict(self).values())

    def ids(self) -> RC23GenesisFundingCoinIds:
        return RC23GenesisFundingCoinIds(
            **{
                label: bytes32(coin.name())
                for label, coin in asdict(self).items()
            }
        )


@dataclass(frozen=True)
class AdminRecoveryKitCommitment:
    """Public recovery identity sealed into the signed ceremony plan."""

    slot: int
    revision: int
    evm_guardian: str
    recovery_bls_pubkey: bytes
    recovery_bls_commitment: bytes32
    drill_challenge_hash: bytes32

    def validate(self) -> None:
        if self.slot not in range(3):
            raise ValueError("recovery-kit slot must be 0, 1, or 2")
        if self.revision < 1:
            raise ValueError("recovery-kit revision must be at least one")
        guardian = self.evm_guardian.lower()
        if not guardian.startswith("0x") or len(guardian) != 42:
            raise ValueError(
                "recovery-kit EVM guardian must be a 20-byte address"
            )
        try:
            guardian_bytes = bytes.fromhex(guardian[2:])
        except ValueError as exc:
            raise ValueError(
                "recovery-kit EVM guardian must be valid hex"
            ) from exc
        if guardian_bytes == b"\x00" * 20:
            raise ValueError("recovery-kit EVM guardian cannot be zero")
        G1Element.from_bytes(self.recovery_bls_pubkey)
        expected = bytes32(keccak256(self.recovery_bls_pubkey))
        if self.recovery_bls_commitment != expected:
            raise ValueError(
                "recovery-kit BLS commitment does not match its key"
            )
        _nonzero(
            self.drill_challenge_hash,
            "recovery-kit drill challenge hash",
        )


@dataclass(frozen=True)
class RC23GenesisCeremonyPlan:
    ceremony_id: bytes32
    network: str
    evm_chain_id: int
    expires_at: int
    source_shas: Mapping[str, str]
    recovery_dependency_manifest_hash: bytes32
    evm_addresses: Mapping[str, str]
    funding: RC23GenesisFundingCoinIds
    protocol: RC22ProtocolDeploymentPlan
    protocol_config: SingletonSurface
    admin_authority: SingletonSurface
    vault_version_registry: SingletonSurface
    property_registry: SingletonSurface
    admin_authority_v3: admin_authority.GenesisAdminAuthorityV3
    admin_roster_hash: bytes32
    admin_recovery_kits: tuple[
        AdminRecoveryKitCommitment,
        AdminRecoveryKitCommitment,
        AdminRecoveryKitCommitment,
    ]
    validator_pubkeys: tuple[bytes, bytes, bytes]
    validator_threshold: int
    bridge_batch: BridgeBatchPlan
    protocol_config_version: int
    admin_authority_version: int
    vault_version: int
    property_registry_version: int
    canonical_vault_params_hash: bytes32
    retired_coordinates: tuple[bytes32, ...]
    plan_hash: bytes32

    @property
    def statutes(self) -> SingletonSurface:
        return SingletonSurface(
            self.protocol.statutes_launcher_id,
            self.protocol.statutes_inner_puzzle_hash,
            self.protocol.statutes_full_puzzle_hash,
        )

    def canonical_payload(self) -> dict[str, Any]:
        return _plan_payload(self, include_hash=True)


@dataclass(frozen=True)
class RC23GenesisCeremonyBundle:
    plan: RC23GenesisCeremonyPlan
    spend_bundle: SpendBundle

    @property
    def spend_bundle_id(self) -> str:
        return _hex(bytes32(self.spend_bundle.name()))


def _plan_payload(
    plan: RC23GenesisCeremonyPlan,
    *,
    include_hash: bool,
) -> dict[str, Any]:
    protocol = plan.protocol
    payload: dict[str, Any] = {
        "schema": RC23_GENESIS_PLAN_SCHEMA,
        "protocolVersion": RC23_PROTOCOL_VERSION,
        "ceremonyId": _hex(plan.ceremony_id),
        "network": plan.network,
        "evmChainId": plan.evm_chain_id,
        "expiresAt": plan.expires_at,
        "sourceManifestVersion": RC23_SOURCE_MANIFEST_VERSION,
        "sourceShas": dict(plan.source_shas),
        "recoveryDependencyManifestHash": _hex(
            plan.recovery_dependency_manifest_hash
        ),
        "evmAddresses": dict(plan.evm_addresses),
        "faucetPuzzleHash": _hex(
            protocol.faucet_inner_puzzle_hash
        ),
        "governanceBlsPubkey": _hex(protocol.governance_bls_pubkey),
        "kosMintExecutePubkey": _hex(
            protocol.kos_mint_execute_pubkey
        ),
        "fundingCoinIds": {
            key: _hex(value)
            for key, value in asdict(plan.funding).items()
        },
        "launcherIds": {
            "pool": _hex(protocol.pool_launcher_id),
            "did": _hex(protocol.did_launcher_id),
            "governance": _hex(protocol.governance_launcher_id),
            "statutes": _hex(protocol.statutes_launcher_id),
            "protocolConfig": _hex(plan.protocol_config.launcher_id),
            "adminAuthority": _hex(plan.admin_authority.launcher_id),
            "adminIdentity0": _hex(
                plan.admin_authority_v3.identity_vaults[0].launcher_id
            ),
            "adminIdentity1": _hex(
                plan.admin_authority_v3.identity_vaults[1].launcher_id
            ),
            "adminIdentity2": _hex(
                plan.admin_authority_v3.identity_vaults[2].launcher_id
            ),
            "vaultVersionRegistry": _hex(
                plan.vault_version_registry.launcher_id
            ),
            "propertyRegistry": _hex(plan.property_registry.launcher_id),
        },
        "solsReserveSeed": {
            "amount": RC23_SOLS_RESERVE_SEED_AMOUNT,
            "puzzleHash": _hex(
                protocol.sols_reserve_seed_puzzle_hash
            ),
            "coinId": _hex(protocol.sols_reserve_seed_coin_id),
            "circulating": False,
            "purpose": "permanent-cat-lineage-anchor",
        },
        "puzzleHashes": {
            "poolInnerMod": _hex(protocol.pool_inner_mod_hash),
            "poolInner": _hex(protocol.pool_inner_puzzle_hash),
            "poolFull": _hex(protocol.pool_full_puzzle_hash),
            "governanceInner": _hex(
                protocol.governance_inner_puzzle_hash
            ),
            "governanceFull": _hex(
                protocol.governance_full_puzzle_hash
            ),
            "statutesInnerMod": _hex(protocol.statutes_inner_mod_hash),
            "statutesInner": _hex(protocol.statutes_inner_puzzle_hash),
            "statutesFull": _hex(protocol.statutes_full_puzzle_hash),
            "didInner": _hex(protocol.did_inner_puzzle_hash),
            "didFull": _hex(protocol.did_full_puzzle_hash),
            "protocolConfigInner": _hex(
                plan.protocol_config.inner_puzzle_hash
            ),
            "protocolConfigFull": _hex(
                plan.protocol_config.full_puzzle_hash
            ),
            "adminAuthorityInner": _hex(
                plan.admin_authority.inner_puzzle_hash
            ),
            "adminAuthorityFull": _hex(
                plan.admin_authority.full_puzzle_hash
            ),
            "adminAuthorityInnerMod": _hex(
                admin_authority.admin_authority_v3_inner_mod_hash()
            ),
            "adminIdentityCustody": [
                _hex(identity.custody_hash)
                for identity in plan.admin_authority_v3.identity_vaults
            ],
            "adminIdentityFull": [
                _hex(identity.full_puzzle_hash)
                for identity in plan.admin_authority_v3.identity_vaults
            ],
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
            "sgtTail": _hex(protocol.sgt_tail_hash),
            "sgtReserveInner": _hex(
                protocol.sgt_reserve_inner_puzzle_hash
            ),
            "solsTail": _hex(protocol.sols_tail_hash),
            "bridgePolicy": _hex(
                protocol.trusted_zkpassport_bridge_policy_hash
            ),
        },
        "protocolParameters": {
            "votingWindowSeconds": protocol.parameters.voting_window_seconds,
            "quorumBps": protocol.parameters.quorum_bps,
            "minProposalStake": protocol.parameters.min_proposal_stake,
            "navValiditySeconds": protocol.parameters.nav_validity_seconds,
            "oracleMaxAgeSeconds": (
                protocol.parameters.oracle_max_age_seconds
            ),
            "exchangeFeeBps": protocol.parameters.exchange_fee_bps,
            "protocolFeeBps": protocol.parameters.protocol_fee_bps,
            "sgtRewardsFeeBps": protocol.parameters.sgt_rewards_fee_bps,
            "rewardEpochSeconds": protocol.parameters.reward_epoch_seconds,
            "sgtTotalSupply": protocol.permanent_rules.sgt_total_supply,
        },
        "permanentRules": {
            "sgtTailHash": _hex(protocol.permanent_rules.sgt_tail_hash),
            "sgtTotalSupply": protocol.permanent_rules.sgt_total_supply,
            "solsTailHash": _hex(protocol.permanent_rules.sols_tail_hash),
            "zkPassportPolicyHash": _hex(
                protocol.permanent_rules.zkpassport_policy_hash
            ),
            "protocolTreasuryPuzzleHash": _hex(
                protocol.permanent_rules.protocol_treasury_puzzle_hash
            ),
            "networkId": _hex(protocol.permanent_rules.network_id),
            "maxExchangeFeeBps": MAX_EXCHANGE_FEE_BPS,
            "upgradeDelaySeconds": UPGRADE_DELAY_SECONDS,
            "voteConservation": True,
            "replayProtection": True,
            "treasuryNonWithdrawal": True,
            "protocolOnlySmartDeedSolsExchange": True,
            "zkPassportRequired": True,
            "solsSupplyNeverMelted": True,
            "solsPrimaryPurchasesDisabled": True,
        },
        "state": {
            "statutesVersion": protocol.statutes_state.registry_version,
            "statutesContentHash": _hex(
                protocol.statutes_state.content_hash
            ),
            "statutesRoots": {
                "parameters": _hex(
                    protocol.statutes_state.parameters_root
                ),
                "collections": _hex(
                    protocol.statutes_state.collections_root
                ),
                "oracles": _hex(protocol.statutes_state.oracle_root),
                "bridgeRoutes": _hex(
                    protocol.statutes_state.routes_root
                ),
                "liquidityVenues": _hex(
                    protocol.statutes_state.liquidity_root
                ),
                "pauses": _hex(protocol.statutes_state.pauses_root),
            },
            "poolVersion": protocol.pool_state.state_version,
            "poolCommitmentHash": _hex(
                protocol.pool_state.commitment_hash
            ),
            "protocolConfigVersion": plan.protocol_config_version,
            "adminAuthorityVersion": plan.admin_authority_version,
            "vaultVersion": plan.vault_version,
            "propertyRegistryVersion": plan.property_registry_version,
        },
        "adminAuthority": {
            "version": 3,
            "threshold": GENESIS_ADMIN_THRESHOLD,
            "policy": GENESIS_ADMIN_POLICY,
            "ownerIndex": GENESIS_ADMIN_OWNER_INDEX,
            "coadminIndices": list(GENESIS_ADMIN_COADMIN_INDICES),
            "coadminThreshold": GENESIS_ADMIN_COADMIN_THRESHOLD,
            "sourceManifestHash": _hex(
                plan.admin_authority_v3.source_manifest_hash
            ),
            "operationalMipsRootHash": _hex(
                plan.admin_authority_v3.operational_root_hash
            ),
            "lostRecoveryMipsRootHashes": [
                _hex(root_hash)
                for root_hash in (
                    plan.admin_authority_v3.lost_recovery_root_hashes
                )
            ],
            "routineDelaySeconds": admin_authority.ROUTINE_DELAY_SECONDS,
            "lostKeyDelaySeconds": (
                admin_authority.LOST_KEY_DELAY_SECONDS
            ),
            "pending": False,
            "identityVaults": [
                {
                    "slot": identity.slot,
                    "launcherAmount": identity.launcher_amount,
                    "launcherId": _hex(identity.launcher_id),
                    "dailyCompressedPubkey": _hex(
                        identity.daily_compressed_pubkey
                    ),
                    "dailyMemberHash": _hex(identity.daily_member_hash),
                    "recoveryMemberHash": _hex(
                        identity.recovery_member_hash
                    ),
                    "recoveryBlsPubkey": _hex(
                        identity.recovery_bls_pubkey
                    ),
                    "custodyHash": _hex(identity.custody_hash),
                    "fullPuzzleHash": _hex(identity.full_puzzle_hash),
                }
                for identity in plan.admin_authority_v3.identity_vaults
            ],
            "compressedPubkeys": [
                _hex(identity.daily_compressed_pubkey)
                for identity in plan.admin_authority_v3.identity_vaults
            ],
            "adminsHash": _hex(plan.admin_roster_hash),
            "fundingAmount": RC23_ADMIN_AUTHORITY_FUNDING_AMOUNT,
        },
        "adminRecoveryKits": [
            {
                "slot": kit.slot,
                "revision": kit.revision,
                "evmGuardian": kit.evm_guardian.lower(),
                "recoveryBlsPubkey": _hex(kit.recovery_bls_pubkey),
                "recoveryBlsCommitment": _hex(
                    kit.recovery_bls_commitment
                ),
                "drillChallengeHash": _hex(kit.drill_challenge_hash),
            }
            for kit in plan.admin_recovery_kits
        ],
        "validatorSet": {
            "threshold": plan.validator_threshold,
            "pubkeys": [_hex(pubkey) for pubkey in plan.validator_pubkeys],
        },
        "bridgeBatch": {
            "fundingAmount": RC23_BRIDGE_BATCH_FUNDING_AMOUNT,
            "parentOutputAmount": RC23_BRIDGE_PARENT_TOTAL,
            "propertyRegistryLauncherAmount": (
                RC23_PROPERTY_REGISTRY_LAUNCHER_AMOUNT
            ),
            "bufferFeeAmount": RC23_BRIDGE_BATCH_BUFFER_AMOUNT,
            "changeAmount": 0,
            "networkFeeSource": "separate-fountain-fee-till",
            "count": len(plan.bridge_batch.bridge_coins),
            "lowWaterMark": plan.bridge_batch.low_water_mark,
            "parentCoinIds": [
                _hex(bytes32(coin.name()))
                for coin in plan.bridge_batch.parent_coins
            ],
            "bridgeCoinIds": [
                _hex(bytes32(coin.name()))
                for coin in plan.bridge_batch.bridge_coins
            ],
        },
        "trustedDestinations": {
            "treasuryReservePuzzleHash": _hex(
                protocol.trusted_treasury_reserve_puzzle_hash
            ),
            "protocolTreasuryPuzzleHash": _hex(
                protocol.trusted_protocol_treasury_puzzle_hash
            ),
            "companySgtSaleTreasuryPuzzleHash": _hex(
                protocol.company_sgt_sale_treasury_puzzle_hash
            ),
            "governanceRewardsPuzzleHash": _hex(
                protocol.trusted_governance_rewards_puzzle_hash
            ),
            "governanceRewardsRoot": _hex(
                protocol.trusted_governance_rewards_root
            ),
        },
        "trustedAssets": {
            "wusdcBAssetId": _hex(protocol.wusdc_b_asset_id),
        },
        "canonicalVaultParamsHash": _hex(
            plan.canonical_vault_params_hash
        ),
        "retiredCoordinates": [
            _hex(value) for value in plan.retired_coordinates
        ],
    }
    if include_hash:
        payload["planHash"] = _hex(plan.plan_hash)
    return payload


def _compute_plan_hash(plan: RC23GenesisCeremonyPlan) -> bytes32:
    payload = _plan_payload(plan, include_hash=False)
    return bytes32(
        hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).digest()
    )


def _source_manifest_hash(
    source_shas: Mapping[str, str],
    recovery_dependency_manifest_hash: bytes32,
) -> bytes32:
    return bytes32(
        hashlib.sha256(
            json.dumps(
                {
                    "version": RC23_SOURCE_MANIFEST_VERSION,
                    "sources": source_shas,
                    "dependencies": {
                        "administratorRecovery": _hex(
                            recovery_dependency_manifest_hash
                        )
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).digest()
    )


def build_rc23_genesis_ceremony_plan(
    *,
    ceremony_id: bytes32,
    expires_at: int,
    source_shas: Mapping[str, str],
    evm_addresses: Mapping[str, str],
    funding: RC23GenesisFundingCoinIds,
    faucet_puzzle_hash: bytes32,
    governance_bls_pubkey: bytes,
    kos_mint_execute_pubkey: bytes,
    admin_compressed_pubkeys: Sequence[bytes],
    admin_recovery_bls_pubkeys: Sequence[bytes],
    admin_recovery_evm_guardians: Sequence[str],
    admin_recovery_revisions: Sequence[int],
    admin_recovery_drill_hashes: Sequence[bytes32],
    validator_pubkeys: Sequence[bytes],
    trusted_treasury_reserve_puzzle_hash: bytes32,
    trusted_protocol_treasury_puzzle_hash: bytes32,
    company_sgt_sale_treasury_puzzle_hash: bytes32,
    wusdc_b_asset_id: bytes32,
    trusted_governance_rewards_puzzle_hash: bytes32,
    trusted_governance_rewards_root: bytes32,
    retired_coordinates: Sequence[bytes32],
    recovery_dependency_manifest_hash: bytes32 | None = None,
    parameters: ProtocolParameters | None = None,
    network: str = GENESIS_NETWORK,
    evm_chain_id: int = GENESIS_EVM_CHAIN_ID,
    protocol_config_version: int = 1,
    admin_authority_version: int = 1,
    vault_version: int = RC23_VAULT_VERSION,
    property_registry_version: int = 0,
) -> RC23GenesisCeremonyPlan:
    if network != GENESIS_NETWORK:
        raise ValueError("RC23 fresh genesis is restricted to testnet11")
    if evm_chain_id != GENESIS_EVM_CHAIN_ID:
        raise ValueError("RC23 fresh genesis requires Base Sepolia")
    _nonzero(ceremony_id, "ceremony_id")
    _nonzero(faucet_puzzle_hash, "faucet_puzzle_hash")
    if expires_at <= 0:
        raise ValueError("expires_at must be positive")
    funding.validate()
    normalized_sources = _normalize_source_shas(source_shas)
    dependency_manifest_hash = (
        recovery_dependency_manifest_hash
        if recovery_dependency_manifest_hash is not None
        else bytes32.from_hexstr(RECOVERY_DEPENDENCY_MANIFEST_HASH)
    )
    _nonzero(
        dependency_manifest_hash,
        "recovery dependency manifest hash",
    )
    normalized_evm = _normalize_evm_addresses(evm_addresses)
    if protocol_config_version < 1 or admin_authority_version < 1:
        raise ValueError("config and authority versions must be at least one")
    if vault_version != RC23_VAULT_VERSION:
        raise ValueError("RC23 fresh genesis requires vault version 2")
    if property_registry_version != 0:
        raise ValueError("fresh genesis requires an empty property registry")
    retired = tuple(
        _nonzero(value, "retired coordinate")
        for value in retired_coordinates
    )
    if len(retired) != len(set(retired)):
        raise ValueError("retired coordinates must be distinct")

    source_manifest_hash = _source_manifest_hash(
        normalized_sources,
        dependency_manifest_hash,
    )
    authority_v3 = admin_authority.build_genesis_admin_authority_v3(
        parent_coin_id=funding.admin_authority,
        network=network,
        daily_compressed_pubkeys=admin_compressed_pubkeys,
        recovery_bls_pubkeys=admin_recovery_bls_pubkeys,
        source_manifest_hash=source_manifest_hash,
    )
    roster_receipt = build_genesis_eip712_admin_quorum(
        network=network,
        compressed_pubkeys=admin_compressed_pubkeys,
    )
    if not (
        len(admin_recovery_evm_guardians)
        == len(admin_recovery_revisions)
        == len(admin_recovery_drill_hashes)
        == 3
    ):
        raise ValueError(
            "exactly three drilled administrator recovery kits are required"
        )
    recovery_kits = tuple(
        AdminRecoveryKitCommitment(
            slot=slot,
            revision=int(admin_recovery_revisions[slot]),
            evm_guardian=str(
                admin_recovery_evm_guardians[slot]
            ).lower(),
            recovery_bls_pubkey=authority_v3.identity_vaults[
                slot
            ].recovery_bls_pubkey,
            recovery_bls_commitment=bytes32(
                keccak256(
                    authority_v3.identity_vaults[
                        slot
                    ].recovery_bls_pubkey
                )
            ),
            drill_challenge_hash=admin_recovery_drill_hashes[slot],
        )
        for slot in range(3)
    )
    for kit in recovery_kits:
        kit.validate()
    if len({kit.evm_guardian for kit in recovery_kits}) != 3:
        raise ValueError(
            "administrator recovery EVM guardians must be distinct"
        )
    if len({kit.drill_challenge_hash for kit in recovery_kits}) != 3:
        raise ValueError("administrator recovery drills must be distinct")
    validator_set = require_genesis_validator_set(
        validator_pubkeys,
        GENESIS_VALIDATOR_THRESHOLD,
    )
    bridge_policy_hash = validator_set.policy_hash
    resolved_parameters = parameters or ProtocolParameters()
    protocol = build_rc22_protocol_deployment_plan(
        network=network,
        parameters=resolved_parameters,
        faucet_inner_puzzle_hash=faucet_puzzle_hash,
        sgt_genesis_coin_id=funding.sgt,
        pool_genesis_coin_id=funding.pool,
        did_genesis_coin_id=funding.did,
        governance_genesis_coin_id=funding.governance,
        statutes_genesis_coin_id=funding.statutes,
        admin_authority_genesis_coin_id=funding.admin_authority,
        governance_bls_pubkey=governance_bls_pubkey,
        kos_mint_execute_pubkey=kos_mint_execute_pubkey,
        trusted_treasury_reserve_puzzle_hash=(
            trusted_treasury_reserve_puzzle_hash
        ),
        trusted_protocol_treasury_puzzle_hash=(
            trusted_protocol_treasury_puzzle_hash
        ),
        company_sgt_sale_treasury_puzzle_hash=(
            company_sgt_sale_treasury_puzzle_hash
        ),
        wusdc_b_asset_id=wusdc_b_asset_id,
        trusted_governance_rewards_puzzle_hash=(
            trusted_governance_rewards_puzzle_hash
        ),
        trusted_governance_rewards_root=trusted_governance_rewards_root,
        trusted_zkpassport_bridge_policy_hash=bridge_policy_hash,
    )

    config_launcher_id = _launcher_id(funding.protocol_config)
    config_inner = protocol_config.make_inner_puzzle_hash(
        governance_bls_pubkey,
        protocol.pool_launcher_id,
        protocol.governance_launcher_id,
        protocol_config.NETWORK_ID_TESTNET11,
        protocol_config_version,
    )
    config_surface = SingletonSurface(
        config_launcher_id,
        config_inner,
        singleton_full_puzzle_hash(config_launcher_id, config_inner),
    )

    admin_inner = authority_v3.inner_puzzle_hash
    admin_surface = SingletonSurface(
        authority_v3.authority_launcher_id,
        admin_inner,
        authority_v3.full_puzzle_hash,
    )

    canonical_vault_params_hash = (
        vault_registry.compute_canonical_params_hash(
            pool_singleton_mod_hash=bytes32(SINGLETON_MOD_HASH),
            pool_launcher_id=protocol.pool_launcher_id,
            pool_singleton_launcher_puzzle_hash=bytes32(
                SINGLETON_LAUNCHER_HASH
            ),
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
    )
    vault_launcher_id = _launcher_id(funding.vault_version_registry)
    vault_inner = vault_registry.make_inner_puzzle_hash(
        admin_authority_launcher_id=protocol.admin_authority_launcher_id,
        governance_launcher_id=protocol.governance_launcher_id,
        vault_inner_mod_hash=protocol.vault_inner_mod_hash,
        canonical_params_hash=canonical_vault_params_hash,
        vault_version=vault_version,
    )
    vault_surface = SingletonSurface(
        vault_launcher_id,
        vault_inner,
        singleton_full_puzzle_hash(vault_launcher_id, vault_inner),
    )

    property_launcher_id = _launcher_id(funding.bridge_batch)
    property_inner = property_registry.make_inner_puzzle_hash(
        governance_bls_pubkey,
        property_registry_version,
        property_registry.EMPTY_REGISTERED_IDS_ROOT,
    )
    property_surface = SingletonSurface(
        property_launcher_id,
        property_inner,
        singleton_full_puzzle_hash(property_launcher_id, property_inner),
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
    plan = RC23GenesisCeremonyPlan(
        ceremony_id=ceremony_id,
        network=network,
        evm_chain_id=evm_chain_id,
        expires_at=expires_at,
        source_shas=normalized_sources,
        recovery_dependency_manifest_hash=dependency_manifest_hash,
        evm_addresses=normalized_evm,
        funding=funding,
        protocol=protocol,
        protocol_config=config_surface,
        admin_authority=admin_surface,
        vault_version_registry=vault_surface,
        property_registry=property_surface,
        admin_authority_v3=authority_v3,
        admin_roster_hash=roster_receipt.admins_hash,
        admin_recovery_kits=recovery_kits,  # type: ignore[arg-type]
        validator_pubkeys=tuple(validator_set.pubkeys),  # type: ignore[arg-type]
        validator_threshold=validator_set.threshold,
        bridge_batch=BridgeBatchPlan(
            policy_hash=bridge_policy_hash,
            parent_coins=bridge_parents,
            bridge_coins=bridge_coins,
            low_water_mark=GENESIS_BRIDGE_LOW_WATER_MARK,
        ),
        protocol_config_version=protocol_config_version,
        admin_authority_version=admin_authority_version,
        vault_version=vault_version,
        property_registry_version=property_registry_version,
        canonical_vault_params_hash=canonical_vault_params_hash,
        retired_coordinates=retired,
        plan_hash=bytes32.zeros,
    )
    object.__setattr__(plan, "plan_hash", _compute_plan_hash(plan))
    return plan


def verify_rc23_genesis_ceremony_plan(
    plan: RC23GenesisCeremonyPlan,
) -> None:
    plan.funding.validate()
    if plan.network != GENESIS_NETWORK:
        raise ValueError("ceremony plan network is not testnet11")
    if plan.evm_chain_id != GENESIS_EVM_CHAIN_ID:
        raise ValueError("ceremony plan EVM chain is not Base Sepolia")
    expected_dependency_hash = bytes32.from_hexstr(
        RECOVERY_DEPENDENCY_MANIFEST_HASH
    )
    if (
        plan.recovery_dependency_manifest_hash
        != expected_dependency_hash
        or plan.admin_authority_v3.source_manifest_hash
        != _source_manifest_hash(
            plan.source_shas,
            expected_dependency_hash,
        )
    ):
        raise ValueError(
            "ceremony plan does not bind the pinned recovery dependencies"
        )
    if (
        plan.admin_authority_v3.authority_launcher_id
        != plan.admin_authority.launcher_id
        or plan.admin_authority_v3.operational_policy.m != 2
        or len(plan.admin_authority_v3.lost_recovery_policies) != 3
        or any(
            policy.m != 2 or len(policy.members) != 2
            for policy in plan.admin_authority_v3.lost_recovery_policies
        )
        or len(plan.admin_authority_v3.identity_vaults) != 3
    ):
        raise ValueError("ceremony plan authority is not owner-plus-one")
    roster_receipt = build_genesis_eip712_admin_quorum(
        network=plan.network,
        compressed_pubkeys=[
            identity.daily_compressed_pubkey
            for identity in plan.admin_authority_v3.identity_vaults
        ],
    )
    if plan.admin_roster_hash != roster_receipt.admins_hash:
        raise ValueError("ceremony administrator roster receipt changed")
    if len(plan.admin_recovery_kits) != 3:
        raise ValueError("ceremony plan recovery roster is incomplete")
    for slot, kit in enumerate(plan.admin_recovery_kits):
        kit.validate()
        identity = plan.admin_authority_v3.identity_vaults[slot]
        if (
            kit.slot != slot
            or kit.recovery_bls_pubkey != identity.recovery_bls_pubkey
            or kit.recovery_bls_commitment
            != bytes32(keccak256(identity.recovery_bls_pubkey))
        ):
            raise ValueError(
                "ceremony recovery kit does not match its identity vault"
            )
    if len({kit.evm_guardian for kit in plan.admin_recovery_kits}) != 3:
        raise ValueError(
            "ceremony recovery EVM guardians are not distinct"
        )
    if (
        plan.validator_threshold != GENESIS_VALIDATOR_THRESHOLD
        or len(plan.validator_pubkeys) != 3
        or len(set(plan.validator_pubkeys)) != 3
    ):
        raise ValueError("ceremony plan validator set is not 2-of-3")
    if len(plan.bridge_batch.bridge_coins) != GENESIS_BRIDGE_BATCH_SIZE:
        raise ValueError("ceremony plan does not contain 32 bridge coins")
    if plan.statutes.launcher_id != _launcher_id(plan.funding.statutes):
        raise ValueError("statutes launcher does not match its funding coin")
    if (
        plan.protocol.pool_inner_mod_hash.hex()
        != "1d4be5fec4d196e6920d8e04f7680e813e310040348ce153b49191e633650768"
    ):
        raise ValueError("ceremony plan does not launch frozen Pool V4")
    if plan.plan_hash != _compute_plan_hash(plan):
        raise ValueError("ceremony plan hash does not match canonical content")


def build_rc23_genesis_ceremony_bundle(
    *,
    plan: RC23GenesisCeremonyPlan,
    faucet: Any,
    funding_coins: RC23GenesisFundingCoins,
) -> RC23GenesisCeremonyBundle:
    """Build the fee-free canonical bundle; submission adds one fee-till input."""
    verify_rc23_genesis_ceremony_plan(plan)
    actual_ids = funding_coins.ids()
    actual_ids.validate()
    if actual_ids != plan.funding:
        raise ValueError("live funding coins do not match the signed RC23 plan")
    for coin in funding_coins.values():
        if coin.puzzle_hash != faucet.address_puzzle_hash:
            raise ValueError(
                "every RC23 funding coin must belong to the ceremony faucet"
            )
    if int(funding_coins.bridge_batch.amount) != (
        RC23_BRIDGE_BATCH_FUNDING_AMOUNT
    ):
        raise ValueError(
            "RC23 bridge batch funding coin must be exactly 530"
        )
    if int(funding_coins.pool.amount) != RC23_POOL_FUNDING_AMOUNT:
        raise ValueError(
            "RC23 pool funding coin must be exactly 2 mojos"
        )
    if int(funding_coins.admin_authority.amount) != (
        RC23_ADMIN_AUTHORITY_FUNDING_AMOUNT
    ):
        raise ValueError(
            "RC23 admin authority funding coin must be exactly 16 mojos"
        )

    spends: list[CoinSpend] = []
    signatures: list[Any] = []
    sgt_spend, signature = _funding_spend(
        faucet=faucet,
        coin=funding_coins.sgt,
        target_puzzle_hash=plan.protocol.sgt_full_puzzle_hash,
        target_amount=plan.protocol.permanent_rules.sgt_total_supply,
        fee=0,
    )
    spends.append(sgt_spend)
    signatures.append(signature)

    pool_conditions = [
        Program.to(
            [
                51,
                bytes32(SINGLETON_LAUNCHER_HASH),
                RC23_PROPERTY_REGISTRY_LAUNCHER_AMOUNT,
            ]
        ),
        Program.to(
            [
                51,
                plan.protocol.sols_reserve_seed_puzzle_hash,
                RC23_SOLS_RESERVE_SEED_AMOUNT,
            ]
        ),
    ]
    pool_funding_spend, pool_signature = _signed_faucet_spend(
        faucet=faucet,
        coin=funding_coins.pool,
        conditions=pool_conditions,
    )
    spends.append(pool_funding_spend)
    signatures.append(pool_signature)
    pool_launcher_coin = Coin(
        funding_coins.pool.name(),
        bytes32(SINGLETON_LAUNCHER_HASH),
        uint64(1),
    )
    if bytes32(pool_launcher_coin.name()) != plan.protocol.pool_launcher_id:
        raise ValueError("pool launcher does not match plan")
    spends.append(
        make_spend(
            pool_launcher_coin,
            SINGLETON_LAUNCHER,
            Program.to(
                [plan.protocol.pool_inner_puzzle_hash, uint64(1), []]
            ),
        )
    )
    reserve_seed_coin = Coin(
        funding_coins.pool.name(),
        plan.protocol.sols_reserve_seed_puzzle_hash,
        uint64(RC23_SOLS_RESERVE_SEED_AMOUNT),
    )
    if bytes32(reserve_seed_coin.name()) != (
        plan.protocol.sols_reserve_seed_coin_id
    ):
        raise ValueError("Sols reserve seed does not match plan")

    singleton_inputs = (
        (
            funding_coins.did,
            SingletonSurface(
                plan.protocol.did_launcher_id,
                plan.protocol.did_inner_puzzle_hash,
                plan.protocol.did_full_puzzle_hash,
            ),
        ),
        (
            funding_coins.governance,
            SingletonSurface(
                plan.protocol.governance_launcher_id,
                plan.protocol.governance_inner_puzzle_hash,
                plan.protocol.governance_full_puzzle_hash,
            ),
        ),
        (funding_coins.statutes, plan.statutes),
        (funding_coins.protocol_config, plan.protocol_config),
        (
            funding_coins.vault_version_registry,
            plan.vault_version_registry,
        ),
    )
    for funding_coin, surface in singleton_inputs:
        singleton_spends, signature = _singleton_spends(
            faucet=faucet,
            funding_coin=funding_coin,
            surface=surface,
            fee=0,
        )
        spends.extend(singleton_spends)
        signatures.append(signature)

    authority_conditions = [
        Program.to(
            [
                51,
                bytes32(SINGLETON_LAUNCHER_HASH),
                admin_authority.AUTHORITY_LAUNCHER_AMOUNT,
            ]
        ),
        *[
            Program.to(
                [51, bytes32(SINGLETON_LAUNCHER_HASH), amount]
            )
            for amount in admin_authority.IDENTITY_LAUNCHER_AMOUNTS
        ],
    ]
    authority_funding_spend, authority_signature = _signed_faucet_spend(
        faucet=faucet,
        coin=funding_coins.admin_authority,
        conditions=authority_conditions,
    )
    spends.append(authority_funding_spend)
    signatures.append(authority_signature)
    authority_surfaces = (
        (
            admin_authority.AUTHORITY_LAUNCHER_AMOUNT,
            plan.admin_authority,
        ),
        *[
            (
                identity.launcher_amount,
                SingletonSurface(
                    identity.launcher_id,
                    identity.custody_hash,
                    identity.full_puzzle_hash,
                ),
            )
            for identity in plan.admin_authority_v3.identity_vaults
        ],
    )
    for amount, surface in authority_surfaces:
        launcher_coin = Coin(
            funding_coins.admin_authority.name(),
            bytes32(SINGLETON_LAUNCHER_HASH),
            uint64(amount),
        )
        if bytes32(launcher_coin.name()) != surface.launcher_id:
            raise ValueError("Authority V3 launcher does not match plan")
        spends.append(
            make_spend(
                launcher_coin,
                SINGLETON_LAUNCHER,
                Program.to([surface.full_puzzle_hash, amount, []]),
            )
        )

    # The batch spends 529 mojos into protocol outputs and leaves the approved
    # one-mojo safety buffer as fee. The separately estimated medium-speed
    # network fee still comes from the bounded fountain fee-till input.
    batch_conditions = [
        Program.to([51, faucet.address_puzzle_hash, int(parent.amount)])
        for parent in plan.bridge_batch.parent_coins
    ]
    batch_conditions.append(
        Program.to(
            [
                51,
                bytes32(SINGLETON_LAUNCHER_HASH),
                RC23_PROPERTY_REGISTRY_LAUNCHER_AMOUNT,
            ]
        )
    )
    batch_spend, batch_signature = _signed_faucet_spend(
        faucet=faucet,
        coin=funding_coins.bridge_batch,
        conditions=batch_conditions,
    )
    spends.append(batch_spend)
    signatures.append(batch_signature)

    property_launcher_coin = Coin(
        funding_coins.bridge_batch.name(),
        bytes32(SINGLETON_LAUNCHER_HASH),
        uint64(1),
    )
    if bytes32(property_launcher_coin.name()) != (
        plan.property_registry.launcher_id
    ):
        raise ValueError("property registry launcher does not match plan")
    spends.append(
        make_spend(
            property_launcher_coin,
            SINGLETON_LAUNCHER,
            Program.to(
                [plan.property_registry.inner_puzzle_hash, uint64(1), []]
            ),
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
            raise ValueError("bridge coin lineage does not match parent")
        conditions = [
            Program.to([51, plan.bridge_batch.policy_hash, 1])
        ]
        if int(parent.amount) > 1:
            conditions.append(
                Program.to(
                    [
                        51,
                        faucet.address_puzzle_hash,
                        int(parent.amount) - 1,
                    ]
                )
            )
        parent_spend, signature = _signed_faucet_spend(
            faucet=faucet,
            coin=parent,
            conditions=conditions,
        )
        spends.append(parent_spend)
        signatures.append(signature)

    if len(spends) != 52:
        raise ValueError(
            f"RC23 ceremony bundle must contain 52 spends, got {len(spends)}"
        )
    return RC23GenesisCeremonyBundle(
        plan=plan,
        spend_bundle=SpendBundle(
            spends,
            AugSchemeMPL.aggregate(signatures),
        ),
    )


__all__ = [
    "RC23_BRIDGE_BATCH_BUFFER_AMOUNT",
    "RC23_BRIDGE_BATCH_FUNDING_AMOUNT",
    "RC23_BRIDGE_PARENT_TOTAL",
    "RC23_GENESIS_PLAN_SCHEMA",
    "RC23_ADMIN_AUTHORITY_FUNDING_AMOUNT",
    "RC23_POOL_FUNDING_AMOUNT",
    "RC23_PROPERTY_REGISTRY_LAUNCHER_AMOUNT",
    "RC23_SOLS_RESERVE_SEED_AMOUNT",
    "RC23GenesisCeremonyBundle",
    "RC23GenesisCeremonyPlan",
    "RC23GenesisFundingCoinIds",
    "RC23GenesisFundingCoins",
    "build_rc23_genesis_ceremony_bundle",
    "build_rc23_genesis_ceremony_plan",
    "verify_rc23_genesis_ceremony_plan",
]
