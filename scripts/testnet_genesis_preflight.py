#!/usr/bin/env python3
"""Offline evidence checks for the Solslot V2 testnet genesis ceremony.

This command never contacts a wallet, signs a message, or broadcasts a spend.
The API performs live coin, signature, and consensus-simulation checks. This
independent gate verifies that exported ceremony evidence, frozen repositories,
and deployed release attestations remain mutually consistent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


PROTOCOL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROTOCOL_ROOT.parent
SOURCE_NAMES = ("protocol", "evm", "api", "customerWeb", "adminPortal")
SOURCE_DEFAULTS = {
    "protocol": PROTOCOL_ROOT,
    "evm": WORKSPACE_ROOT / "solslot-evm",
    "api": WORKSPACE_ROOT / "solslot-api",
    "customerWeb": WORKSPACE_ROOT / "solslot",
    "adminPortal": WORKSPACE_ROOT / "solslot-portal",
}
LAUNCHER_NAMES = (
    "pool",
    "did",
    "governance",
    "navRegistry",
    "protocolConfig",
    "adminAuthority",
    "vaultVersionRegistry",
)
FUNDING_NAMES = (
    "sgt",
    "pool",
    "did",
    "governance",
    "navRegistry",
    "protocolConfig",
    "adminAuthority",
    "vaultVersionRegistry",
    "bridgeBatch",
)
EVM_NAMES = ("forwarder", "verifierAdapter", "attestationEmitter")
AUDIT_LANES = (
    "protocol",
    "evm",
    "credentialBridge",
    "ceremonyOrchestrator",
)
CONSUMERS = ("api", "customerWeb", "adminPortal")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_RE = re.compile(r"^0x[0-9a-f]+$")


@dataclass(frozen=True)
class Finding:
    severity: str
    message: str


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ceremony-state", type=Path, required=True)
    parser.add_argument("--protocol-repo", type=Path, default=SOURCE_DEFAULTS["protocol"])
    parser.add_argument("--evm-repo", type=Path, default=SOURCE_DEFAULTS["evm"])
    parser.add_argument("--api-repo", type=Path, default=SOURCE_DEFAULTS["api"])
    parser.add_argument(
        "--customer-web-repo", type=Path, default=SOURCE_DEFAULTS["customerWeb"]
    )
    parser.add_argument(
        "--admin-portal-repo", type=Path, default=SOURCE_DEFAULTS["adminPortal"]
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Print blockers but return exit status zero.",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify Solslot V2 ceremony evidence without broadcasting.",
    )
    phases = parser.add_subparsers(dest="phase", required=True)

    before = phases.add_parser(
        "pre-broadcast",
        help="Verify frozen commits, quorum, simulation, and approval evidence.",
    )
    _add_common_arguments(before)
    before.add_argument("--preflight-evidence", type=Path, required=True)
    before.add_argument("--audit-approval", type=Path, required=True)
    before.add_argument("--output-dir", type=Path, required=True)
    before.add_argument("--now", type=int, default=None, help=argparse.SUPPRESS)

    after = phases.add_parser(
        "post-genesis",
        help="Verify the locked artifact, checksums, and deployed release pins.",
    )
    _add_common_arguments(after)
    after.add_argument("--public-artifact", type=Path, required=True)
    after.add_argument("--bootstrap-lock", type=Path, required=True)
    after.add_argument("--evidence-dir", type=Path, required=True)
    after.add_argument("--release-attestation", type=Path, required=True)
    return parser.parse_args(argv)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def canonical_hash(value: Any) -> str:
    return "0x" + hashlib.sha256(canonical_json(value)).hexdigest()


def plan_hash(plan: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in plan.items() if key != "planHash"}
    return canonical_hash(unsigned)


def artifact_hash(artifact: Mapping[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in artifact.items()
        if key not in {"artifactHash", "signatures"}
    }
    return canonical_hash(unsigned)


def load_json(path: Path, findings: list[Finding], label: str) -> dict[str, Any] | None:
    if not path.is_file():
        findings.append(Finding("error", f"{label} is missing: {path}"))
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        findings.append(Finding("error", f"{label} is invalid JSON: {path} ({exc})"))
        return None
    if not isinstance(payload, dict):
        findings.append(Finding("error", f"{label} must be a JSON object: {path}"))
        return None
    return payload


def is_hex(value: Any, byte_length: int, *, nonzero: bool = True) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.lower()
    if len(normalized) != 2 + byte_length * 2 or not HEX_RE.fullmatch(normalized):
        return False
    return not nonzero or normalized != "0x" + "00" * byte_length


def _require_hex(
    value: Any,
    byte_length: int,
    label: str,
    findings: list[Finding],
    *,
    nonzero: bool = True,
) -> str | None:
    if not is_hex(value, byte_length, nonzero=nonzero):
        findings.append(
            Finding("error", f"{label} must be a {'nonzero ' if nonzero else ''}0x{byte_length}-byte value")
        )
        return None
    return str(value).lower()


def _require_mapping(
    value: Any, label: str, findings: list[Finding]
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        findings.append(Finding("error", f"{label} must be an object"))
        return None
    return value


def _integer(
    value: Any,
    label: str,
    findings: list[Finding],
    *,
    minimum: int | None = None,
) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        findings.append(Finding("error", f"{label} must be an integer"))
        return None
    if minimum is not None and parsed < minimum:
        findings.append(Finding("error", f"{label} must be at least {minimum}"))
        return None
    return parsed


def _require_exact_keys(
    value: Mapping[str, Any], expected: Sequence[str], label: str, findings: list[Finding]
) -> None:
    actual = set(value)
    required = set(expected)
    if actual != required:
        findings.append(
            Finding(
                "error",
                f"{label} keys differ (missing={sorted(required - actual)}, extra={sorted(actual - required)})",
            )
        )


def validate_source_shas(
    value: Any, findings: list[Finding], label: str = "sourceShas"
) -> dict[str, str] | None:
    mapping = _require_mapping(value, label, findings)
    if mapping is None:
        return None
    _require_exact_keys(mapping, SOURCE_NAMES, label, findings)
    normalized: dict[str, str] = {}
    for name in SOURCE_NAMES:
        sha = str(mapping.get(name, "")).lower()
        if not GIT_SHA_RE.fullmatch(sha):
            findings.append(Finding("error", f"{label}.{name} must be a full Git SHA"))
        else:
            normalized[name] = sha
    return normalized if len(normalized) == len(SOURCE_NAMES) else None


def repository_paths(args: argparse.Namespace) -> dict[str, Path]:
    return {
        "protocol": args.protocol_repo,
        "evm": args.evm_repo,
        "api": args.api_repo,
        "customerWeb": args.customer_web_repo,
        "adminPortal": args.admin_portal_repo,
    }


def check_repositories(
    source_shas: Mapping[str, str], paths: Mapping[str, Path], findings: list[Finding]
) -> None:
    for name in SOURCE_NAMES:
        path = paths[name]
        if not (path / ".git").exists():
            findings.append(Finding("error", f"{name} repository is missing: {path}"))
            continue
        try:
            head = subprocess.run(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip().lower()
            status = subprocess.run(
                ["git", "-C", str(path), "status", "--porcelain"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            findings.append(Finding("error", f"cannot inspect {name} repository {path}: {exc}"))
            continue
        if head != source_shas.get(name):
            findings.append(
                Finding(
                    "error",
                    f"{name} HEAD {head or '<missing>'} does not match frozen SHA {source_shas.get(name)}",
                )
            )
        if status:
            findings.append(Finding("error", f"{name} worktree is dirty: {path}"))


def _validate_roster(record: Mapping[str, Any], findings: list[Finding]) -> list[str]:
    invitations = record.get("invitations")
    if not isinstance(invitations, list) or len(invitations) != 3:
        findings.append(Finding("error", "ceremony must contain three administrator slots"))
        return []
    objects: list[Mapping[str, Any]] = []
    for item in invitations:
        if not isinstance(item, Mapping):
            findings.append(Finding("error", "administrator slot entry must be an object"))
        else:
            objects.append(item)
    ordered = sorted(
        objects,
        key=lambda item: int(item.get("slot", 0))
        if str(item.get("slot", "")).isdigit()
        else 0,
    )
    if [item.get("slot") for item in ordered] != [1, 2, 3]:
        findings.append(Finding("error", "administrator slots must be exactly 1, 2, and 3"))
    keys: list[str] = []
    wallets: list[str] = []
    for item in ordered:
        if item.get("consumed_at") is None:
            findings.append(Finding("error", f"administrator slot {item.get('slot')} is not enrolled"))
        key = _require_hex(
            item.get("compressed_pubkey"), 33, "administrator compressed pubkey", findings
        )
        wallet = _require_hex(item.get("wallet_address"), 20, "administrator wallet", findings)
        if key:
            keys.append(key)
        if wallet:
            wallets.append(wallet)
    if len(set(keys)) != 3:
        findings.append(Finding("error", "administrator public keys must be distinct"))
    if len(set(wallets)) != 3:
        findings.append(Finding("error", "administrator wallets must be distinct"))
    return keys


def _validate_quorum_signatures(
    record: Mapping[str, Any], roster_keys: Sequence[str], findings: list[Finding]
) -> None:
    signatures = record.get("plan_signatures")
    if not isinstance(signatures, list) or not (2 <= len(signatures) <= 3):
        findings.append(Finding("error", "two distinct administrator plan signatures are required"))
        return
    seen: set[int] = set()
    for entry in signatures:
        if not isinstance(entry, Mapping):
            findings.append(Finding("error", "plan signature entry must be an object"))
            continue
        try:
            slot = int(entry.get("slot", 0))
        except (TypeError, ValueError):
            slot = 0
        if slot not in (1, 2, 3) or slot in seen:
            findings.append(Finding("error", "plan signatures must use distinct roster slots"))
            continue
        seen.add(slot)
        if entry.get("plan_hash") != record.get("plan_hash"):
            findings.append(Finding("error", f"plan signature slot {slot} has the wrong plan hash"))
        key = str(entry.get("compressed_pubkey", "")).lower()
        if len(roster_keys) == 3 and key != roster_keys[slot - 1]:
            findings.append(Finding("error", f"plan signature slot {slot} does not match its roster key"))
        _require_hex(entry.get("signature"), 65, f"plan signature slot {slot}", findings)


def _validate_plan(
    record: Mapping[str, Any], findings: list[Finding], *, now: int
) -> tuple[Mapping[str, Any] | None, dict[str, str] | None]:
    if record.get("state") != "plan_approved":
        findings.append(Finding("error", "ceremony state must be plan_approved"))
    ceremony_id = _require_hex(record.get("ceremony_id"), 32, "ceremony_id", findings)
    draft = _require_mapping(record.get("draft"), "ceremony draft", findings)
    plan = _require_mapping(record.get("plan"), "ceremony plan", findings)
    source_shas = validate_source_shas(draft.get("sourceShas") if draft else None, findings)
    if draft:
        if draft.get("schemaVersion") != 2 or draft.get("network") != "testnet11":
            findings.append(Finding("error", "ceremony draft is not Solslot V2 testnet11"))
        if draft.get("evmChainId") != 11155111:
            findings.append(Finding("error", "ceremony draft is not bound to Sepolia"))
    if plan is None:
        return None, source_shas
    if plan.get("schema") != "solslot-genesis-plan-v2":
        findings.append(Finding("error", "ceremony plan schema is not V2"))
    if plan.get("protocolVersion") != "solslot-v2":
        findings.append(Finding("error", "ceremony plan protocolVersion is not solslot-v2"))
    if plan.get("network") != "testnet11" or plan.get("evmChainId") != 11155111:
        findings.append(Finding("error", "ceremony plan is not testnet11/Sepolia"))
    if ceremony_id and plan.get("ceremonyId") != ceremony_id:
        findings.append(Finding("error", "ceremony plan is bound to a different ceremony"))
    plan_sources = validate_source_shas(plan.get("sourceShas"), findings, "plan.sourceShas")
    if source_shas and plan_sources != source_shas:
        findings.append(Finding("error", "plan source SHAs differ from the frozen draft"))
    expected_hash = plan_hash(plan)
    if plan.get("planHash") != expected_hash or record.get("plan_hash") != expected_hash:
        findings.append(Finding("error", "plan hash does not match canonical plan content"))
    expires_at = _integer(record.get("plan_expires_at"), "plan_expires_at", findings)
    if expires_at is None or plan.get("expiresAt") != expires_at or expires_at <= now:
        findings.append(Finding("error", "ceremony plan is expired or has inconsistent expiry"))

    funding = _require_mapping(plan.get("fundingCoinIds"), "plan.fundingCoinIds", findings)
    if funding:
        _require_exact_keys(funding, FUNDING_NAMES, "plan.fundingCoinIds", findings)
        values = [
            _require_hex(funding.get(name), 32, f"plan.fundingCoinIds.{name}", findings)
            for name in FUNDING_NAMES
        ]
        valid_values = [value for value in values if value]
        if len(set(valid_values)) != len(valid_values):
            findings.append(Finding("error", "ceremony funding coins must be distinct"))

    launchers = _require_mapping(plan.get("launcherIds"), "plan.launcherIds", findings)
    active_launchers: list[str] = []
    if launchers:
        _require_exact_keys(launchers, LAUNCHER_NAMES, "plan.launcherIds", findings)
        active_launchers = [
            value
            for name in LAUNCHER_NAMES
            if (value := _require_hex(launchers.get(name), 32, f"plan.launcherIds.{name}", findings))
        ]
        if len(set(active_launchers)) != len(active_launchers):
            findings.append(Finding("error", "ceremony launcher IDs must be distinct"))

    addresses = _require_mapping(plan.get("evmAddresses"), "plan.evmAddresses", findings)
    if addresses:
        _require_exact_keys(addresses, EVM_NAMES, "plan.evmAddresses", findings)
        values = [
            value
            for name in EVM_NAMES
            if (value := _require_hex(addresses.get(name), 20, f"plan.evmAddresses.{name}", findings))
        ]
        if len(set(values)) != len(values):
            findings.append(Finding("error", "fresh EVM contract addresses must be distinct"))

    admin = _require_mapping(plan.get("adminAuthority"), "plan.adminAuthority", findings)
    roster_keys = _validate_roster(record, findings)
    if admin:
        keys = [str(value).lower() for value in admin.get("compressedPubkeys", [])]
        if admin.get("threshold") != 2 or keys != roster_keys:
            findings.append(Finding("error", "plan administrator authority is not the frozen 2-of-3 roster"))
        if admin.get("adminsHash") != record.get("roster_hash"):
            findings.append(Finding("error", "plan administrator hash differs from the frozen roster"))
        _require_hex(admin.get("adminsHash"), 32, "plan.adminAuthority.adminsHash", findings)
        _require_hex(admin.get("mipsRootHash"), 32, "plan.adminAuthority.mipsRootHash", findings)

    validators = _require_mapping(plan.get("validatorSet"), "plan.validatorSet", findings)
    if validators:
        keys = validators.get("pubkeys")
        if validators.get("threshold") != 2 or not isinstance(keys, list) or len(keys) != 3:
            findings.append(Finding("error", "validator authority must be 2-of-3"))
        else:
            normalized = [
                _require_hex(key, 48, "validator public key", findings) for key in keys
            ]
            if None in normalized or len(set(normalized)) != 3:
                findings.append(Finding("error", "validator public keys must be three distinct values"))

    bridge = _require_mapping(plan.get("bridgeBatch"), "plan.bridgeBatch", findings)
    if bridge:
        parents = bridge.get("parentCoinIds")
        coins = bridge.get("bridgeCoinIds")
        if bridge.get("count") != 32 or bridge.get("lowWaterMark") != 8:
            findings.append(Finding("error", "bridge batch must contain 32 coins with low-water mark 8"))
        for values, label in ((parents, "parent"), (coins, "bridge")):
            if not isinstance(values, list) or len(values) != 32:
                findings.append(Finding("error", f"bridge batch must contain 32 {label} coin IDs"))
                continue
            normalized = [
                _require_hex(value, 32, f"bridge batch {label} coin", findings)
                for value in values
            ]
            if None in normalized or len(set(normalized)) != 32:
                findings.append(Finding("error", f"bridge batch {label} coin IDs must be distinct"))

    retired = plan.get("retiredCoordinates")
    if not isinstance(retired, list) or not retired:
        findings.append(Finding("error", "plan must enumerate retired coordinates"))
    else:
        normalized = [
            _require_hex(value, 32, "retired coordinate", findings) for value in retired
        ]
        valid_retired = [value for value in normalized if value]
        if len(set(valid_retired)) != len(valid_retired):
            findings.append(Finding("error", "retired coordinates must be distinct"))
        if set(valid_retired) & set(active_launchers):
            findings.append(Finding("error", "an active launcher appears in retired coordinates"))

    _validate_quorum_signatures(record, roster_keys, findings)
    return plan, source_shas


def _validate_audit_approval(
    approval: Mapping[str, Any],
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    spend_bundle_id: str,
    findings: list[Finding],
) -> None:
    draft = record.get("draft")
    draft_sources = draft.get("sourceShas") if isinstance(draft, Mapping) else None
    expected = {
        "schemaVersion": 2,
        "ceremonyId": record.get("ceremony_id"),
        "planHash": record.get("plan_hash"),
        "sourceShas": draft_sources,
        "consensusSimulationBundleId": spend_bundle_id,
    }
    for key, value in expected.items():
        if approval.get(key) != value:
            findings.append(Finding("error", f"audit approval {key} does not match ceremony"))
    lanes = approval.get("approvals")
    if not isinstance(lanes, list) or {item.get("lane") for item in lanes if isinstance(item, Mapping)} != set(AUDIT_LANES):
        findings.append(Finding("error", "all four independent audit lanes must be present"))
    else:
        for lane in lanes:
            if not isinstance(lane, Mapping):
                findings.append(Finding("error", "audit lane entry must be an object"))
                continue
            if lane.get("approved") is not True or not str(lane.get("reviewer", "")).strip():
                findings.append(Finding("error", f"audit lane {lane.get('lane')} is not approved"))
            _require_hex(lane.get("evidenceHash"), 32, "audit evidence hash", findings)
    deployments = _require_mapping(approval.get("evmContracts"), "audit EVM deployments", findings)
    plan_addresses = plan.get("evmAddresses", {})
    if deployments:
        _require_exact_keys(deployments, EVM_NAMES, "audit EVM deployments", findings)
        for name in EVM_NAMES:
            deployment = _require_mapping(deployments.get(name), f"audit EVM deployment {name}", findings)
            if not deployment:
                continue
            if str(deployment.get("address", "")).lower() != str(plan_addresses.get(name, "")).lower():
                findings.append(Finding("error", f"audited EVM address {name} differs from the plan"))
            _require_hex(deployment.get("bytecodeHash"), 32, f"{name} bytecode hash", findings)
            confirmations = _integer(
                deployment.get("confirmations"),
                f"{name} confirmations",
                findings,
                minimum=0,
            )
            if confirmations is None or confirmations < 12:
                findings.append(Finding("error", f"{name} lacks 12 Sepolia confirmations"))
    validators = _require_mapping(approval.get("validators"), "validator health evidence", findings)
    plan_validators = plan.get("validatorSet", {})
    if validators and (
        validators.get("threshold") != 2
        or validators.get("pubkeys") != plan_validators.get("pubkeys")
        or validators.get("healthy") != [True, True, True]
    ):
        findings.append(Finding("error", "validator health evidence does not prove all three planned signers"))


def check_pre_broadcast(
    record: Mapping[str, Any],
    preflight: Mapping[str, Any],
    approval: Mapping[str, Any],
    output_dir: Path,
    findings: list[Finding],
    *,
    now: int,
    repos: Mapping[str, Path] | None = None,
) -> None:
    plan, source_shas = _validate_plan(record, findings, now=now)
    spend_bundle_id = _require_hex(
        preflight.get("spendBundleId"), 32, "preflight spendBundleId", findings
    )
    if preflight.get("ready") is not True:
        findings.append(Finding("error", "API preflight evidence is not ready"))
    if preflight.get("ceremonyId") != record.get("ceremony_id"):
        findings.append(Finding("error", "API preflight evidence has the wrong ceremony ID"))
    if preflight.get("planHash") != record.get("plan_hash"):
        findings.append(Finding("error", "API preflight evidence has the wrong plan hash"))
    spend_count = _integer(
        preflight.get("spendCount"), "preflight spendCount", findings, minimum=1
    )
    if spend_count is None:
        findings.append(Finding("error", "API preflight evidence has no simulated spends"))
    if preflight.get("auditApprovalHash") != canonical_hash(approval):
        findings.append(Finding("error", "audit approval hash differs from API preflight evidence"))
    if plan is not None and spend_bundle_id is not None:
        _validate_audit_approval(approval, record, plan, spend_bundle_id, findings)
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        findings.append(Finding("error", f"ceremony output directory is not empty: {output_dir}"))
    if repos is not None and source_shas is not None:
        check_repositories(source_shas, repos, findings)


def _validate_artifact(
    artifact: Mapping[str, Any], findings: list[Finding]
) -> dict[str, str] | None:
    if artifact.get("schemaVersion") != 2 or artifact.get("protocolVersion") != "solslot-v2":
        findings.append(Finding("error", "public artifact is not schema/protocol V2"))
    if artifact.get("network") != "testnet11" or artifact.get("evmChainId") != 11155111:
        findings.append(Finding("error", "public artifact is not testnet11/Sepolia"))
    expected_hash = artifact_hash(artifact)
    if artifact.get("artifactHash") != expected_hash:
        findings.append(Finding("error", "public artifact hash does not match canonical content"))
    source_shas = validate_source_shas(artifact.get("sourceShas"), findings, "artifact.sourceShas")

    launchers = _require_mapping(artifact.get("launcherIds"), "artifact.launcherIds", findings)
    active: list[str] = []
    if launchers:
        _require_exact_keys(launchers, LAUNCHER_NAMES, "artifact.launcherIds", findings)
        active = [
            value
            for name in LAUNCHER_NAMES
            if (value := _require_hex(launchers.get(name), 32, f"artifact.launcherIds.{name}", findings))
        ]
        if len(set(active)) != len(active):
            findings.append(Finding("error", "artifact launcher IDs must be distinct"))
    _require_hex(artifact.get("sgtGenesisCoinId"), 32, "artifact.sgtGenesisCoinId", findings)
    _require_hex(artifact.get("sgtTailHash"), 32, "artifact.sgtTailHash", findings)

    retired = artifact.get("retiredCoordinates")
    if not isinstance(retired, list) or not retired:
        findings.append(Finding("error", "artifact must enumerate retired coordinates"))
    else:
        values = [_require_hex(value, 32, "retired coordinate", findings) for value in retired]
        valid = [value for value in values if value]
        if len(set(valid)) != len(valid) or set(valid) & set(active):
            findings.append(Finding("error", "artifact retired coordinates are duplicated or active"))

    admin = _require_mapping(artifact.get("adminAuthority"), "artifact.adminAuthority", findings)
    admin_keys: list[str] = []
    if admin:
        admin_keys = [str(value).lower() for value in admin.get("compressedPubkeys", [])]
        if admin.get("threshold") != 2 or len(admin_keys) != 3 or len(set(admin_keys)) != 3:
            findings.append(Finding("error", "artifact administrator authority is not 2-of-3"))
        for key in admin_keys:
            _require_hex(key, 33, "artifact administrator public key", findings)
    policy = _require_mapping(artifact.get("signaturePolicy"), "artifact.signaturePolicy", findings)
    if admin and policy and (
        policy.get("type") != "SolslotGenesisArtifact"
        or policy.get("threshold") != 2
        or policy.get("rosterHash") != admin.get("rosterHash")
    ):
        findings.append(Finding("error", "artifact signature policy differs from administrator authority"))

    signatures = artifact.get("signatures")
    if not isinstance(signatures, list) or not (2 <= len(signatures) <= 3):
        findings.append(Finding("error", "artifact requires two administrator signatures"))
    else:
        seen: set[int] = set()
        for entry in signatures:
            if not isinstance(entry, Mapping):
                findings.append(Finding("error", "artifact signature entry must be an object"))
                continue
            try:
                index = int(entry.get("adminIndex", -1))
            except (TypeError, ValueError):
                index = -1
            if index not in (0, 1, 2) or index in seen:
                findings.append(Finding("error", "artifact signatures must use distinct roster slots"))
                continue
            seen.add(index)
            if len(admin_keys) == 3 and str(entry.get("compressedPubkey", "")).lower() != admin_keys[index]:
                findings.append(Finding("error", f"artifact signature slot {index} has the wrong roster key"))
            _require_hex(entry.get("signature"), 65, f"artifact signature slot {index}", findings)

    validators = _require_mapping(artifact.get("validatorSet"), "artifact.validatorSet", findings)
    if validators:
        keys = validators.get("pubkeys")
        if validators.get("threshold") != 2 or not isinstance(keys, list) or len(keys) != 3:
            findings.append(Finding("error", "artifact validator authority is not 2-of-3"))
        else:
            values = [_require_hex(key, 48, "artifact validator key", findings) for key in keys]
            if None in values or len(set(values)) != 3:
                findings.append(Finding("error", "artifact validator keys must be distinct"))

    bridge = _require_mapping(artifact.get("bridgePolicy"), "artifact.bridgePolicy", findings)
    if bridge:
        if (
            bridge.get("policyVersion") != 2
            or bridge.get("initialCoinCount") != 32
            or bridge.get("lowWaterMark") != 8
        ):
            findings.append(Finding("error", "artifact bridge policy is not the V2 32-coin policy"))
        _require_hex(bridge.get("policyHash"), 32, "artifact bridge policy hash", findings)
        for key in ("parentCoinIds", "bridgeCoinIds"):
            values = bridge.get(key)
            if not isinstance(values, list) or len(values) != 32:
                findings.append(Finding("error", f"artifact bridgePolicy.{key} must contain 32 values"))
            else:
                normalized = [_require_hex(value, 32, f"artifact {key}", findings) for value in values]
                if None in normalized or len(set(normalized)) != 32:
                    findings.append(Finding("error", f"artifact bridgePolicy.{key} values must be distinct"))

    addresses = _require_mapping(artifact.get("evmAddresses"), "artifact.evmAddresses", findings)
    if addresses:
        _require_exact_keys(addresses, EVM_NAMES, "artifact.evmAddresses", findings)
        values = [_require_hex(addresses.get(name), 20, f"artifact.evmAddresses.{name}", findings) for name in EVM_NAMES]
        if None in values or len(set(values)) != 3:
            findings.append(Finding("error", "artifact EVM addresses must be three distinct values"))
    return source_shas


def _validate_checksums(
    evidence_dir: Path, artifact: Mapping[str, Any], findings: list[Finding]
) -> None:
    sums_path = evidence_dir / "sha256sums.txt"
    if not evidence_dir.is_dir() or not sums_path.is_file():
        findings.append(Finding("error", f"ceremony checksum evidence is missing: {sums_path}"))
        return
    entries: dict[str, str] = {}
    for line in sums_path.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        if not match or match.group(2) in entries:
            findings.append(Finding("error", f"invalid checksum line: {line!r}"))
            continue
        entries[match.group(2)] = match.group(1)
    required = {"plan.json", "spend_bundle.json", "audit_approval.json", "public_artifact.json"}
    if not required.issubset(entries):
        findings.append(Finding("error", f"checksum evidence is missing {sorted(required - set(entries))}"))
    actual_files = {path.name for path in evidence_dir.iterdir() if path.is_file()} - {"sha256sums.txt"}
    if actual_files != set(entries):
        findings.append(Finding("error", "checksum manifest does not cover exactly the evidence files"))
    for name, expected in entries.items():
        path = evidence_dir / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            findings.append(Finding("error", f"checksum mismatch for ceremony evidence {name}"))
    evidence_artifact = load_json(evidence_dir / "public_artifact.json", findings, "evidence artifact")
    if evidence_artifact is not None and evidence_artifact != artifact:
        findings.append(Finding("error", "evidence artifact differs from the public artifact"))


def _validate_release_attestation(
    attestation: Mapping[str, Any], artifact: Mapping[str, Any], findings: list[Finding]
) -> None:
    if (
        attestation.get("schemaVersion") != 2
        or attestation.get("protocolVersion") != "solslot-v2"
        or attestation.get("network") != "testnet11"
        or attestation.get("artifactHash") != artifact.get("artifactHash")
    ):
        findings.append(Finding("error", "release attestation does not match the V2 testnet artifact"))
    locks = _require_mapping(attestation.get("writeLocks"), "release writeLocks", findings)
    if locks and locks != {
        "alphaWritesEnabled": False,
        "mintingEnabled": False,
        "ceremonyModeEnabled": False,
    }:
        findings.append(Finding("error", "Alpha writes, minting, and ceremony mode must remain locked"))
    consumers = _require_mapping(attestation.get("consumers"), "release consumers", findings)
    sources = artifact.get("sourceShas", {})
    if consumers:
        _require_exact_keys(consumers, CONSUMERS, "release consumers", findings)
        for name in CONSUMERS:
            entry = _require_mapping(consumers.get(name), f"release consumer {name}", findings)
            if not entry:
                continue
            if (
                entry.get("reachable") is not True
                or entry.get("artifactHash") != artifact.get("artifactHash")
                or entry.get("sourceSha") != sources.get(name)
            ):
                findings.append(Finding("error", f"release consumer {name} is not pinned to its signed source/artifact"))


def check_post_genesis(
    record: Mapping[str, Any],
    artifact: Mapping[str, Any],
    lock: Mapping[str, Any],
    evidence_dir: Path,
    attestation: Mapping[str, Any],
    findings: list[Finding],
    *,
    repos: Mapping[str, Path] | None = None,
) -> None:
    if record.get("state") != "locked":
        findings.append(Finding("error", "ceremony state must be locked"))
    source_shas = _validate_artifact(artifact, findings)
    ceremony = _require_mapping(artifact.get("ceremony"), "artifact.ceremony", findings)
    if ceremony:
        expected = {
            "ceremonyId": record.get("ceremony_id"),
            "planHash": record.get("plan_hash"),
            "spendBundleId": record.get("spend_bundle_id"),
            "confirmedBlockIndex": record.get("confirmed_block_index"),
            "requiredChiaConfirmations": 3,
        }
        for key, value in expected.items():
            if ceremony.get(key) != value:
                findings.append(Finding("error", f"artifact ceremony {key} differs from locked state"))
    if record.get("artifact_hash") != artifact.get("artifactHash"):
        findings.append(Finding("error", "locked state artifact hash differs from public artifact"))
    stored_artifact = record.get("artifact")
    if isinstance(stored_artifact, Mapping):
        expected_stored = dict(artifact)
        expected_stored["signatures"] = []
        if stored_artifact != expected_stored:
            findings.append(Finding("error", "locked state artifact payload differs from public artifact"))
    else:
        findings.append(Finding("error", "locked state is missing its canonical artifact"))

    lock_expected = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "ceremonyId": record.get("ceremony_id"),
        "planHash": record.get("plan_hash"),
        "artifactHash": artifact.get("artifactHash"),
        "spendBundleId": record.get("spend_bundle_id"),
        "confirmedBlockIndex": record.get("confirmed_block_index"),
    }
    for key, value in lock_expected.items():
        if lock.get(key) != value:
            findings.append(Finding("error", f"bootstrap lock {key} differs from locked ceremony"))
    locked_at = _integer(lock.get("lockedAt"), "bootstrap lock lockedAt", findings, minimum=1)
    if locked_at is None:
        findings.append(Finding("error", "bootstrap lock has no lockedAt timestamp"))

    state_signatures = record.get("artifact_signatures")
    public_signatures = artifact.get("signatures")
    if isinstance(state_signatures, list) and isinstance(public_signatures, list):
        expected: list[dict[str, Any]] = []
        for entry in state_signatures:
            if not isinstance(entry, Mapping):
                findings.append(Finding("error", "locked artifact signature entry must be an object"))
                continue
            slot = _integer(entry.get("slot"), "locked artifact signature slot", findings)
            if slot is None:
                continue
            expected.append(
                {
                    "adminIndex": slot - 1,
                    "compressedPubkey": entry.get("compressed_pubkey"),
                    "signature": entry.get("signature"),
                }
            )
        if expected != public_signatures:
            findings.append(Finding("error", "public artifact signatures differ from locked state"))
    else:
        findings.append(Finding("error", "locked state is missing artifact signatures"))

    _validate_checksums(evidence_dir, artifact, findings)
    _validate_release_attestation(attestation, artifact, findings)
    if repos is not None and source_shas is not None:
        check_repositories(source_shas, repos, findings)


def print_report(phase: str, findings: Sequence[Finding]) -> None:
    errors = [item for item in findings if item.severity == "error"]
    warnings = [item for item in findings if item.severity == "warn"]
    infos = [item for item in findings if item.severity == "info"]
    print(f"Solslot V2 genesis {phase} preflight")
    print(f"errors={len(errors)} warnings={len(warnings)} info={len(infos)}")
    for severity in ("error", "warn", "info"):
        subset = [item for item in findings if item.severity == severity]
        if subset:
            print(f"\n{severity.upper()}:")
            for item in subset:
                print(f"- {item.message}")
    print("\nREADY: all offline evidence gates passed." if not errors else "\nNOT READY: ceremony remains blocked.")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    findings: list[Finding] = []
    record = load_json(args.ceremony_state, findings, "ceremony state")
    if args.phase == "pre-broadcast":
        preflight = load_json(args.preflight_evidence, findings, "API preflight evidence")
        approval = load_json(args.audit_approval, findings, "independent audit approval")
        if record is not None and preflight is not None and approval is not None:
            check_pre_broadcast(
                record,
                preflight,
                approval,
                args.output_dir,
                findings,
                now=args.now if args.now is not None else int(time.time()),
                repos=repository_paths(args),
            )
    else:
        artifact = load_json(args.public_artifact, findings, "public artifact")
        lock = load_json(args.bootstrap_lock, findings, "bootstrap lock")
        attestation = load_json(args.release_attestation, findings, "release attestation")
        if record is not None and artifact is not None and lock is not None and attestation is not None:
            check_post_genesis(
                record,
                artifact,
                lock,
                args.evidence_dir,
                attestation,
                findings,
                repos=repository_paths(args),
            )
    print_report(args.phase, findings)
    has_errors = any(item.severity == "error" for item in findings)
    return 0 if args.report_only or not has_errors else 1


if __name__ == "__main__":
    sys.exit(main())
