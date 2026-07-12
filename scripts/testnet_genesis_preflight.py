#!/usr/bin/env python3
"""Preflight checks for the Solslot testnet genesis/bootstrap ceremony.

The script is intentionally dependency-light so it can run before virtualenv
activation.  It does not deploy anything; it checks whether the local ceremony
inputs and downstream API/frontend pins are coherent enough to proceed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
HEX32_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
HEX48_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{96}$")

BASE_DEPLOYMENT_FIELDS = (
    "network",
    "params",
    "faucet_inner_puzhash",
    "pgt_genesis_coin_id",
    "pool_genesis_coin_id",
    "did_genesis_coin_id",
    "gov_genesis_coin_id",
    "pool_launcher_id",
    "did_launcher_id",
    "tracker_launcher_id",
    "pgt_tail_hash",
    "pgt_full_puzhash",
    "pool_token_tail_hash",
    "pool_inner_puzhash",
    "pool_full_puzhash",
    "did_inner_puzhash",
    "did_full_puzhash",
    "tracker_inner_puzhash",
    "tracker_full_puzhash",
)

V2_TRUST_ANCHORS = (
    "trusted_nav_registry_mod_hash",
    "trusted_nav_registry_launcher_id",
    "trusted_nav_registry_gov_pubkey",
    "trusted_treasury_reserve_puzhash",
    "trusted_protocol_treasury_puzhash",
    "trusted_governance_rewards_puzhash",
    "trusted_governance_rewards_root",
)

FRONTEND_COORDINATES = {
    "poolLauncherId": ("pool_launcher_id",),
    "poolInnerPuzzleHash": ("pool_inner_puzhash", "pool_inner_puzzle_hash"),
    "bridgePolicyHash": ("bridge_policy_hash", "zkpassport_bridge_policy_hash"),
    "membersMerkleRoot": ("members_merkle_root",),
    "protocolConfigLauncherId": ("protocol_config_launcher_id",),
    "vaultVersionRegistryLauncherId": ("vault_version_registry_launcher_id",),
}


@dataclass
class Finding:
    severity: str
    message: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Solslot testnet genesis/bootstrap readiness.",
    )
    parser.add_argument("--network", default="testnet11")
    parser.add_argument(
        "--deployment-manifest",
        type=Path,
        default=WORKSPACE_ROOT / "populis_api" / "deployment_manifest.json",
    )
    parser.add_argument(
        "--bootstrap-manifest",
        type=Path,
        default=WORKSPACE_ROOT / "populis_api" / "bootstrap_manifest.json",
    )
    parser.add_argument(
        "--portal-runtime-config",
        type=Path,
        default=WORKSPACE_ROOT / "populis_api" / "portal_runtime_config.json",
    )
    parser.add_argument(
        "--slui-env",
        type=Path,
        default=WORKSPACE_ROOT
        / "research"
        / "solslot-portal"
        / "slui"
        / "src"
        / "environments"
        / "environment.staging.ts",
    )
    parser.add_argument(
        "--solslot-portal-env",
        "--populis-portal-env",
        dest="solslot_portal_env",
        type=Path,
        default=WORKSPACE_ROOT
        / "populis_portal"
        / "src"
        / "environments"
        / "environment.shared.ts",
    )
    parser.add_argument("--bridge-policy-hash")
    parser.add_argument("--members-merkle-root")
    parser.add_argument("--protocol-config-launcher-id")
    parser.add_argument("--vault-version-registry-launcher-id")
    parser.add_argument(
        "--allow-existing-bootstrap",
        action="store_true",
        help="Do not treat an existing bootstrap_manifest.json as a ceremony lock.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Always exit 0 after printing findings.",
    )
    return parser.parse_args()


def load_json(path: Path, findings: list[Finding], label: str) -> dict[str, Any] | None:
    if not path.exists():
        findings.append(Finding("error", f"{label} missing: {path}"))
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - operator-facing preflight
        findings.append(Finding("error", f"{label} is not valid JSON: {path} ({exc})"))
        return None
    if not isinstance(value, dict):
        findings.append(Finding("error", f"{label} must be a JSON object: {path}"))
        return None
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def content_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def is_hex32(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX32_RE.fullmatch(value))


def is_nonzero_hex32(value: Any) -> bool:
    return is_hex32(value) and set(str(value)[2:]) != {"0"}


def is_bls_g1(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX48_RE.fullmatch(value))


def is_nonzero_bls_g1(value: Any) -> bool:
    text = str(value)
    text = text[2:] if text.startswith("0x") else text
    return is_bls_g1(value) and set(text) != {"0"}


def env_solslot_protocol(path: Path, findings: list[Finding], label: str) -> dict[str, str]:
    if not path.exists():
        findings.append(Finding("warn", f"{label} env missing: {path}"))
        return {}
    text = path.read_text(encoding="utf-8")
    object_name = "solslotProtocol"
    start = text.find(object_name)
    if start < 0:
        object_name = "populisProtocol"
        start = text.find(object_name)
        if start < 0:
            findings.append(Finding("warn", f"{label} has no solslotProtocol object: {path}"))
            return {}
        findings.append(
            Finding(
                "warn",
                f"{label} uses legacy populisProtocol object; rename to solslotProtocol: {path}",
            )
        )
    brace_start = text.find("{", start)
    if brace_start < 0:
        findings.append(Finding("warn", f"{label} {object_name} object is malformed: {path}"))
        return {}

    depth = 0
    end = -1
    for index in range(brace_start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end < 0:
        findings.append(Finding("warn", f"{label} {object_name} object is unterminated: {path}"))
        return {}

    body = text[brace_start + 1 : end]
    values: dict[str, str] = {}
    pattern = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*)\s*:\s*['\"]([^'\"]*)['\"]")
    for key, value in pattern.findall(body):
        values[key] = value
    return values


def apply_overrides(coordinates: dict[str, str], args: argparse.Namespace) -> None:
    overrides = {
        "bridgePolicyHash": args.bridge_policy_hash,
        "membersMerkleRoot": args.members_merkle_root,
        "protocolConfigLauncherId": args.protocol_config_launcher_id,
        "vaultVersionRegistryLauncherId": args.vault_version_registry_launcher_id,
    }
    for key, value in overrides.items():
        if value:
            coordinates[key] = value


def coordinate_from_manifest(deployment: dict[str, Any]) -> dict[str, str]:
    coordinates: dict[str, str] = {}
    for frontend_key, manifest_keys in FRONTEND_COORDINATES.items():
        for manifest_key in manifest_keys:
            value = deployment.get(manifest_key)
            if value:
                coordinates[frontend_key] = str(value)
                break
    return coordinates


def check_deployment_manifest(
    deployment: dict[str, Any] | None,
    args: argparse.Namespace,
    findings: list[Finding],
) -> dict[str, str]:
    if deployment is None:
        return {}

    if deployment.get("network") != args.network:
        findings.append(
            Finding(
                "error",
                f"deployment_manifest network {deployment.get('network')!r} != {args.network!r}",
            )
        )

    missing = [key for key in BASE_DEPLOYMENT_FIELDS if key not in deployment]
    if missing:
        findings.append(Finding("error", f"deployment_manifest missing base fields: {missing}"))

    for key in BASE_DEPLOYMENT_FIELDS:
        if key in {"network", "params"} or key not in deployment:
            continue
        if not is_nonzero_hex32(deployment[key]):
            findings.append(
                Finding("error", f"deployment_manifest.{key} is not a nonzero 0x32 value")
            )

    params = deployment.get("params")
    if not isinstance(params, dict):
        findings.append(Finding("error", "deployment_manifest.params must be an object"))
    elif not isinstance(params.get("min_nav_registry_version"), int):
        findings.append(
            Finding(
                "error",
                "deployment_manifest.params.min_nav_registry_version is required for Pool Economic V2",
            )
        )

    for key in V2_TRUST_ANCHORS:
        value = deployment.get(key)
        if key == "trusted_nav_registry_gov_pubkey":
            if not is_nonzero_bls_g1(value):
                findings.append(
                    Finding(
                        "error",
                        "deployment_manifest.trusted_nav_registry_gov_pubkey "
                        "must be a nonzero 48-byte BLS G1 pubkey",
                    )
                )
        elif not is_nonzero_hex32(value):
            findings.append(
                Finding("error", f"deployment_manifest.{key} is required and must be nonzero 0x32")
            )

    coordinates = coordinate_from_manifest(deployment)
    apply_overrides(coordinates, args)
    for frontend_key in FRONTEND_COORDINATES:
        value = coordinates.get(frontend_key)
        if not is_nonzero_hex32(value):
            findings.append(
                Finding(
                    "error",
                    f"canonical frontend coordinate {frontend_key} is missing or invalid",
                )
            )
    return coordinates


def check_bootstrap_artifacts(
    deployment: dict[str, Any] | None,
    bootstrap: dict[str, Any] | None,
    runtime: dict[str, Any] | None,
    args: argparse.Namespace,
    findings: list[Finding],
) -> None:
    if args.bootstrap_manifest.exists() and not args.allow_existing_bootstrap:
        findings.append(
            Finding(
                "error",
                "bootstrap_manifest.json already exists at the selected path; "
                "the bootstrapper is locked for a fresh ceremony unless a new output path is used",
            )
        )
    if bootstrap is None or deployment is None:
        return

    artifact_hashes = bootstrap.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict):
        findings.append(Finding("error", "bootstrap_manifest.artifact_hashes must exist"))
        return
    expected_deployment_hash = artifact_hashes.get("deployment_manifest_json")
    actual_deployment_hash = content_hash(deployment)
    if expected_deployment_hash != actual_deployment_hash:
        findings.append(
            Finding(
                "error",
                "bootstrap_manifest deployment_manifest_json hash does not match "
                f"deployment_manifest.json ({expected_deployment_hash} != {actual_deployment_hash})",
            )
        )

    protocol = bootstrap.get("protocol")
    if isinstance(protocol, dict):
        for key in (
            "pool_launcher_id",
            "did_launcher_id",
            "tracker_launcher_id",
            "pgt_tail_hash",
            "pool_token_tail_hash",
            "pool_full_puzhash",
            "tracker_full_puzhash",
        ):
            if protocol.get(key) != deployment.get(key):
                findings.append(
                    Finding("error", f"bootstrap_manifest.protocol.{key} does not match deployment")
                )
    else:
        findings.append(Finding("error", "bootstrap_manifest.protocol must exist"))

    if runtime is not None:
        expected_runtime_hash = artifact_hashes.get("portal_runtime_config_json")
        actual_runtime_hash = content_hash(runtime)
        if expected_runtime_hash != actual_runtime_hash:
            findings.append(
                Finding(
                    "error",
                    "bootstrap_manifest portal_runtime_config_json hash does not match "
                    f"portal_runtime_config.json ({expected_runtime_hash} != {actual_runtime_hash})",
                )
            )


def check_frontend_env(
    env_values: dict[str, str],
    coordinates: dict[str, str],
    findings: list[Finding],
    label: str,
) -> None:
    if not env_values:
        return
    for key, expected in coordinates.items():
        if key not in env_values:
            findings.append(Finding("warn", f"{label} has no {key} pin"))
            continue
        actual = env_values.get(key, "")
        if not actual:
            findings.append(Finding("error", f"{label}.{key} is empty; frontend must stay locked"))
        elif expected and actual.lower() != expected.lower():
            findings.append(
                Finding(
                    "error",
                    f"{label}.{key} does not match canonical coordinate "
                    f"({actual} != {expected})",
                )
            )


def print_report(findings: list[Finding]) -> None:
    errors = [item for item in findings if item.severity == "error"]
    warnings = [item for item in findings if item.severity == "warn"]
    infos = [item for item in findings if item.severity == "info"]
    print("Solslot testnet genesis preflight")
    print(f"errors={len(errors)} warnings={len(warnings)} info={len(infos)}")
    for severity in ("error", "warn", "info"):
        subset = [item for item in findings if item.severity == severity]
        if not subset:
            continue
        print(f"\n{severity.upper()}:")
        for item in subset:
            print(f"- {item.message}")
    if not errors:
        print("\nREADY: no blocking findings.")
    else:
        print("\nNOT READY: resolve blocking findings before ceremony/unlock.")


def main() -> int:
    args = parse_args()
    findings: list[Finding] = []
    findings.append(Finding("info", f"workspace root: {WORKSPACE_ROOT}"))

    deployment = load_json(args.deployment_manifest, findings, "deployment_manifest.json")
    bootstrap = load_json(args.bootstrap_manifest, findings, "bootstrap_manifest.json")
    runtime = load_json(args.portal_runtime_config, findings, "portal_runtime_config.json")

    coordinates = check_deployment_manifest(deployment, args, findings)
    check_bootstrap_artifacts(deployment, bootstrap, runtime, args, findings)

    slui_env = env_solslot_protocol(args.slui_env, findings, "slui staging")
    check_frontend_env(slui_env, coordinates, findings, "slui staging solslotProtocol")

    portal_env = env_solslot_protocol(args.solslot_portal_env, findings, "solslot portal")
    check_frontend_env(portal_env, coordinates, findings, "solslot portal solslotProtocol")

    print_report(findings)
    has_errors = any(item.severity == "error" for item in findings)
    if args.report_only:
        return 0
    return 1 if has_errors else 0


if __name__ == "__main__":
    sys.exit(main())
