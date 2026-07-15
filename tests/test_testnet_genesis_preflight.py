from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "testnet_genesis_preflight.py"
SPEC = importlib.util.spec_from_file_location("solslot_genesis_preflight", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)


def _hex(index: int, length: int = 32) -> str:
    return "0x" + index.to_bytes(length, "big").hex()


def _address(index: int) -> str:
    return _hex(index, 20)


def _admin_key(index: int) -> str:
    return "0x02" + index.to_bytes(32, "big").hex()


def _source_shas() -> dict[str, str]:
    return {
        "protocol": "1" * 40,
        "evm": "2" * 40,
        "api": "3" * 40,
        "customerWeb": "4" * 40,
        "adminPortal": "5" * 40,
    }


def _ceremony_plan() -> tuple[dict, dict, dict, dict]:
    ceremony_id = _hex(1)
    sources = _source_shas()
    admin_keys = [_admin_key(index) for index in (1, 2, 3)]
    roster_hash = _hex(220)
    evm_addresses = {
        "forwarder": _address(1),
        "verifierAdapter": _address(2),
        "attestationEmitter": _address(3),
    }
    validator_keys = [_hex(index, 48) for index in (31, 32, 33)]
    plan = {
        "schema": "solslot-genesis-plan-v2",
        "protocolVersion": "solslot-v2",
        "ceremonyId": ceremony_id,
        "network": "testnet11",
        "evmChainId": 11155111,
        "expiresAt": 2_000_000_000,
        "sourceShas": sources,
        "evmAddresses": evm_addresses,
        "fundingCoinIds": {
            name: _hex(10 + index)
            for index, name in enumerate(preflight.FUNDING_NAMES)
        },
        "launcherIds": {
            name: _hex(30 + index)
            for index, name in enumerate(preflight.LAUNCHER_NAMES)
        },
        "puzzleHashes": {
            "poolInner": _hex(50),
            "poolFull": _hex(51),
            "didInner": _hex(52),
            "didFull": _hex(53),
            "governanceInner": _hex(54),
            "governanceFull": _hex(55),
            "navRegistryInner": _hex(56),
            "navRegistryFull": _hex(57),
            "protocolConfigInner": _hex(58),
            "protocolConfigFull": _hex(59),
            "adminAuthorityInner": _hex(60),
            "adminAuthorityFull": _hex(61),
            "vaultVersionRegistryInner": _hex(62),
            "vaultVersionRegistryFull": _hex(63),
            "sgtTail": _hex(64),
            "bridgePolicy": _hex(65),
        },
        "protocolParameters": {"quorum_bps": 5000},
        "stateVersions": {
            "navRegistry": 1,
            "protocolConfig": 1,
            "adminAuthority": 2,
            "vault": 2,
        },
        "adminAuthority": {
            "threshold": 2,
            "compressedPubkeys": admin_keys,
            "adminsHash": roster_hash,
            "mipsRootHash": _hex(221),
        },
        "validatorSet": {"threshold": 2, "pubkeys": validator_keys},
        "bridgeBatch": {
            "count": 32,
            "lowWaterMark": 8,
            "parentCoinIds": [_hex(1000 + index) for index in range(32)],
            "bridgeCoinIds": [_hex(2000 + index) for index in range(32)],
        },
        "trustedDestinations": {
            "treasuryReservePuzzleHash": _hex(70),
            "protocolTreasuryPuzzleHash": _hex(71),
            "governanceRewardsPuzzleHash": _hex(72),
            "governanceRewardsRoot": _hex(73),
        },
        "canonicalVaultParamsHash": _hex(74),
        "retiredCoordinates": [_hex(75), _hex(76)],
    }
    plan["planHash"] = preflight.plan_hash(plan)
    record = {
        "ceremony_id": ceremony_id,
        "network": "testnet11",
        "state": "plan_approved",
        "draft": {
            "schemaVersion": 2,
            "network": "testnet11",
            "evmChainId": 11155111,
            "sourceShas": sources,
        },
        "roster_hash": roster_hash,
        "plan": plan,
        "plan_hash": plan["planHash"],
        "plan_expires_at": plan["expiresAt"],
        "invitations": [
            {
                "slot": slot,
                "expires_at": 2_000_000_000,
                "consumed_at": 1,
                "wallet_address": _address(100 + slot),
                "compressed_pubkey": admin_keys[slot - 1],
            }
            for slot in (1, 2, 3)
        ],
        "plan_signatures": [
            {
                "slot": slot,
                "plan_hash": plan["planHash"],
                "compressed_pubkey": admin_keys[slot - 1],
                "signature": _hex(400 + slot, 65),
                "submitted_at": 2,
            }
            for slot in (1, 3)
        ],
        "artifact_signatures": [],
    }
    spend_bundle_id = _hex(230)
    approval = {
        "schemaVersion": 2,
        "ceremonyId": ceremony_id,
        "planHash": plan["planHash"],
        "sourceShas": sources,
        "consensusSimulationBundleId": spend_bundle_id,
        "approvals": [
            {
                "lane": lane,
                "approved": True,
                "reviewer": f"reviewer-{index}",
                "evidenceHash": _hex(300 + index),
            }
            for index, lane in enumerate(preflight.AUDIT_LANES)
        ],
        "evmContracts": {
            name: {
                "address": address,
                "bytecodeHash": _hex(500 + index),
                "confirmations": 12,
            }
            for index, (name, address) in enumerate(evm_addresses.items())
        },
        "validators": {
            "threshold": 2,
            "pubkeys": validator_keys,
            "healthy": [True, True, True],
        },
    }
    api_evidence = {
        "ready": True,
        "ceremonyId": ceremony_id,
        "planHash": plan["planHash"],
        "spendBundleId": spend_bundle_id,
        "spendCount": 42,
        "auditApprovalHash": preflight.canonical_hash(approval),
    }
    return record, plan, approval, api_evidence


def _public_artifact(record: dict, plan: dict) -> dict:
    admin_keys = plan["adminAuthority"]["compressedPubkeys"]
    artifact = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "network": "testnet11",
        "evmChainId": 11155111,
        "buildTimestamp": "2026-07-14T00:00:00+00:00",
        "ceremony": {
            "ceremonyId": record["ceremony_id"],
            "planHash": record["plan_hash"],
            "spendBundleId": record["spend_bundle_id"],
            "confirmedBlockIndex": record["confirmed_block_index"],
            "requiredChiaConfirmations": 3,
        },
        "sourceShas": plan["sourceShas"],
        "puzzleHashes": plan["puzzleHashes"],
        "launcherIds": plan["launcherIds"],
        "sgtGenesisCoinId": _hex(80),
        "sgtTailHash": plan["puzzleHashes"]["sgtTail"],
        "governanceStruct": {
            "treeHash": _hex(81),
            "launcherId": plan["launcherIds"]["governance"],
        },
        "protocolParameters": plan["protocolParameters"],
        "stateVersions": plan["stateVersions"],
        "adminAuthority": {
            "threshold": 2,
            "rosterHash": plan["adminAuthority"]["adminsHash"],
            "mipsRootHash": plan["adminAuthority"]["mipsRootHash"],
            "compressedPubkeys": admin_keys,
        },
        "validatorSet": plan["validatorSet"],
        "bridgePolicy": {
            "policyVersion": 2,
            "policyHash": plan["puzzleHashes"]["bridgePolicy"],
            "initialCoinCount": 32,
            "lowWaterMark": 8,
            "parentCoinIds": plan["bridgeBatch"]["parentCoinIds"],
            "bridgeCoinIds": plan["bridgeBatch"]["bridgeCoinIds"],
        },
        "canonicalVaultParamsHash": plan["canonicalVaultParamsHash"],
        "evmAddresses": plan["evmAddresses"],
        "retiredCoordinates": plan["retiredCoordinates"],
        "signaturePolicy": {
            "type": "SolslotGenesisArtifact",
            "threshold": 2,
            "rosterHash": plan["adminAuthority"]["adminsHash"],
        },
        "signatures": [
            {
                "adminIndex": index,
                "compressedPubkey": admin_keys[index],
                "signature": _hex(600 + index, 65),
            }
            for index in (0, 2)
        ],
    }
    artifact["artifactHash"] = preflight.artifact_hash(artifact)
    return artifact


def _write_evidence(path: Path, plan: dict, approval: dict, artifact: dict) -> None:
    payloads = {
        "plan.json": plan,
        "spend_bundle.json": {"aggregatedSignature": "00", "coinSpends": []},
        "audit_approval.json": approval,
        "public_artifact.json": artifact,
    }
    path.mkdir()
    for name, payload in payloads.items():
        (path / name).write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="ascii"
        )
    sums = "".join(
        hashlib.sha256((path / name).read_bytes()).hexdigest() + "  " + name + "\n"
        for name in sorted(payloads)
    )
    (path / "sha256sums.txt").write_text(sums, encoding="ascii")


def test_pre_broadcast_accepts_complete_frozen_evidence(tmp_path: Path) -> None:
    record, _plan, approval, api_evidence = _ceremony_plan()
    findings: list[preflight.Finding] = []
    preflight.check_pre_broadcast(
        record,
        api_evidence,
        approval,
        tmp_path / "new-output",
        findings,
        now=1_900_000_000,
    )
    assert findings == []


def test_pre_broadcast_rejects_expiry_and_lost_quorum(tmp_path: Path) -> None:
    record, _plan, approval, api_evidence = _ceremony_plan()
    record["plan_signatures"] = record["plan_signatures"][:1]
    findings: list[preflight.Finding] = []
    preflight.check_pre_broadcast(
        record,
        api_evidence,
        approval,
        tmp_path / "new-output",
        findings,
        now=2_100_000_000,
    )
    messages = "\n".join(item.message for item in findings)
    assert "expired" in messages
    assert "two distinct administrator plan signatures" in messages


def test_post_genesis_accepts_locked_checksummed_release(tmp_path: Path) -> None:
    record, plan, approval, _api_evidence = _ceremony_plan()
    record.update(
        state="locked",
        spend_bundle_id=_hex(230),
        confirmed_block_index=1234,
    )
    artifact = _public_artifact(record, plan)
    record["artifact_hash"] = artifact["artifactHash"]
    record["artifact"] = {**artifact, "signatures": []}
    record["artifact_signatures"] = [
        {
            "slot": entry["adminIndex"] + 1,
            "artifact_hash": artifact["artifactHash"],
            "compressed_pubkey": entry["compressedPubkey"],
            "signature": entry["signature"],
            "submitted_at": 3,
        }
        for entry in artifact["signatures"]
    ]
    lock = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "ceremonyId": record["ceremony_id"],
        "planHash": record["plan_hash"],
        "artifactHash": artifact["artifactHash"],
        "spendBundleId": record["spend_bundle_id"],
        "confirmedBlockIndex": record["confirmed_block_index"],
        "lockedAt": 1_900_000_100,
    }
    evidence_dir = tmp_path / "evidence"
    _write_evidence(evidence_dir, plan, approval, artifact)
    attestation = {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "network": "testnet11",
        "artifactHash": artifact["artifactHash"],
        "writeLocks": {
            "alphaWritesEnabled": False,
            "mintingEnabled": False,
            "ceremonyModeEnabled": False,
        },
        "consumers": {
            name: {
                "reachable": True,
                "artifactHash": artifact["artifactHash"],
                "sourceSha": artifact["sourceShas"][name],
            }
            for name in preflight.CONSUMERS
        },
    }
    findings: list[preflight.Finding] = []
    preflight.check_post_genesis(
        record,
        artifact,
        lock,
        evidence_dir,
        attestation,
        findings,
    )
    assert findings == []

    broken = copy.deepcopy(attestation)
    broken["consumers"]["customerWeb"]["sourceSha"] = "f" * 40
    broken_findings: list[preflight.Finding] = []
    preflight.check_post_genesis(
        record,
        artifact,
        lock,
        evidence_dir,
        broken,
        broken_findings,
    )
    assert any("customerWeb" in item.message for item in broken_findings)


def test_repository_gate_rejects_dirty_or_wrong_frozen_commit(tmp_path: Path) -> None:
    paths: dict[str, Path] = {}
    sources: dict[str, str] = {}
    for name in preflight.SOURCE_NAMES:
        path = tmp_path / name
        path.mkdir()
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.email", "test@solslot.invalid"], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.name", "Solslot Test"], check=True)
        (path / "tracked.txt").write_text(name, encoding="ascii")
        subprocess.run(["git", "-C", str(path), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "-qm", "fixture"], check=True)
        sources[name] = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        paths[name] = path

    findings: list[preflight.Finding] = []
    preflight.check_repositories(sources, paths, findings)
    assert findings == []

    (paths["api"] / "tracked.txt").write_text("dirty", encoding="ascii")
    sources["evm"] = "f" * 40
    broken: list[preflight.Finding] = []
    preflight.check_repositories(sources, paths, broken)
    messages = "\n".join(item.message for item in broken)
    assert "api worktree is dirty" in messages
    assert "evm HEAD" in messages


def test_malformed_operator_evidence_fails_closed_without_crashing(tmp_path: Path) -> None:
    record, _plan, approval, api_evidence = _ceremony_plan()
    record["invitations"][0] = "not-an-object"
    record["plan_signatures"][0] = None
    record["plan_expires_at"] = "not-an-integer"
    approval["approvals"][0] = None
    approval["evmContracts"]["forwarder"]["confirmations"] = "bad"
    api_evidence["spendCount"] = "bad"

    findings: list[preflight.Finding] = []
    preflight.check_pre_broadcast(
        record,
        api_evidence,
        approval,
        tmp_path / "new-output",
        findings,
        now=1_900_000_000,
    )
    assert any(item.severity == "error" for item in findings)
    assert any("must be an object" in item.message for item in findings)
    assert any("must be an integer" in item.message for item in findings)
