from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from solslot_puzzles.artifact_schema_v4 import build_public_artifact
from tests.test_genesis_ceremony_rc23 import (
    ceremony_plan as protocol_ceremony_plan,
    funding_coins,
)
from tests.test_protocol_deployment import _FakeFaucet


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
        "omnichain": "3" * 40,
        "api": "4" * 40,
        "legacyBackend": "5" * 40,
        "keyOfSolomon": "6" * 40,
        "samuel": "7" * 40,
        "customerWeb": "8" * 40,
        "adminPortal": "9" * 40,
    }


def _ceremony_plan() -> tuple[dict, dict, dict, dict]:
    faucet = _FakeFaucet()
    plan = protocol_ceremony_plan(
        faucet,
        funding_coins(faucet),
    ).canonical_payload()
    ceremony_id = plan["ceremonyId"]
    sources = plan["sourceShas"]
    admin_keys = plan["adminAuthority"]["compressedPubkeys"]
    roster_hash = plan["adminAuthority"]["adminsHash"]
    evm_addresses = plan["evmAddresses"]
    validator_keys = plan["validatorSet"]["pubkeys"]
    record = {
        "ceremony_id": ceremony_id,
        "network": "testnet11",
        "state": "plan_approved",
        "draft": {
            "schemaVersion": 2,
            "sourceManifestVersion": 4,
            "network": "testnet11",
            "evmChainId": 11155111,
            "reviewClass": "independent-release-review",
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
        "sourceManifestVersion": 4,
        "ceremonyId": ceremony_id,
        "planHash": plan["planHash"],
        "sourceShas": sources,
        "consensusSimulationBundleId": spend_bundle_id,
        "authorityV3Review": {
            "artifactHash": _hex(290),
            "fileSha256": _hex(291),
            "reviewerCount": 4,
            "scopes": [
                "chialisp-wrapper",
                "mips-composition",
                "safe-recovery-module",
                "safe-authority-guards",
            ],
        },
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
        "reviewApproval": copy.deepcopy(approval),
    }
    return record, plan, approval, api_evidence


def _public_artifact(record: dict, plan: dict) -> dict:
    faucet = _FakeFaucet()
    plan_object = protocol_ceremony_plan(
        faucet,
        funding_coins(faucet),
    )
    assert plan_object.canonical_payload() == plan
    admin_keys = plan["adminAuthority"]["compressedPubkeys"]
    return build_public_artifact(
        plan=plan_object,
        spend_bundle_id=record["spend_bundle_id"],
        confirmed_block_index=record["confirmed_block_index"],
        build_timestamp="2026-07-29T00:00:00+00:00",
        signatures=[
            {
                "adminIndex": index,
                "compressedPubkey": admin_keys[index],
                "signature": _hex(600 + index, 65),
            }
            for index in (0, 2)
        ],
        review_class="independent-release-review",
    )


def _write_evidence(path: Path, plan: dict, approval: dict, artifact: dict) -> None:
    review_receipt = {
        "schemaVersion": 1,
        "kind": "solslot-authority-v3-independent-review",
        "artifactHash": approval["authorityV3Review"][
            "artifactHash"
        ],
    }
    review_bytes = (
        json.dumps(review_receipt, sort_keys=True, indent=2) + "\n"
    ).encode("ascii")
    archived_approval = copy.deepcopy(approval)
    archived_approval["authorityV3Review"]["fileSha256"] = (
        "0x" + hashlib.sha256(review_bytes).hexdigest()
    )
    payloads = {
        "plan.json": plan,
        "spend_bundle.json": {"aggregatedSignature": "00", "coinSpends": []},
        "audit_approval.json": archived_approval,
        "public_artifact.json": artifact,
    }
    path.mkdir()
    for name, payload in payloads.items():
        (path / name).write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="ascii"
        )
    (path / "authority_v3_review.json").write_bytes(review_bytes)
    evidence_names = sorted(
        [*payloads, "authority_v3_review.json"]
    )
    sums = "".join(
        hashlib.sha256((path / name).read_bytes()).hexdigest() + "  " + name + "\n"
        for name in evidence_names
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
        now=1_700_000_000,
    )
    assert findings == []


def test_pre_broadcast_accepts_internal_engineering_testnet_review(tmp_path: Path) -> None:
    record, plan, approval, api_evidence = _ceremony_plan()
    record["draft"]["reviewClass"] = "internal-engineering-testnet"
    approval.pop("approvals")
    approval.update(
        reviewClass="internal-engineering-testnet",
        auditStatus="unaudited",
        testOnly=True,
        administratorReview={
            "threshold": 2,
            "roster": [
                {
                    "slot": item["slot"],
                    "wallet": item["wallet_address"],
                    "compressedPubkey": item["compressed_pubkey"],
                }
                for item in record["invitations"]
            ],
            "planSignerSlots": [1, 3],
        },
    )
    api_evidence["auditApprovalHash"] = preflight.canonical_hash(approval)
    api_evidence["reviewApproval"] = copy.deepcopy(approval)

    findings: list[preflight.Finding] = []
    preflight.check_pre_broadcast(
        record,
        api_evidence,
        approval,
        tmp_path / "new-output",
        findings,
        now=1_700_000_000,
    )
    assert findings == []

    approval["testOnly"] = False
    api_evidence["auditApprovalHash"] = preflight.canonical_hash(approval)
    api_evidence["reviewApproval"] = copy.deepcopy(approval)
    rejected: list[preflight.Finding] = []
    preflight.check_pre_broadcast(
        record,
        api_evidence,
        approval,
        tmp_path / "new-output",
        rejected,
        now=1_700_000_000,
    )
    assert any("test-only" in item.message for item in rejected)


def test_pre_broadcast_rejects_review_record_not_returned_by_api(tmp_path: Path) -> None:
    record, _plan, approval, api_evidence = _ceremony_plan()
    api_evidence["reviewApproval"]["ceremonyId"] = _hex(999)

    findings: list[preflight.Finding] = []
    preflight.check_pre_broadcast(
        record,
        api_evidence,
        approval,
        tmp_path / "new-output",
        findings,
        now=1_700_000_000,
    )

    assert any("canonical API preflight record" in item.message for item in findings)


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


def _rehash_plan_record(record: dict, plan: dict) -> None:
    plan["planHash"] = preflight.plan_hash(plan)
    record["plan_hash"] = plan["planHash"]
    for signature in record["plan_signatures"]:
        signature["plan_hash"] = plan["planHash"]


def test_pre_broadcast_rejects_recovery_dependency_drift() -> None:
    record, plan, _approval, _api_evidence = _ceremony_plan()
    plan["recoveryDependencyManifestHash"] = _hex(999)
    _rehash_plan_record(record, plan)

    findings: list[preflight.Finding] = []
    preflight._validate_plan(record, findings, now=1_700_000_000)

    assert any("pinned administrator recovery dependencies" in item.message for item in findings)


def test_pre_broadcast_rejects_identity_launcher_split_drift() -> None:
    record, plan, _approval, _api_evidence = _ceremony_plan()
    plan["adminAuthority"]["identityVaults"][1]["launcherAmount"] = 9
    _rehash_plan_record(record, plan)

    findings: list[preflight.Finding] = []
    preflight._validate_plan(record, findings, now=1_700_000_000)

    assert any("identity slot 1 is not canonical" in item.message for item in findings)


def test_pre_broadcast_rejects_bridge_funding_drift() -> None:
    record, plan, _approval, _api_evidence = _ceremony_plan()
    plan["bridgeBatch"]["fundingAmount"] = 531
    _rehash_plan_record(record, plan)

    findings: list[preflight.Finding] = []
    preflight._validate_plan(record, findings, now=1_700_000_000)

    assert any("bridge batch must contain 32 coins" in item.message for item in findings)


def test_pre_broadcast_rejects_authority_source_commitment_drift() -> None:
    record, plan, _approval, _api_evidence = _ceremony_plan()
    plan["adminAuthority"]["sourceManifestHash"] = _hex(998)
    _rehash_plan_record(record, plan)

    findings: list[preflight.Finding] = []
    preflight._validate_plan(record, findings, now=1_700_000_000)

    assert any("Authority V3 source commitment" in item.message for item in findings)


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
        "schemaVersion": 4,
        "sourceManifestVersion": 4,
        "protocolVersion": "solslot-v2-rc23",
        "reviewClass": artifact["reviewClass"],
        "testOnly": artifact["testOnly"],
        "auditStatus": artifact["auditStatus"],
        "ceremonyId": record["ceremony_id"],
        "planHash": record["plan_hash"],
        "artifactHash": artifact["artifactHash"],
        "spendBundleId": record["spend_bundle_id"],
        "confirmedBlockIndex": record["confirmed_block_index"],
        "lockedAt": 1_700_000_100,
    }
    evidence_dir = tmp_path / "evidence"
    _write_evidence(evidence_dir, plan, approval, artifact)
    attestation = {
        "schemaVersion": 4,
        "sourceManifestVersion": 4,
        "protocolVersion": "solslot-v2-rc23",
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

    (evidence_dir / "authority_v3_review.json").write_text(
        "{}\n",
        encoding="ascii",
    )
    tampered_findings: list[preflight.Finding] = []
    preflight.check_post_genesis(
        record,
        artifact,
        lock,
        evidence_dir,
        attestation,
        tampered_findings,
    )
    assert any(
        "Authority V3 review" in item.message
        or "authority_v3_review.json" in item.message
        for item in tampered_findings
    )


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
        now=1_700_000_000,
    )
    assert any(item.severity == "error" for item in findings)
    assert any("must be an object" in item.message for item in findings)
    assert any("must be an integer" in item.message for item in findings)
