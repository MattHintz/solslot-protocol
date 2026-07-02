"""Cross-repo schema drift checks for the alpha protocol contract.

These tests intentionally read sibling repository source files instead of
importing their runtime modules.  They are tripwires for accidental wire-shape
drift across Chialisp drivers, the API, the Angular portal, and the EVM bridge.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from populis_puzzles.property_registry_driver import canonicalise_property_id


PROTOCOL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROTOCOL_ROOT.parent
SCHEMA = json.loads(
    (PROTOCOL_ROOT / "schema_contracts" / "alpha_protocol_schema.json").read_text(
        encoding="utf-8"
    )
)


def test_mint_draft_schema_matches_api_and_portal() -> None:
    api = _sibling("populis_api")
    portal = _sibling("populis_portal")
    expected = SCHEMA["mint_publish"]["draft_fields"]

    api_request_fields = _python_class_annotations(
        api / "populis_api" / "mint_endpoints.py",
        "ProposeMintRequest",
    )
    portal_request_fields = _ts_interface_fields(
        portal / "src" / "app" / "services" / "admin-api.service.ts",
        "ProposeMintRequest",
    )

    assert api_request_fields == expected
    assert portal_request_fields == expected


def test_mint_publish_metadata_wire_shape_matches_api_and_portal() -> None:
    api = _sibling("populis_api")
    portal = _sibling("populis_portal")
    expected = SCHEMA["mint_publish"]["proposal_metadata_fields"]

    api_validation_fields = _python_class_annotations(
        api / "populis_api" / "mint_publish_validation.py",
        "PublishProposalMetadata",
    )
    api_request_fields = _python_class_annotations(
        api / "populis_api" / "mint_endpoints.py",
        "PublishProposalMetadataRequest",
    )
    portal_wire_fields = _ts_interface_fields(
        portal / "src" / "app" / "services" / "committee-api.service.ts",
        "PublishProposalMetadataJson",
    )
    runner_payload_fields = _ts_object_keys_after_type(
        portal
        / "src"
        / "app"
        / "services"
        / "mint-proposal-v2"
        / "mint-proposal-v2-publish-runner.service.ts",
        "proposalMetadata",
        "PublishProposalMetadataJson",
    )

    assert api_validation_fields == expected
    assert api_request_fields == expected
    assert portal_wire_fields == expected
    assert runner_payload_fields == expected


def test_mint_publish_protocol_context_env_mapping_matches_api_and_portal() -> None:
    api = _sibling("populis_api")
    portal = _sibling("populis_portal")
    expected = SCHEMA["mint_publish"]["protocol_context"]

    api_env_pairs = _api_field_to_env_pairs(
        api / "populis_api" / "mint_publish_validation.py"
    )
    expected_pairs = [(item["api_setting"], item["api_env"]) for item in expected]
    assert api_env_pairs == expected_pairs

    api_settings = set(
        _python_class_annotations(api / "populis_api" / "config.py", "Settings")
    )
    for item in expected:
        assert item["api_setting"] in api_settings

    for env_path in [
        portal / "src" / "environments" / "environment.ts",
        portal / "src" / "environments" / "environment.prod.ts",
    ]:
        portal_keys = _portal_populis_protocol_keys(env_path)
        for item in expected:
            assert item["portal_key"] in portal_keys


def test_property_id_and_asset_class_contract_matches_protocol_and_portal() -> None:
    portal = _sibling("populis_portal")
    utils_path = portal / "src" / "app" / "utils" / "mint-property-id.ts"
    text = utils_path.read_text(encoding="utf-8")

    assert ".trim().toUpperCase()" in text
    assert "new TextEncoder().encode(canonicalizeMintPropertyId(raw))" in text
    assert canonicalise_property_id(" us-tx-travis-9001 ").hex() == (
        hashlib.sha256(b"US-TX-TRAVIS-9001").hexdigest()
    )
    assert _ts_string_number_map(text, "ALPHA_ASSET_CLASS_CODES") == SCHEMA[
        "mint_publish"
    ]["asset_classes"]


def test_zkpassport_schema_matches_evm_and_portal() -> None:
    evm = _sibling("populis_evm")
    portal = _sibling("populis_portal")
    expected = SCHEMA["zkpassport"]

    solidity = (evm / "contracts" / "PopulisZkPassportAttestationEmitter.sol").read_text(
        encoding="utf-8"
    )
    assert _solidity_struct_fields(solidity, "VaultAttestation") == [
        (item["name"], item["type"])
        for item in expected["vault_attestation_components"]
    ]
    assert _solidity_event_fields(solidity, "VaultAttestationVerified") == [
        (item["name"], item["type"], item["indexed"])
        for item in expected["vault_attestation_verified_event"]
    ]
    assert _solidity_constructor_fields(
        solidity, "PopulisZkPassportAttestationEmitter"
    ) == [(item["name"], item["type"]) for item in expected["emitter_constructor"]]
    assert _solidity_validator_message_fields(solidity) == expected[
        "validator_message_fields"
    ]

    attestation_service = (
        portal / "src" / "app" / "services" / "zkpassport-attestation.service.ts"
    ).read_text(encoding="utf-8")
    poller_service = (
        portal
        / "src"
        / "app"
        / "services"
        / "zkpassport-evm-attestation-poller.service.ts"
    ).read_text(encoding="utf-8")
    assert _portal_validator_message_fields(attestation_service) == expected[
        "validator_message_fields"
    ]
    assert _portal_event_abi_fields(poller_service, "VaultAttestationVerified") == [
        (item["name"], item["type"], item["indexed"])
        for item in expected["vault_attestation_verified_event"]
    ]


def test_mint_lifecycle_states_match_api_and_portal() -> None:
    api = _sibling("populis_api")
    portal = _sibling("populis_portal")
    expected = SCHEMA["state"]["mint_lifecycle_states"]

    assert _python_literal_assignment(
        api / "populis_api" / "mint_proposals.py", "ALL_STATES"
    ) == tuple(expected)
    portal_states = _ts_union_literals(
        portal / "src" / "app" / "services" / "admin-api.service.ts",
        "MintProposalState",
    )
    assert set(portal_states) == set(expected)
    assert len(portal_states) == len(expected)

    assert "EXECUTING" not in _read_tree_text(portal / "src" / "app")


def _sibling(name: str) -> Path:
    path = WORKSPACE_ROOT / name
    if not path.exists():
        pytest.skip(f"{name} sibling checkout is not available")
    return path


def _python_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _python_class_annotations(path: Path, class_name: str) -> list[str]:
    tree = _python_tree(path)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            fields: list[str] = []
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    fields.append(item.target.id)
            return fields
    raise AssertionError(f"{class_name} not found in {path}")


def _python_literal_assignment(path: Path, name: str) -> Any:
    tree = _python_tree(path)
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
        ):
            return ast.literal_eval(node.value)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} assignment not found in {path}")


def _api_field_to_env_pairs(path: Path) -> list[tuple[str, str]]:
    tree = _python_tree(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "build_protocol_publish_context":
            for item in node.body:
                if (
                    isinstance(item, ast.Assign)
                    and any(
                        isinstance(t, ast.Name) and t.id == "field_to_env"
                        for t in item.targets
                    )
                ):
                    return list(ast.literal_eval(item.value))
    raise AssertionError(f"field_to_env not found in {path}")


def _ts_interface_fields(path: Path, interface_name: str) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"export\s+interface\s+{re.escape(interface_name)}\s*{{(?P<body>.*?)^}}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"{interface_name} not found in {path}")
    return re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\??\s*:", match.group("body"), re.MULTILINE)


def _ts_object_keys_after_type(path: Path, const_name: str, type_name: str) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"const\s+{re.escape(const_name)}\s*:\s*{re.escape(type_name)}\s*=\s*{{(?P<body>.*?)^\s*}};",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"{const_name}: {type_name} object not found in {path}")
    return re.findall(r"^\s*([a-z_][a-z0-9_]*)\s*:", match.group("body"), re.MULTILINE)


def _portal_populis_protocol_keys(path: Path) -> set[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(
        (idx for idx, line in enumerate(lines) if re.match(r"\s*populisProtocol:\s*{", line)),
        None,
    )
    if start is None:
        raise AssertionError(f"populisProtocol object not found in {path}")
    body: list[str] = []
    for line in lines[start + 1 :]:
        if re.match(r"\s{2}},?\s*$", line):
            break
        body.append(line)
    return set(re.findall(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*:", "\n".join(body), re.MULTILINE))


def _ts_string_number_map(text: str, const_name: str) -> dict[str, int]:
    match = re.search(
        rf"const\s+{re.escape(const_name)}[^=]*=\s*{{(?P<body>.*?)}};",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"{const_name} map not found")
    return {
        key: int(value)
        for key, value in re.findall(
            r"['\"]([^'\"]+)['\"]\s*:\s*(\d+)", match.group("body")
        )
    }


def _ts_union_literals(path: Path, type_name: str) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"export\s+type\s+{re.escape(type_name)}\s*=\s*(?P<body>.*?);",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"{type_name} union not found in {path}")
    return re.findall(r"'([^']+)'", match.group("body"))


def _solidity_struct_fields(text: str, struct_name: str) -> list[tuple[str, str]]:
    body = _solidity_block(text, rf"struct\s+{re.escape(struct_name)}")
    return [
        (name, typ)
        for typ, name in re.findall(r"^\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+);", body, re.MULTILINE)
    ]


def _solidity_event_fields(text: str, event_name: str) -> list[tuple[str, str, bool]]:
    match = re.search(rf"event\s+{re.escape(event_name)}\s*\((?P<body>.*?)\);", text, re.DOTALL)
    if not match:
        raise AssertionError(f"{event_name} event not found")
    fields: list[tuple[str, str, bool]] = []
    for raw in match.group("body").split(","):
        item = raw.strip()
        if not item:
            continue
        parts = item.split()
        indexed = "indexed" in parts
        parts = [p for p in parts if p != "indexed"]
        if len(parts) != 2:
            raise AssertionError(f"Cannot parse event field: {item!r}")
        fields.append((parts[1], parts[0], indexed))
    return fields


def _solidity_constructor_fields(text: str, contract_name: str) -> list[tuple[str, str]]:
    contract_body = _solidity_block(text, rf"contract\s+{re.escape(contract_name)}[^\n]*")
    match = re.search(r"constructor\s*\((?P<body>.*?)\)", contract_body, re.DOTALL)
    if not match:
        raise AssertionError(f"{contract_name} constructor not found")
    fields: list[tuple[str, str]] = []
    for raw in match.group("body").split(","):
        item = raw.strip()
        if not item:
            continue
        parts = item.split()
        if len(parts) < 2:
            raise AssertionError(f"Cannot parse constructor field: {item!r}")
        fields.append((parts[-1], parts[0]))
    return fields


def _solidity_validator_message_fields(text: str) -> list[str]:
    body = _solidity_block(text, r"function\s+_validatorMessageFields[^{]*")
    assignments: dict[int, str] = {}
    for index, expr in re.findall(r"fields\[(\d+)\]\s*=\s*([^;]+);", body):
        assignments[int(index)] = _validator_expr_name(expr.strip())
    return [assignments[i] for i in range(len(assignments))]


def _validator_expr_name(expr: str) -> str:
    if "POLICY_VERSION" in expr:
        return "policyVersion"
    if expr == "bridgePolicyHash":
        return "bridgePolicyHash"
    match = re.search(r"attestation\.([A-Za-z0-9_]+)", expr)
    if match:
        return match.group(1)
    raise AssertionError(f"Cannot map validator expression {expr!r}")


def _portal_validator_message_fields(text: str) -> list[str]:
    method = re.search(
        r"computeValidatorBridgeMessage[^{]*{(?P<body>.*?)return\s+bytesToHex",
        text,
        re.DOTALL,
    )
    if not method:
        raise AssertionError("computeValidatorBridgeMessage not found")
    hashes = re.search(r"const\s+hashes\s*=\s*\[(?P<body>.*?)\];", method.group("body"), re.DOTALL)
    if not hashes:
        raise AssertionError("validator-message hashes array not found")
    fields: list[str] = []
    for line in hashes.group("body").splitlines():
        line = line.strip()
        if "treeHashAtom" not in line:
            continue
        if "uintBytes32(policyVersion)" in line:
            fields.append("policyVersion")
            continue
        match = re.search(r"bytes32\(input\.([A-Za-z0-9_]+),\s*'([^']+)'\)", line)
        if match:
            assert match.group(1) == match.group(2)
            fields.append(match.group(1))
            continue
        match = re.search(r"uintBytes32\(input\.([A-Za-z0-9_]+)\)", line)
        if match:
            fields.append(match.group(1))
            continue
        raise AssertionError(f"Cannot parse validator-message line: {line!r}")
    return fields


def _portal_event_abi_fields(text: str, event_name: str) -> list[tuple[str, str, bool]]:
    match = re.search(rf"event\s+{re.escape(event_name)}\((?P<body>.*?)\)", text, re.DOTALL)
    if not match:
        raise AssertionError(f"{event_name} ABI string not found")
    fields: list[tuple[str, str, bool]] = []
    for raw in match.group("body").split(","):
        item = raw.strip().strip("'\"")
        parts = item.split()
        indexed = "indexed" in parts
        parts = [p for p in parts if p != "indexed"]
        if len(parts) != 2:
            raise AssertionError(f"Cannot parse ABI event field: {item!r}")
        fields.append((parts[1], parts[0], indexed))
    return fields


def _solidity_block(text: str, prefix_pattern: str) -> str:
    match = re.search(prefix_pattern + r"\s*{", text)
    if not match:
        raise AssertionError(f"Solidity block not found: {prefix_pattern}")
    start = match.end() - 1
    depth = 0
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : idx]
    raise AssertionError(f"Unclosed Solidity block: {prefix_pattern}")


def _read_tree_text(root: Path) -> str:
    chunks: list[str] = []
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".ts", ".html", ".scss", ".css"}:
            chunks.append(path.read_text(encoding="utf-8"))
    return "\n".join(chunks)
