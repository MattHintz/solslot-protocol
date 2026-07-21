"""Canonical property dossier commitments for governed SmartDeed mints.

The Chialisp contracts deliberately remain unaware of JSON.  This module
defines the off-chain/chain-reconstruction contract used by the admin desk,
API indexer, and public verifier:

* a deterministic RFC 8785-compatible JSON profile;
* a SHA-256 metadata root over canonical UTF-8 bytes;
* ordered, versioned CREATE_COIN memos for the first deed launcher; and
* collection deed-allocation invariants.

The JSON profile accepts only null, booleans, strings, safe integers, arrays,
and objects with string keys.  Floating-point numbers are rejected.  Dossier
money and percentage values are strings by contract, so this restriction
removes the only cross-language ambiguity in RFC 8785 number formatting.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from chia_rs.sized_bytes import bytes32


PROPERTY_DOSSIER_SCHEMA = "solslot.property-dossier.v1"
METADATA_ENVELOPE_SCHEMA = "solslot.metadata-envelope.v1"
PROPERTY_AMENDMENT_SCHEMA = "solslot.property-amendment.v1"
MAX_CANONICAL_METADATA_BYTES = 24 * 1024
MAX_MEMO_BYTES = 1024
TARGET_ALLOCATION_PPM = 1_000_000

_SAFE_INTEGER_MAX = (1 << 53) - 1
_HEADER_MAGIC = b"SOLSMD"
_CHUNK_MAGIC = b"SOLSMC"
_REFERENCE_MAGIC = b"SOLSMR"
_MEMO_VERSION = 1
_HEADER_BYTES = len(_HEADER_MAGIC) + 1 + 32 + 4 + 2
_CHUNK_PREFIX_BYTES = len(_CHUNK_MAGIC) + 1 + 2 + 2
_CHUNK_PAYLOAD_BYTES = MAX_MEMO_BYTES - _CHUNK_PREFIX_BYTES


class MetadataValidationError(ValueError):
    """Raised when metadata cannot be committed or reconstructed safely."""


@dataclass(frozen=True)
class MetadataCommitment:
    """Canonical bytes and their deterministic SHA-256 root."""

    canonical_json: bytes
    metadata_root: bytes32

    @property
    def byte_size(self) -> int:
        return len(self.canonical_json)


@dataclass(frozen=True)
class MetadataReference:
    """Compact metadata reference used by later proposals in a collection."""

    metadata_root: bytes32
    metadata_anchor_id: bytes32


def canonicalize_json(value: Any) -> bytes:
    """Return canonical UTF-8 JSON for the Solslot RFC 8785 profile.

    Object keys are ordered by their UTF-16 code units, matching RFC 8785/JCS.
    Strings containing lone UTF-16 surrogates are rejected because they cannot
    be represented as valid UTF-8.  Integers must fit JavaScript's safe range,
    which guarantees byte-identical Python and TypeScript serialization.
    """

    return _encode_json(value).encode("utf-8", errors="strict")


def commit_metadata(value: Any, *, enforce_size: bool = True) -> MetadataCommitment:
    canonical = canonicalize_json(value)
    if enforce_size and len(canonical) > MAX_CANONICAL_METADATA_BYTES:
        raise MetadataValidationError(
            "canonical metadata is "
            f"{len(canonical)} bytes; limit is {MAX_CANONICAL_METADATA_BYTES}"
        )
    return MetadataCommitment(
        canonical_json=canonical,
        metadata_root=bytes32(hashlib.sha256(canonical).digest()),
    )


def validate_deed_allocation(
    deeds: Sequence[Mapping[str, Any]],
) -> None:
    """Require unique deed ids and exactly 1,000,000 planned share ppm."""

    if not deeds:
        raise MetadataValidationError("deed allocation must contain at least one deed")
    seen: set[str] = set()
    total = 0
    for index, deed in enumerate(deeds):
        deed_id = deed.get("deedId")
        share_ppm = deed.get("sharePpm")
        if not isinstance(deed_id, str) or not deed_id.strip():
            raise MetadataValidationError(f"deed allocation row {index} has no deedId")
        normalized = deed_id.strip().upper()
        if normalized in seen:
            raise MetadataValidationError(f"duplicate deedId: {deed_id}")
        seen.add(normalized)
        if isinstance(share_ppm, bool) or not isinstance(share_ppm, int):
            raise MetadataValidationError(
                f"deed allocation row {index} sharePpm must be an integer"
            )
        if share_ppm <= 0 or share_ppm > TARGET_ALLOCATION_PPM:
            raise MetadataValidationError(
                f"deed allocation row {index} sharePpm must be in 1..1000000"
            )
        total += share_ppm
    if total != TARGET_ALLOCATION_PPM:
        raise MetadataValidationError(
            f"deed allocation totals {total} ppm; expected {TARGET_ALLOCATION_PPM}"
        )


def build_metadata_memos(commitment: MetadataCommitment) -> tuple[bytes, ...]:
    """Encode the full canonical dossier as ordered CREATE_COIN memos.

    Memo zero is a compact envelope header.  Remaining memos contain an index,
    total chunk count, and payload.  Every memo is at most 1024 bytes.
    """

    payload = commitment.canonical_json
    if len(payload) > MAX_CANONICAL_METADATA_BYTES:
        raise MetadataValidationError(
            f"canonical metadata exceeds {MAX_CANONICAL_METADATA_BYTES} bytes"
        )
    chunks = tuple(
        payload[offset : offset + _CHUNK_PAYLOAD_BYTES]
        for offset in range(0, len(payload), _CHUNK_PAYLOAD_BYTES)
    ) or (b"",)
    if len(chunks) > 0xFFFF:
        raise MetadataValidationError("metadata requires too many memo chunks")
    header = (
        _HEADER_MAGIC
        + bytes([_MEMO_VERSION])
        + bytes(commitment.metadata_root)
        + len(payload).to_bytes(4, "big")
        + len(chunks).to_bytes(2, "big")
    )
    assert len(header) == _HEADER_BYTES
    memos = [header]
    for index, chunk in enumerate(chunks):
        memos.append(
            _CHUNK_MAGIC
            + bytes([_MEMO_VERSION])
            + index.to_bytes(2, "big")
            + len(chunks).to_bytes(2, "big")
            + chunk
        )
    if any(len(memo) > MAX_MEMO_BYTES for memo in memos):
        raise AssertionError("metadata memo encoder exceeded the consensus memo cap")
    return tuple(memos)


def build_metadata_reference_memo(reference: MetadataReference) -> bytes:
    """Encode a later proposal's root + first deed launcher reference."""

    return (
        _REFERENCE_MAGIC
        + bytes([_MEMO_VERSION])
        + bytes(reference.metadata_root)
        + bytes(reference.metadata_anchor_id)
    )


def parse_metadata_reference_memo(memo: bytes) -> MetadataReference:
    expected = len(_REFERENCE_MAGIC) + 1 + 32 + 32
    if len(memo) != expected or not memo.startswith(_REFERENCE_MAGIC):
        raise MetadataValidationError("invalid metadata reference memo")
    version_offset = len(_REFERENCE_MAGIC)
    if memo[version_offset] != _MEMO_VERSION:
        raise MetadataValidationError("unsupported metadata reference version")
    start = version_offset + 1
    return MetadataReference(
        metadata_root=bytes32(memo[start : start + 32]),
        metadata_anchor_id=bytes32(memo[start + 32 : start + 64]),
    )


def reconstruct_metadata_memos(memos: Sequence[bytes]) -> MetadataCommitment:
    """Reconstruct and verify a canonical dossier from ordered chain memos."""

    if len(memos) < 2:
        raise MetadataValidationError("metadata envelope is missing header or chunks")
    header = bytes(memos[0])
    if len(header) != _HEADER_BYTES or not header.startswith(_HEADER_MAGIC):
        raise MetadataValidationError("invalid metadata envelope header")
    version_offset = len(_HEADER_MAGIC)
    if header[version_offset] != _MEMO_VERSION:
        raise MetadataValidationError("unsupported metadata envelope version")
    cursor = version_offset + 1
    expected_root = bytes32(header[cursor : cursor + 32])
    cursor += 32
    expected_length = int.from_bytes(header[cursor : cursor + 4], "big")
    cursor += 4
    expected_chunks = int.from_bytes(header[cursor : cursor + 2], "big")
    if expected_length > MAX_CANONICAL_METADATA_BYTES:
        raise MetadataValidationError("metadata envelope declares an oversized payload")
    if expected_chunks == 0 or len(memos) != expected_chunks + 1:
        raise MetadataValidationError("metadata envelope chunk count mismatch")

    payload_parts: list[bytes] = []
    for expected_index, raw_memo in enumerate(memos[1:]):
        memo = bytes(raw_memo)
        if len(memo) > MAX_MEMO_BYTES or not memo.startswith(_CHUNK_MAGIC):
            raise MetadataValidationError("invalid metadata chunk memo")
        chunk_version_offset = len(_CHUNK_MAGIC)
        if memo[chunk_version_offset] != _MEMO_VERSION:
            raise MetadataValidationError("unsupported metadata chunk version")
        chunk_cursor = chunk_version_offset + 1
        actual_index = int.from_bytes(memo[chunk_cursor : chunk_cursor + 2], "big")
        chunk_cursor += 2
        actual_count = int.from_bytes(memo[chunk_cursor : chunk_cursor + 2], "big")
        chunk_cursor += 2
        if actual_index != expected_index:
            raise MetadataValidationError("metadata chunks are reordered or duplicated")
        if actual_count != expected_chunks:
            raise MetadataValidationError("metadata chunk total does not match header")
        payload_parts.append(memo[chunk_cursor:])

    canonical = b"".join(payload_parts)
    if len(canonical) != expected_length:
        raise MetadataValidationError("metadata payload length mismatch")
    actual_root = bytes32(hashlib.sha256(canonical).digest())
    if actual_root != expected_root:
        raise MetadataValidationError("metadata root mismatch")
    try:
        decoded = json.loads(canonical.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MetadataValidationError("metadata payload is not valid UTF-8 JSON") from exc
    if canonicalize_json(decoded) != canonical:
        raise MetadataValidationError("metadata payload is not canonical JSON")
    return MetadataCommitment(canonical_json=canonical, metadata_root=actual_root)


def estimate_consensus_cost(byte_size: int, *, cost_per_byte: int = 12_000) -> int:
    if byte_size < 0:
        raise MetadataValidationError("byte_size must be non-negative")
    return byte_size * cost_per_byte


def _encode_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        _assert_valid_unicode(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        if abs(value) > _SAFE_INTEGER_MAX:
            raise MetadataValidationError(
                f"integer {value} exceeds the cross-language safe range"
            )
        return str(value)
    if isinstance(value, float):
        raise MetadataValidationError(
            "floating-point values are prohibited; use decimal strings"
        )
    if isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise MetadataValidationError("JSON object keys must be strings")
            _assert_valid_unicode(key)
        parts = []
        for key in sorted(value, key=_utf16_sort_key):
            parts.append(f"{_encode_json(key)}:{_encode_json(value[key])}")
        return "{" + ",".join(parts) + "}"
    if isinstance(value, Sequence) and not isinstance(
        value, (bytes, bytearray, memoryview)
    ):
        return "[" + ",".join(_encode_json(item) for item in value) + "]"
    raise MetadataValidationError(f"unsupported JSON value type: {type(value).__name__}")


def _assert_valid_unicode(value: str) -> None:
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise MetadataValidationError("lone UTF-16 surrogates are prohibited")


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


__all__ = [
    "MAX_CANONICAL_METADATA_BYTES",
    "MAX_MEMO_BYTES",
    "METADATA_ENVELOPE_SCHEMA",
    "MetadataCommitment",
    "MetadataReference",
    "MetadataValidationError",
    "PROPERTY_AMENDMENT_SCHEMA",
    "PROPERTY_DOSSIER_SCHEMA",
    "TARGET_ALLOCATION_PPM",
    "build_metadata_memos",
    "build_metadata_reference_memo",
    "canonicalize_json",
    "commit_metadata",
    "estimate_consensus_cost",
    "parse_metadata_reference_memo",
    "reconstruct_metadata_memos",
    "validate_deed_allocation",
]
