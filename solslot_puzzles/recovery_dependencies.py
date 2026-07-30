"""Pinned dependency evidence for the RC23 administrator recovery policy."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Final


PINNED_CNI_WALLET_SDK_REPOSITORY: Final = (
    "https://github.com/Chia-Network/cni-wallet-sdk"
)
PINNED_CNI_WALLET_SDK_COMMIT: Final = (
    "fb8f4ea8279709287b022d6c388aef4751765d4c"
)
PINNED_CNI_WALLET_SDK_LICENSE: Final = "Apache-2.0"
RECOVERY_DEPENDENCY_MANIFEST_PATH: Final = (
    Path(__file__).resolve().parents[1]
    / "release-manifests"
    / "rc23-recovery-dependencies.json"
)


def canonical_dependency_manifest_bytes() -> bytes:
    payload = json.loads(
        RECOVERY_DEPENDENCY_MANIFEST_PATH.read_text(encoding="utf-8")
    )
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def compute_recovery_dependency_manifest_hash() -> str:
    return hashlib.sha256(canonical_dependency_manifest_bytes()).hexdigest()


# This value is part of the RC23 Authority V3 source commitment. The integrity
# test independently re-hashes the committed manifest and every installed MIPS
# module before a ceremony package can pass CI.
RECOVERY_DEPENDENCY_MANIFEST_HASH: Final = (
    "66c4d3c002311ef964e3326cafc87922e277babbf1c1dba8888c980b4cf8d1a1"
)


__all__ = [
    "PINNED_CNI_WALLET_SDK_COMMIT",
    "PINNED_CNI_WALLET_SDK_LICENSE",
    "PINNED_CNI_WALLET_SDK_REPOSITORY",
    "RECOVERY_DEPENDENCY_MANIFEST_HASH",
    "RECOVERY_DEPENDENCY_MANIFEST_PATH",
    "canonical_dependency_manifest_bytes",
    "compute_recovery_dependency_manifest_hash",
]
