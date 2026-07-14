#!/usr/bin/env python3
"""Fail when a retired namespace appears in active release material."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable


FORBIDDEN_DIGEST = "4b61ef4fda96729ef3703e602087708f3fa1ebfc2d809e0be3398086f8ec6706"
FORBIDDEN_LENGTH = 7
HEX_RUN = re.compile(rb"[0-9a-fA-F]{14,}")
ARCHIVE_SUFFIXES = (".tar", ".tgz", ".tar.gz", ".zip")
EXCLUDED_PARTS = frozenset(
    {
        ".angular",
        ".cache",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "cache",
        "node_modules",
        "venv",
    }
)


def _contains_forbidden_raw(data: bytes) -> bool:
    lowered = data.lower()
    if len(lowered) < FORBIDDEN_LENGTH:
        return False
    for index in range(len(lowered) - FORBIDDEN_LENGTH + 1):
        window = lowered[index : index + FORBIDDEN_LENGTH]
        if hashlib.sha256(window).hexdigest() == FORBIDDEN_DIGEST:
            return True
    return False


def contains_forbidden(data: bytes) -> bool:
    if _contains_forbidden_raw(data):
        return True
    for match in HEX_RUN.finditer(data):
        run = match.group()
        for offset in (0, 1):
            encoded = run[offset:]
            if len(encoded) % 2:
                encoded = encoded[:-1]
            if len(encoded) < FORBIDDEN_LENGTH * 2:
                continue
            if _contains_forbidden_raw(bytes.fromhex(encoded.decode("ascii"))):
                return True
    return False


def tracked_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    return [repo_root / Path(raw.decode()) for raw in result.stdout.split(b"\0") if raw]


def iter_paths(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from (
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and not any(part in EXCLUDED_PARTS for part in candidate.parts)
            )
        elif path.is_file() and not any(
            part in EXCLUDED_PARTS for part in path.parts
        ):
            yield path


def archive_violations(path: Path) -> list[str]:
    violations: list[str] = []
    lower_name = path.name.lower()
    if lower_name.endswith((".tar", ".tgz", ".tar.gz")):
        with tarfile.open(path, "r:*") as archive:
            for member in archive.getmembers():
                if contains_forbidden(member.name.encode()):
                    violations.append(f"{path}:{member.name} (path)")
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is not None and contains_forbidden(stream.read()):
                        violations.append(f"{path}:{member.name} (content)")
    elif lower_name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if contains_forbidden(name.encode()):
                    violations.append(f"{path}:{name} (path)")
                if not name.endswith("/") and contains_forbidden(archive.read(name)):
                    violations.append(f"{path}:{name} (content)")
    return violations


def scan_file(path: Path) -> list[str]:
    violations: list[str] = []
    if contains_forbidden(str(path).encode()):
        violations.append(f"{path} (path)")
    try:
        data = path.read_bytes()
    except OSError as error:
        return [f"{path} (unreadable: {error})"]
    if contains_forbidden(data):
        violations.append(f"{path} (content)")
    try:
        printable = subprocess.run(
            ["strings", "-a", str(path)], check=False, capture_output=True
        ).stdout
        if contains_forbidden(printable) and f"{path} (content)" not in violations:
            violations.append(f"{path} (strings)")
    except OSError:
        pass
    if path.name.lower().endswith(ARCHIVE_SUFFIXES):
        try:
            violations.extend(archive_violations(path))
        except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
            violations.append(f"{path} (invalid archive: {error})")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--paths", nargs="*", type=Path)
    args = parser.parse_args()

    root = args.repo_root.resolve()
    candidates = list(iter_paths(args.paths)) if args.paths else tracked_files(root)
    violations = [item for path in candidates for item in scan_file(path)]
    if violations:
        print("Retired namespace detected:")
        for violation in violations:
            print(f"  {violation}")
        return 1
    print(f"Namespace gate passed for {len(candidates)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
