#!/usr/bin/env python3
"""Fail if committed CLSP hex files drift from freshly compiled sources."""

from __future__ import annotations

import sys
from pathlib import Path

from chia.wallet.puzzles.load_clvm import load_clvm

from solslot_puzzles import PUZZLE_FILENAMES


ROOT = Path(__file__).resolve().parents[1]
PUZZLE_DIR = ROOT / "solslot_puzzles"


def _committed_hex(path: Path) -> str:
    return "".join(path.read_text(encoding="utf-8").split()).lower()


def main() -> int:
    failures: list[str] = []

    for filename in PUZZLE_FILENAMES:
        hex_path = PUZZLE_DIR / f"{filename}.hex"
        if not hex_path.exists():
            failures.append(f"{hex_path.relative_to(ROOT)} is missing")
            continue

        compiled = load_clvm(
            filename,
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        actual_hex = bytes(compiled).hex()
        expected_hex = _committed_hex(hex_path)
        if actual_hex != expected_hex:
            failures.append(f"{hex_path.relative_to(ROOT)} is stale")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print(f"CLSP hex drift check passed for {len(PUZZLE_FILENAMES)} puzzles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
