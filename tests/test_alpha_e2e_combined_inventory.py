"""The combined release preserves both independently prepared inventories."""
import hashlib
import json
from pathlib import Path

from solslot_puzzles import FROZEN_CHECKSUM, PUZZLE_FILENAMES, load_puzzle


def test_combined_inventory_preserves_reviewed_v4_and_base_test_token_bytes():
    root = Path(__file__).resolve().parents[1]
    current = json.loads((root / "release-manifests/alpha-e2e-draft66-puzzle-hashes.json").read_text())
    assert current["deployable"] is False
    assert current["replacements"] == []
    assert current["canonicalChecksum"] == FROZEN_CHECKSUM
    assert tuple(current["puzzleHashes"]) == PUZZLE_FILENAMES
    for evidence in current["preservedManifests"]:
        raw = (root / "release-manifests" / evidence["filename"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == evidence["sha256"]
        previous = json.loads(raw)
        for name, expected in previous["puzzleHashes"].items():
            assert current["puzzleHashes"][name] == expected
    for row in current["preserved"] + current["additions"]:
        assert load_puzzle(row["filename"]).get_tree_hash().hex() == row["treeHash"]
        for suffix, field in [("", "sourceSha256"), (".hex", "hexSha256")]:
            assert hashlib.sha256((root / "solslot_puzzles" / (row["filename"] + suffix)).read_bytes()).hexdigest() == row[field]
    assert current["puzzleHashes"]["admin_authority_v4_inner.clsp"] == "84e403582322e3f05df52bde4e179ab6b9968413647a3e0667ec2c365b09aaa1"
