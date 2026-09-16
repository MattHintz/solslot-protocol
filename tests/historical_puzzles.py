"""Read retained pre-draft46 modules when verifying historical release manifests."""
import json
from pathlib import Path
from chia.types.blockchain_format.program import Program
from solslot_puzzles import load_puzzle

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / 'release-manifests/alpha-draft46-puzzle-hashes.json').read_text())
REPLACED = {row['filename'] for row in MANIFEST['replacements']}


def historical_source_path(name):
    if name.removesuffix('.hex') in REPLACED:
        return ROOT / 'release-manifests/alpha-draft46-predecessor' / name
    return ROOT / 'solslot_puzzles' / name


def historical_puzzle(name):
    if name in REPLACED:
        return Program.fromhex(historical_source_path(name + '.hex').read_text().strip())
    return load_puzzle(name)
