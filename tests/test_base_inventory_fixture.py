"""Browser commitments must remain reproducible from the actual protocol."""
import json
from pathlib import Path
from scripts.dump_governance_v2_inventory_fixture import build_fixture


def test_base_inventory_fixture_matches_python_builder():
    path = Path(__file__).resolve().parents[1] / 'fixtures/mint-proposal-v2/base-inventory.fixture.json'
    assert json.loads(path.read_text()) == build_fixture(inventory_version=3)
