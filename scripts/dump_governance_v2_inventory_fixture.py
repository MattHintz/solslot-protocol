"""Additive current-governance fixture; historical mint fixtures are unchanged."""
from dataclasses import fields
import json
from pathlib import Path
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.mint_publish_driver import build_mint_publish_artifacts, PrimaryPurchaseMintConfig
from solslot_puzzles.stripe_settlement_v1_driver import PRIMARY_PURCHASE_PROVIDER_ID
from scripts.dump_inventory_mint_fixtures import build_inventory_fixture


def build_fixture():
    baseline = build_inventory_fixture()
    kwargs = {}
    for key, value in baseline['inputs'].items():
        if key.endswith('_singleton_struct_hex'):
            kwargs[key.removesuffix('_hex')] = Program.from_bytes(bytes.fromhex(value[2:]))
        elif key == 'jurisdiction_hex':
            kwargs['jurisdiction'] = bytes.fromhex(value[2:])
        elif isinstance(value, str) and value.startswith('0x'):
            kwargs[key] = bytes32.fromhex(value[2:])
        else:
            kwargs[key] = value
    config = PrimaryPurchaseMintConfig(network='testnet11', usd_amount_minor=101,
        technology_fee_bps=100, protocol_treasury_puzhash=bytes32.fromhex(baseline['treasury'][2:]),
        validator_pubkeys=tuple(bytes.fromhex(key[2:]) for key in baseline['validators']),
        provider_id=PRIMARY_PURCHASE_PROVIDER_ID, inventory_version=2)
    result = build_mint_publish_artifacts(**kwargs, primary_purchase=config,
        metadata_root=bytes32.fromhex(baseline['metadataRoot'][2:]), governance_tracker_version=2)
    expected = {}
    for field in fields(result):
        value = getattr(result, field.name)
        if isinstance(value, Program):
            expected[field.name+'_hex'] = '0x'+bytes(value).hex()
            expected[field.name+'_hash'] = '0x'+value.get_tree_hash().hex()
        else:
            expected[field.name] = '0x'+bytes(value).hex()
    return dict(governanceTrackerVersion=2, inventoryVersion=2, base=101, expected=expected)


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    raw = json.dumps(build_fixture(), indent=2)+'\n'
    name = 'governance-v2-inventory.fixture.json'
    (root/'fixtures/mint-proposal-v2'/name).write_text(raw)
    (root.parent/'admin-portal/src/app/services/mint-proposal-v2'/name).write_text(raw)
