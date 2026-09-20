"""Executed offline conditions and synthetic BLS controls, not live receipts."""
from dataclasses import replace
from tests.historical_puzzles import historical_puzzle, historical_source_path
import hashlib
import json
from pathlib import Path

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, SINGLETON_MOD_HASH, lineage_proof_for_coinsol
from chia_rs import AugSchemeMPL, G1Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle, PUZZLE_FILENAMES, FROZEN_CHECKSUM
from solslot_puzzles.payment_artifacts_v2 import PaymentRail, PaymentArtifactError
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1, build_inventory_reservation_spend,
    build_inventory_release_spend, build_inventory_extension_spend,
    make_inventory_available_inner, make_mint_offer_v5_inner,
    inventory_terms_for_puzzle_hash,
)
from tests.test_stripe_settlement_v1_driver import settlement, b32

KEYS = tuple(AugSchemeMPL.key_gen(bytes([i]) * 32) for i in (41, 42, 43))
# Deliberately local: these signatures cannot serve as customer Testnet receipts.
DOMAIN = hashlib.sha256(b"solslot-draft11-offline-signature-domain").digest()


def fixture(rail, version=2):
    receipt, terms = settlement()
    launcher = Coin(b32(90), terms.deed_launcher_puzzle_hash, uint64(1))
    purchase = replace(receipt.artifact, deed_launcher_id=launcher.name(),
                       delivery_asset_id=launcher.name())
    if rail == PaymentRail.EVM_TEST_USD:
        purchase = replace(purchase, rail=rail, rail_chain_id=84532,
            rail_asset_id=bytes32.fromhex("000000000000000000000000036cbd53842c5426634e7929541ec2318f3dcf7e"),
            rail_asset_decimals=6, rail_amount=purchase.subtotal_minor * 10000)
    elif rail in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        decimals = 12 if rail == PaymentRail.CHIA_XCH else 3
        purchase = replace(purchase, rail=rail, rail_asset_id=b32(0 if rail == PaymentRail.CHIA_XCH else 55),
            rail_asset_decimals=decimals, rail_amount=(purchase.subtotal_minor * 10**decimals + 2499)//2500,
            oracle_round_hash=b32(56), oracle_price_usd_minor_per_asset=2500, source_evidence_root=b32(57))
    terms = replace(terms, deed_launcher_id=launcher.name(), inventory_version=version)
    struct = Program.to((SINGLETON_MOD_HASH, (launcher.name(), terms.deed_launcher_puzzle_hash)))
    available = Coin(launcher.name(), SINGLETON_MOD.curry(struct, make_inventory_available_inner(terms)).get_tree_hash(), uint64(1))
    reservation = InventoryReservationV1(purchase, purchase.quote_expires_at)
    transition = build_inventory_reservation_spend(available_coin=available, deed_singleton_struct=struct,
        lineage_proof=LineageProof(launcher.parent_coin_info, amount=uint64(1)),
        reservation=reservation, signer_indices=(0, 2), terms=terms)
    return terms, struct, reservation, transition


def execute(spend):
    cost, conditions = Program.from_bytes(bytes(spend.puzzle_reveal)).run_with_cost(
        11_000_000_000, Program.from_bytes(bytes(spend.solution)))
    assert cost < 2_000_000
    return conditions.as_python()


def assert_output(spend, conditions, expected):
    outputs = [Coin(spend.coin.name(), bytes32(row[1]), uint64(int.from_bytes(row[2], "big")))
               for row in conditions if row[0] == b"\x33"]
    assert outputs == [expected]


def assert_signed(spend, conditions, message):
    rows = [row for row in conditions if row[0] == b"\x32"]
    assert [(row[1], row[2]) for row in rows] == [(bytes(KEYS[i].get_g1()), bytes(message)) for i in (0, 2)]
    messages = [row[2] + bytes(spend.coin.name()) + DOMAIN for row in rows]
    keys = [G1Element.from_bytes(row[1]) for row in rows]
    sig = AugSchemeMPL.aggregate([AugSchemeMPL.sign(KEYS[i], msg) for i, msg in zip((0, 2), messages)])
    assert AugSchemeMPL.aggregate_verify(keys, messages, sig)
    assert not AugSchemeMPL.aggregate_verify(keys, [msg[:-1] + bytes([msg[-1] ^ 1]) for msg in messages], sig)
    assert not AugSchemeMPL.aggregate_verify(keys, messages, AugSchemeMPL.sign(KEYS[0], messages[0]))
    return sig


@pytest.mark.parametrize("rail", list(PaymentRail))
def test_executed_reserve_timeout_fresh_reserve_outputs_and_signatures(rail):
    terms, struct, reservation, first = fixture(rail)
    conditions = execute(first.spend)
    assert_output(first.spend, conditions, first.reserved_coin)
    first_sig = assert_signed(first.spend, conditions, first.validator_message)
    assert [r[1] for r in conditions if r[0] == b"\x55"] == [Program.to(reservation.expires_at).as_atom()]
    release = build_inventory_release_spend(reserved_coin=first.reserved_coin,
        deed_singleton_struct=struct, lineage_proof=lineage_proof_for_coinsol(first.spend),
        reservation=reservation, terms=terms, timed_out=True)
    released = execute(release.spend)
    assert_output(release.spend, released, release.next_coin)
    assert not any(r[0] == b"\x32" for r in released)
    assert [r[1] for r in released if r[0] == b"\x51"] == [Program.to(reservation.expires_at).as_atom()]
    fresh = replace(reservation, artifact=replace(reservation.artifact, authorization_nonce=b32(70),
                    quote_expires_at=reservation.expires_at+300), expires_at=reservation.expires_at+300)
    second = build_inventory_reservation_spend(available_coin=release.next_coin,
        deed_singleton_struct=struct, lineage_proof=lineage_proof_for_coinsol(release.spend),
        reservation=fresh, signer_indices=(0, 2), terms=terms)
    conditions = execute(second.spend)
    assert_output(second.spend, conditions, second.reserved_coin)
    assert_signed(second.spend, conditions, second.validator_message)
    messages = [r[2] + bytes(second.spend.coin.name()) + DOMAIN for r in conditions if r[0] == b"\x32"]
    assert not AugSchemeMPL.aggregate_verify([KEYS[i].get_g1() for i in (0, 2)], messages, first_sig)
    assert first.reserved_coin != second.reserved_coin


@pytest.mark.parametrize("rail", list(PaymentRail))
@pytest.mark.parametrize("position,value", [(5, b"x"*32), (6, b"\0"*32), (14, 1), (20, 0),
    (20, 1_900_000_000), (21, [0,0]), (21, [2,0]), (21, [0]), (21, [0,3]), (11, 1)])
def test_clvm_rejects_invalid_vault_identity_rail_expiry_or_quorum(rail, position, value):
    _, _, _, result = fixture(rail)
    solution = Program.from_bytes(bytes(result.spend.solution)).as_python()
    solution[2][position] = value
    with pytest.raises(ValueError):
        Program.from_bytes(bytes(result.spend.puzzle_reveal)).run_with_cost(11_000_000_000, Program.to(solution))


@pytest.mark.parametrize("version", [1,2])
def test_known_version_selection_and_no_cross_version_reinterpretation(version):
    terms, struct, reservation, first = fixture(PaymentRail.STRIPE, version)
    assert inventory_terms_for_puzzle_hash(replace(terms, inventory_version=3-version), struct,
                                           first.spend.coin.puzzle_hash) == terms
    assert inventory_terms_for_puzzle_hash(terms, struct, first.reserved_coin.puzzle_hash,
                                           reservation=reservation) == terms
    with pytest.raises(PaymentArtifactError):
        inventory_terms_for_puzzle_hash(terms, struct, b32(60))
    with pytest.raises(PaymentArtifactError):
        build_inventory_release_spend(reserved_coin=first.reserved_coin, deed_singleton_struct=struct,
            lineage_proof=lineage_proof_for_coinsol(first.spend), reservation=reservation,
            terms=replace(terms, inventory_version=3-version), timed_out=True)
    extension = build_inventory_extension_spend(reserved_coin=first.reserved_coin, deed_singleton_struct=struct,
        lineage_proof=lineage_proof_for_coinsol(first.spend), reservation=reservation,
        next_expires_at=reservation.expires_at+60, signer_indices=(0,2), terms=terms)
    conditions = execute(extension.spend)
    assert_output(extension.spend, conditions, extension.next_coin)
    assert_signed(extension.spend, conditions, extension.validator_message)
    failure = build_inventory_release_spend(reserved_coin=first.reserved_coin, deed_singleton_struct=struct,
        lineage_proof=lineage_proof_for_coinsol(first.spend), reservation=reservation,
        signer_indices=(0,2), terms=terms, timed_out=False)
    conditions = execute(failure.spend)
    assert_output(failure.spend, conditions, failure.next_coin)
    assert_signed(failure.spend, conditions, failure.validator_message)


@pytest.mark.parametrize("version", [0,4,True,"2",None])
def test_unknown_or_coerced_version_rejected(version):
    _, terms = settlement()
    with pytest.raises(PaymentArtifactError):
        replace(terms, inventory_version=version)


def test_all_historical_puzzle_source_bytes_and_hashes_preserved():
    root = Path(__file__).parents[1]
    manifest = json.loads((root/'release-manifests/inventory-v2-draft11-puzzle-hashes.json').read_text())
    # This historical inventory remains a strict byte/hash prefix as later
    # additive modules are appended; do not rewrite its original checksum.
    historical = tuple(r['filename'] for r in manifest['preserved']) + (manifest['newPuzzle']['filename'],)
    assert PUZZLE_FILENAMES[:len(historical)] == historical
    assert hashlib.sha256(b''.join(bytes(historical_puzzle(name).get_tree_hash()) for name in historical)).hexdigest() == manifest['canonicalChecksum']
    for row in manifest['preserved']:
        name = row['filename']
        assert hashlib.sha256(historical_source_path(name).read_bytes()).hexdigest() == row['sourceSha256']
        assert hashlib.sha256(historical_source_path(name+'.hex').read_bytes()).hexdigest() == row['hexSha256']
        assert historical_puzzle(name).get_tree_hash().hex() == row['treeHash']
    assert historical_puzzle(manifest['newPuzzle']['filename']).get_tree_hash().hex() == manifest['newPuzzle']['treeHash']
