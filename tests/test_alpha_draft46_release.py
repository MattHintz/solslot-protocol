"""The fresh release is explicit; old manifests retain their exact sources."""
import hashlib
from pathlib import Path

from solslot_puzzles import FROZEN_CHECKSUM, PUZZLE_FILENAMES, load_puzzle
from solslot_puzzles.vault_driver import VAULT_INNER_MOD, puzzle_for_vault_full, one_leaf_merkle_root
from solslot_puzzles.vault_v2_driver import puzzle_for_vault_v2_full, vault_v2_inner_mod_hash
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from tests.historical_puzzles import MANIFEST, REPLACED, ROOT, historical_puzzle, historical_source_path


def test_exact_replacements_and_complete_current_manifest():
    assert REPLACED == {'vault_singleton_inner_v2.clsp', 'p2_vault.clsp', 'pool_singleton_inner_v4.clsp'}
    # Later modules append without rewriting this historical release.
    historical_names = PUZZLE_FILENAMES[:len(MANIFEST['puzzleHashes'])]
    assert tuple(MANIFEST['puzzleHashes']) == historical_names
    assert MANIFEST['canonicalChecksum'] == hashlib.sha256(b''.join(bytes(load_puzzle(name).get_tree_hash()) for name in historical_names)).hexdigest()
    for name, expected in MANIFEST['puzzleHashes'].items():
        assert load_puzzle(name).get_tree_hash().hex() == expected
    for row in MANIFEST['replacements']:
        name = row['filename']
        assert historical_puzzle(name).get_tree_hash().hex() == row['previousTreeHash']
        assert load_puzzle(name).get_tree_hash().hex() == row['treeHash']
        assert row['treeHash'] != row['previousTreeHash']
        for suffix, field in [('', 'SourceSha256'), ('.hex', 'HexSha256')]:
            assert hashlib.sha256(historical_source_path(name + suffix).read_bytes()).hexdigest() == row['previous' + field]
            assert hashlib.sha256((ROOT / 'solslot_puzzles' / (name + suffix)).read_bytes()).hexdigest() == row[field[0].lower() + field[1:]]
    assert hashlib.sha256(b''.join(bytes(historical_puzzle(name).get_tree_hash()) for name in historical_names)).hexdigest() == MANIFEST['preservedCanonicalChecksum']


def test_shared_fresh_vault_builder_and_swap_module_are_identical():
    b = lambda n: bytes32(bytes([n]) * 32)
    owner = bytes(AugSchemeMPL.key_gen(bytes([19]) * 32).get_g1())
    assert VAULT_INNER_MOD.get_tree_hash() == vault_v2_inner_mod_hash()
    for identity in [None, b(20)]:
        extra = {} if identity is None else {'identity_attest_root': identity}
        ordinary = puzzle_for_vault_full(b(1), owner, 1, one_leaf_merkle_root(owner), b(2), zkpassport_bridge_policy_hash=b(3), **extra)
        swap = puzzle_for_vault_v2_full(vault_launcher_id=b(1), owner_pubkey=owner, auth_type=1, members_merkle_root=one_leaf_merkle_root(owner), pool_launcher_id=b(2), zkpassport_bridge_policy_hash=b(3), **extra)
        assert ordinary == swap
