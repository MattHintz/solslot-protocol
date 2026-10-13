"""Cross-runtime reconstruction vectors; synthetic identities, no live evidence."""
import json
import sys
from pathlib import Path
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton, SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH
from solslot_puzzles import load_puzzle


def main(destination):
    b = lambda n: bytes([n]) * 32
    launcher = b(1)
    struct = Program.to((SINGLETON_MOD_HASH, (launcher, SINGLETON_LAUNCHER_HASH)))
    fixtures = []

    def add(name, kind, mod, old, new, solution):
        parent = puzzle_for_singleton(launcher, mod.curry(*old))
        child = puzzle_for_singleton(launcher, mod.curry(*new))
        fixtures.append(dict(name=name, kind=kind, reveal=bytes(parent).hex(),
            solution=bytes(Program.to([[], 1, solution])).hex(),
            parentPuzzleHash=parent.get_tree_hash().hex(), currentPuzzleHash=child.get_tree_hash().hex(),
            moduleHash=mod.get_tree_hash().hex(), output=bytes(child).hex()))

    registry = load_puzzle('vault_version_registry_inner.clsp')
    old = [registry.get_tree_hash(), SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH, b(2), b(3), b(4), b(5), 1]
    for action, code in [(1, b(4)), (2, b(6))]:
        add(f'registry-{action}', 'registry', registry, old, old[:5] + [code, b(7), 2],
            [action, 1, b(9), code, b(7), 2])
    vault = load_puzzle('vault_singleton_inner.clsp')
    old = [struct, bytes([10])*48, 1, b(11), b(12), b(13), SINGLETON_MOD_HASH, b(14), SINGLETON_LAUNCHER_HASH]
    new = old.copy(); new[4] = b(15)
    add('vault-identity-stamp', 'vault', vault, old, new,
        [b(20), vault.curry(*old).get_tree_hash(), 1, b'z', [vault.get_tree_hash(), b(15), b(21), 1, 1000, []]])
    new = old.copy(); new[1:4] = [bytes([16])*48, 1, b(17)]
    add('vault-key-rotation', 'vault', vault, old, new,
        [b(20), vault.curry(*old).get_tree_hash(), 1, b'k', [vault.get_tree_hash(), *new[1:4], [], 1000, []]])
    add('vault-state-preserved', 'vault', vault, old, old,
        [b(20), vault.curry(*old).get_tree_hash(), 1, b'm', [b(22), b(23), 1000, []]])
    Path(destination).write_text(json.dumps(fixtures, indent=2) + '\n')


if __name__ == '__main__':
    main(sys.argv[1])
