"""Optimized immutable updates must preserve complete-rebuild proof bytes."""
from hashlib import sha256
from random import Random
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.holdings import HoldingsTree,Holding,HoldingKind


def h(n):return bytes32(sha256(str(n).encode()).digest())


def test_updates_insert_replace_delete_match_full_rebuild_and_preserve_prior_tree():
    random=Random(220);tree=HoldingsTree({})
    keys=[h(i) for i in range(24)]
    for i in range(60):
        key=random.choice(keys);before=tree.holdings.get(key)
        kind=HoldingKind(random.randint(1,4))
        after=None if before is not None and i%3==0 else Holding(h(31),i+1,kind,h(32),h(33) if kind==HoldingKind.LOCKED_HOLDER else None)
        prior_root=tree.root;prior_proof=tree.proof(key);prior=dict(tree.holdings)
        updated=tree.replace(key,before,after);rebuilt=HoldingsTree(updated.holdings)
        assert tree.root==prior_root and tree.holdings==prior and tree.proof(key)==prior_proof
        assert updated.root==rebuilt.root
        for candidate in keys:assert updated.proof(candidate)==rebuilt.proof(candidate)
        tree=updated
