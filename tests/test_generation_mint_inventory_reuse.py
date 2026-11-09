"""Same-call reuse preserves frozen native inventory bytes and rejection rules."""
from dataclasses import replace
from hashlib import sha256

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_mint import GenerationMint,TestMintEdition,MintRow


@pytest.fixture
def inventory():
    b=lambda n:bytes32(bytes([n])*32)
    keys=tuple(bytes(AugSchemeMPL.key_gen(bytes([n])*32).get_g1())for n in (41,42,43))
    bindings=Program.to([b(1),b(2),load_puzzle('generation_pool_v2.clsp').get_tree_hash(),[],b(3),b(4),[],list(keys)])
    mint=GenerationMint(*(b(n)for n in range(1,9)),keys,b(9),primary_batch_bindings=bindings)
    edition=TestMintEdition(b(1),b(101),b(102),b(103),b(104),b(105),100,1,b'US-IL',
        tuple(MintRow(b(110+i),40_000,300_000,1_500_000_000_000_000)for i in range(25)))
    return mint,edition


def test_frozen_inventory_bytes_are_preserved_with_one_local_authority_hash(inventory,monkeypatch):
    mint,edition=inventory;original=GenerationMint.inner;calls=[]
    def counted(self):
        calls.append(self.launcher_id);return original(self)
    monkeypatch.setattr(GenerationMint,'inner',counted)
    rows=mint.inventories(edition)
    # Captured from the deployed builder before the same-call optimization.
    frozen=sha256(b''.join(bytes(r.launcher_spend)+bytes(r.coin)+bytes(r.inner)+bytes(r.smart_deed)for r in rows)).hexdigest()
    assert frozen=='86db86a77ccc96b6e1c236b9c26fe1c243617ef8674fad5fb3276dbf9d925a9f'
    assert len(rows)==25 and len({r.coin.name()for r in rows})==25
    assert calls==[mint.launcher_id]


@pytest.mark.parametrize('changed',['generation','duplicate','allocation','issued'])
def test_same_call_reuse_never_admits_tampered_or_repeated_issuance(inventory,changed):
    mint,edition=inventory
    if changed=='generation':edition=replace(edition,generation=bytes32(b'Z'*32))
    elif changed=='duplicate':edition=replace(edition,rows=(edition.rows[0],)*25)
    elif changed=='allocation':edition=replace(edition,rows=edition.rows[:-1])
    else:mint=mint.minted(edition)
    with pytest.raises(ValueError):mint.inventories(edition)
