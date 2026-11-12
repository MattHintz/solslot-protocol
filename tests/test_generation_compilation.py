"""Never trust modification times for release contract compilation.

Chia's load_clvm recompiles a changed .clsp, but ignores the timestamps of
included libraries. Compile each new-generation module into an empty directory
and compare exact serialized programs, including transitive include changes.
This test does not rewrite compiled artifacts or historical release evidence.
"""
from pathlib import Path

import pytest
from chia.wallet.puzzles import load_clvm
from chia.types.blockchain_format.program import Program

from solslot_puzzles.generation_inventory import GENERATION_PUZZLE_FILENAMES

PUZZLES = Path(__file__).resolve().parents[1]/'solslot_puzzles'


def test_inventory_covers_every_new_generation_contract():
    actual={p.name for p in PUZZLES.glob('generation_*.clsp')}
    actual.add('vault_singleton_inner_generation_v1.clsp')
    actual.add('vault_sols_generation_v1.clsp')
    assert actual==set(GENERATION_PUZZLE_FILENAMES)


@pytest.mark.parametrize('name',GENERATION_PUZZLE_FILENAMES)
def test_new_generation_compiled_bytes_match_all_current_sources(name,tmp_path):
    output=tmp_path/(name+'.hex')
    load_clvm.compile_clvm(PUZZLES/name,output,
        search_paths=[PUZZLES,Path(load_clvm.__file__).parent])
    compiled=bytes.fromhex(output.read_text().strip())
    checked_in=bytes.fromhex((PUZZLES/(name+'.hex')).read_text().strip())
    assert compiled==checked_in, f'{name}: rebuild the candidate after source or included-library changes'
    assert Program.from_bytes(compiled).get_tree_hash()==Program.from_bytes(checked_in).get_tree_hash()
