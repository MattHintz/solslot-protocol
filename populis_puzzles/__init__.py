"""Legacy import alias for the Solslot puzzle package."""
from __future__ import annotations

from importlib import import_module

from solslot_puzzles import *  # noqa: F401,F403

_solslot_puzzles = import_module("solslot_puzzles")
__path__ = _solslot_puzzles.__path__
