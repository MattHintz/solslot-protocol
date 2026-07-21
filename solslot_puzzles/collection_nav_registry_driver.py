"""Driver helpers for collection_nav_registry_inner.clsp."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle


NAV_REGISTRY_TAG = 0x4E415652
NAV_EVIDENCE_TAG = 0x4E415645

_COLLECTION_NAV_REGISTRY_INNER_MOD: Program | None = None


def collection_nav_registry_inner_mod() -> Program:
    global _COLLECTION_NAV_REGISTRY_INNER_MOD
    if _COLLECTION_NAV_REGISTRY_INNER_MOD is None:
        _COLLECTION_NAV_REGISTRY_INNER_MOD = load_puzzle(
            "collection_nav_registry_inner.clsp"
        )
    return _COLLECTION_NAV_REGISTRY_INNER_MOD


def collection_nav_registry_inner_mod_hash() -> bytes32:
    return bytes32(collection_nav_registry_inner_mod().get_tree_hash())


def _as_b32(value: bytes | bytes32, label: str) -> bytes32:
    b = bytes(value)
    if len(b) != 32:
        raise ValueError(f"{label} must be 32 bytes, got {len(b)}")
    return bytes32(b)


def normalise_nav_entries(
    entries: Sequence[tuple[bytes | bytes32, int]],
) -> list[tuple[bytes32, int]]:
    seen: set[bytes32] = set()
    out: list[tuple[bytes32, int]] = []
    for i, (collection_id, nav) in enumerate(entries):
        cid = _as_b32(collection_id, f"entries[{i}].collection_id")
        if cid in seen:
            raise ValueError(f"duplicate collection id at entries[{i}]")
        if nav <= 0:
            raise ValueError(f"entries[{i}].nav_value_mojos must be positive")
        if nav >= 2**64:
            raise ValueError(f"entries[{i}].nav_value_mojos must fit uint64")
        seen.add(cid)
        out.append((cid, int(nav)))
    return out


def entries_program(entries: Sequence[tuple[bytes | bytes32, int]]) -> Program:
    normalised = normalise_nav_entries(entries)
    return Program.to([(cid, nav) for cid, nav in normalised])


def collection_nav_root(entries: Sequence[tuple[bytes | bytes32, int]]) -> bytes32:
    return bytes32(entries_program(entries).get_tree_hash())


EMPTY_COLLECTION_NAV_ROOT = collection_nav_root([])


def upsert_nav_entry(
    entries: Sequence[tuple[bytes | bytes32, int]],
    collection_id_canon: bytes | bytes32,
    nav_value_mojos: int,
) -> list[tuple[bytes32, int]]:
    current = normalise_nav_entries(entries)
    cid = _as_b32(collection_id_canon, "collection_id_canon")
    if nav_value_mojos <= 0:
        raise ValueError("nav_value_mojos must be positive")
    if nav_value_mojos >= 2**64:
        raise ValueError("nav_value_mojos must fit uint64")
    for i, (existing, _) in enumerate(current):
        if existing == cid:
            current[i] = (cid, int(nav_value_mojos))
            return current
    return [(cid, int(nav_value_mojos)), *current]


def nav_value_for_collection(
    entries: Sequence[tuple[bytes | bytes32, int]],
    collection_id_canon: bytes | bytes32,
) -> int:
    current = normalise_nav_entries(entries)
    cid = _as_b32(collection_id_canon, "collection_id_canon")
    for existing, nav in current:
        if existing == cid:
            return nav
    raise ValueError("collection_id_canon is not present in registry entries")


def compute_nav_message(
    collection_id_canon: bytes32,
    nav_value_mojos: int,
    old_root: bytes32,
    new_root: bytes32,
    new_registry_version: int,
) -> bytes32:
    _as_b32(collection_id_canon, "collection_id_canon")
    _as_b32(old_root, "old_root")
    _as_b32(new_root, "new_root")
    if nav_value_mojos <= 0:
        raise ValueError("nav_value_mojos must be positive")
    if new_registry_version < 0:
        raise ValueError("new_registry_version must be non-negative")
    return bytes32(
        Program.to(
            [
                NAV_REGISTRY_TAG,
                collection_id_canon,
                nav_value_mojos,
                old_root,
                new_root,
                new_registry_version,
            ]
        ).get_tree_hash()
    )


def compute_nav_evidence_message(
    collection_id_canon: bytes32,
    nav_value_mojos: int,
    current_root: bytes32,
    registry_version: int,
) -> bytes32:
    _as_b32(collection_id_canon, "collection_id_canon")
    _as_b32(current_root, "current_root")
    if nav_value_mojos <= 0:
        raise ValueError("nav_value_mojos must be positive")
    if registry_version < 0:
        raise ValueError("registry_version must be non-negative")
    return bytes32(
        Program.to(
            [
                NAV_EVIDENCE_TAG,
                collection_id_canon,
                nav_value_mojos,
                current_root,
                registry_version,
            ]
        ).get_tree_hash()
    )


def nav_announcement_message(
    collection_id_canon: bytes32,
    nav_value_mojos: int,
    old_root: bytes32,
    new_root: bytes32,
    new_registry_version: int,
) -> bytes:
    return b"\x53" + compute_nav_message(
        collection_id_canon,
        nav_value_mojos,
        old_root,
        new_root,
        new_registry_version,
    )


def nav_evidence_announcement_message(
    collection_id_canon: bytes32,
    nav_value_mojos: int,
    current_root: bytes32,
    registry_version: int,
) -> bytes:
    return b"\x53" + compute_nav_evidence_message(
        collection_id_canon,
        nav_value_mojos,
        current_root,
        registry_version,
    )


@dataclass(frozen=True)
class CollectionNavRegistryState:
    self_mod_hash: bytes32
    gov_pubkey: bytes
    collection_nav_root: bytes32
    registry_version: int


@dataclass(frozen=True)
class NavUpdateSpendArtifacts:
    inner_solution: Program
    new_entries: list[tuple[bytes32, int]]
    new_collection_nav_root: bytes32
    new_inner_puzzle_hash: bytes32
    signing_message: bytes32
    announcement_message: bytes


@dataclass(frozen=True)
class NavReadEvidenceArtifacts:
    inner_solution: Program
    nav_value_mojos: int
    collection_nav_root: bytes32
    registry_version: int
    inner_puzzle_hash: bytes32
    evidence_message: bytes32
    announcement_message: bytes


def make_inner_puzzle(
    gov_pubkey: bytes,
    registry_version: int,
    nav_root: bytes32 = EMPTY_COLLECTION_NAV_ROOT,
) -> Program:
    if len(gov_pubkey) != 48:
        raise ValueError(f"gov_pubkey must be 48 bytes, got {len(gov_pubkey)}")
    if registry_version < 0:
        raise ValueError("registry_version must be non-negative")
    _as_b32(nav_root, "nav_root")
    return collection_nav_registry_inner_mod().curry(
        collection_nav_registry_inner_mod_hash(),
        gov_pubkey,
        nav_root,
        registry_version,
    )


def make_inner_puzzle_hash(
    gov_pubkey: bytes,
    registry_version: int,
    nav_root: bytes32 = EMPTY_COLLECTION_NAV_ROOT,
) -> bytes32:
    return bytes32(
        make_inner_puzzle(
            gov_pubkey=gov_pubkey,
            registry_version=registry_version,
            nav_root=nav_root,
        ).get_tree_hash()
    )


def parse_inner_puzzle(curried_inner_puzzle: Program) -> CollectionNavRegistryState:
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != collection_nav_registry_inner_mod_hash():
        raise ValueError("puzzle reveal does not instantiate collection_nav_registry_inner.clsp")
    args_list = args.as_iter()
    values = list(args_list)
    if len(values) != 4:
        raise ValueError(f"expected 4 curried args, got {len(values)}")
    self_mod_hash = bytes32(values[0].as_atom())
    gov_pubkey = bytes(values[1].as_atom())
    root = bytes32(values[2].as_atom())
    version = int(values[3].as_int())
    return CollectionNavRegistryState(
        self_mod_hash=self_mod_hash,
        gov_pubkey=gov_pubkey,
        collection_nav_root=root,
        registry_version=version,
    )


def build_nav_update_spend(
    *,
    current: CollectionNavRegistryState,
    collection_id_canon: bytes32,
    nav_value_mojos: int,
    current_entries: Sequence[tuple[bytes | bytes32, int]],
    my_amount: int,
) -> NavUpdateSpendArtifacts:
    if current.self_mod_hash != collection_nav_registry_inner_mod_hash():
        raise ValueError("current.self_mod_hash does not match collection NAV registry mod")
    if collection_nav_root(current_entries) != current.collection_nav_root:
        raise ValueError("current_entries root does not match registry state")
    if my_amount <= 0:
        raise ValueError("my_amount must be positive")
    new_version = current.registry_version + 1
    new_entries = upsert_nav_entry(current_entries, collection_id_canon, nav_value_mojos)
    new_root = collection_nav_root(new_entries)
    signing_message = compute_nav_message(
        collection_id_canon,
        nav_value_mojos,
        current.collection_nav_root,
        new_root,
        new_version,
    )
    solution = Program.to(
        [
            my_amount,
            collection_id_canon,
            nav_value_mojos,
            [(cid, nav) for cid, nav in normalise_nav_entries(current_entries)],
            new_version,
        ]
    )
    return NavUpdateSpendArtifacts(
        inner_solution=solution,
        new_entries=new_entries,
        new_collection_nav_root=new_root,
        new_inner_puzzle_hash=make_inner_puzzle_hash(
            current.gov_pubkey,
            new_version,
            new_root,
        ),
        signing_message=signing_message,
        announcement_message=b"\x53" + signing_message,
    )


def build_nav_read_evidence_spend(
    *,
    current: CollectionNavRegistryState,
    collection_id_canon: bytes32,
    current_entries: Sequence[tuple[bytes | bytes32, int]],
    my_amount: int,
) -> NavReadEvidenceArtifacts:
    if current.self_mod_hash != collection_nav_registry_inner_mod_hash():
        raise ValueError("current.self_mod_hash does not match collection NAV registry mod")
    if collection_nav_root(current_entries) != current.collection_nav_root:
        raise ValueError("current_entries root does not match registry state")
    if my_amount <= 0:
        raise ValueError("my_amount must be positive")
    nav_value_mojos = nav_value_for_collection(current_entries, collection_id_canon)
    evidence_message = compute_nav_evidence_message(
        collection_id_canon,
        nav_value_mojos,
        current.collection_nav_root,
        current.registry_version,
    )
    solution = Program.to(
        [
            my_amount,
            collection_id_canon,
            nav_value_mojos,
            [(cid, nav) for cid, nav in normalise_nav_entries(current_entries)],
            current.registry_version,
        ]
    )
    return NavReadEvidenceArtifacts(
        inner_solution=solution,
        nav_value_mojos=nav_value_mojos,
        collection_nav_root=current.collection_nav_root,
        registry_version=current.registry_version,
        inner_puzzle_hash=make_inner_puzzle_hash(
            current.gov_pubkey,
            current.registry_version,
            current.collection_nav_root,
        ),
        evidence_message=evidence_message,
        announcement_message=b"\x53" + evidence_message,
    )


def build_nav_update_coin_spend(
    *,
    registry_coin: Coin,
    singleton_struct: Program,
    lineage_proof: LineageProof,
    current: CollectionNavRegistryState,
    collection_id_canon: bytes32,
    nav_value_mojos: int,
    current_entries: Sequence[tuple[bytes | bytes32, int]],
) -> CoinSpend:
    inner = make_inner_puzzle(
        current.gov_pubkey,
        current.registry_version,
        current.collection_nav_root,
    )
    full = puzzle_for_singleton(singleton_struct, inner)
    artifacts = build_nav_update_spend(
        current=current,
        collection_id_canon=collection_id_canon,
        nav_value_mojos=nav_value_mojos,
        current_entries=current_entries,
        my_amount=int(registry_coin.amount),
    )
    full_solution = solution_for_singleton(
        lineage_proof,
        registry_coin.amount,
        artifacts.inner_solution,
    )
    return make_spend(registry_coin, full, full_solution)


__all__ = [
    "NAV_REGISTRY_TAG",
    "NAV_EVIDENCE_TAG",
    "EMPTY_COLLECTION_NAV_ROOT",
    "CollectionNavRegistryState",
    "NavUpdateSpendArtifacts",
    "NavReadEvidenceArtifacts",
    "collection_nav_registry_inner_mod",
    "collection_nav_registry_inner_mod_hash",
    "collection_nav_root",
    "entries_program",
    "normalise_nav_entries",
    "upsert_nav_entry",
    "nav_value_for_collection",
    "compute_nav_message",
    "compute_nav_evidence_message",
    "nav_announcement_message",
    "nav_evidence_announcement_message",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "parse_inner_puzzle",
    "build_nav_read_evidence_spend",
    "build_nav_update_spend",
    "build_nav_update_coin_spend",
]
