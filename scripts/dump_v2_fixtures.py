"""Generate fixture file for the portal's TS port of admin_authority_v2_driver.

The Solslot portal service reproduces a subset of the Python
driver helpers (``compute_state_hash``, ``compute_admins_hash``,
``compute_pending_ops_hash``, ``admin_authority_v2_inner_mod_hash``,
``make_inner_puzzle_hash``, ``compute_roster_update_binding_hash``) so
that the portal can construct + verify v2 admin authority spends entirely
client-side without depending on the Solslot API.

This script writes a JSON fixture mapping each helper to a list of
``(input, expected_output)`` cases.  The portal's Karma test reads
the fixture and asserts the TS implementation produces matching hex.

Usage::

    cd solslot-protocol
    .venv/bin/python scripts/dump_v2_fixtures.py

The fixture is also exported by the regression test in
``tests/test_v2_fixtures.py`` so CI re-checks it on every PR.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v2_driver import (
    DEFAULT_COOLDOWN_BLOCKS,
    DEFAULT_MAX_ADMINS,
    DEFAULT_MAX_KEYS_PER_ADMIN,
    DEFAULT_PGT_GOVERNANCE_PUZZLE_HASH,
    DEFAULT_RECOVERY_TIMEOUT_BLOCKS,
    EMPTY_LIST_HASH,
    AdminRecord,
    PendingOp,
    admin_authority_v2_inner_mod_hash,
    compute_admins_hash,
    compute_launch_outputs,
    compute_pending_ops_hash,
    compute_roster_update_binding_hash,
    compute_state_hash,
    make_inner_puzzle_hash,
    singleton_full_puzzle_hash,
)


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def build_fixture() -> dict[str, Any]:
    """Compute every fixture case using the production Python helpers.

    Returns:
        A dict ready to be serialised to JSON. The portal's Karma test
        deserialises this and asserts the TS implementation matches.

    Cases are chosen to cover:
      * ``mod_hash`` — the bare uncurried inner mod tree hash. Crucial
        because it's curried into every v2 inner puzzle; getting it
        wrong silently breaks every spend.
      * ``empty_list_hash`` — the sentinel ``sha256tree(())``. Portal
        needs this for the default ``pending_ops_hash`` of a freshly
        launched singleton.
      * ``state_hash`` — sha256tree of the 4-tuple
        (mips_root_hash, admins_hash, pending_ops_hash, version).
        Five cases vary each field independently to catch a TS port
        getting the field order wrong.
      * ``admins_hash`` — sha256tree of an N-element list of
        AdminRecord triples. Cases: empty list, single record with
        one leaf, two records each with two leaves.
      * ``pending_ops_hash`` — sha256tree of an N-element list of
        PendingOp 4-tuples. Cases: empty list, one ADD op,
        one REMOVE op, mixed list of two.
      * ``inner_puzzle_hash`` — full ``make_inner_puzzle_hash`` for
        the default policy + a custom policy.  This binds the entire
        curry-order contract: any TS drift in the curry sequence
        will surface here.
      * ``roster_update_binding_hash`` — sha256tree of the local
        A.5 ADMIN_ROSTER_UPDATE signer binding tuple. Cases vary
        pending ops and versions so a TS port that reorders fields or
        relies on backend output fails fast.
    """
    # Sentinel 32-byte hashes (distinct so a TS port that swaps two
    # fields in the curry order produces a different output).
    h1 = bytes32(b"\x11" * 32)
    h2 = bytes32(b"\x22" * 32)
    h3 = bytes32(b"\x33" * 32)
    h4 = bytes32(b"\x44" * 32)

    state_cases: list[dict[str, Any]] = []
    for mips, admins, pending, version, label in (
        (h1, h2, EMPTY_LIST_HASH, 1, "fresh-launch-default"),
        (h1, h2, EMPTY_LIST_HASH, 7, "version-bumped"),
        (h1, h2, h3, 1, "with-pending-op"),
        (h2, h1, EMPTY_LIST_HASH, 1, "swapped-mips-and-admins"),
        (h4, h3, h2, 99, "all-distinct-fields"),
    ):
        state_cases.append(
            {
                "label": label,
                "input": {
                    "mips_root_hash": _hex(mips),
                    "admins_hash": _hex(admins),
                    "pending_ops_hash": _hex(pending),
                    "authority_version": version,
                },
                "expected": _hex(
                    compute_state_hash(
                        mips_root_hash=mips,
                        admins_hash=admins,
                        pending_ops_hash=pending,
                        authority_version=version,
                    )
                ),
            }
        )

    admins_cases: list[dict[str, Any]] = []
    for admins, label in (
        ([], "empty"),
        ([AdminRecord(admin_idx=0, leaves=(h1,), m_within=1)], "single-one-leaf"),
        (
            [
                AdminRecord(admin_idx=0, leaves=(h1, h2), m_within=2),
                AdminRecord(admin_idx=1, leaves=(h3, h4), m_within=1),
            ],
            "two-with-two-leaves",
        ),
    ):
        admins_cases.append(
            {
                "label": label,
                "input": [
                    {
                        "admin_idx": a.admin_idx,
                        "leaves": [_hex(leaf) for leaf in a.leaves],
                        "m_within": a.m_within,
                    }
                    for a in admins
                ],
                "expected": _hex(compute_admins_hash(admins)),
            }
        )

    pending_cases: list[dict[str, Any]] = []
    for ops, label in (
        ([], "empty"),
        (
            [PendingOp(admin_idx=0, op_kind=1, target_hash=h1, activates_at=1024)],
            "single-add",
        ),
        (
            [PendingOp(admin_idx=2, op_kind=2, target_hash=h2, activates_at=5040)],
            "single-remove",
        ),
        (
            [
                PendingOp(admin_idx=0, op_kind=1, target_hash=h1, activates_at=1024),
                PendingOp(admin_idx=1, op_kind=2, target_hash=h2, activates_at=2048),
            ],
            "mixed-add-and-remove",
        ),
    ):
        pending_cases.append(
            {
                "label": label,
                "input": [
                    {
                        "admin_idx": op.admin_idx,
                        "op_kind": op.op_kind,
                        "target_hash": _hex(op.target_hash),
                        "activates_at": op.activates_at,
                    }
                    for op in ops
                ],
                "expected": _hex(compute_pending_ops_hash(ops)),
            }
        )

    inner_puzzle_cases: list[dict[str, Any]] = []
    for params, label in (
        (
            {
                "mips_root_hash": h1,
                "admins_hash": h2,
                "pending_ops_hash": EMPTY_LIST_HASH,
                "authority_version": 1,
            },
            "default-policy-fresh-launch",
        ),
        (
            {
                "mips_root_hash": h2,
                "admins_hash": h3,
                "pending_ops_hash": h4,
                "authority_version": 42,
                "max_admins": 7,
                "max_keys_per_admin": 5,
                "cooldown_blocks": 100,
                "recovery_timeout_blocks": 1000,
                "pgt_governance_puzzle_hash": h1,
            },
            "custom-policy-with-pending-op",
        ),
    ):
        inner_puzzle_cases.append(
            {
                "label": label,
                "input": {
                    k: (_hex(v) if isinstance(v, (bytes, bytes32)) else v)
                    for k, v in params.items()
                },
                "expected": _hex(make_inner_puzzle_hash(**params)),
            }
        )

    roster_update_binding_cases: list[dict[str, Any]] = []
    for params, label in (
        (
            {
                "current_mips_root_hash": h1,
                "current_admins_hash": h2,
                "current_pending_ops_hash": EMPTY_LIST_HASH,
                "current_authority_version": 1,
                "new_admins_hash": h3,
                "new_mips_root_hash": h4,
                "new_authority_version": 2,
            },
            "fresh-slot-add-empty-pending",
        ),
        (
            {
                "current_mips_root_hash": h4,
                "current_admins_hash": h3,
                "current_pending_ops_hash": h2,
                "current_authority_version": 7,
                "new_admins_hash": h1,
                "new_mips_root_hash": h2,
                "new_authority_version": 8,
            },
            "with-pending-op-version-bump",
        ),
        (
            {
                "current_mips_root_hash": h2,
                "current_admins_hash": h1,
                "current_pending_ops_hash": EMPTY_LIST_HASH,
                "current_authority_version": 41,
                "new_admins_hash": h4,
                "new_mips_root_hash": h3,
                "new_authority_version": 42,
            },
            "all-distinct-roster-update-fields",
        ),
    ):
        roster_update_binding_cases.append(
            {
                "label": label,
                "input": {
                    k: (_hex(v) if isinstance(v, (bytes, bytes32)) else v)
                    for k, v in params.items()
                },
                "expected": _hex(compute_roster_update_binding_hash(**params)),
            }
        )

    # ──────────────────────────────────────────────────────────────────
    # singleton_full_puzzle_hash + compute_launch_outputs (D-2.1).
    # ──────────────────────────────────────────────────────────────────

    # singleton_full_puzzle_hash cases.  Use distinct launcher_ids and
    # inner_puzzle_hashes so the TS port can't get away with constant
    # output regardless of input.
    singleton_full_cases: list[dict[str, Any]] = []
    for launcher_id, inner, label in (
        (h1, h2, "h1-h2"),
        (h2, h1, "swapped-h1-h2"),
        (h3, h4, "h3-h4"),
    ):
        singleton_full_cases.append(
            {
                "label": label,
                "input": {
                    "launcher_id": _hex(launcher_id),
                    "inner_puzzle_hash": _hex(inner),
                },
                "expected": _hex(singleton_full_puzzle_hash(launcher_id, inner)),
            }
        )

    # compute_launch_outputs cases.  Each case bundles a parent coin id
    # + an eve inner puzzle hash and emits every deterministic output.
    # The TS port replays this and asserts byte equivalence on each
    # field — catches divergence in launcher coin computation, eve
    # full puzzle hash, launcher solution shape, or announcement
    # formula.
    representative_inner_hash = make_inner_puzzle_hash(
        mips_root_hash=h1,
        admins_hash=h2,
        pending_ops_hash=EMPTY_LIST_HASH,
        authority_version=1,
    )

    launch_cases: list[dict[str, Any]] = []
    for parent_coin_id, eve_inner, eve_amount, label in (
        (h1, representative_inner_hash, 1, "default-fresh-launch"),
        (h2, representative_inner_hash, 1, "different-funding-coin"),
        (h1, h3, 1, "different-eve-state"),
        # Higher eve amount — kept low (still odd) for singleton compatibility.
        # Most operators will use 1, but the helper accepts arbitrary values.
        (h1, representative_inner_hash, 3, "non-default-eve-amount"),
    ):
        outputs = compute_launch_outputs(
            parent_coin_id=parent_coin_id,
            eve_inner_puzzle_hash=eve_inner,
            eve_amount=eve_amount,
        )
        launch_cases.append(
            {
                "label": label,
                "input": {
                    "parent_coin_id": _hex(parent_coin_id),
                    "eve_inner_puzzle_hash": _hex(eve_inner),
                    "eve_amount": eve_amount,
                },
                "expected": {
                    "launcher_id": _hex(outputs.launcher_id),
                    "eve_full_puzzle_hash": _hex(outputs.eve_full_puzzle_hash),
                    "launcher_announcement_message": _hex(
                        outputs.launcher_announcement_message
                    ),
                    "launcher_announcement_id": _hex(outputs.launcher_announcement_id),
                },
            }
        )

    return {
        # Constants surfaced for the TS port to embed verbatim.
        "constants": {
            "mod_hash": _hex(admin_authority_v2_inner_mod_hash()),
            "empty_list_hash": _hex(EMPTY_LIST_HASH),
            "default_max_admins": DEFAULT_MAX_ADMINS,
            "default_max_keys_per_admin": DEFAULT_MAX_KEYS_PER_ADMIN,
            "default_cooldown_blocks": DEFAULT_COOLDOWN_BLOCKS,
            "default_recovery_timeout_blocks": DEFAULT_RECOVERY_TIMEOUT_BLOCKS,
            "default_pgt_governance_puzzle_hash": _hex(
                DEFAULT_PGT_GOVERNANCE_PUZZLE_HASH
            ),
            # Canonical chia singleton constants — bundled here so the
            # TS port can hardcode them and have a fixture-level guard
            # against drift (e.g. if the chia-blockchain package ever
            # changes the launcher puzzle bytecode).
            "singleton_mod_hash": _hex(SINGLETON_MOD_HASH),
            "singleton_launcher_hash": _hex(SINGLETON_LAUNCHER_HASH),
        },
        "state_hash": state_cases,
        "admins_hash": admins_cases,
        "pending_ops_hash": pending_cases,
        "inner_puzzle_hash": inner_puzzle_cases,
        "roster_update_binding_hash": roster_update_binding_cases,
        "singleton_full_puzzle_hash": singleton_full_cases,
        "launch_outputs": launch_cases,
    }


def fixture_destination() -> Path:
    """Resolve the canonical protocol-owned fixture destination."""
    protocol_root = Path(__file__).resolve().parents[1]
    return (
        protocol_root
        / "fixtures"
        / "admin-authority-v2"
        / "admin-authority-v2.fixtures.json"
    )


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    print(f"wrote fixture to {dest}")
    print(
        f"  mod_hash={fixture['constants']['mod_hash']}, "
        f"{len(fixture['state_hash'])} state cases, "
        f"{len(fixture['admins_hash'])} admins cases, "
        f"{len(fixture['pending_ops_hash'])} pending cases, "
        f"{len(fixture['inner_puzzle_hash'])} inner-puzzle cases, "
        f"{len(fixture['roster_update_binding_hash'])} roster-update binding cases, "
        f"{len(fixture['singleton_full_puzzle_hash'])} singleton-full cases, "
        f"{len(fixture['launch_outputs'])} launch cases"
    )


if __name__ == "__main__":
    main()
