# Solslot Admin Authority v2 Design

Status: draft contract for implementation
Date: 2026-05-10

## Purpose

`admin_authority_v2_inner.clsp` is the protocol admin singleton for Solslot.
It replaces the v1 flat BLS allowlist with a CHIP-0043-style authority model:

- An **admin slot** represents one protocol admin.
- Each admin slot owns a **OneOfN** set of personal authentication members.
- Operational admin decisions are authorized by a protocol-level **MofN** over admin slots.
- The active MofN authorization puzzle is committed as `MIPS_ROOT_HASH`.
- The durable admin roster is committed as `ADMINS_HASH`.

The design goal is to let genesis create admin slot `0`, then let the existing admin authority vote in additional admins so normal admin decisions become a supermajority over admin slots.

## State

The v2 singleton curries immutable policy plus mutable state.

Immutable policy:

```text
SELF_MOD_HASH
MAX_ADMINS
MAX_KEYS_PER_ADMIN
COOLDOWN_BLOCKS
RECOVERY_TIMEOUT_BLOCKS
SGT_GOVERNANCE_PUZZLE_HASH
```

Mutable state:

```text
MIPS_ROOT_HASH
ADMINS_HASH
PENDING_KEY_OPS_HASH
AUTHORITY_VERSION
```

Admin records are flat list entries:

```text
(admin_idx leaves_list m_within)
```

Where:

- `admin_idx` is the stable admin slot index.
- `leaves_list` is the list of member tree hashes this admin can use.
- `m_within` is the within-admin removal quorum for destructive key removal.

Pending key operations are flat list entries:

```text
(admin_idx op_kind target_hash activates_at)
```

Where `op_kind` is one of:

```text
OP_KIND_ADD
OP_KIND_REMOVE
```

## Role Separation

Admin authority and SGT governance are separate systems.

- **Admin authority** controls protocol admin decisions and admin roster/key lifecycle.
- **SGT governance** controls governance-token participant decisions.
- SGT holders do not automatically become admin-desk admins.
- Admin-desk admins do not automatically represent SGT governance.

The admin roster is self-governed by the existing admin authority, not by bootstrap tokens or SGT holder votes.

## Genesis

Genesis creates exactly one first admin slot:

```text
admin slot 0
```

The bootstrap ceremony must commit:

```text
ADMINS_HASH = sha256tree([(0 leaves_0 m_within_0)])
MIPS_ROOT_HASH = tree hash of 1-of-1 over admin slot 0
AUTHORITY_VERSION = initial version
```

No normal admin vote can create the first admin because no admin authority exists before genesis.

## Existing Spend Tags

The current six spend tags are:

```text
0x01 OPERATIONAL
0x02 KEY_ADD_PROPOSE
0x03 KEY_ADD_ACTIVATE
0x04 KEY_ADD_VETO
0x05 KEY_REMOVE_QUORUM
0x06 KEY_REMOVE_EMERGENCY
```

### OPERATIONAL

`OPERATIONAL` verifies that the supplied MIPS reveal hashes to `MIPS_ROOT_HASH`, runs that reveal, and wraps the emitted conditions with the singleton self-recurry and state announcement.

Only `AUTHORITY_VERSION` changes during an operational spend.

### KEY_ADD_* and KEY_REMOVE_*

The `KEY_*` spend tags mutate keys inside an existing admin slot.

They do not create new admin slots.
They do not update `MIPS_ROOT_HASH`.
They must not be used as the mechanism for voting in a new protocol admin.
Every approving member puzzle is run with the key operation binding hash
prepended to its solution, so BLS-style members sign the exact
`(admin_idx, op_kind, member_hash, activates_at)` pending operation, or
the exact immediate quorum-removal tuple.

Brick 0.5 pins this with tests:

- `KEY_ADD_PROPOSE` appends a pending key operation and leaves `ADMINS_HASH` unchanged.
- `KEY_ADD_ACTIVATE` appends a key to an existing admin record only.
- A pending add for a brand-new `admin_idx` is rejected.
- Key add/remove paths leave `MIPS_ROOT_HASH` unchanged.

## Required Admin Roster Update Path

To let admin slot `0` vote in admin slot `1`, the protocol needs a distinct roster update spend.

Recommended spend tag:

```text
0x07 ADMIN_ROSTER_UPDATE
```

A roster update is any mutation that changes the set of admin slots or the operational admin quorum. It must atomically update both:

```text
ADMINS_HASH
MIPS_ROOT_HASH
```

This prevents split-brain authority where the admin records claim one roster but operational MIPS authorization still verifies against an older roster.

## Admin Supermajority Rule

Operational admin decisions use a supermajority threshold over admin slots:

```text
threshold = ceil(2 * admin_count / 3)
```

Integer form:

```text
threshold = (2 * admin_count + 2) // 3
```

Examples:

```text
1 admin  -> 1-of-1
2 admins -> 2-of-2
3 admins -> 2-of-3
4 admins -> 3-of-4
5 admins -> 4-of-5
```

Therefore the first post-genesis admin add changes authority from:

```text
[admin 0]      -> 1-of-1
[admin 0, 1]   -> 2-of-2
```

After admin slot `1` is activated, ordinary admin decisions require both admin slots.

## ADMIN_ROSTER_UPDATE Semantics

The first implementation can be deliberately narrow: append exactly one new admin slot.

Inputs should include:

```text
current_admins_list
current_pending_ops_list
current_mips_reveal
current_mips_solution
new_admin_record
new_mips_root_hash
```

The spend must verify:

```text
sha256tree(current_admins_list) == ADMINS_HASH
sha256tree(current_pending_ops_list) == PENDING_KEY_OPS_HASH
sha256tree(current_mips_reveal) == MIPS_ROOT_HASH
```

Then it must run:

```text
(a current_mips_reveal current_mips_solution)
```

The emitted member conditions are consensus-enforced and represent current admin supermajority approval.

For admin-slot append, it must validate:

```text
current_admins_list is non-empty
len(current_admins_list) < MAX_ADMINS
new_admin_record.admin_idx == max(existing admin_idx) + 1
new_admin_record.admin_idx is not already present
new_admin_record.leaves_list is non-empty
len(new_admin_record.leaves_list) <= MAX_KEYS_PER_ADMIN
new_admin_record.m_within is in [1, len(new_admin_record.leaves_list)]
new_mips_root_hash != MIPS_ROOT_HASH
```

The new state is:

```text
new_admins_list = append(current_admins_list, new_admin_record)
new_admins_hash = sha256tree(new_admins_list)
new_pending_key_ops_hash = PENDING_KEY_OPS_HASH
new_authority_version = AUTHORITY_VERSION + 1
new_mips_root_hash = tree hash of supermajority MIPS over new_admins_list
```

The singleton recurs with:

```text
MIPS_ROOT_HASH = new_mips_root_hash
ADMINS_HASH = new_admins_hash
PENDING_KEY_OPS_HASH = unchanged
AUTHORITY_VERSION = new_authority_version
```

## Required Test Vectors

Before implementing CLSP behavior, tests should pin these contracts:

1. Admin slot add from one admin to two admins produces `2-of-2` threshold.
2. Admin slot add changes both `ADMINS_HASH` and `MIPS_ROOT_HASH` atomically.
3. The old `1-of-1` MIPS reveal is rejected after the roster update.
4. The new `2-of-2` MIPS reveal is accepted after the roster update.
5. Duplicate `admin_idx` is rejected.
6. Non-contiguous `admin_idx` is rejected.
7. Empty admin leaf list is rejected.
8. `m_within` outside `[1, len(leaves)]` is rejected.
9. Roster updates past `MAX_ADMINS` are rejected.
10. `new_authority_version != AUTHORITY_VERSION + 1` is rejected.

## Operator Flow

For the first post-genesis admin add:

1. Admin slot `0` signs an `ADMIN_ROSTER_UPDATE` intent.
2. The spend appends admin slot `1`.
3. The spend updates `ADMINS_HASH` to include slots `0` and `1`.
4. The spend updates `MIPS_ROOT_HASH` to the `2-of-2` admin-slot MIPS tree.
5. All future operational admin decisions require both admin slots.

## Non-Goals

This design does not make SGT holders protocol admins.
It does not use bootstrap credentials after genesis finalization.
It does not overload `KEY_ADD_*` to mean admin-slot addition.
It does not allow admin roster and MIPS root to drift independently.

## Implementation Order

Recommended atomic bricks:

```text
0.6A — Design + pure driver preview helpers for admin-slot add.
0.6B — Failing CLVM tests for ADMIN_ROSTER_UPDATE.
0.6C — CLSP implementation of append-one-admin ADMIN_ROSTER_UPDATE.
0.6D — Portal service/UI ceremony for admin 0 adding admin 1.
0.6E — API/manifest/runtime config update for post-genesis admin records, if needed.
```
