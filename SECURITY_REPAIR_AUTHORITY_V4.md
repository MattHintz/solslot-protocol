# Authority V4 announcement guard (M-ANN-INJECT)

Authority V3 forwards delegated conditions. An authorized operational spend
can therefore emit a lost-key preparation announcement without entering the
pending state. Checking the emitting Authority puzzle alone does not prove
that it executed that transition.

## Consensus change

`admin_authority_v4_inner.clsp` preserves the V3 state machine and adds one
shared guard at all three external condition boundaries:

- operational MIPS output;
- preparation MIPS output;
- preparation replacement-member output.

Each boundary rejects `CREATE_PUZZLE_ANNOUNCEMENT` (62) with a 34-byte message
starting with `0x53`. This reserves the entire one-byte state-tag namespace,
including duplicate and currently unused tags. Only the wrapper's validated
`emit-state` path can emit these messages. The guard runs before external
conditions are merged with trusted wrapper output.

Other announcements remain available, including the canonical 32-byte
transition binding hashes. Administrator thresholds, identity slots, delays,
vetoes, completion, and pending-state freezes are unchanged.

## Version and rollout boundary

This is additive to protocol candidate
`7b7fbebb842ce367dcffc771a384912942107e8e`. Every existing puzzle source and hex
file remains unchanged. The new module tree hash is
`84e403582322e3f05df52bde4e179ab6b9968413647a3e0667ec2c365b09aaa1`.
`release-manifests/authority-v4-puzzle-hashes.json` records the new inventory
and is explicitly non-deployable pending coordinated release review.

Fresh ceremony plans select puzzle version 4 and hash-bind
`genesisPlan.authorityPuzzleVersion`. An omitted field still reconstructs V3
for historical artifacts. Existing V3 driver names and the Authority V3 wire
schema remain stable; puzzle version is separate from the incrementing
Authority state version. Low-level driver defaults remain V3 for compatibility.

Existing V3 coins do not acquire this guard. There is no in-place module
upgrade or migration in this patch. A new reviewed genesis is required for
V4, together with the companion API change that preserves the selected module
through lineage replay, recovery reconstruction, and launch-review inventory.
Deployment consumers must pin the resulting coordinated commits and obtain
new review evidence. Prior source approval and signed plans do not authorize
this changed candidate or its execution.

## Regression evidence

`tests/test_admin_authority_v4.py` covers reserved messages at all boundaries,
duplicates, permitted messages, exact module/self-hash parsing, and historical
artifact preservation. Its signed simulator regression uses two daily-key
authorizations and the target identity's recovery BLS signature: V3 accepts
the operational bundle carrying a forged preparation announcement; V4 rejects
the equivalent bundle. This demonstrates the preparation/state mismatch, not
a completed takeover or a bypass of the recovery delay.

`tests/test_admin_authority_v3.py` runs the existing operational, preparation,
recovery-kit, veto, freeze, completion-delay, and signed routine-bundle checks
against both versions. The API companion tests exercise signed preparation,
cancellation, delayed completion, and version-preserving reconstruction.

Run the repository's namespace, compiled-hex, checksum, and full pytest gates.
The protocol CI also requires its pinned sibling `admin-portal` fixture checkout.
Acceptance of this patch remains separate from launch authorization.
