# Solslot V2 Security Handoff

## Release State

Alpha writes and minting remain locked. No current deployment coordinate is
eligible for reuse. The next deployment must be built from clean, reviewed
commits in all six release repositories.

## Canonical Consensus Surface

- Announcement namespace: `0x53`.
- Governance token: SGT.
- Pool: `pool_singleton_inner_v3.clsp` only.
- SmartDeed custody: `smart_deed_inner_v2.clsp` and `p2_pool_v2.clsp`.
- Authority and mint proposal: MIPS-based V2 modules only.
- Vault credential policy: Solslot V2 domains and bridge policy.

Retired implementations are absent from the release package. Their exact
sources, PoCs, manifests, and working-tree state are held in the external,
checksummed V1 evidence archive.

## Required Gates

1. `python scripts/check_namespace.py` passes for tracked files and packaged artifacts.
2. The complete protocol suite passes with the frozen puzzle checksum.
3. API, EVM, legacy backend, customer web, and admin portal report their
   artifact-bound source SHAs; the consumer-facing services report the same
   artifact hash.
4. Independent review closes all open findings against the frozen commits.
5. Secrets are rotated after the release commits are frozen.
6. The API live preflight and offline `pre-broadcast` gate pass from a new,
   empty artifact directory.
7. The locked artifact, checksum archive, consumer release pins, and write
   locks pass the offline `post-genesis` gate.

No gate may be waived for Alpha.
