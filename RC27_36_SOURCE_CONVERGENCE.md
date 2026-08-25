# RC27.36 source convergence

RC27.36 supersedes the immutable RC27.35 Testnet11 candidate after the
release-packet validator correctly rejected the prior packet builder's
patch-release truncation. RC27.35 refs and evidence remain immutable historical
evidence and must not be moved, rewritten, or reused as approval for RC27.36.

## Source delta

- Protocol advances only the coordinated release identity, deterministic
  manifest tooling, additive puzzle-inventory metadata, tests, and the current
  Testnet11 runbook. `rc27.36-puzzle-hashes.json` preserves the exact RC27.35
  canonical checksum with no changed or new puzzle hashes.
- API preserves the full patch release token in the Authority V3 review-packet
  validator and advances only the current release defaults, operator
  documentation, and tests to RC27.36.
- EVM, omnichain, legacy backend, Key of Solomon, Samuel, customer web, and
  admin portal remain source-identical to their RC27.35 commits.

## Release identity

- Release ID and annotated tag:
  `solslot-v2-alpha-rc27.36-20260824`
- Release branch:
  `release/testnet-alpha-rc27.36-20260824`
- Network: Chia Testnet11 and Ethereum Sepolia only
- Classification: `testOnly: true`

## Required sequence

1. Review and merge the minimal Protocol and API convergence changes and
   require exact post-merge CI.
2. Create the RC27.36 branch and annotated tag at each repository's exact
   reviewed `main` commit without force.
3. Build and independently verify a new nine-source manifest and source-freeze
   evidence from unique clean release worktrees.
4. Regenerate the Authority V3 review request for the final RC27.36 source
   commitment and obtain an outside-implementation-team review.
5. Repeat the protected staging, rollback, and closed smoke gates before any
   initialization authorization.

No release-convergence step authorizes an owner claim, enrollment, funding,
signature, contract deployment, gate activation, transaction broadcast,
finalization, customer write, purchase, or mint.
