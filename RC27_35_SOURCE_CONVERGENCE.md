# RC27.35 source convergence

RC27.35 supersedes the immutable RC27.33 Testnet11 candidate after the
independent Authority V3 source review identified H1, H2, and M1. RC27.33
release refs and evidence remain historical and must not be moved, rewritten,
or reused as approval for this release.

## Source delta

- Protocol appends one recovery member puzzle that requires the current
  Authority singleton puzzle to be spent concurrently. Every historical CLSP
  module remains byte-for-byte unchanged.
- Omnichain rejects a replacement daily EVM key already assigned to an
  administrator role, bounds prepared changes, and permits cleanup after
  expiry.
- API and Protocol advance only the official release identity, frozen puzzle
  inventory, manifest tooling, configuration defaults, tests, and runbooks.
- EVM, legacy backend, Key of Solomon, Samuel, customer web, and admin portal
  remain source-identical to their final RC27.33 commits unless a separately
  reviewed change is merged before the RC27.35 freeze.

## Release identity

- Release ID and annotated tag:
  `solslot-v2-alpha-rc27.35-20260823`
- Release branch:
  `release/testnet-alpha-rc27.35-20260823`
- Network: Chia Testnet11 and Ethereum Sepolia only
- Classification: `testOnly: true`

## Required sequence

1. Obtain the outside-implementation-team disposition of the exact H1/H2/M1
   remediation commits.
2. Merge all reviewed RC27.35 changes and require post-merge CI.
3. Create the RC27.35 branch and annotated tag at each repository's exact
   reviewed `main` commit without force.
4. Build the nine-source manifest and source-freeze evidence from unique clean
   release worktrees using the frozen Protocol builder and the additive
   `rc27.35-puzzle-hashes.json` inventory.
5. Verify all nine worktrees independently, seal checksums, and regenerate the
   Authority V3 review request for the final source commitment.
6. Complete the protected staging backup, isolated restore, closed deployment,
   and 15-minute zero-ceremony smoke gate before any initialization envelope.

No release convergence step authorizes an owner claim, enrollment, funding,
signature, contract deployment, gate activation, transaction broadcast,
finalization, customer write, purchase, or mint.
