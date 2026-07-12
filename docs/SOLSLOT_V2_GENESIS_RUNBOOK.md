# Solslot V2 Genesis Runbook

## Preconditions

- All release worktrees are clean and pinned to reviewed commit SHAs.
- Namespace, test, secret-scan, and artifact-reproducibility gates pass.
- Staging write endpoints are disabled.
- Fresh EVM contracts are deployed and their addresses are reviewed.
- A new ceremony output directory exists and contains no prior state.

## Ceremony Order

1. Rotate bootstrap, admin, JWT, validator, relayer, faucet, deployer, SSH, and CI secrets.
2. Derive the bridge policy from the fresh EVM deployment and validator set.
3. Run the Chia deployment dry-run and review every launcher, module hash, and destination.
4. Launch SGT, pool, DID, governance, NAV registry, protocol config, admin authority, and vault-version registry.
5. Bind first-admin authority and finalize bootstrap once.
6. Write the lock manifest last.
7. Build the schema V2 public artifact with all five source SHAs.
8. Sign the artifact, generate SHA256 sums, and archive public and private evidence separately.
9. Atomically deploy API, customer web, and admin portal against that artifact hash.
10. Run EVM and BLS vault creation plus zkPassport-to-Chia confirmation smoke tests.

## Abort Rules

Any mismatch, failed push, stale state file, reused bridge coin, missing signature,
or dirty worktree aborts the ceremony. Do not repair a partial ceremony in place.
Start again with fresh coordinates and a new output directory.

Minting stays disabled until independent review and live smoke evidence are signed off.
