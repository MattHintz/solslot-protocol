# Solslot V2 Testnet Genesis Runbook

## Safety Boundary

This runbook does not authorize a production or mainnet ceremony. Alpha
writes, credential enrollment, offers, and minting remain disabled until the
selected review class and pre-broadcast gate pass against six frozen release
commits.

`internal-engineering-testnet` is the disposable test path. It is accepted
only on testnet11, requires three distinct administrator wallets and normal
2-of-3 plan/artifact signatures, and marks the signed artifact `testOnly: true`
and `auditStatus: "unaudited"`. It does not satisfy an independently reviewed
release or permit mainnet.

The current deployment is retired. Never reuse its contracts, launchers,
vaults, proofs, bridge coins, manifests, or browser state. A failed or
ambiguous V2 ceremony is abandoned rather than repaired or rebroadcast.

## Required Roles

- Three genesis administrators using distinct EIP-712-capable EVM wallets.
- Three validator identities on separately controlled signer hosts.
- Two validator signatures required for every credential stamp.
- Two administrator signatures required for the deterministic plan.
- Two administrator signatures required for the public artifact.
- Four independent review lanes for `independent-release-review`, or the three
  enrolled administrator engineers for `internal-engineering-testnet`.

The API coordinator holds no validator private key. Invitation fragments and
administrator signing happen on each administrator's own computer.

## Freeze The Release

1. Commit every reviewed change in `solslot-protocol`, `research/solslot-omnichain`,
   `solslot-api`, `research/solslot-backend`, `solslot`, and `solslot-portal`.
2. Require clean worktrees and record all six full commit SHAs.
3. Run complete tests, schema drift, namespace, secret, package, and
   reproducibility gates from those exact commits.
4. Select the review class. For the disposable internal test, record
   `internal-engineering-testnet`; for a reviewed release, obtain all four
   independent approvals and evidence hashes.
5. Complete the RC2 credential carryover record. Revoke and replace only the
   provider credential exposed in public history; retain secure reusable
   credentials, reuse signer 0, and generate signer 1/2, WireGuard, mTLS,
   invitation, and one-time ceremony material.
6. Deploy fresh reviewed Sepolia contracts and wait for 12 confirmations.
7. Confirm all three validator signer hosts are healthy over the private
   mTLS/WireGuard network.
8. Select nine distinct, confirmed, unspent Chia funding coins and a new,
   empty ceremony output directory.

Do not construct a plan from a dirty checkout or before the credential
carryover checkpoint and fresh EVM deployment are complete.

## Build The Plan

The admin portal drives the endpoints below under `/admin/genesis`. Preserve
the JSON response from every state transition in the private ceremony archive.

1. `POST /drafts` with the six frozen source SHAs and explicit `reviewClass`.
2. `POST /{ceremonyId}/invitations/{slot}` for slots 1, 2, and 3.
3. Each administrator calls `/invitations/prepare`, signs
   `SolslotGenesisAdminEnrollment`, then calls `/invitations/accept`.
4. `POST /{ceremonyId}/roster/freeze` only after all three slots are enrolled.
5. `POST /{ceremonyId}/plan` with the fresh EVM addresses, three validator
   keys, nine funding coin IDs, trusted destinations, and retired coordinates.
6. Two administrators independently prepare, review, and submit
   `SolslotGenesisPlan` signatures.
7. Export the resulting ceremony state after it reaches `plan_approved`.

The deterministic plan covers SGT plus eight singleton launchers: pool, DID,
governance, NAV registry, protocol config, admin authority, and vault-version
registry, plus the empty property registry. It also commits to 32 unique
one-mojo bridge parents and bridge coins with a low-water mark of eight.

## Pre-Broadcast Gate

Call `POST /admin/genesis/{ceremonyId}/preflight`. The API re-reads all funding
coins, reconstructs the exact plan and atomic spend bundle, runs the consensus
simulation, verifies the selected review evidence, checks the EVM deployment
live at 12 confirmations, probes all validators over mTLS, and refuses a
non-empty output directory. The internal test class generates its review
record from those live checks and the two recorded plan signatures; no
independent-approval file is fabricated.

Save that response as `preflight.json`, extract the exact review record returned
by the API, then run the independent offline gate:

```bash
mkdir -p /secure/ceremony
jq -e '.ready == true and (.reviewApproval | type == "object")' \
  /secure/ceremony/preflight.json >/dev/null
jq -S '.reviewApproval' /secure/ceremony/preflight.json \
  > /secure/ceremony/audit-approval.json

cd solslot-protocol
.venv/bin/python scripts/testnet_genesis_preflight.py pre-broadcast \
  --ceremony-state /secure/ceremony/state-plan-approved.json \
  --preflight-evidence /secure/ceremony/preflight.json \
  --audit-approval /secure/ceremony/audit-approval.json \
  --output-dir /secure/ceremony/output/<ceremony-id>
```

Repository paths default to the six canonical repositories. Use the explicit
`--protocol-repo`, `--evm-repo`, `--api-repo`, `--legacy-backend-repo`,
`--customer-web-repo`, and `--admin-portal-repo` options only when validating
clean checkouts elsewhere.

Both preflights must report ready immediately before broadcast. Any changed
input coin, expired plan, changed source SHA, dirty worktree, missing reviewer,
unhealthy validator, EVM mismatch, or output file invalidates the plan and its
signatures.

## Broadcast And Finalize

1. `POST /admin/genesis/{ceremonyId}/broadcast` exactly once.
2. If the response is rejected, missing, timed out, or ambiguous, mark the
   ceremony abandoned. Never retry the same ceremony.
3. Poll `POST /admin/genesis/{ceremonyId}/confirmation` until every predicted
   output is current and the bundle has three Chia testnet11 confirmations.
4. `POST /admin/genesis/{ceremonyId}/artifact` to construct the canonical
   schema V2 public artifact.
5. Two administrators independently prepare, review, and submit
   `SolslotGenesisArtifact` signatures.
6. `POST /admin/genesis/{ceremonyId}/finalize` once. This verifies the signed
   artifact, writes private evidence and SHA256 sums, publishes the artifact,
   and writes the read-only bootstrap lock last.

Do not manually edit an artifact, lock, checksum file, or ceremony database.

## Deploy Consumers

Deploy the API, customer web, and admin portal atomically from the artifact's
exact source SHAs. Each release must report the same artifact hash. Keep all
three write flags false:

```json
{
  "schemaVersion": 2,
  "protocolVersion": "solslot-v2",
  "network": "testnet11",
  "artifactHash": "0x...",
  "writeLocks": {
    "alphaWritesEnabled": false,
    "mintingEnabled": false,
    "ceremonyModeEnabled": false
  },
  "consumers": {
    "api": {"reachable": true, "artifactHash": "0x...", "sourceSha": "..."},
    "customerWeb": {"reachable": true, "artifactHash": "0x...", "sourceSha": "..."},
    "adminPortal": {"reachable": true, "artifactHash": "0x...", "sourceSha": "..."}
  }
}
```

Capture those live results as `release-attestation.json` and run:

```bash
cd solslot-protocol
.venv/bin/python scripts/testnet_genesis_preflight.py post-genesis \
  --ceremony-state /secure/ceremony/state-locked.json \
  --public-artifact /secure/ceremony/public_artifact.json \
  --bootstrap-lock /secure/ceremony/bootstrap_lock.json \
  --evidence-dir /secure/ceremony/output/<ceremony-id> \
  --release-attestation /secure/ceremony/release-attestation.json
```

The post-genesis gate verifies canonical artifact content, 2-of-3 signature
binding, locked ceremony state, three-confirmation policy, retired-coordinate
separation, checksummed evidence, clean source SHAs, consumer pins, and write
locks. Signature recovery and live chain confirmation are enforced by the API
state transitions before `locked`; this offline gate independently detects
evidence or release drift.

## Live Smoke Gate

After post-genesis preflight passes:

1. Create one fresh EVM vault and one fresh BLS vault.
2. Complete the full zkPassport to Sepolia event to 2-of-3 validator to Chia
   `SPEND_UPDATE_IDENTITY` path for each vault.
3. Clear browser storage, reconnect, and prove both receipts recover from the
   current unspent Chia singleton coin plus the API index.
4. Verify one validator cannot stamp, any valid two can, and replayed events,
   nullifiers, bridge coins, owner actions, and stale messages fail.
5. Verify Beta ignores Alpha sessions and exposes no protocol vault or proof
   state.
6. Verify retired coordinates fail through the API, both portals, and crafted
   offer files.

For the disposable engineering test only, enable minting after both vault
stamps recover successfully and run one synthetic SmartDeed through publish,
vote, five-spend execution, offer acceptance, pool/deposit, and redemption.
Disable minting again after the evidence is captured. Valued assets and
mainnet remain prohibited.

## Abort Rules

Abort on any mismatch, failed push, ambiguous response, dirty worktree,
signature discrepancy, stale input, reused bridge coin, missing checksum,
unexpected on-chain spend, or consumer pin mismatch. Preserve all evidence,
mark the ceremony abandoned, rotate affected one-time material, and start with
fresh coordinates and a new output directory.
