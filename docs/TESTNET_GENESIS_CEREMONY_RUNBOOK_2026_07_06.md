# Testnet Genesis Ceremony Runbook - 2026-07-06

This is the operator checklist for a Populis Pool Economic V2 testnet genesis
ceremony. It is intentionally stricter than a normal staging deploy: the goal is
to create one canonical testnet protocol context, publish the matching API and
frontend pins, and keep the new vault path locked until those pins exist.

## Current Verdict

Ready for a controlled rehearsal: yes.

Ready to unlock customer-facing new Populis vaults: no.

The current local state still has old/local bootstrap artifacts and does not
contain the full Pool V2 trust-anchor set required by the hardened contracts.
Run the preflight checker before every ceremony attempt:

```bash
cd populis_protocol
python3 scripts/testnet_genesis_preflight.py --report-only
```

Use a nonzero exit as a hard no-go unless this is only a rehearsal report.

## Repos And Branches

Primary ceremony repo:

- `populis_protocol` on `feat/pool-economic-v2`

Integration repos after ceremony:

- `populis_api` on `codex/solslot-protocol-artifacts`
- `research/solslot-frontend/slui` on `codex/solslot-alpha-recovered-ui-hardening`
- `populis_portal` on `codex/solslot-protocol-vault-console-convergence` for reference/pin parity

Do not change protocol code during the ceremony. Freeze commits first, then
generate artifacts from that frozen tree.

## Hard Inputs

Before starting, collect and record:

- Testnet network: `testnet11`.
- Fresh server-side output directory for deployment/bootstrap artifacts.
- Server/Admin UI access to the `populis_api` and `populis_portal` staging
  host that will run the ceremony.
- Funded server faucet/deployer wallet and Coinset/node connectivity.
- Operator approval to spend the ceremony faucet coins.
- Admin slot 0 authority material for first-admin finalize.
- zkPassport bridge policy config already set in server-side API settings.
- Optional members file if this ceremony should start with non-empty members.

Do not manually paste generated NAV registry, protocol-config, vault-registry,
treasury, rewards, or launcher ids. `/admin/deploy/protocol` derives the public
Pool V2 anchors on the API host. `/admin/bootstrap/finalize` folds in the
vault-version registry coordinate after first-admin authority is known.

All generated hashes and launcher ids must be real nonzero values in the final
artifact bundle. Sentinel zeros, placeholder strings, and stale local JSON are
no-go conditions.

## Pre-Ceremony Gates

1. Confirm protocol tests are clean.

```bash
cd populis_protocol
.venv/bin/python -m pytest -q -p no:anchorpy -p no:cacheprovider
```

2. Confirm the audit handoff is current and points auditors at the same commit
   that will be used for genesis.

3. Confirm no generated/debug local file is accidentally part of ceremony
   state, especially `solslot_puzzles/main.sym`.

4. Confirm the existing API local files are not reused as the ceremony output:
   `deployment_manifest.json`, `bootstrap_manifest.json`,
   `portal_runtime_config.json`, and `admin_records.json` are local artifacts,
   not proof that this V2 ceremony has been run.

5. Run the preflight checker against the intended artifact paths. If the
   ceremony writes to non-default paths, pass them explicitly:

```bash
cd populis_protocol
python3 scripts/testnet_genesis_preflight.py \
  --deployment-manifest /path/to/deployment_manifest.json \
  --bootstrap-manifest /path/to/bootstrap_manifest.json \
  --portal-runtime-config /path/to/portal_runtime_config.json
```

## Ceremony Order

Run the ceremony from the server/Admin UI, not from a local workstation.

1. Open the Admin Genesis page on the staging host and start a bootstrap
   session with the one-shot operator token.

2. Run the dry-run step. Review the server-generated anchor preview:
   pool launcher, pool inner puzzle hash, bridge policy, members root,
   protocol-config launcher, and pending vault-version registry status.

3. Deploy the base protocol from the Admin Genesis page. This pushes the base
   protocol bundle plus NAV registry and protocol-config singleton launches.

4. Persist `deployment_manifest.json` with every trust-critical coordinate:
   Pool launcher, pool inner puzzle hash, all V2 trust anchors, bridge policy,
   members root, and protocol config launcher.

5. Bind first-admin authority. Bootstrap finalization will then launch or bind
   the vault-version registry and update `deployment_manifest.json`.

6. Generate the portal runtime config from that same manifest.

7. Write `bootstrap_manifest.json` last. Treat it as the ceremony lock file.
   If it already exists for the target path, stop and choose a fresh output
   directory unless intentionally verifying an existing ceremony with
   `--allow-existing-bootstrap`.

8. Run the preflight checker again without `--report-only`. It must exit 0
   before the frontend can unlock new Populis vaults.

## API And Frontend Unlock

After the ceremony:

1. Keep the canonical manifest/runtime config on the server and export only the
   public artifact bundle needed by auditors and Solslot.

2. Confirm the artifact endpoint rejects caller-supplied mismatched coordinates.

3. Populate `research/solslot-frontend/slui/src/environments/environment.staging.ts`
   with the six frontend unlock pins:
   `poolLauncherId`, `poolInnerPuzzleHash`, `bridgePolicyHash`,
   `membersMerkleRoot`, `protocolConfigLauncherId`, and
   `vaultVersionRegistryLauncherId`.

4. Keep `strictProtocolCoordinatePins` enabled anywhere public/staging users can
   sign.

5. Deploy staging and smoke test the browser:
   `Vault Connect` should remain locked before pins exist and should only show
   wallet choices after the ceremony coordinates are populated.

6. Confirm wallet signature alone never creates `populis_session_v1` with a
   vault launcher id and never shows `Vault connected`.

## Browser Smoke

Use a clean profile or clear local storage first.

- First load starts at the top with no scroll jump.
- Header shows `Vault Connect` and `Legacy Connect*`.
- `Legacy Connect*` states it is recall-only and blocked from new listings.
- `Vault Connect` shows bootstrap-locked copy before genesis.
- After pins and API are live, `Vault Connect` allows Goby, EVM, and
  WalletConnect choices.
- Wallet-only signature shows setup/discovery state, not vault-ready state.
- Existing vault discovery stores `populis_session_v1` and mirrors only a real
  launcher id into `POPULIS_VAULT_LAUNCHER_ID`.
- Pending launcher shows `Vault launching` and blocks purchase.
- Confirmed launcher unlocks the vault console and purchase readiness checks.

## No-Go Conditions

- Any Pool V2 trust anchor is missing, zero, or a placeholder.
- `params.min_nav_registry_version` is missing.
- A frontend pin is empty or mismatches the canonical manifest.
- API emits artifacts from caller-supplied coordinates instead of canonical
  settings/manifest values.
- The new vault path can be opened before genesis/bootstrap.
- A wallet signature alone marks the user vault-ready.
- Old local `bootstrap_manifest.json` is reused as the new ceremony lock.
- Auditor has not rerun the old attack cases against the current working tree.

## Auditor Handoff After Ceremony

Ask the auditor to rerun:

- Pool V2 contract attack cases against the frozen genesis commit.
- API coordinate-canonicalization tests against the deployed manifest.
- Frontend wallet-signing and offer-acceptance coordinate guard tests.
- Browser smoke for `Vault Connect`, `Legacy Connect*`, and purchase gating.
