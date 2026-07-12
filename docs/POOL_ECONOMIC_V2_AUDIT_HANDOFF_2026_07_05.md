# Pool Economic V2 Audit Handoff - 2026-07-05

This packet is the current auditor entry point for the Pool Economic V2 hardening work.
It consolidates the three active repos and supersedes the earlier attack notes that were
written against `populis_protocol` commit `b50b7eb` before the hardening patches below.

## Repos And Branches

| Repo | Branch | Base HEAD | Current state |
| --- | --- | --- | --- |
| `populis_protocol` | `feat/pool-economic-v2` | `b50b7eb` | Working tree contains Pool V2 contract hardening and tests. |
| `populis_api` | `codex/solslot-protocol-artifacts` | `1c9b4bf` | Working tree contains protocol artifact coordinate canonicalization, mint-publish schema drift cleanup, and server-side testnet11 ceremony automation. |
| `populis_portal` | `codex/solslot-protocol-vault-console-convergence` | `7f79013` | Working tree contains frontend acceptance-coordinate guard and Admin Genesis ceremony UI. |

Primary audit repo: `populis_protocol`.

Integration audit repos: `populis_api` and `populis_portal`.

## Previous Findings Status

| Prior finding | Current status | Evidence to audit |
| --- | --- | --- |
| `POP-V2-CRIT-1`: pool accepted any NAV registry | Fixed in working tree. Pool inner puzzle curries trusted NAV registry mod hash, gov pubkey, launcher id, and a min registry version floor. | `solslot_puzzles/pool_singleton_inner.clsp`, `solslot_puzzles/protocol_deployment.py`, `tests/test_pool.py` |
| `POP-V2-CRIT-2`: specific deed swap destinations caller-controlled | Fixed in working tree. Reserve, protocol treasury, governance rewards destination hash/root are trusted curried values and caller values must match. | `pool_singleton_inner.clsp`, `tests/test_pool.py` |
| `POP-V2-CRIT-3`: reserve acquisition seller price unbounded | Fixed in working tree. Seller token price must be `<= compute_deed_nav(collection_nav_mojos, share_ppm)`. | `pool_singleton_inner.clsp`, `tests/test_pool.py`, `tests/test_pool_economics_v2.py` |
| `POP-V2-HIGH-1`: pool token tail does not derive full puzzle hash | Fixed in working tree. Tail derives/validates the pool full puzzle hash from trusted pool singleton context. | `solslot_puzzles/pool_token_tail.clsp`, `tests/test_pool_token.py` |
| `POP-V2-HIGH-2`: stale NAV versions accepted | Fixed in working tree for the configured freshness floor. All V2 spend cases reject `nav_registry_version < MIN_NAV_REGISTRY_VERSION`. | `pool_singleton_inner.clsp`, `tests/test_pool.py` |
| API trusted relayer risk | Partially fixed in working tree. Artifact endpoint now validates request coordinates against manifest/settings canonical coordinates before emitting artifacts. | `populis_api/protocol_artifacts.py`, `populis_api/tests/test_protocol_artifacts.py` |
| Frontend coordinate override risk | Partially fixed in working tree. Offer acceptance UI and final spend builder reject artifact/input coordinates that mismatch pinned environment coordinates. | `populis_portal/src/app/services/protocol-coordinate-guard.ts`, offer detail page, accept-offer spend builder |

## Diff Review Follow-Up

The 2026-07-05 diff review closed the five original Pool V2 findings and
raised three defense-in-depth recommendations. Current status:

- `R1`: addressed. `ProtocolDeploymentPlan` now rejects sentinel V2 trust
  anchors before deployment-plan construction can proceed, and
  `tests/test_protocol_deployment.py` includes an empty-anchor rejection test.
- `R2`: addressed. `populis_portal` now has `strictProtocolCoordinatePins`;
  it is disabled for local dev and enabled for staging/production builds.
  In strict mode, `resolveProtocolCoordinate` rejects an artifact fallback when
  the build has no pinned protocol coordinate.
- `R4`: addressed. `pool_singleton_inner.clsp` now documents that the NAV
  registry trust hash assumes the standard Chia singleton launcher puzzle hash.
- Schema drift: addressed. The API now exposes the mint-publish metadata
  validation module expected by `tests/test_protocol_schema_drift.py`, draft
  mint requests carry `collection_id` and `share_ppm`, and the full protocol
  suite now passes with schema drift included.
- Genesis ceremony gate: added `scripts/testnet_genesis_preflight.py` and
  `docs/TESTNET_GENESIS_CEREMONY_RUNBOOK_2026_07_06.md`. Current local
  artifact/config state is intentionally not genesis-ready until the real V2
  trust anchors and frontend/API pins are populated.
- Server-side testnet11 ceremony automation: `/admin/deploy/protocol` now
  generates Pool V2 trust anchors on the API host, includes NAV registry and
  protocol-config singleton launches in the genesis spend bundle, and persists
  public V2 coordinates into `deployment_manifest.json`. Bootstrap finalization
  folds in the vault-version registry coordinate after first-admin authority is
  known, then writes the public artifact bundle.
- Bootstrapper faucet fan-out: `/admin/deploy/protocol` now detects the
  funded-faucet-but-too-few-UTXOs case and, when no manual coin ids are
  supplied, plans six distinct ceremony funding coins from one large faucet
  coin. The pushed genesis bundle includes that fan-out spend atomically before
  the PGT, pool, DID, governance, NAV registry, and protocol-config spends.

## Protocol Files Changed

Auditor should review these protocol files first:

- `solslot_puzzles/pool_singleton_inner.clsp`
- `solslot_puzzles/pool_token_tail.clsp`
- `solslot_puzzles/pool_economics_v2.py`
- `solslot_puzzles/protocol_deployment.py`
- `scripts/dump_pool_economics_v2_fixtures.py`
- `scripts/testnet_genesis_preflight.py`
- `tests/test_pool.py`
- `tests/test_pool_economics_v2.py`
- `tests/test_pool_token.py`
- `tests/test_protocol_deployment.py`
- `tests/test_deposit_tokenize.py`
- `tests/test_e2e_simulation.py`

Generated hashes/fixtures changed:

- `solslot_puzzles/__init__.py`
- `solslot_puzzles/pool_singleton_inner.clsp.hex`
- `solslot_puzzles/pool_token_tail.clsp.hex`
- `populis_portal/src/app/services/pool-economics-v2.fixtures.json`

Do not treat untracked `solslot_puzzles/main.sym` as part of this audit unless it is intentionally added later.

Ceremony/operator docs:

- `docs/TESTNET_GENESIS_CEREMONY_RUNBOOK_2026_07_06.md`

## API Files Changed

Review these API files for integration safety:

- `populis_api/admin.py`
- `populis_api/admin_bootstrap.py`
- `populis_api/bootstrap_manifest.py`
- `populis_api/config.py`
- `populis_api/mint_endpoints.py`
- `populis_api/mint_proposals.py`
- `populis_api/mint_publish_validation.py`
- `populis_api/protocol_artifacts.py`
- `populis_api/tests/test_admin_bootstrap.py`
- `populis_api/tests/test_admin_unit.py`
- `populis_api/tests/test_bootstrap_manifest.py`
- `populis_api/tests/test_mint_endpoints.py`
- `populis_api/tests/test_mint_proposals.py`
- `populis_api/tests/test_protocol_artifacts.py`

The key rule is that request-scoped coordinates can no longer select the pool or protocol context.
If a request supplies a coordinate, it must match the canonical deployment manifest/settings value.
If no canonical coordinate exists, the request value is rejected rather than trusted.

The mint-publish schema rule is that API, portal, and protocol schema-contract
field order must stay aligned for draft mint fields, publish metadata fields,
and protocol context environment mapping.

The testnet11 ceremony rule is that operators do not paste V2 launcher ids or
trust anchors manually. The API host selects funded faucet coins, derives the
NAV registry, protocol-config, treasury, rewards, bridge, members, and later
vault-version registry coordinates, then emits the public artifact bundle.

Pre-existing untracked local JSON files in `populis_api` are not part of the patch:

- `admin_records.json`
- `bootstrap_manifest.json`
- `bootstrap_recovery_anchor.json`
- `deployment_manifest.json`
- `portal_runtime_config.json`

## Frontend Files Changed

Review these frontend files for wallet-signing safety:

- `populis_portal/src/app/pages/admin/genesis/genesis.component.ts`
- `populis_portal/src/app/pages/admin/genesis/genesis.component.spec.ts`
- `populis_portal/src/app/services/admin-genesis.service.ts`
- `populis_portal/src/app/services/protocol-coordinate-guard.ts`
- `populis_portal/src/app/services/vault-accept-offer-spend.service.ts`
- `populis_portal/src/app/services/vault-accept-offer-spend.service.spec.ts`
- `populis_portal/src/app/pages/offers/offer-detail.component.ts`
- `populis_portal/src/app/pages/offers/offer-detail.component.spec.ts`

The key rule is that a protocol artifact can provide acceptance coordinates only when this build
has no pin for that coordinate. If the build pins `poolLauncherId`, `poolInnerPuzzleHash`, or
`bridgePolicyHash`, the artifact/input value must match the pin before any wallet signing path
can proceed.

## Verification Already Run

Protocol:

```bash
cd populis_protocol
pytest tests/test_pool.py
pytest tests/test_protocol_integrity.py tests/test_protocol_deployment.py tests/test_pool_economics_v2.py tests/test_pool_token.py tests/test_v2_fixtures.py
pytest -q -k "not schema_drift"
.venv/bin/python -m pytest tests/test_protocol_schema_drift.py -q -p no:anchorpy -p no:cacheprovider
.venv/bin/python -m pytest -q -p no:anchorpy -p no:cacheprovider
```

Observed result:

- `tests/test_pool.py`: 33 passed.
- Compile/integrity/fixture slice: 23 passed.
- Broad protocol suite excluding schema drift: 793 passed, 24 skipped, 3 warnings.
- Schema drift: 6 passed.
- Full protocol suite with schema drift included: 800 passed, 24 skipped, 3 warnings.

API:

```bash
cd populis_api
.venv/bin/python -m pytest tests/test_protocol_artifacts.py -q
.venv/bin/python -m pytest tests/test_mint_proposals.py -q
env POPULIS_BOOTSTRAP_MANIFEST_PATH=/tmp/populis-api-test/bootstrap_manifest.json POPULIS_ADMIN_RECORDS_PATH= \
  .venv/bin/python -m pytest \
  tests/test_mint_endpoints.py::TestPropose \
  tests/test_mint_endpoints.py::TestListAndDetail \
  tests/test_mint_endpoints.py::TestCancel \
  tests/test_mint_endpoints.py::TestStepBStubs -q
.venv/bin/python -m pytest \
  tests/test_admin_unit.py \
  tests/test_bootstrap_manifest.py \
  tests/test_protocol_artifacts.py \
  tests/test_admin_bootstrap.py::test_configured_v2_vault_registry_is_folded_into_deployment_manifest -q
```

Observed result:

- Protocol artifacts: 9 passed, 10 warnings.
- Mint proposal store: 61 passed.
- Isolated auth-backed mint endpoint slice: 19 passed.
- Ceremony/admin focused slice: 94 passed, 10 warnings. Warnings are the known
  Chia `LazyNode` TestClient thread warning in protocol-artifact HTTP tests.
- Bootstrapper faucet fan-out unit slice: 28 passed locally; 3 focused fan-out
  tests passed on the EC2 ceremony release before service restart.

Known API test noise:

```bash
.venv/bin/python -m pytest tests/test_protocol_artifacts.py tests/test_protocol_config.py tests/test_audit_fixes.py -q
.venv/bin/python -m pytest tests/test_mint_endpoints.py -q
```

Observed result: unrelated/local-config failures around startup admin settings and existing
A.3 protocol-config/manifest gating. The full mint endpoint file also observes local
deployment JSON auto-discovery from untracked `admin_records.json` unless the test run
isolates `POPULIS_BOOTSTRAP_MANIFEST_PATH`, and its committee-vote dependency path still
has the pre-existing chia `LazyNode` test-thread warning.

Frontend:

```bash
cd populis_portal
npx ng test --watch=false --browsers=ChromeHeadless \
  --include=src/app/services/protocol-coordinate-guard.spec.ts \
  --include=src/app/services/vault-accept-offer-spend.service.spec.ts \
  --include=src/app/pages/offers/offer-detail.component.spec.ts
npx ng test --watch=false --browsers=ChromeHeadless \
  --include=src/app/services/admin-genesis.service.spec.ts \
  --include=src/app/pages/admin/genesis/genesis.component.spec.ts
```

Observed result:

- Wallet/offer guard slice: 19 success.
- Admin Genesis ceremony slice: 20 success.

Diff-review follow-up:

```bash
cd populis_protocol
.venv/bin/python -m pytest tests/test_protocol_deployment.py -q -p no:anchorpy -p no:cacheprovider
.venv/bin/python -m pytest tests/test_compile.py tests/test_puzzle_integrity.py tests/test_protocol_deployment.py -q -p no:anchorpy -p no:cacheprovider
```

Observed result: 20 passed for deployment tests; 40 passed for compile,
puzzle-integrity, and deployment tests.

Whitespace checks:

```bash
git -C populis_protocol diff --check
git -C populis_api diff --check
git -C populis_portal diff --check
```

All were clean after their respective bricks.

Genesis readiness:

```bash
cd populis_protocol
python3 -m py_compile scripts/testnet_genesis_preflight.py
python3 scripts/testnet_genesis_preflight.py --report-only
```

Observed result:

- Preflight script compiles.
- Current local/default artifact state reports `NOT READY`, as expected. Blocking
  findings include missing V2 deployment trust anchors, missing canonical
  frontend coordinates, an existing local bootstrap lock file, and empty Solslot
  staging protocol pins.
- After the server-side ceremony automation brick, current local/default
  artifact state still reports `NOT READY`, as expected. The next readiness
  check must point at fresh server-generated testnet11 artifacts, not local
  stale JSON files.
- EC2 ceremony API dry-run against the funded server faucet now returns HTTP
  200 with `genesis_v2.faucet_coin_fanout` present. The preview observed 4
  unspent faucet coins and planned six child ceremony amounts
  `[1000000, 1, 2, 3, 4, 5]` from the large faucet coin without broadcasting.

## Audit Focus Checklist

Protocol contract review:

- Confirm `trusted_nav_registry_puzzle_hash` cannot be reproduced by an attacker-controlled registry.
- Confirm every V2 spend case uses the trusted NAV registry hash and rejects stale versions below the floor.
- Confirm specific deed swap payment destinations cannot be redirected by the buyer.
- Confirm reserve acquisition cannot mint more than the NAV-backed deed value.
- Confirm pool token tail mint/melt authority is still exactly the intended pool singleton.
- Confirm all new curry parameters are included in inner puzzle hash self-reconstruction.
- Confirm old V1 spend paths still reconstruct the same intent after the argument list expansion.

API integration review:

- Confirm artifact endpoint output uses manifest/settings canonical coordinates.
- Confirm malformed or missing deployment manifests fail closed where trust-critical coordinates are requested.
- Confirm no future V2 endpoint accepts `pool_launcher_id`, `pool_inner_puzzle_hash`,
  `nav_registry_launcher_id`, or treasury destinations directly from the caller without canonical validation.

Frontend integration review:

- Confirm offer artifacts cannot override pinned protocol coordinates before wallet signing.
- Confirm the final spend builder repeats the coordinate guard even if called outside the offer page.
- Confirm production/staging environment pins are populated before enabling real Pool V2 acceptance.
- Confirm WalletConnect/EVM/Chia login remains a login path only and does not authorize Pool V2 spends.

Genesis ceremony review:

- Confirm the ceremony runbook matches the actual deploy command sequence.
- Confirm `scripts/testnet_genesis_preflight.py` catches missing/zero V2 trust anchors.
- Confirm stale local bootstrap artifacts cannot be reused as proof of a fresh V2 ceremony.
- Confirm frontend unlock pins are populated only from canonical ceremony artifacts.
- Confirm `/admin/deploy/protocol` dry-run previews server-generated public V2
  anchors and the pushed deploy writes them into `deployment_manifest.json`.
- Confirm `/admin/deploy/protocol` faucet fan-out is included only when manual
  coin ids are absent, emits six distinct child coins, and is aggregated into
  the same pushed genesis bundle before manifest persistence.
- Confirm `/admin/bootstrap/finalize` writes artifacts in order and adds the
  vault-version registry launcher before `bootstrap_manifest.json` locks.
- Confirm the Admin Genesis UI never asks the operator to paste generated
  launcher ids manually.

## Remaining Before Merge

1. Run the Admin Genesis UI dry-run on the server and review the generated V2
   anchor preview.
2. Push the server ceremony on testnet11, bind first-admin authority, finalize
   bootstrap, and preserve the generated public artifact bundle.
3. Re-run `scripts/testnet_genesis_preflight.py` against the server artifact
   paths without `--report-only` and require a clean exit before unlocking new
   vaults.
4. Populate Solslot staging runtime pins only from the final public artifact
   bundle, then have the auditor rerun old attack cases and integration-coordinate
   review against the current working tree and ceremony artifacts.
