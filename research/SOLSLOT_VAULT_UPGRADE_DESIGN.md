# Solslot Vault Upgrade Design

Status: draft contract for implementation
Date: 2026-06-15

## Purpose

Solslot vaults are permanent singletons. Their protocol parameters — the pool
reference, the zkPassport bridge policy hash, and the `vault_singleton_inner`
module itself — are curried at mint and are **immutable**. When the protocol
ships a new vault version (a new inner-puzzle module, or new canonical
parameters), existing vaults cannot change in place.

This document pins a **decentralized, backend-free** mechanism that lets the
admin (now) and an admin-authority/committee (later) publish a new canonical
vault version on chain, and lets any client:

1. Detect that a user's vault is outdated by reading the chain directly.
2. Offer the user a one-click upgrade that creates a new vault at the current
   version and migrates the old vault's contents into it.

An upgrade is offered **only when a new known vault version exists on chain.**

## Goals / Non-goals

Goals:

- **Decentralized.** Detection and upgrade read the chain directly
  (coinset.org). There is **no Solslot backend dependency** in the detection or
  upgrade path.
- **On-chain version source of truth.** An upgrade is offered only when a new
  known vault version is advertised on chain.
- **Admin-published now, committee-governed later**, using the existing
  authority model (`protocol_config_inner.clsp` / `admin_authority_v2`).
- **One-click, client-side, non-custodial.** The user's wallet signs every
  spend; no backend holds keys or moves assets.

Non-goals:

- No automatic or forced upgrades. Users opt in.
- No retroactive in-place upgrade of already-deployed vaults — impossible,
  because curried params are immutable.
- No custodial migration.

## Motivating example

The zkPassport bridge-policy-hash bug (fixed in `solslot_api` commit `a59bd02`)
minted vaults with a zero `ZKPASSPORT_BRIDGE_POLICY_HASH`, making them
permanently un-enrollable. Such vaults must be replaced by a new vault at the
correct parameters — exactly the upgrade flow this design enables.

## On-chain vault version registry (the version source)

A dedicated singleton `vault_version_registry_inner.clsp`, mirroring the proven
`protocol_config_inner.clsp` (A.3) state-machine pattern.

Curried immutable policy:

- `SELF_MOD_HASH` — for self-recurry on update.
- `ADMIN_AUTHORITY_LAUNCHER_ID` — launcher id of the live `admin_authority_v2`
  singleton (testnet11:
  `0xf3fd2dedfc77a5b8f65acdfaff04d3786844a8c4d0529d3dbc4d37dc4012bb84`).
  The registry has **no key of its own** and is **never singly centralized by
  construction**. A version publish is authorized by the authority's *current
  quorum*, asserted on chain (see the update spend). This is deliberately NOT a
  fixed `GOV_PUBKEY`. Today the authority roster is a single admin slot in
  `mofn1of1` mode (you), so a publish needs only your one signature — matching
  "for now I push as admin." As you vote in more admin slots
  (`ADMIN_ROSTER_UPDATE`, tag 0x07), the operational quorum automatically
  becomes a supermajority (`ceil(2n/3)`) and publishes require the committee —
  with **no change to the registry or to any vault**.

Curried mutable state:

- `VAULT_INNER_MOD_HASH` — tree hash of the canonical current
  `vault_singleton_inner` module (the puzzle version).
- `CANONICAL_PARAMS_HASH` — `sha256tree` of the canonical curried vault params
  every new vault must use.
- `VAULT_VERSION` — uint64, **monotonically increasing**. Replay/downgrade
  guard, asserted strictly increasing on every update spend.

Canonical params hash (the immutable-at-mint params, excluding per-user
identity):

```text
CANONICAL_PARAMS_HASH = sha256tree(list
  POOL_SINGLETON_MOD_HASH
  POOL_LAUNCHER_ID
  POOL_SINGLETON_LAUNCHER_PUZZLE_HASH
  ZKPASSPORT_BRIDGE_POLICY_HASH)
```

Content hash and update spend. A publish is co-spent with the
`admin_authority_v2` singleton: the authority's quorum-authorized `OPERATIONAL`
spend (0x01) emits an approval announcement committing to the new registry
state, and the registry asserts it.

```text
content_hash(state) = sha256tree(list VAULT_INNER_MOD_HASH CANONICAL_PARAMS_HASH VAULT_VERSION)

On a valid publish-version spend (co-spent with the admin_authority_v2 coin):
  ASSERT_<authority>_ANNOUNCEMENT (approve || content_hash(new_state))
  CREATE_COIN new_inner_puzhash my_amount
  CREATE_PUZZLE_ANNOUNCEMENT (PROTOCOL_PREFIX || content_hash(new_state))
  assert (> new_VAULT_VERSION VAULT_VERSION)
```

The exact announcement binding (coin vs puzzle announcement, and how the
registry identifies the authority's current coin from its launcher id) is a
Brick 2 detail pinned with consensus tests. The invariant is that
authorization is the authority's **live quorum** — never a key curried into
the registry. Whether a **SGT staker ratification vote is *also* required**
depends on the tier — see **Governance model** below: vault **code** changes
always need SGT ratification; **parameter-only** repair is an admin fast-track.

Discovery: the registry singleton's launcher id is published in
`deployment_manifest.json` and the portal `environment.ts` as a public,
chain-anchored constant. Clients walk its lineage on coinset.org to read the
latest state — identical to how `protocol_config` is read today.

## Governance model: who authorizes a version publish

RESOLVED (tiered, option C + i): the tier is determined by an objective,
CLVM-enforced property of the diff — whether the vault's executable code
changes — never by an admin's discretionary label. Recorded here so it is
enforced, not assumed.

### Current protocol reality (2026-06)

- **SGT staked governance exists but is mint-scoped.**
  `governance_singleton_inner.clsp` (the proposal tracker) enforces a real
  SGT-stake quorum (`VOTE_TALLY * 10000 >= QUORUM_BPS * SGT_TOTAL_SUPPLY`) but
  its `dispatch_bill` handles only **three fixed bills**: `MINT` (→ DID),
  `FREEZE` (→ pool), `SETTLE` (→ pool); any other tag fails `(x)`. Per
  `docs/GOVERNANCE_V2_DESIGN.md` §1–3, this is intentional, and
  `vault_singleton_inner.clsp` is explicitly listed **"unchanged / out of
  scope"** in that design's contract inventory. There is **no vault/protocol
  bill type today.**
- **The admin authority is separate and self-governed** by its own MofN
  (`admin_authority_v2`). Its curried `SGT_GOVERNANCE_PUZZLE_HASH` is a
  **reserved, unwired hook** ("for ADMIN_SLOT_* spends, out of scope")
  defaulting to zeros — SGT does not gate admin-authority actions today.
- **The committee on-chain SGT-VOTE submission path is not wired yet.**
  `/admin/committee/vote` returns `501` and the portal `/committee` page is
  "not wired yet." The admin → propose → SGT → ratify → execute lifecycle is
  documented for **mints** (`ADMIN_DESK_DESIGN.md` §5) but not finished
  end-to-end.

### Resolved model: tiered by code-vs-parameter change

The tier is an **objective, CLVM-enforced property of the diff**, never an
admin's discretionary "emergency" label. The registry state is
`(VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, VAULT_VERSION)`, so the
determinant is simply *which of those changes*:

- **Routine — the vault CODE changes (`VAULT_INNER_MOD_HASH` differs).** New
  vault logic, spend cases, or features. **Always requires affirmative SGT
  quorum ratification** (the governance tracker's EXECUTE for a `vault-version`
  bill). For a security fix a **shortened emergency-vote window** (faster
  deadline / emergency threshold) may be used, but SGT still ratifies. **The
  admin can NEVER unilaterally change the code a user's vault executes.**
- **Emergency — PARAMETERS only (`CANONICAL_PARAMS_HASH` differs, code
  byte-identical).** Repairing a misconfigured/compromised curried constant
  (e.g. the bridge-policy-hash bug, a rotated pool reference). The
  `admin_authority_v2` MofN may **fast-track** it, because the code is provably
  unchanged. It stays **SGT-vetoable within a mandatory cooldown**: the new
  version is not enforced-canonical until the cooldown elapses, during which a
  SGT veto-quorum can revoke it.

Enforcement (so "emergency" is structural, not a claim):

- The registry's fast-track (params-only) spend case **asserts
  `new VAULT_INNER_MOD_HASH == VAULT_INNER_MOD_HASH`** — a code change through
  the fast path is rejected by consensus.
- The fast-track path is **strictly weaker** than the routine path (delayed +
  SGT-vetoable), so there is no incentive to misuse it. Only the routine SGT
  vote yields an immediately-final, non-vetoable version. **SGT is supreme in
  every path.**

This depends on the same SGT wiring the mint flow needs: a `vault-version` bill
type in `governance_singleton_inner.clsp` for the routine path (a consensus
change — the tracker was deliberately 3-bill-scoped), plus a veto mechanism and
the committee-vote path. Until that lands, only the params-only admin
fast-track is operable (today the admin quorum is your 1-of-1), and code
changes are blocked from shipping at all — fail-safe.

## Vault version identity & outdated detection (client-side, no backend)

A vault's **version identity** is the pair
`(vault_inner_mod_hash, canonical_params_hash)` it was minted with. The portal
already reconstructs a vault's curried params from chain (see
`zkpassport-vault-enrollment-spend.service.ts`).

A vault is **CURRENT** iff both hold:

- its `vault_inner_mod_hash` == `registry.VAULT_INNER_MOD_HASH`, and
- its `canonical_params_hash` == `registry.CANONICAL_PARAMS_HASH`.

Otherwise it is **OUTDATED**, and an upgrade to `registry.VAULT_VERSION` is
offered. Detection is pure: read the registry singleton + the user's live vault
coin from coinset.org, compute both hashes client-side, compare. **No backend.**

Existing vaults carry no explicit version number; comparison is by mod-hash +
params-hash, which works retroactively. Future vault modules MAY also curry an
explicit `VAULT_VERSION` for display.

## The upgrade transaction (create new + migrate contents)

Conceptually one user-signed operation:

1. **Launch a NEW vault singleton** at the canonical params (new launcher id),
   reusing the user's identity (owner pubkey, auth type, members root). The
   launcher spend is client-built (no backend) and funded by the user (or the
   faucet during alpha).
2. **Move the old vault's contents** to the new vault:
   - XCH and pool-share CATs (ungated, freely transferable) → sent to the new
     vault's `p2_vault` / owner address. Movable with existing puzzles.
   - Deeds held at `p2_vault` / deposited in the pool → require a new `migrate`
     spend case in `vault_singleton_inner.clsp` that authorizes sending the
     deed to the **new** vault's `p2_vault`. **This is a consensus change.**
3. The old vault is left empty (and, if a melt case is added later, may be
   melted to reclaim its mojo).

**Chicken-and-egg:** the `migrate` spend case can only be used by vaults that
were minted **with** it. Vaults minted before it (including the bridge-bug
vaults) can move only freely-transferable assets and must abandon the old
launcher. Therefore the `migrate` case must ship in the next vault module so
that all subsequent upgrades are seamless.

## Decentralization invariants

- **No Solslot backend** participates in version detection or upgrade. The
  portal reads coinset.org directly and the wallet signs locally.
- The single trust root is the on-chain `vault_version_registry` singleton,
  whose publishes are authorized by the live `admin_authority_v2` quorum — a
  single admin slot (you) in `mofn1of1` mode today, an MofN committee as the
  roster grows. The registry holds **no key of its own** and is never singly
  centralized by construction.
- **The admin can never unilaterally change vault code.** Any change to
  `VAULT_INNER_MOD_HASH` requires SGT ratification; the admin fast-track is
  limited to parameter repair (code byte-identical) and is SGT-vetoable within
  a cooldown.
- An upgrade is offered **only** when the on-chain registry advertises a higher
  `VAULT_VERSION` (or a differing canonical identity) than the user's vault. No
  client-side or env-injected version can trigger an upgrade.
- Users opt in; nothing is forced or custodial.

## Phased brick plan

- **Brick 1 (this doc):** design contract + docs-contract test.
- **Brick 1.5 (governance — RESOLVED, tiered by code-vs-params):** the registry
  has two publish paths. (a) **Params-only fast-track**: `admin_authority_v2`
  MofN, with the spend case asserting `new VAULT_INNER_MOD_HASH ==
  VAULT_INNER_MOD_HASH`; SGT-vetoable within a cooldown. (b) **Code-change
  routine**: requires the SGT proposal tracker's EXECUTE for a NEW
  `vault-version` bill in `governance_singleton_inner.clsp` (consensus change),
  plus the committee SGT-VOTE wiring (`/admin/committee/vote`, portal
  `/committee`) and a veto path. Build (a) first (operable today via the admin
  1-of-1); (b) gates code upgrades and lands with the SGT wiring.
- **Brick 2 (protocol):** `vault_version_registry_inner.clsp` + driver + tests,
  mirroring `protocol_config_inner` (authority-quorum-authorized via
  `admin_authority_v2`, monotonic version, content-hash, announcement).
- **Brick 3 (protocol, consensus-critical) — DONE:** added the `migrate` (`'m'`)
  spend case to `vault_singleton_inner.clsp` **in place** (the vault mod hash
  changes, so new vaults gain it and pre-`migrate` vaults cannot — the
  chicken-and-egg above). It is **BLS-only** and the owner signs over the
  destination `(SPEND_MIGRATE, deed_launcher_id, new_p2_vault_puzzlehash, my_id)`
  so a relayer cannot redirect the deed; it emits the
  `CREATE_PUZZLE_ANNOUNCEMENT` the deed's `p2_vault` asserts, re-binding the deed
  (identity/launcher preserved) to the new vault's `p2_vault`. The optional
  `VAULT_VERSION` curry is **deferred** (detection works by mod-hash +
  params-hash; the explicit number is display-only, see above). Driver:
  `build_vault_migrate_spend` / `migrate_bls_signing_tree`; tests in
  `tests/test_vault.py::TestVaultBLSMigrate` (incl. the end-to-end p2_vault
  announcement match). secp256k1/secp256r1 migrate is deferred (needs a new
  EIP-712 typehash covering the destination), consistent with `'a'`/`'k'`.
- **Brick 4 (api/protocol):** registry launch + admin publish-version helper;
  faucet mints new vaults at the canonical params/version.
- **Brick 5 (portal):** read the registry from chain (no backend), compute
  outdated detection, show an "Upgrade available" banner.
- **Brick 6 (portal):** one-click upgrade — build the new-vault launch +
  asset-migration spends client-side, wallet-signed.

## Open decisions

- RESOLVED: governance model is **tiered by code-vs-parameter change** (see
  **Governance model**). Vault code changes always require SGT ratification;
  parameter-only repair is an admin fast-track that is SGT-vetoable.
- RESOLVED: the registry binds to the `admin_authority_v2` quorum by launcher
  id (no standalone key). It resolves to your 1-of-1 today and to the committee
  MofN as the roster grows, with no redeploy.
- Whether to add a `melt`/reclaim case to empty old vaults.
- Faucet vs user funding for the new launcher coin during alpha.
