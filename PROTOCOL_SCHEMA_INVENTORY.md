# Populis Protocol Schema Inventory

This inventory is the cross-repo contract for the current alpha protocol
surface. Code remains authoritative; this document names where each schema is
defined and which tests should fail on drift.

## Mint Publish

- Chialisp and Python source: `smart_deed_inner.clsp`,
  `mint_proposal_inner_v2.clsp`, `governance_singleton_inner.clsp`,
  `mint_publish_driver.py`.
- API guard: `populis_api.mint_publish_validation` re-derives
  `build_mint_publish_artifacts` from `proposal_metadata` and rejects bundles
  whose tracker proposal hash, bill op, or Artifact A launch commitments drift.
- MINT bill op is
  `(BILL_MINT, deed_full_puzhash, property_id_canon, property_registry_puzzle_hash)`.
  The first payload slot remains the deed puzzle hash consumed by current
  `EXECUTE_MINT`; the extra fields bind the proposal to the property id and
  the property-registry singleton puzzle hash observed at publish time.
- API/portal `proposal_metadata` wire shape is
  `property_id_canon`, `property_registry_puzzle_hash`, `par_value_mojos`,
  `asset_class`, `jurisdiction`, `royalty_puzhash`, `royalty_bps`,
  `quorum_threshold`, `owner_member_hash`, `gov_member_hash`.
- Portal pure assembly: `PublishMintArgsAssemblerService` derives and validates
  the draft/env inputs:
  - `property_id_canon = sha256(upper(trim(property_id)) UTF-8)`.
  - `par_value_mojos = draft.par_value`; the API draft value is already in
    mojos/cents and is not converted client-side.
  - `asset_class = 1` for alpha `RWA-RE-RES`; unknown classes reject.
  - `owner_member_hash` from the connected EVM admin pubkey via
    `EvmWalletService.recoverFirstAdminPubkey()` and `Eip712LeafHashService`.
- Portal registry material: `PropertyRegistryRegistrationMaterialService` is
  the authority for `property_registry_puzzle_hash` and the registry co-spend.
  It walks the A4 property-registry singleton lineage once. Fresh/eve registries
  reconstruct the inner puzzle from `propertyRegistryGovPubkey`; non-eve
  registries reconstruct current state from the latest prior registry spend and
  reject if the rebuilt full puzzle hash does not match the current coin.
- `MintProposalV2PublishRunnerService` signs/posts a five-spend bundle: XCH
  parent, Artifact A launcher, governance tracker `PROPOSE`, PGT first-vote
  `LOCK`, and property-registry registration. The XCH parent asserts the A4
  property-registration announcement; the registry co-spend creates it.
- API validation requires the expected property-registry
  `CREATE_PUZZLE_ANNOUNCEMENT` and matching `ASSERT_PUZZLE_ANNOUNCEMENT` to be
  present in the replayed bundle, then re-runs `build_mint_publish_artifacts`
  from `proposal_metadata`.
- Fixture contract: `scripts/dump_mint_publish_fixtures.py` feeds protocol and
  portal mint-publish specs. Regenerate fixtures when Chialisp curry order or
  protocol constants change.

## zkPassport Bridge

- EVM source: `PopulisZkPassportAttestationEmitter.sol`,
  `ZkPassportRealVerifierAdapter.sol`, `PopulisForwarder.sol`.
- EVM ABI guard:
  `populis_evm/test/PopulisZkPassportAttestationEmitter.test.js` pins the
  constructor, `verifyAndEmit` tuple, `validatorMessageFields` tuple, and
  `VaultAttestationVerified` event names/types/indexed flags.
- EVM deployment requires non-zero verifier and ERC-2771 trusted forwarder
  addresses plus a non-zero bridge policy hash; constructor tests enforce this.
- Validator message fields are exactly:
  `policyVersion`, `vaultLauncherId`, `attestationRoot`, `bridgePolicyHash`,
  `bridgeCoinId`, `bridgeMessage`, `attestationLeafHash`, `scopedNullifier`,
  `nullifierType`, `serviceScopeHash`, `serviceSubscopeHash`, `proofTimestamp`.
- Portal source: `ZkPassportAttestationService` and
  `ZkPassportEvmAttestationPollerService` must preserve this field order.
- API source: `zkpassport_validator.py` signs only the 32-byte tree hash of the
  canonical validator message.
- Protocol source: `zkpassport_bridge_message.clsp` verifies quorum signatures
  and emits the bridge coin announcement consumed by `vault_singleton_inner`.

## State And Storage

- API mint lifecycle states are `DRAFT`, `PROPOSED`, `VOTING`, `PASSED`,
  `FAILED`, `EXECUTED`, `MINTED`, `CANCELED`.
- Portal local drafts mirror the API response shape, but localStorage is only a
  browser audit cache. On-chain spends are authoritative after publish.
- Successful portal publish stores computed artifact hashes, proposal singleton
  launcher id, deed launcher id, bundle id, deadline, and `published_at`.
  It also stores `pgt_lock_coin_id`, derived as the CAT-created first-vote
  locked child id from the selected free PGT coin, locked CAT puzzle hash, and
  stake amount.
- Portal chain evidence for a published draft walks the stored proposal
  singleton launcher id and compares the live state coin's puzzle hash against
  `puzzle_for_singleton(launcher_id, computed.eve_inner_puzhash)`. This proves
  the local `PROPOSED` mirror is backed by the expected A.1 DRAFT-v0 singleton
  without trusting localStorage. If that DRAFT coin has been spent, the portal
  replays the latest proposal singleton spend, parses the prior curried V2
  state plus inner transition solution, verifies the
  `PROTOCOL_PREFIX || transition_message` announcement, and compares the live
  child puzzle hash against the recomputed APPROVED/CANCELLED singleton hash.
  When `pgt_lock_coin_id` is stored, the same check fetches that coin record
  from chain and marks it as confirmed-unspent, confirmed-spent, unconfirmed,
  or malformed local metadata.
  While the proposal singleton is still DRAFT-v0, the check also reads the
  governance tracker snapshot and binds the active tracker proposal hash and
  voting deadline back to the local mint publish artifacts.

## Property Registry

- Chialisp and Python source: `property_registry_inner.clsp` and
  `property_registry_driver.py`.
- Curry args are
  `(SELF_MOD_HASH, GOV_PUBKEY, REGISTERED_IDS_ROOT, REGISTRY_VERSION)`.
- Spend solution is
  `(my_amount, property_id_canon, registered_ids, new_registry_version)`.
- `property_id_canon = sha256(upper(trim(property_id)) UTF-8)`; empty
  normalized property ids reject in the driver.
- `registered_ids` is the full current registered-id witness for alpha:
  every entry is bytes32, `sha256tree(registered_ids)` must match
  `REGISTERED_IDS_ROOT`, `count(registered_ids)` must equal
  `REGISTRY_VERSION`, and `property_id_canon` must be absent.
- The recreated singleton carries
  `sha256tree((property_id_canon . registered_ids))`; newest id is at the
  head. This makes duplicate registry registration consensus-impossible.
- Registration announcement body is
  `PROTOCOL_PREFIX || property_id_canon`.
- Tests: `tests/test_property_registry.py`,
  `tests/test_mint_publish_fixtures.py`,
  portal `property-registry-registration-material.service.spec.ts`,
  `mint-publish-spend-builder.service.spec.ts`,
  `mint-proposal-v2-publish-runner.service.spec.ts`, and
  `mint-detail.component.spec.ts`.
- Mint publish now consumes the registry registration co-spend and announcement
  assertion in the same bundle. Local `MintProposalStore` duplicate checks are
  UI/cache ergonomics, not the mint-path authority.

## Governance Settlement

- SETTLE bill schema is:
  `(S splitxch_root_hash total_amount num_deeds deed_releases_hash)`.
- `deed_releases_hash = sha256tree(deed_releases)` where `deed_releases` is the
  exact CLVM release list passed to the pool settlement spend.
- Governance EXECUTE sends the pool message over:
  `(SETT splitxch_root_hash total_amount num_deeds deed_releases_hash)`.
- Pool settlement spends recompute `sha256tree(deed_releases)` and require that
  hash in both the `RECEIVE_MESSAGE` condition and settlement batch
  announcement. Reordering releases, changing a destination, or using the old
  count-only message changes the required governance message.
- Tests:
  `tests/test_governance.py::TestExecute::test_execute_settle_sends_message_to_pool`
  and `tests/test_pool.py::TestPoolSettlementBinding`.

## Deployment Context

- API settings, portal environment, and protocol deployment manifests must agree
  on: protocol DID singleton struct, protocol DID puzzle hash, `p2_pool` mod
  hash, `p2_vault` mod hash, PGT tail genesis coin id, governance launcher id,
  zkPassport bridge policy hash, and vault version registry coordinates.
- Hardening target: replace hand-copied constants with generated runtime
  artifacts and drift tests across API, portal, protocol fixtures, and EVM ABI.

## Hardening Ledger

- Re-run the April 2026 protocol audit against current Chialisp and mark every
  finding fixed, open, deferred, or obsolete with a test/proof reference.
- Fixed:
  - SOR-1 / `p2_deed_settlement` burn destination binding:
    `p2_deed_settlement.clsp` hardcodes the canonical all-zero burn inner
    puzzle hash instead of accepting it as a curried setup parameter.
    Covered by `tests/test_p2_deed_settlement.py`.
  - Governance settlement release-set binding:
    SETTLE bills now carry `deed_releases_hash = sha256tree(deed_releases)`,
    and `pool_singleton_inner.clsp` recomputes that hash from the release list
    before accepting the governance message. Covered by
    `tests/test_governance.py::TestExecute::test_execute_settle_sends_message_to_pool`
    and `tests/test_pool.py::TestPoolSettlementBinding`.
  - A4 property registry global uniqueness/non-membership proof:
    `property_registry_inner.clsp` now carries `REGISTERED_IDS_ROOT` and
    requires a full-set registered-id witness whose root and count match
    before accepting a new property id. Covered by
    `tests/test_property_registry.py`.
- Priority open reviews:
  - A1 proposal indexing from chain instead of local draft cache.
  - A2 admin roster hash fetched directly from chain after first spend.
  - API dual-source chain confirmation risk.
  - Vault secp support or explicit UI gating for spend cases that remain
    BLS-only.
