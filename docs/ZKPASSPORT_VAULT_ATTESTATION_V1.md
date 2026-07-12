# zkPassport Vault Attestation V1

This document pins the V1 integration model before any vault puzzle or driver
changes land.  The goal is to keep the overhaul atomic: first freeze the
security model, then add helpers, then add vault state, then add spend logic.

## Summary

Solslot uses zkPassport as a one-time identity attestation source for a vault.
The user proves eligibility in the zkPassport/EVM world, a verifier + bridge
path produces a canonical attestation message, and the Chia vault consumes that
message exactly once to enroll an anonymous identity-attestation root.

After enrollment, future deed purchases do **not** require repeated KYC or a
new bridge message.  The vault proves membership against its stored
`IDENTITY_ATTEST_ROOT` when spending `SPEND_ACCEPT_OFFER`.

## Non-goals

- No backend autosigning for normal identity enrollment.
- No admin oracle that marks a user as KYC'd.
- No raw passport data, nationality, date of birth, or personal identifier on
  Chia.
- No mandatory repeated zkPassport proof for every purchase.
- No attempt in V1 to solve multi-document-per-person uniqueness globally.

## Trust boundary

The KYC witness lives outside Chia:

1. The user generates a zkPassport proof using `compressed-evm` mode.
2. The EVM verifier validates the proof.
3. A Solslot/zkPassport verifier contract emits or sends a canonical
   attestation through the chosen omnichain / Warp-style bridge path.
4. The Chia vault consumes that bridge attestation in an identity-enrollment
   spend.

The Chia puzzle verifies only the bridge-side commitment format that Solslot
accepts.  It does not verify a full zk-SNARK locally.

## zkPassport public-input mapping

Every zkPassport proof exposes public inputs in deterministic order:

| Index | Field | Solslot V1 use |
|-------|-------|----------------|
| 0 | `certificate_registry_root` | Must be accepted by the EVM verifier / registry at proof time. |
| 1 | `circuit_registry_root` | Must be accepted by the EVM verifier / registry at proof time. |
| 2 | `current_date` | Proof timestamp; verifier enforces freshness window. |
| 3 | `service_scope` | `Poseidon2("solslot.app")`. |
| 4 | `service_subscope` | Rotatable per use case.  V1 vault enrollment uses a vault-bound subscope. |
| 5..N | `param_commitments` | Bound commitments such as launcher id / policy version. |
| N+1 | `nullifier_type` | Document type discriminator. |
| N+2 | `scoped_nullifier` | Unique anonymous ID for `(document, scope, subscope)`. |

For V1, the Chia side does not need the raw zkPassport public inputs.  It
consumes a bridge-attested commitment derived from them.

## Scope and subscope

Use a stable domain and vault-bound subscope:

- `domain = "solslot.app"`
- `subscope = "vault:<vault_launcher_id>"`

This makes the enrollment nullifier deterministic for recovery with the same
passport and same vault, while avoiding linkability to other Solslot use cases
that can rotate the subscope later, for example:

- `deed:<deed_launcher_id>`
- `governance:<proposal_id>`

V1 must leave room for future vOPRF-salted nullifiers / `oprfKeyId` without
rewriting vault state.

## Bound data

For Chia, bind with zkPassport `custom_data`, not EVM `user_address` or `chain`.
A V1 enrollment proof should bind at least:

- `vault_launcher_id`
- Solslot zkPassport policy version
- bridge/verifier domain identifier

Total zkPassport bind data must stay under the SDK's 500-byte limit.

## Chia vault state

V1 adds an anonymous identity commitment to the vault singleton state:

- `IDENTITY_ATTEST_ROOT`: 32-byte Merkle root / commitment root.
- Optional verifier or bridge policy hash if needed by the final bridge design.

A fresh vault should start with an empty identity-attestation root.  The
enrollment spend updates it exactly once from empty to non-empty.

## New spend case

Planned spend tag:

- `SPEND_UPDATE_IDENTITY = 'z'`

Expected V1 behavior:

1. Assert the current `IDENTITY_ATTEST_ROOT` is empty, or otherwise reject a
   second enrollment.
2. Verify the bridge-attested enrollment payload is bound to this vault's
   launcher id / singleton id.
3. Verify the payload commits to a valid anonymous attestation leaf/root.
4. Recreate the vault singleton with the new `IDENTITY_ATTEST_ROOT`.
5. Emit a protocol-prefixed announcement so off-chain monitors can index the
   update.

## Accept-offer gate

`SPEND_ACCEPT_OFFER ('a')` should require a membership proof against the stored
`IDENTITY_ATTEST_ROOT`.

The proof should show that the vault owner has an acceptable anonymous
attestation leaf without revealing passport data.  A valid accept-offer spend
therefore depends on:

- existing vault owner authorization,
- the offer / token / deed constraints already enforced today,
- membership in `IDENTITY_ATTEST_ROOT`.

## Recovery semantics

Because the scoped nullifier is deterministic for the same `(document, domain,
subscope)`, a user can recover by rescanning the same passport with the same
vault-bound subscope.  V1 uniqueness is therefore best described as:

> one document per vault-bound nullifier

not globally one human forever.  Stronger personhood assumptions can be added
with FaceMatch or future salted-nullifier designs, but they are outside the V1
Chia puzzle boundary.

## Privacy notes

- Public chain state stores commitments and roots, not disclosed identity
  fields.
- A passport issuer or government with the document database, domain, and
  subscope may be able to rederive current unsalted nullifiers.  V1 state must
  remain compatible with future nullifier salting.
- FaceMatch strengthens one-person semantics but has device attestation limits
  and should not be assumed universally available.

## Atomic implementation sequence

1. Add pure Python attestation hash helpers and known-answer tests.
2. Add vault curry/parse state slots only.
3. Add `SPEND_UPDATE_IDENTITY ('z')` with positive and negative tests.
4. Gate `SPEND_ACCEPT_OFFER ('a')` on membership proof.
5. Refresh puzzle hex / checksum and run the full protocol gate.
6. Add portal client helpers.
7. Add portal enrollment UI.
8. Add portal accept-offer proof assembly.
9. Add API docs/config discovery only if bridge constants need a server-side
   publication point.

Each step must be committed and pushed before the next begins.
