# Native Primary Purchases

RC19 creates XCH and CAT primary-purchase offers on demand. There is no static
offer inventory and the issuer half-offer is never returned to a browser.

## Trust Boundary

1. The coordinator creates a canonical `PurchaseArtifactV2` from the sealed
   collection allocation and an authorized oracle round.
2. The artifact binds one deed launcher, one metadata root and anchor, one
   share allocation, one exact payment amount, one authorization expiry, and
   one canonical `p2_vault` derived from a chain-confirmed zkPassport vault.
3. A payer wallet, which may be different from the vault owner, signs only the
   buyer half-offer. It offers the quoted XCH or CAT and requests that exact
   deed directly into the artifact-bound vault.
4. Two independent validators recheck the live credential, deed coin, quote,
   buyer signature, and vault destination before signing the artifact hash.
5. The coordinator creates the issuer half from the current governed deed coin
   and combines both halves. Chia Offer settlement makes payment and delivery
   atomic.

The native puzzle accepts only XCH and CAT rail tags. Stripe and EVM settlement
do not have an alternate branch in this puzzle; they use the separately
reviewed Omnichain, Key of Solomon, and Samuel flow.

## Fail-Closed Rules

- Exactly one governed deed is requested and delivered.
- The destination must equal the canonical vault puzzle hash derived from the
  approved vault launcher.
- The payment amount and asset must equal the system quote.
- The collection, deed identifier, launcher, share allocation, metadata, and
  current unspent deed coin must still match the executed mint proposal.
- Generic `chia` rails, browser-supplied raw offers, extra requested assets,
  substitute deeds, substitute vaults, stale credentials, and expired quotes
  are rejected.

`payment_artifacts_v2.py` is the shared canonical artifact and oracle model.
`primary_purchase_v2_driver.py` and `mint_offer_delegate_v2.clsp` implement
only the native atomic exchange.
