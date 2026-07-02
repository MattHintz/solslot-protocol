# Pool Economic V2

Pool Economic V2 treats the Populis pool token as a global ETF-like share of
the whole smart-deed pool. Fixed-par V1 math remains a development artifact;
alpha redemption must price deed exits from governed collection NAV evidence.

## Canonical Fields

- `collection_id_canon`: `sha256(upper(trim(collection_id)) UTF-8)`.
- `share_ppm`: integer in `1..1_000_000`; `1_000_000` equals 100% of a collection.
- Deed NAV: `ceil(collection_nav_mojos * share_ppm / 1_000_000)`.
- Circulating pool-token supply:
  `total_pool_token_supply - treasury_reserve_tokens`.
- Pool-token NAV:
  `total_nav_locked / circulating_supply`.
- Pool state is curried as:
  `POOL_STATUS`, `TOTAL_VALUE_LOCKED`, `DEED_COUNT`,
  `TOTAL_POOL_TOKEN_SUPPLY`, and `TREASURY_RESERVE_TOKENS`.

## Pricing

Specific deed swap:

- Principal tokens:
  `ceil(deed_nav * circulating_supply / total_nav_locked)`.
- Buyer pays principal plus a 1% surcharge.
- Principal moves into treasury reserve. Total supply is unchanged.
- 0.3% goes to protocol treasury.
- 0.7% goes into a PGT-holder claimable rewards root.

True redemption:

- Principal tokens are melted/burned.
- Total supply decreases by principal.
- The deed exits to the holder vault.

Reserve acquisition:

- Existing treasury reserve tokens pay the seller first.
- Fresh minting only covers reserve shortfall.
- Total NAV locked and deed count increase when the deed enters the pool.

## CircuitDAO-Inspired Methodology

The V2 migration follows the same style used elsewhere in the audit notes:

- bind full payloads into hashes/announcements, not individual loose fields;
- keep registries as on-chain sources of truth;
- assert lineage/evidence rather than trusting API mirrors;
- use Merkle roots for broad fee fanout instead of in-spend fanout;
- avoid free payout/burn destinations in settlement paths.

## Implementation Status

Implemented in this slice:

- `collection_nav_registry_inner.clsp`;
- `collection_nav_registry_driver.py`;
- no-op collection NAV read-evidence spends:
  `PROTOCOL_PREFIX || sha256tree(NAVE collection_id_canon nav_value_mojos root version)`;
- `pool_economics_v2.py`;
- protocol action specs for specific deed swaps, true redemptions, and
  reserve-funded acquisitions, including token output/authorization messages;
- `pool_singleton_inner.clsp` case `6` (`POOL_SPEND_V2_SPECIFIC_DEED_SWAP`),
  which consensus-enforces:
  - governed collection NAV read evidence;
  - exact smart-deed `collection_id_canon` / `share_ppm` release evidence;
  - NAV-pro-rata principal calculation;
  - CAT settlement payment fanout to treasury reserve, protocol treasury, and
    PGT rewards;
  - 0.3% protocol fee and 0.7% PGT rewards-root fee commitments;
  - next pool `total_nav_locked` / `deed_count` /
    `treasury_reserve_tokens` recreation in curried state;
- `pool_singleton_inner.clsp` case `7` (`POOL_SPEND_V2_TRUE_REDEMPTION`),
  which consensus-enforces:
  - governed collection NAV read evidence;
  - exact smart-deed `collection_id_canon` / `share_ppm` release evidence;
  - NAV-pro-rata principal calculation;
  - pool CAT melt authorization;
  - V2 action announcement field order matching `build_true_redemption_spec`;
  - next pool `total_nav_locked` / `deed_count` /
    `total_pool_token_supply` recreation in curried state;
- `pool_singleton_inner.clsp` case `8`
  (`POOL_SPEND_V2_RESERVE_ACQUISITION`), which consensus-enforces:
  - governed collection NAV read evidence;
  - exact smart-deed `property_id_canon` / `collection_id_canon` /
    `share_ppm` deposit evidence;
  - reserve-token seller payment before fresh minting;
  - optional pool CAT mint authorization only for reserve shortfall;
  - a fixed seller-payment assertion plus bounded helper fanout, keeping
    faucet/payment code from becoming an unbounded spend surface;
  - V2 action announcement field order matching
    `build_reserve_acquisition_spec`;
  - next pool `total_nav_locked` / `deed_count` /
    `total_pool_token_supply` / `treasury_reserve_tokens` recreation in
    curried state;
- V1 compatibility deposit/redeem state recreation now also updates/preserves
  the curried V2 supply/reserve fields;
- portal `PoolEconomicsV2Service`;
- portal Pool V2 singleton spend and bounded unsigned bundle builders;
- portal Pool Economic V2 quote console that separates “Swap for deed,”
  “Redeem and burn,” and reserve-first acquisition outcomes;
- API/portal draft schema fields for `collection_id` and `share_ppm`;
- cross-repo schema-drift checks for the V2 mint draft shape.

Still required before final alpha redemption:

- regenerate protocol manifests, portal puzzle hex, and mint fixtures;
- add live pool/deed/NAV witness discovery for the portal quote console;
- wire signed submission only after the live witnesses are discovered and
  replay-checked client-side.
