# Sols Economics V3

## Purpose

Sols is the freely transferable pool-share CAT. It is not SGT and it is not a
primary SmartDeed payment rail. Sols enters or leaves circulation only through
the protocol's binary secondary SmartDeed market.

This document freezes the agreed economic behavior before matching CLVM and
release hashes are created.

## Units

- Sols has three decimal places: `1 Sols = 1,000 Sols mojos`.
- Governed value uses six-decimal micro-USD integers.
- The first confirmed eligible SmartDeed deposit uses
  `1 Sols = $3.33` of governed SmartDeed value.
- Seller payouts round down. Buyer principal and buyer fees round up.
- No floating-point value participates in a quote or state transition.

## Backing And Supply

`backing = pool-held SmartDeed NAV + valued treasury assets - proven liabilities`

`circulating Sols = total minted Sols - canonical pool reserve Sols`

Only reserve Sols are excluded from circulation. Sols held by users, Warp,
protocol fee custody, and SGT reward escrows remain circulating. Reserve Sols
are never melted in alpha.

Direct XCH or approved-stablecoin contributions increase backing without
minting Sols or creating repayment rights. Only on-chain-provable obligations
may be subtracted as liabilities.

## Automatic Binary Swaps

An SGT-approved collection commits each eligible deed identity, allocation,
and aggregate value. Individual swaps do not require administrator or SGT
approval.

### SmartDeed To Sols

1. The verified holder authorizes the exact deed deposit.
2. The protocol validates collection membership, current NAV, identity,
   inventory uniqueness, pause state, and exact state commitments.
3. The first deposit uses the fixed $3.33 bootstrap rate.
4. Later deposits use pre-transaction dynamic NAV and round seller Sols down.
5. Reserve Sols pay first; only the exact shortfall is minted.

### Sols To SmartDeed

1. A verified Sols holder selects an exact pool-held SmartDeed.
2. Buyer principal uses pre-transaction dynamic NAV and rounds up.
3. Principal returns to reserve and is excluded from circulation.
4. Supply is unchanged and no Sols are melted.
5. The buyer pays a governed exchange fee capped permanently at 1%.

The alpha fee starts at 1% of principal: 0.3% to protocol fee custody and 0.7%
to non-expiring SGT reward epochs. Both portions remain circulating Sols and
are not backing.

## NAV And Safety

Collection NAV updates are administrator-drafted, owner-plus-one published,
SGT-supported, and applied atomically to every affected pool-held deed. A
published NAV or settlement proposal pauses only affected deeds until it
resolves. Prepared swaps bind the exact pool coin, inventory root, NAV version,
and settlement state.

New NAV-priced operations pause automatically when backing is zero or negative,
NAV is stale, fewer than two approved oracle observations remain, or a healthy
stablecoin leaves its governed range. Transfers, funded settlement claims, SGT
voting, and earned reward claims remain available.

## Settlement

Property sale or refinance settlement is one typed collection proposal. Before
voting, the issuer funds a proposal-bound wUSDC.b deposit committed to the
collection, proposal, payout root, and refund puzzle. Execution atomically
creates one exact escrow per deed.

Allocation follows the approved legal waterfall and `share_ppm`. Integer dust
uses largest-remainder allocation with deed ID as the deterministic tie-breaker.
The protocol publishes a permanent funded maker offer per deed. The current
verified holder creates only the acceptance half, and the SmartDeed enforces
payment to that same canonical vault. Acceptance burns the deed permanently.

Settlement escrows are liabilities, never Sols backing. Pool-held settled deeds
remain secondary inventory at their exact funded value; the pool itself cannot
redeem them.

## Governance Boundary

SGT holders may request and discuss proposals. Only owner-plus-one
administrators may publish a typed executable bill, and an SGT sponsor must
lock the governed minimum stake. Support uses the existing 50% fixed-supply
threshold and five-minute Testnet11 window. Stakes unlock without slashing.

Adjustable statutes include voting parameters, NAV validity, oracle rules,
asset haircuts, collection allocation ceilings, fees within the hard cap,
reward epochs, bridge routes, and scoped pauses.

Permanent commitments include SGT identity and supply, Sols identity,
zkPassport SmartDeed gates, treasury non-withdrawal, vote conservation, replay
protection, and the 1% maximum fee. Code upgrades must preserve those
commitments, include source hashes, receive SGT ratification, and wait 24 hours.

## Explicitly Removed

- Sols cannot purchase primary SmartDeeds.
- No peer-to-peer SmartDeed/Sols swap is valid.
- No per-swap governance proposal exists.
- No "true redemption" melts Sols to release a deed.
- No arbitrary administrator liability or treasury withdrawal exists.
- No raw API or UI value can override chain-derived state.
