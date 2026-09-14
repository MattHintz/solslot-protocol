# Draft40: current Base voucher delivery

Scope: Base Sepolia USDC voucher purchase parsing and reserved SmartDeed delivery.
Parent protocol fd3908f22c8a179a00438e7073c79739f8746858; coordinated API change required.
New Base presales use PurchaseArtifactV3 with VoucherCommitmentV2. The independent
schema versions retain the exact paid artifact hash. No historical V2 artifact
is converted. Official Testnet11/Base Sepolia USDC, presale kind, fees, treasury,
series, sale window, metadata, vault and payment bindings are enforced. The
existing V5 voucher branch delivers the reserved DID-bound SmartDeed. No CLSP,
compiled puzzle, dependency, deployment or network configuration changed.

Validation: hash-locked Python 3.12 environment; protocol suite 1371 passed,
6 sibling-path skips. All six skipped schema checks were separately executed
against the nine candidate sources using local sibling aliases and passed.
Thirteen added tests cover both inventory versions, exact outputs, canonical
V3 parsing, wrong deployment/direct purchase, rebound economics and historical
V2 preservation. Namespace, compiled-puzzle drift, runtime and build dependency
audits passed. This is local CLVM/source evidence, not a public-chain outcome.

Fresh investigator/reviewer agents were unavailable at the session limit;
separate parent review passes do not constitute independent launch approval.
Original46 remains 18 fixed_at_source / 26 still_vulnerable / 2 inconclusive.
Launch remains NO-GO. Long presale reservation creation/extension, signed live
transaction outcomes, provider evidence, emulator journeys and the broader audit
still need their own evidence. XCH vouchers remain unavailable in this release.
