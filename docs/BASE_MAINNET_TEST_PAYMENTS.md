# Base mainnet test-payment preparation

The selected alpha payment token is `TEST-SOLS` (`Solslot Alpha Test Token`),
with six decimals and no monetary value. It is separate from SGT and from
USDC. EVM execution is on Base mainnet, chain 8453; the asset network remains
Chia Testnet11. This source preparation does not enable live purchases.

The exact deployment plan predicts token address
`0xd48548a2dccb9b05f31a3f342f7bfd14b72c29c3` from operator
`0x4035edd8499ebdd6da3d4f825a7e96e4730993bb` at nonce zero. The token runtime
hash and metadata are pinned in `alpha_payment_profile.py`. Those constants
are **not a deployment receipt**. A release must verify the confirmed CREATE
transaction and runtime before activating this profile. Nonce drift requires
replanning; it cannot be repaired by silently substituting a token address.

New inventory version 3 uses additive `mint_offer_inventory_available_v3`
and `mint_offer_delegate_v6` modules. They retain the prior layouts, prices,
fee calculation, reserve/extend/release mechanics and two-of-three validator
requirements, while pinning the Base-mainnet test token and Chia Testnet11.
Historical modules, including inventory V1/V2 and reserved V5, keep their
exact source bytes and hashes. The new manifest records every preserved file.
Existing purchase-artifact V3 encoding already commits to the EVM chain and
asset, so its encoding and purchase ID definition remain unchanged.

Selecting these modules requires a separately authenticated
`solslot.inventory-activation.v2` extension, inventoryVersion 3,
adapterVersion 2, the exact alpha payment profile, and explicit mainnet
enrollment activation V2. Historical inventory activation V1 still selects
inventory V2; it cannot be relabeled by changing runtime configuration.
Inventory recovery V2 similarly selects the new version explicitly. A
content validator is not an authenticator or evidence of human review.

Local tests execute CLVM reservation, extension, timeout/failure release and
negative network/token/amount/quorum cases. They also retain the historical
voucher and mint regressions. They use synthetic keys, not live validators.

The candidate remains non-deployable until API and signing-client adapters,
voucher settlement, escrow/ownership evidence, and the dedicated Samuel
Base-mainnet/Testnet11 route support this profile together. The existing Base
checkout deliberately refuses payment; do not remove that guard solely because
the test token has been deployed. UI amounts must identify test tokens and
simulated prices. Real Base ETH is required for network fees.
