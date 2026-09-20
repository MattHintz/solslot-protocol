"""Explicit alpha payment coordinates; never inferred from the Chia network.

The address is pinned by the exact nonce-zero Base deployment plan. Constants
are not evidence of deployment or authority to enable payments. A release must
also authenticate deployment, validator route and the complete signed artifact.
"""
from chia_rs.sized_bytes import bytes32

BASE_MAINNET_CHAIN_ID = 8453
BASE_MAINNET_ALPHA_TEST_ADDRESS = "0xd48548a2dccb9b05f31a3f342f7bfd14b72c29c3"
BASE_MAINNET_ALPHA_TEST_ASSET_ID = bytes32(bytes(12) + bytes.fromhex(BASE_MAINNET_ALPHA_TEST_ADDRESS[2:]))
BASE_MAINNET_ALPHA_TEST_RUNTIME_HASH = "0xd9b0429c4c62d4e8f698a683d13ed521acd286fc9b94de1ea15d1017a5764869"


def alpha_payment_profile() -> dict:
    """A fresh value for inclusion in an authenticated release extension."""
    return dict(schema="solslot.alpha-payment-profile.v1", assetNetwork="testnet11",
        evmNetwork="baseMainnet", chainId=BASE_MAINNET_CHAIN_ID,
        tokenAddress=BASE_MAINNET_ALPHA_TEST_ADDRESS, tokenDecimals=6,
        tokenSymbol="TEST-SOLS", tokenName="Solslot Alpha Test Token",
        tokenRuntimeCodeHash=BASE_MAINNET_ALPHA_TEST_RUNTIME_HASH,
        assetKind="valueless-test-token", hasMonetaryValue=False)


def is_alpha_payment_tuple(network, chain_id, asset_id, decimals) -> bool:
    return (network == "testnet11" and type(chain_id) is int and chain_id == BASE_MAINNET_CHAIN_ID
            and bytes(asset_id) == bytes(BASE_MAINNET_ALPHA_TEST_ASSET_ID)
            and type(decimals) is int and decimals == 6)
