"""Deterministic synthetic records; no live release files or signing authority."""
import hashlib
import json


SYNTHETIC_PLAN_HASH = "0x" + "d1" * 32


def _seal(record):
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return {**record, "artifactHash": "0x" + hashlib.sha256(encoded).hexdigest()}


def synthetic_identity_records():
    """Return fresh records for real amendment validation, never live activation."""
    names = ("forwarder", "verifierAdapter", "attestationEmitter")
    base = {
        "schema": "solslot.synthetic-genesis-fixture.v1",
        "testOnly": True,
        "ceremony": {"ceremonyId": "0x" + "b1" * 32},
        "network": "testnet11",
        "evmChainId": 11155111,
        "evmAddresses": {name: "0x" + f"{i:02x}" * 20
                         for i, name in enumerate(names, start=1)},
        "launcherIds": {"adminAuthority": "0x" + "b2" * 32},
        "permanentRules": {"zkPassportPolicyHash": "0x" + "b3" * 32},
    }
    deployment = {
        "schema": "solslot.synthetic-deployment-fixture.v1",
        "testOnly": True,
        "chainId": 11155111,
        "network": "sepolia",
        **{name + "Address": "0x" + f"{i:02x}" * 20
           for i, name in enumerate(names, start=7)},
        "deploymentTransactions": {
            name: {"hash": "0x" + f"{i:02x}" * 32, "blockNumber": 100 + i,
                   "blockHash": "0x" + f"{i + 10:02x}" * 32, "nonce": i - 1,
                   "initCodeHash": "0x" + f"{i + 20:02x}" * 32}
            for i, name in enumerate(names, start=1)
        },
        "runtimeCodeHashes": {
            **{name: "0x" + f"{i + 30:02x}" * 32
               for i, name in enumerate(names, start=1)},
            "zkPassportRootVerifier": "0xd03ae3bc396b99a680f6af1d6b3a957f0f932f3763c20e311df5f676c0bfee5b",
        },
        "zkPassportRootVerifierAddress": "0x1d000001000efd9a6371f4d90bb8920d5431c0d8",
        "trustedDirectRelayerAddress": "0x" + "aa" * 20,
        "credentialPolicyVersion": 2,
        "identityPolicy": {
            "schema": "solslot.identity-policy.v1",
            "adapter": "SolslotZkPassportEligibilityVerifierV2",
            "domain": "solslot.com", "devMode": False, "minimumAge": 18,
            "sanctions": {"countries": "all", "lists": "all", "strict": False},
        },
        "sourceShas": {"evm": "6" * 40, "api": "7" * 40, "protocol": "8" * 40},
    }
    return _seal(base), _seal(deployment)
