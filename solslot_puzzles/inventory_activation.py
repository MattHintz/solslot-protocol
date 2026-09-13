"""Optional signed activation extension; historical RC23 projections stay exact."""
from __future__ import annotations

from typing import Any, Mapping
import re
from . import load_puzzle


def validate_inventory_activation(artifact: Mapping[str, Any], *, required: bool = False,
                                  environment: str | None = None) -> Mapping[str, Any] | None:
    """Validate content only. Caller MUST first authenticate the complete artifact.

    The artifact's committee signatures cover this block, including the review
    evidence digest. This function neither performs nor attests an independent
    review. No existing signed artifact is implicitly upgraded.
    """
    value = artifact.get("inventoryActivation")
    if value is None and not required:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("signed inventory V2 activation evidence is required")
    expected = {
        "schema": "solslot.inventory-activation.v1", "network": "testnet11",
        "deploymentId": artifact.get("ceremony", {}).get("ceremonyId"),
        "inventoryVersion": 2, "adapterVersion": 1,
        "availableModuleHash": "0x" + load_puzzle("mint_offer_inventory_available_v2.clsp").get_tree_hash().hex(),
        "reservedModuleHash": "0x" + load_puzzle("mint_offer_delegate_v5.clsp").get_tree_hash().hex(),
        "sourceShas": artifact.get("sourceShas"),
    }
    if (set(value) != set(expected) | {"environment", "reviewEvidenceSha256"}
            or any(value.get(k) != v for k, v in expected.items())
            or type(value.get("inventoryVersion")) is not int or type(value.get("adapterVersion")) is not int
            or artifact.get("network") != "testnet11"
            or value.get("environment") not in ("staging-alpha", "production-alpha")
            or (environment is not None and value["environment"] != environment)
            or not isinstance(value.get("reviewEvidenceSha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["reviewEvidenceSha256"])
            or value["reviewEvidenceSha256"] == "0" * 64):
        raise ValueError("signed inventory activation does not match this environment, deployment or release")
    return value


def validate_inventory_recovery(artifact: Mapping[str, Any], *, required: bool = False,
                                environment: str | None = None) -> Mapping[str, Any] | None:
    """Authenticate the full artifact before using this separate recovery gate."""
    value = artifact.get('inventoryRecovery')
    if value is None and not required:
        return None
    activation = validate_inventory_activation(artifact, required=True, environment=environment)
    expected = dict(schema='solslot.inventory-recovery.v1', network='testnet11',
        environment=activation['environment'], deploymentId=activation['deploymentId'],
        inventoryVersion=2, adapterVersion=1, validatorLedgerVersion=10, minConfirmations=3,
        availableModuleHash=activation['availableModuleHash'], sourceShas=artifact.get('sourceShas'))
    if (not isinstance(value, Mapping) or set(value) != set(expected) | {'reviewEvidenceSha256', 'historicalArtifactHashes'}
            or any(value.get(k) != v for k, v in expected.items())
            or any(type(value.get(k)) is not int for k in ('inventoryVersion', 'adapterVersion', 'validatorLedgerVersion', 'minConfirmations'))
            or not isinstance(value.get('reviewEvidenceSha256'), str)
            or re.fullmatch(r'[0-9a-f]{64}', value['reviewEvidenceSha256']) is None
            or value['reviewEvidenceSha256'] == '0' * 64):
        raise ValueError('signed inventory recovery does not match this environment, deployment or release')
    history = value['historicalArtifactHashes']
    if (not isinstance(history, list) or len(history) > 32
            or any(not isinstance(h, str) or re.fullmatch(r'0x[0-9a-f]{64}', h) is None or h == '0x'+'0'*64 for h in history)
            or len(history) != len(set(history))):
        raise ValueError('signed inventory recovery historical artifact hashes are invalid')
    return value
