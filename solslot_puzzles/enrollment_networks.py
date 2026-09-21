"""Versioned EVM selection, independent of the Chia asset network.

Pure metadata validation: no CLVM imports or signature authority. Callers must
authenticate the enclosing ceremony/artifact before applying this selection.
"""
from __future__ import annotations

from typing import Any, Mapping

from .genesis_constants import GENESIS_EVM_CHAIN_ID

LEGACY_ENROLLMENT_SCHEMA = "solslot.enrollment-activation.v1"
BASE_MAINNET_ENROLLMENT_SCHEMA = "solslot.enrollment-activation.v2"


def enrollment_operational_chain_id(activation: Mapping[str, Any] | None) -> int:
    if activation is None:
        return GENESIS_EVM_CHAIN_ID
    if not isinstance(activation, Mapping):
        raise ValueError("enrollment activation network selection must be an object")
    schema = activation.get("schema")
    identity_chain = activation.get("evmChainId")
    if type(identity_chain) is not int:
        raise ValueError("enrollment activation identity chain must be an integer")
    if schema == LEGACY_ENROLLMENT_SCHEMA and identity_chain in (8453, 84532):
        return 84532
    if schema == BASE_MAINNET_ENROLLMENT_SCHEMA and identity_chain == 8453:
        return 8453
    raise ValueError("enrollment activation network selection is unsupported")
