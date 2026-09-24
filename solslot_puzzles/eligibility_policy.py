"""Exact policy selected by a fresh signed genesis, never by a browser flag."""
from collections.abc import Mapping
import json

ELIGIBILITY_POLICY = {
    "schema": "solslot.identity-policy.v1",
    "adapter": "SolslotZkPassportEligibilityVerifierV1",
    "domain": "solslot.com",
    "devMode": False,
    "minimumAge": 18,
    "sanctions": {"countries": "all", "lists": "all", "strict": False},
}


def validate_identity_policy(value, *, evm_chain_id=11155111, enrollment_activation=None):
    if value is None:
        return None
    # Canonical JSON equality also rejects boolean/integer substitutions and
    # extra disclosures. This first policy uses the existing Sepolia emitter.
    if (not isinstance(value, Mapping) or type(evm_chain_id) is not int
            or evm_chain_id != 11155111 or enrollment_activation is not None
            or json.dumps(value, sort_keys=True) != json.dumps(ELIGIBILITY_POLICY, sort_keys=True)):
        raise ValueError("identity policy must be the reviewed age-plus-sanctions policy on Sepolia")
    return json.loads(json.dumps(value))


def identity_policy_from_artifact(artifact):
    plan = artifact.get("genesisPlan", {})
    if not isinstance(plan, Mapping):
        raise ValueError("identity policy has no signed genesis plan")
    if ("identityPolicy" in artifact) != ("identityPolicy" in plan):
        raise ValueError("identity policy differs from the signed plan")
    if "identityPolicy" not in plan:
        return None
    if artifact["identityPolicy"] is None or artifact["identityPolicy"] != plan["identityPolicy"]:
        raise ValueError("identity policy differs from the signed plan")
    return validate_identity_policy(artifact["identityPolicy"], evm_chain_id=artifact.get("evmChainId"),
                                    enrollment_activation=artifact.get("enrollmentActivation"))


def require_eligibility_inputs(inputs: bytes):
    """Admission/privacy check only; the adapter verifies the proof and root."""
    if not isinstance(inputs, bytes) or len(inputs) != 41:
        raise ValueError("identity proof requires age and sanctions without disclosures")
    offset = 0
    seen = set()
    while offset < len(inputs):
        if len(inputs) - offset < 3:
            raise ValueError("identity proof query is malformed")
        kind = inputs[offset]
        length = int.from_bytes(inputs[offset+1:offset+3], 'big')
        offset += 3
        body = inputs[offset:offset+length]
        if len(body) != length or kind in seen:
            raise ValueError("identity proof query is malformed")
        if kind == 1 and body == bytes([18, 0]):
            pass
        elif kind == 9 and length == 33 and body[-1] == 0:
            pass
        else:
            raise ValueError("identity proof query differs from age-plus-sanctions policy")
        seen.add(kind)
        offset += length
    if seen != {1, 9}:
        raise ValueError("identity proof requires age and sanctions")
