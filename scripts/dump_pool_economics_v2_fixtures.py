"""Generate portal fixtures for Pool Economic V2 action specs.

The portal mirrors :mod:`solslot_puzzles.pool_economics_v2` for quote display
and pre-bundle action messages.  This fixture pins the Python source of truth
so the TypeScript service can prove byte-equivalence before spend builders and
UI controls consume the values.

Usage::

    cd populis_protocol
    .venv/bin/python scripts/dump_pool_economics_v2_fixtures.py
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.collection_nav_registry_driver import (
    NAV_EVIDENCE_TAG,
    collection_nav_registry_inner_mod_hash,
    make_inner_puzzle_hash,
)
from solslot_puzzles.pool_economics_v2 import (
    DEED_SPEND_POOL_DEPOSIT,
    DEED_SPEND_POOL_REDEEM,
    DEFAULT_GOVERNANCE_FEE_BPS,
    DEFAULT_PROTOCOL_FEE_BPS,
    DEFAULT_SWAP_FEE_BPS,
    FEE_BPS_DENOMINATOR,
    MAX_POOL_V2_TOKEN_OUTPUTS,
    POOL_V2_RESERVE_ACQUISITION_TAG,
    POOL_V2_SPECIFIC_DEED_SWAP_TAG,
    POOL_V2_TRUE_REDEMPTION_TAG,
    PROTOCOL_PREFIX,
    SHARE_PPM_DENOMINATOR,
    TOKEN_MELT,
    TOKEN_MINT,
    CollectionNavEvidence,
    PoolEconomicState,
    PoolV2ActionSpec,
    TokenOutput,
    build_reserve_acquisition_spec,
    build_specific_deed_swap_spec,
    build_true_redemption_spec,
    token_settlement_payment_message,
)
from solslot_puzzles.protocol_deployment import singleton_full_puzzle_hash
from solslot_puzzles.vault_driver import puzzle_for_p2_vault


def b32(byte: int) -> bytes32:
    return bytes32(bytes([byte]) * 32)


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


STATE = PoolEconomicState(
    total_nav_locked_mojos=1_000_000_000,
    deed_count=10,
    total_pool_token_supply=800_000_000,
    treasury_reserve_tokens=200_000_000,
)

POOL_ACTIVE = 1
FP_SCALE = 1000
POOL_SPEND_V2_SPECIFIC_DEED_SWAP = 6
POOL_SPEND_V2_TRUE_REDEMPTION = 7
POOL_SPEND_V2_RESERVE_ACQUISITION = 8

COLLECTION_ID = b32(0xA1)
PROPERTY_ID = b32(0xA2)
DEED_ID = b32(0xD1)
TOKEN_COIN_ID = b32(0xE1)
POOL_LAUNCHER_ID = b32(0x13)
POOL_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
PROTOCOL_DID_PUZHASH = b32(0x14)
POOL_PARENT_COIN_ID = b32(0x15)
POOL_LINEAGE_PARENT_PARENT_COIN_ID = b32(0x16)
POOL_LINEAGE_PARENT_INNER_PUZZLE_HASH = b32(0x17)
POOL_AMOUNT = uint64(1)
BUYER_VAULT_LAUNCHER_ID = b32(0xD3)
P2_VAULT = bytes32(puzzle_for_p2_vault(BUYER_VAULT_LAUNCHER_ID).get_tree_hash())
TREASURY_RESERVE = b32(0xF1)
PROTOCOL_TREASURY = b32(0xF2)
GOVERNANCE_REWARDS = b32(0xF3)
GOVERNANCE_REWARDS_ROOT = b32(0xF4)
SELLER = b32(0xB1)
NAV_REGISTRY_MOD_HASH = collection_nav_registry_inner_mod_hash()
NAV_REGISTRY_GOV_PUBKEY = b"\xc8" * 48
NAV_REGISTRY_LAUNCHER_ID = b32(0xC9)
MIN_NAV_REGISTRY_VERSION = 7


def nav_registry_puzzle_hash(nav_root: bytes32, registry_version: int) -> bytes32:
    inner_hash = make_inner_puzzle_hash(
        gov_pubkey=NAV_REGISTRY_GOV_PUBKEY,
        registry_version=registry_version,
        nav_root=nav_root,
    )
    return singleton_full_puzzle_hash(NAV_REGISTRY_LAUNCHER_ID, inner_hash)


def _pool_token_tail_hash() -> bytes32:
    mod = load_clvm(
        "pool_token_tail.clsp",
        package_or_requirement="solslot_puzzles",
        recompile=True,
    )
    return bytes32(
        mod.curry(
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            SINGLETON_LAUNCHER_HASH,
        ).get_tree_hash()
    )


def _p2_vault_mod_hash() -> bytes32:
    mod = load_clvm(
        "p2_vault.clsp",
        package_or_requirement="solslot_puzzles",
        recompile=True,
    )
    return bytes32(mod.get_tree_hash())


def _pool_inner_mod() -> Program:
    return load_clvm(
        "pool_singleton_inner.clsp",
        package_or_requirement="solslot_puzzles",
        recompile=True,
    )


POOL_TOKEN_TAIL_HASH = _pool_token_tail_hash()
P2_VAULT_MOD_HASH = _p2_vault_mod_hash()
POOL_INNER_MOD = _pool_inner_mod()
POOL_INNER_MOD_HASH = bytes32(POOL_INNER_MOD.get_tree_hash())
POOL_INNER = POOL_INNER_MOD.curry(
    POOL_INNER_MOD_HASH,
    POOL_SINGLETON_STRUCT,
    PROTOCOL_DID_PUZHASH,
    POOL_TOKEN_TAIL_HASH,
    CAT_MOD_HASH,
    OFFER_MOD_HASH,
    P2_VAULT_MOD_HASH,
    NAV_REGISTRY_MOD_HASH,
    NAV_REGISTRY_GOV_PUBKEY,
    NAV_REGISTRY_LAUNCHER_ID,
    MIN_NAV_REGISTRY_VERSION,
    TREASURY_RESERVE,
    PROTOCOL_TREASURY,
    GOVERNANCE_REWARDS,
    GOVERNANCE_REWARDS_ROOT,
    FP_SCALE,
    POOL_ACTIVE,
    STATE.total_nav_locked_mojos,
    STATE.deed_count,
    STATE.total_pool_token_supply,
    STATE.treasury_reserve_tokens,
)
POOL_INNER_PUZZLE_HASH = bytes32(POOL_INNER.get_tree_hash())
POOL_FULL_PUZZLE = SINGLETON_MOD.curry(POOL_SINGLETON_STRUCT, POOL_INNER)
POOL_FULL_PUZZLE_HASH = bytes32(POOL_FULL_PUZZLE.get_tree_hash())
POOL_COIN = Coin(POOL_PARENT_COIN_ID, POOL_FULL_PUZZLE_HASH, POOL_AMOUNT)
POOL_COIN_ID = bytes32(POOL_COIN.name())
POOL_LINEAGE_PROOF = [
    POOL_LINEAGE_PARENT_PARENT_COIN_ID,
    POOL_LINEAGE_PARENT_INNER_PUZZLE_HASH,
    POOL_AMOUNT,
]

NAV_EVIDENCE = CollectionNavEvidence(
    registry_coin_id=b32(0xC1),
    registry_puzzle_hash=nav_registry_puzzle_hash(b32(0xC3), 7),
    collection_id_canon=COLLECTION_ID,
    nav_value_mojos=1_000_000_000,
    collection_nav_root=b32(0xC3),
    registry_version=7,
)

ACQUISITION_NAV_EVIDENCE = CollectionNavEvidence(
    registry_coin_id=b32(0xC1),
    registry_puzzle_hash=nav_registry_puzzle_hash(b32(0xC3), 7),
    collection_id_canon=COLLECTION_ID,
    nav_value_mojos=400_000_000,
    collection_nav_root=b32(0xC3),
    registry_version=7,
)


def _state_dict(state: PoolEconomicState) -> dict[str, int]:
    return {
        "total_nav_locked_mojos": state.total_nav_locked_mojos,
        "deed_count": state.deed_count,
        "total_pool_token_supply": state.total_pool_token_supply,
        "treasury_reserve_tokens": state.treasury_reserve_tokens,
    }


def _nav_evidence_dict(evidence: CollectionNavEvidence) -> dict[str, Any]:
    return {
        "registry_coin_id": _hex(evidence.registry_coin_id),
        "registry_puzzle_hash": _hex(evidence.registry_puzzle_hash),
        "collection_id_canon": _hex(evidence.collection_id_canon),
        "nav_value_mojos": evidence.nav_value_mojos,
        "collection_nav_root": _hex(evidence.collection_nav_root),
        "registry_version": evidence.registry_version,
    }


def _token_output_dict(output: TokenOutput) -> dict[str, Any]:
    return {
        "puzzle_hash": _hex(output.puzzle_hash),
        "amount": output.amount,
        "role": output.role,
        "memos": [_hex(memo) for memo in output.memos],
    }


def _quote_dict(spec: PoolV2ActionSpec) -> dict[str, Any]:
    quote = spec.quote
    out: dict[str, Any] = {
        "deed_nav_mojos": quote.deed_nav_mojos,
        "principal_tokens": getattr(quote, "principal_tokens", None),
        "next_total_nav_locked_mojos": quote.next_total_nav_locked_mojos,
        "next_deed_count": quote.next_deed_count,
        "next_total_pool_token_supply": quote.next_total_pool_token_supply,
        "next_treasury_reserve_tokens": quote.next_treasury_reserve_tokens,
        "next_circulating_supply": quote.next_circulating_supply,
    }
    if hasattr(quote, "fee_split"):
        out["fee_split"] = {
            "protocol_fee_tokens": quote.fee_split.protocol_fee_tokens,
            "governance_fee_tokens": quote.fee_split.governance_fee_tokens,
            "total_fee_tokens": quote.fee_split.total_fee_tokens,
        }
        out["buyer_total_tokens"] = quote.buyer_total_tokens
    if hasattr(quote, "reserve_tokens_paid"):
        out["reserve_tokens_paid"] = quote.reserve_tokens_paid
        out["fresh_tokens_to_mint"] = quote.fresh_tokens_to_mint
    return {k: v for k, v in out.items() if v is not None}


def _spec_expected_dict(spec: PoolV2ActionSpec) -> dict[str, Any]:
    return {
        "action_tag": spec.action_tag,
        "quote": _quote_dict(spec),
        "next_state": _state_dict(spec.next_state),
        "nav_evidence_message": _hex(spec.nav_evidence.evidence_message),
        "required_nav_evidence_message": _hex(spec.required_nav_evidence_message),
        "pool_action_message": _hex(spec.pool_action_message),
        "deed_message": _hex(spec.deed_message),
        "token_outputs": [_token_output_dict(output) for output in spec.token_outputs],
        "token_authorizations": [
            {
                "mint_or_melt": auth.mint_or_melt,
                "token_coin_id": _hex(auth.token_coin_id),
                "amount": auth.amount,
                "announcement_message": _hex(auth.announcement_message),
            }
            for auth in spec.token_authorizations
        ],
    }


def _coin_dict(coin: Coin) -> dict[str, Any]:
    return {
        "parent_coin_info": _hex(coin.parent_coin_info),
        "puzzle_hash": _hex(coin.puzzle_hash),
        "amount": int(coin.amount),
        "coin_id": _hex(coin.name()),
    }


def _lineage_proof_dict() -> dict[str, Any]:
    return {
        "parent_name": _hex(POOL_LINEAGE_PARENT_PARENT_COIN_ID),
        "inner_puzzle_hash": _hex(POOL_LINEAGE_PARENT_INNER_PUZZLE_HASH),
        "amount": int(POOL_AMOUNT),
    }


def _inner_solution_program(spend_case: int, params: list[Any]) -> Program:
    return Program.to(
        [
            POOL_COIN_ID,
            POOL_INNER_PUZZLE_HASH,
            POOL_AMOUNT,
            spend_case,
            params,
        ]
    )


def _inner_solution_hex(spend_case: int, params: list[Any]) -> str:
    return _hex(bytes(_inner_solution_program(spend_case, params)))


def _pool_full_solution_hex(spend_case: int, params: list[Any]) -> str:
    return _hex(
        bytes(
            Program.to(
                [
                    POOL_LINEAGE_PROOF,
                    POOL_AMOUNT,
                    _inner_solution_program(spend_case, params),
                ]
            )
        )
    )


def _pool_coin_spend_dict(spend_case: int, params: list[Any]) -> dict[str, Any]:
    return {
        "coin": _coin_dict(POOL_COIN),
        "puzzle_reveal": _hex(bytes(POOL_FULL_PUZZLE)),
        "solution": _pool_full_solution_hex(spend_case, params),
    }


def build_fixture() -> dict[str, Any]:
    swap = build_specific_deed_swap_spec(
        STATE,
        deed_id=DEED_ID,
        p2_vault_puzzle_hash=P2_VAULT,
        collection_id_canon=COLLECTION_ID,
        share_ppm=250_000,
        nav_evidence=NAV_EVIDENCE,
        treasury_reserve_puzhash=TREASURY_RESERVE,
        protocol_treasury_puzhash=PROTOCOL_TREASURY,
        governance_rewards_puzhash=GOVERNANCE_REWARDS,
        governance_rewards_root=GOVERNANCE_REWARDS_ROOT,
    )
    redemption = build_true_redemption_spec(
        STATE,
        deed_id=DEED_ID,
        p2_vault_puzzle_hash=P2_VAULT,
        collection_id_canon=COLLECTION_ID,
        share_ppm=250_000,
        nav_evidence=NAV_EVIDENCE,
        token_coin_id=TOKEN_COIN_ID,
    )
    acquisition = build_reserve_acquisition_spec(
        STATE,
        deed_id=DEED_ID,
        property_id_canon=PROPERTY_ID,
        par_value_mojos=123_000,
        asset_class=1,
        collection_id_canon=COLLECTION_ID,
        share_ppm=500_000,
        nav_evidence=ACQUISITION_NAV_EVIDENCE,
        seller_puzhash=SELLER,
        seller_token_price=200_000_000,
    )
    swap_params = [
        DEED_ID,
        COLLECTION_ID,
        250_000,
        NAV_EVIDENCE.nav_value_mojos,
        NAV_EVIDENCE.collection_nav_root,
        NAV_EVIDENCE.registry_version,
        NAV_EVIDENCE.registry_coin_id,
        NAV_EVIDENCE.registry_puzzle_hash,
        BUYER_VAULT_LAUNCHER_ID,
        SINGLETON_LAUNCHER_HASH,
        TREASURY_RESERVE,
        PROTOCOL_TREASURY,
        GOVERNANCE_REWARDS,
        GOVERNANCE_REWARDS_ROOT,
    ]
    redemption_params = [
        DEED_ID,
        COLLECTION_ID,
        250_000,
        NAV_EVIDENCE.nav_value_mojos,
        NAV_EVIDENCE.collection_nav_root,
        NAV_EVIDENCE.registry_version,
        NAV_EVIDENCE.registry_coin_id,
        NAV_EVIDENCE.registry_puzzle_hash,
        BUYER_VAULT_LAUNCHER_ID,
        SINGLETON_LAUNCHER_HASH,
        TOKEN_COIN_ID,
    ]
    acquisition_params = [
        DEED_ID,
        PROPERTY_ID,
        123_000,
        1,
        COLLECTION_ID,
        500_000,
        ACQUISITION_NAV_EVIDENCE.nav_value_mojos,
        ACQUISITION_NAV_EVIDENCE.collection_nav_root,
        ACQUISITION_NAV_EVIDENCE.registry_version,
        ACQUISITION_NAV_EVIDENCE.registry_coin_id,
        ACQUISITION_NAV_EVIDENCE.registry_puzzle_hash,
        SELLER,
        200_000_000,
        None,
    ]

    return {
        "constants": {
            "share_ppm_denominator": SHARE_PPM_DENOMINATOR,
            "fee_bps_denominator": FEE_BPS_DENOMINATOR,
            "default_swap_fee_bps": DEFAULT_SWAP_FEE_BPS,
            "default_protocol_fee_bps": DEFAULT_PROTOCOL_FEE_BPS,
            "default_governance_fee_bps": DEFAULT_GOVERNANCE_FEE_BPS,
            "max_pool_v2_token_outputs": MAX_POOL_V2_TOKEN_OUTPUTS,
            "protocol_prefix": _hex(PROTOCOL_PREFIX),
            "token_mint": TOKEN_MINT,
            "token_melt": TOKEN_MELT,
            "deed_spend_pool_deposit": DEED_SPEND_POOL_DEPOSIT,
            "deed_spend_pool_redeem": DEED_SPEND_POOL_REDEEM,
            "pool_spend_v2_specific_deed_swap": POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
            "pool_spend_v2_true_redemption": POOL_SPEND_V2_TRUE_REDEMPTION,
            "pool_spend_v2_reserve_acquisition": POOL_SPEND_V2_RESERVE_ACQUISITION,
            "nav_evidence_tag": NAV_EVIDENCE_TAG,
            "pool_v2_specific_deed_swap_tag": POOL_V2_SPECIFIC_DEED_SWAP_TAG,
            "pool_v2_true_redemption_tag": POOL_V2_TRUE_REDEMPTION_TAG,
            "pool_v2_reserve_acquisition_tag": POOL_V2_RESERVE_ACQUISITION_TAG,
        },
        "common": {
            "state": _state_dict(STATE),
            "pool_launcher_id": _hex(POOL_LAUNCHER_ID),
            "pool_coin_id": _hex(POOL_COIN_ID),
            "pool_coin": _coin_dict(POOL_COIN),
            "pool_lineage_proof": _lineage_proof_dict(),
            "pool_inner_puzzle_hex": _hex(bytes(POOL_INNER)),
            "pool_inner_puzzle_hash": _hex(POOL_INNER_PUZZLE_HASH),
            "pool_full_puzzle_hash": _hex(POOL_FULL_PUZZLE_HASH),
            "min_nav_registry_version": MIN_NAV_REGISTRY_VERSION,
            "pool_amount": int(POOL_AMOUNT),
            "deed_id": _hex(DEED_ID),
            "p2_vault_puzzle_hash": _hex(P2_VAULT),
            "buyer_vault_launcher_id": _hex(BUYER_VAULT_LAUNCHER_ID),
            "launcher_puzzle_hash": _hex(SINGLETON_LAUNCHER_HASH),
            "property_id_canon": _hex(PROPERTY_ID),
            "collection_id_canon": _hex(COLLECTION_ID),
            "token_coin_id": _hex(TOKEN_COIN_ID),
            "nav_evidence": _nav_evidence_dict(NAV_EVIDENCE),
            "acquisition_nav_evidence": _nav_evidence_dict(ACQUISITION_NAV_EVIDENCE),
        },
        "specific_deed_swap": {
            "inputs": {
                "share_ppm": 250_000,
                "treasury_reserve_puzhash": _hex(TREASURY_RESERVE),
                "protocol_treasury_puzhash": _hex(PROTOCOL_TREASURY),
                "governance_rewards_puzhash": _hex(GOVERNANCE_REWARDS),
                "governance_rewards_root": _hex(GOVERNANCE_REWARDS_ROOT),
            },
            "expected": {
                **_spec_expected_dict(swap),
                "token_settlement_payment_message": _hex(
                    token_settlement_payment_message(POOL_COIN_ID, swap.token_outputs)
                ),
                "inner_solution_hex": _inner_solution_hex(
                    POOL_SPEND_V2_SPECIFIC_DEED_SWAP, swap_params
                ),
                "pool_full_solution_hex": _pool_full_solution_hex(
                    POOL_SPEND_V2_SPECIFIC_DEED_SWAP, swap_params
                ),
                "pool_coin_spend": _pool_coin_spend_dict(
                    POOL_SPEND_V2_SPECIFIC_DEED_SWAP, swap_params
                ),
            },
        },
        "true_redemption": {
            "inputs": {"share_ppm": 250_000},
            "expected": {
                **_spec_expected_dict(redemption),
                "inner_solution_hex": _inner_solution_hex(
                    POOL_SPEND_V2_TRUE_REDEMPTION, redemption_params
                ),
                "pool_full_solution_hex": _pool_full_solution_hex(
                    POOL_SPEND_V2_TRUE_REDEMPTION, redemption_params
                ),
                "pool_coin_spend": _pool_coin_spend_dict(
                    POOL_SPEND_V2_TRUE_REDEMPTION, redemption_params
                ),
            },
        },
        "reserve_acquisition": {
            "inputs": {
                "share_ppm": 500_000,
                "par_value_mojos": 123_000,
                "asset_class": 1,
                "seller_puzhash": _hex(SELLER),
                "seller_token_price": 200_000_000,
            },
            "expected": {
                **_spec_expected_dict(acquisition),
                "inner_solution_hex": _inner_solution_hex(
                    POOL_SPEND_V2_RESERVE_ACQUISITION, acquisition_params
                ),
                "pool_full_solution_hex": _pool_full_solution_hex(
                    POOL_SPEND_V2_RESERVE_ACQUISITION, acquisition_params
                ),
                "pool_coin_spend": _pool_coin_spend_dict(
                    POOL_SPEND_V2_RESERVE_ACQUISITION, acquisition_params
                ),
            },
        },
    }


def _services_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "populis_portal" / "src" / "app" / "services"


def fixture_destination() -> Path:
    return _services_dir() / "pool-economics-v2.fixtures.json"


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    print(f"wrote fixture to {dest}")
    print(
        "  specific_deed_swap="
        f"{fixture['specific_deed_swap']['expected']['pool_action_message']}\n"
        "  true_redemption="
        f"{fixture['true_redemption']['expected']['pool_action_message']}\n"
        "  reserve_acquisition="
        f"{fixture['reserve_acquisition']['expected']['pool_action_message']}"
    )


if __name__ == "__main__":
    main()
