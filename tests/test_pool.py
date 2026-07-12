"""Unit tests for pool_singleton_inner_v3.clsp — the pool state machine.

Tests run curried puzzles via Program.run() to verify:
  1. Deposit case produces correct conditions when ACTIVE (with state recreation)
  2. Deposit case fails when FROZEN
  3. Redeem case produces correct conditions when ACTIVE (with state recreation)
  4. Generate-offer case produces correct conditions
  5. Governance case produces conditions (freeze/unfreeze)
  6. Invalid spend case fails
  7. Protocol prefix on announcements
  8. REMARK driver hints present
  9. State recreation via curry_hashes (CREATE_COIN with new inner puzzle hash)
"""
import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.util.curry_and_treehash import (
    calculate_hash_of_quoted_mod_hash,
    curry_and_treehash,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.pgt_driver import deed_releases_hash
from solslot_puzzles.collection_nav_registry_driver import (
    collection_nav_registry_inner_mod_hash,
    make_inner_puzzle_hash,
)
from solslot_puzzles.protocol_deployment import singleton_full_puzzle_hash
from solslot_puzzles.pool_economics_v2 import (
    CollectionNavEvidence,
    PoolEconomicState,
    build_reserve_acquisition_spec,
    build_specific_deed_swap_spec,
    build_true_redemption_spec,
    token_settlement_payment_message,
)

POOL_INNER_MOD: Program = load_clvm(
    "pool_singleton_inner_v3.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

# Test constants
LAUNCHER_PUZZLE_HASH = SINGLETON_LAUNCHER_HASH
POOL_LAUNCHER_ID = bytes32(b"\xbb" * 32)
POOL_SINGLETON_STRUCT = Program.to((SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH)))
GOVERNANCE_LAUNCHER_ID = bytes32(b"\xbc" * 32)
GOVERNANCE_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (GOVERNANCE_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH))
)
PROTOCOL_DID_PUZHASH = bytes32(b"\x03" * 32)
TOKEN_TAIL_HASH = bytes32(b"\x04" * 32)
CAT_MOD_HASH = bytes32(b"\x05" * 32)
OFFER_MOD_HASH = bytes32(b"\x06" * 32)
P2_VAULT_MOD_HASH = bytes32(b"\x07" * 32)
NAV_REGISTRY_MOD_HASH = collection_nav_registry_inner_mod_hash()
NAV_REGISTRY_GOV_PUBKEY = b"\x08" * 48
NAV_REGISTRY_LAUNCHER_ID = bytes32(b"\xc9" * 32)
MIN_NAV_REGISTRY_VERSION = 7
TRUSTED_TREASURY_RESERVE_PUZHASH = bytes32(b"\xf1" * 32)
TRUSTED_PROTOCOL_TREASURY_PUZHASH = bytes32(b"\xf2" * 32)
TRUSTED_GOVERNANCE_REWARDS_PUZHASH = bytes32(b"\xf3" * 32)
TRUSTED_GOVERNANCE_REWARDS_ROOT = bytes32(b"\xf4" * 32)
DEED_LAUNCHER_ID = bytes32(b"\xd2" * 32)
DEED_PAR_VALUE = 123_000
DEED_ASSET_CLASS = 1
DEED_PROPERTY_ID = bytes32(b"\xa2" * 32)
FP_SCALE = 1000
MOD_HASH = POOL_INNER_MOD.get_tree_hash()

# Spend case constants
POOL_SPEND_DEPOSIT = 1
POOL_SPEND_REDEEM = 2
POOL_SPEND_SETTLEMENT = 3
POOL_SPEND_GOVERNANCE = 4
POOL_SPEND_GENERATE_OFFER = 5
POOL_SPEND_V2_SPECIFIC_DEED_SWAP = 6
POOL_SPEND_V2_TRUE_REDEMPTION = 7
POOL_SPEND_V2_RESERVE_ACQUISITION = 8
POOL_V2_SPECIFIC_DEED_SWAP_TAG = 0x53574150
POOL_V2_TRUE_REDEMPTION_TAG = 0x5244454D
POOL_V2_RESERVE_ACQUISITION_TAG = 0x41435152

POOL_ACTIVE = 1
POOL_FROZEN = 0

# Protocol prefix
PROTOCOL_PREFIX = b"\x50"

# Condition codes used in settlement assertions.
REMARK = 1
CREATE_COIN = 51
CREATE_COIN_ANNOUNCEMENT = 60
ASSERT_COIN_ANNOUNCEMENT = 61
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
SEND_MESSAGE = 66
RECEIVE_MESSAGE = 67


def curry_pool(
    pool_status=POOL_ACTIVE,
    tvl=0,
    deed_count=0,
    total_pool_token_supply=0,
    treasury_reserve_tokens=0,
) -> Program:
    """Curry pool with MOD_HASH, immutable params, and mutable state."""
    return POOL_INNER_MOD.curry(
        MOD_HASH,
        POOL_SINGLETON_STRUCT,
        GOVERNANCE_SINGLETON_STRUCT,
        PROTOCOL_DID_PUZHASH,
        TOKEN_TAIL_HASH,
        CAT_MOD_HASH,
        OFFER_MOD_HASH,
        P2_VAULT_MOD_HASH,
        NAV_REGISTRY_MOD_HASH,
        NAV_REGISTRY_GOV_PUBKEY,
        NAV_REGISTRY_LAUNCHER_ID,
        MIN_NAV_REGISTRY_VERSION,
        TRUSTED_TREASURY_RESERVE_PUZHASH,
        TRUSTED_PROTOCOL_TREASURY_PUZHASH,
        TRUSTED_GOVERNANCE_REWARDS_PUZHASH,
        TRUSTED_GOVERNANCE_REWARDS_ROOT,
        FP_SCALE,
        pool_status,
        tvl,
        deed_count,
        total_pool_token_supply,
        treasury_reserve_tokens,
    )


def make_pool_solution(my_id, my_inner_puzhash, my_amount,
                       spend_case, params_list):
    """Build solution — state is now curried, not in solution."""
    return Program.to([
        my_id, my_inner_puzhash, my_amount,
        spend_case, params_list,
    ])


def atom_int(value) -> int:
    return int.from_bytes(value, "big") if isinstance(value, bytes) else int(value)


def settlement_message(splitxch_root, total_amount, deed_count, releases) -> bytes:
    return PROTOCOL_PREFIX + Program.to([
        b"SETT",
        splitxch_root,
        total_amount,
        deed_count,
        deed_releases_hash(releases),
    ]).get_tree_hash()


def old_count_only_settlement_message(splitxch_root, total_amount, deed_count) -> bytes:
    return PROTOCOL_PREFIX + Program.to([
        b"SETT",
        splitxch_root,
        total_amount,
        deed_count,
    ]).get_tree_hash()


def computed_p2_vault_ph(vault_launcher_id: bytes32) -> bytes32:
    quoted_mod = calculate_hash_of_quoted_mod_hash(P2_VAULT_MOD_HASH)
    return bytes32(
        curry_and_treehash(
            quoted_mod,
            hashlib.sha256(b"\x01" + bytes(SINGLETON_MOD_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(vault_launcher_id)).digest(),
            hashlib.sha256(b"\x01" + bytes(LAUNCHER_PUZZLE_HASH)).digest(),
        )
    )


def computed_cat_offer_puzzle_hash() -> bytes32:
    quoted_mod = calculate_hash_of_quoted_mod_hash(CAT_MOD_HASH)
    return bytes32(
        curry_and_treehash(
            quoted_mod,
            hashlib.sha256(b"\x01" + bytes(CAT_MOD_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(TOKEN_TAIL_HASH)).digest(),
            OFFER_MOD_HASH,
        )
    )


def computed_nav_registry_puzzle_hash(nav_root: bytes32, registry_version: int) -> bytes32:
    inner_hash = make_inner_puzzle_hash(
        gov_pubkey=NAV_REGISTRY_GOV_PUBKEY,
        registry_version=registry_version,
        nav_root=nav_root,
    )
    return singleton_full_puzzle_hash(NAV_REGISTRY_LAUNCHER_ID, inner_hash)


class TestPoolDeposit:
    """Test SPEND CASE 1 — DEPOSIT."""

    def test_deposit_active_returns_conditions(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xdd" * 32)
        deed_par_value = 100000
        depositor_puzhash = bytes32(b"\xee" * 32)
        token_coin_id = bytes32(b"\xff" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_DEPOSIT,
            [
                deed_id,
                DEED_LAUNCHER_ID,
                deed_par_value,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                depositor_puzhash,
                token_coin_id,
            ],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 9 conditions: state, deed evidence, token authorization, deed ack,
        # remark, and the three singleton identity assertions.
        assert len(conditions) == 9
        # CREATE_COIN (recreate with updated state via curry_hashes)
        assert conditions[0][0] == bytes([51])
        assert conditions[1][0] == bytes([61])
        # CREATE_PUZZLE_ANNOUNCEMENT (token mint authorization)
        assert conditions[2][0] == bytes([62])
        assert conditions[2][1][:1] == PROTOCOL_PREFIX
        # CREATE_COIN_ANNOUNCEMENT (same token mint authorization body)
        assert conditions[3][0] == bytes([60])
        assert conditions[3][1] == conditions[2][1]
        # SEND_MESSAGE 0x10 (CHIP-25 message to deed)
        assert conditions[4][0] == bytes([66])
        assert conditions[4][1] == bytes([0x10])  # mode: sender commits puzzle_hash
        assert conditions[4][2][:1] == PROTOCOL_PREFIX
        # REMARK (driver hint with new state)
        assert conditions[5][0] == bytes([1])  # REMARK = 1
        # ASSERT_MY_COIN_ID
        assert conditions[6][0] == bytes([70])
        assert conditions[6][1] == my_id
        # ASSERT_MY_AMOUNT
        assert conditions[7][0] == bytes([73])
        # ASSERT_MY_PUZZLEHASH
        assert conditions[8][0] == bytes([72])

    def test_deposit_frozen_fails(self):
        curried = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_DEPOSIT,
            [bytes32(b"\xdd" * 32), DEED_LAUNCHER_ID, 100000, 1,
             DEED_PROPERTY_ID, bytes32(b"\xa1" * 32), 250_000,
             bytes32(b"\xee" * 32), bytes32(b"\xff" * 32)],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_deposit_state_recreation(self):
        """Verify CREATE_COIN puzzle hash matches expected new state curry."""
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_par_value = 100000

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_DEPOSIT,
            [bytes32(b"\xdd" * 32), DEED_LAUNCHER_ID, deed_par_value, 1,
             DEED_PROPERTY_ID, bytes32(b"\xa1" * 32), 250_000,
             bytes32(b"\xee" * 32), bytes32(b"\xff" * 32)],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # The CREATE_COIN puzzle hash should match a pool curried with new state
        expected_new = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=deed_par_value,
            deed_count=1,
            total_pool_token_supply=deed_par_value,
        )
        assert conditions[0][1] == expected_new.get_tree_hash()


class TestPoolRedeem:
    """Legacy SPEND CASE 2 is permanently disabled in v3."""

    def test_redeem_active_fails(self):
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=100000,
            deed_count=1,
            total_pool_token_supply=100000,
        )
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xdd" * 32)
        deed_par_value = 100000
        vault_launcher_id = bytes32(b"\xee" * 32)
        token_coin_id = bytes32(b"\xff" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_REDEEM, [deed_id, deed_par_value, vault_launcher_id, LAUNCHER_PUZZLE_HASH, token_coin_id],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_redeem_frozen_fails(self):
        curried = curry_pool(pool_status=POOL_FROZEN, tvl=100000, deed_count=1)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_REDEEM, [bytes32(b"\xdd" * 32), 100000, bytes32(b"\xee" * 32), LAUNCHER_PUZZLE_HASH, bytes32(b"\xff" * 32)],
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestPoolGenerateOffer:
    """Legacy SPEND CASE 5 is permanently disabled in v3."""

    def test_generate_offer_fails(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=100000, deed_count=1)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xdd" * 32)
        deed_par_value = 100000
        buyer_vault_launcher_id = bytes32(b"\xee" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GENERATE_OFFER, [deed_id, deed_par_value, buyer_vault_launcher_id, LAUNCHER_PUZZLE_HASH],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_generate_offer_frozen_fails(self):
        curried = curry_pool(pool_status=POOL_FROZEN, tvl=100000, deed_count=1)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GENERATE_OFFER, [bytes32(b"\xdd" * 32), 100000, bytes32(b"\xee" * 32), LAUNCHER_PUZZLE_HASH],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_generate_offer_empty_pool_fails(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GENERATE_OFFER, [bytes32(b"\xdd" * 32), 100000, bytes32(b"\xee" * 32), LAUNCHER_PUZZLE_HASH],
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestPoolV2SpecificDeedSwap:
    """Test SPEND CASE 6 — Pool Economic V2 specific deed swap."""

    def test_specific_deed_swap_binds_nav_deed_payment_fanout_and_fees(self):
        state = PoolEconomicState(
            total_nav_locked_mojos=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=state.total_nav_locked_mojos,
            deed_count=state.deed_count,
            total_pool_token_supply=state.total_pool_token_supply,
            treasury_reserve_tokens=state.treasury_reserve_tokens,
        )
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xd1" * 32)
        collection_id = bytes32(b"\xa1" * 32)
        nav_root = bytes32(b"\xc3" * 32)
        nav_registry_coin_id = bytes32(b"\xc1" * 32)
        buyer_vault_launcher_id = bytes32(b"\xee" * 32)
        treasury_reserve_puzhash = TRUSTED_TREASURY_RESERVE_PUZHASH
        protocol_treasury_puzhash = TRUSTED_PROTOCOL_TREASURY_PUZHASH
        governance_rewards_puzhash = TRUSTED_GOVERNANCE_REWARDS_PUZHASH
        governance_rewards_root = TRUSTED_GOVERNANCE_REWARDS_ROOT
        share_ppm = 250_000
        collection_nav_mojos = 1_000_000_000
        registry_version = 7
        nav_registry_puzzle_hash = computed_nav_registry_puzzle_hash(nav_root, registry_version)
        p2_vault = computed_p2_vault_ph(buyer_vault_launcher_id)
        evidence = CollectionNavEvidence(
            registry_coin_id=nav_registry_coin_id,
            registry_puzzle_hash=nav_registry_puzzle_hash,
            collection_id_canon=collection_id,
            nav_value_mojos=collection_nav_mojos,
            collection_nav_root=nav_root,
            registry_version=registry_version,
        )
        spec = build_specific_deed_swap_spec(
            state,
            deed_id=deed_id,
            deed_launcher_id=DEED_LAUNCHER_ID,
            par_value_mojos=DEED_PAR_VALUE,
            asset_class=DEED_ASSET_CLASS,
            property_id_canon=DEED_PROPERTY_ID,
            p2_vault_puzzle_hash=p2_vault,
            collection_id_canon=collection_id,
            share_ppm=share_ppm,
            nav_evidence=evidence,
            treasury_reserve_puzhash=treasury_reserve_puzhash,
            protocol_treasury_puzhash=protocol_treasury_puzhash,
            governance_rewards_puzhash=governance_rewards_puzhash,
            governance_rewards_root=governance_rewards_root,
        )

        sol = make_pool_solution(
            my_id,
            my_inner_puzhash,
            1,
            POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
            [
                deed_id,
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                collection_id,
                share_ppm,
                collection_nav_mojos,
                nav_root,
                registry_version,
                nav_registry_coin_id,
                nav_registry_puzzle_hash,
                buyer_vault_launcher_id,
                LAUNCHER_PUZZLE_HASH,
                treasury_reserve_puzhash,
                protocol_treasury_puzhash,
                governance_rewards_puzhash,
                governance_rewards_root,
            ],
        )
        conditions = curried.run(sol).as_python()

        assert len(conditions) == 10
        assert atom_int(conditions[0][0]) == CREATE_COIN
        expected_next = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=spec.next_state.total_nav_locked_mojos,
            deed_count=spec.next_state.deed_count,
            total_pool_token_supply=spec.next_state.total_pool_token_supply,
            treasury_reserve_tokens=spec.next_state.treasury_reserve_tokens,
        )
        assert conditions[0][1] == expected_next.get_tree_hash()

        assert atom_int(conditions[1][0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        assert conditions[1][1] == hashlib.sha256(
            bytes(nav_registry_puzzle_hash) + spec.required_nav_evidence_message
        ).digest()

        assert atom_int(conditions[2][0]) == ASSERT_COIN_ANNOUNCEMENT
        assert conditions[2][1] == hashlib.sha256(bytes(deed_id) + spec.deed_message).digest()

        assert atom_int(conditions[3][0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        expected_payment_message = token_settlement_payment_message(my_id, spec.token_outputs)
        assert conditions[3][1] == hashlib.sha256(
            bytes(computed_cat_offer_puzzle_hash()) + bytes(expected_payment_message)
        ).digest()

        assert atom_int(conditions[4][0]) == CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[4][1] == spec.pool_action_message

        assert atom_int(conditions[5][0]) == CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[5][1] == PROTOCOL_PREFIX + Program.to([
            my_id,
            deed_id,
            spec.deed_commitment,
            p2_vault,
        ]).get_tree_hash()

        assert atom_int(conditions[6][0]) == REMARK
        assert conditions[6][1] == PROTOCOL_PREFIX
        assert atom_int(conditions[6][2]) == POOL_V2_SPECIFIC_DEED_SWAP_TAG
        assert atom_int(conditions[6][3]) == spec.next_state.total_nav_locked_mojos
        assert atom_int(conditions[6][4]) == spec.next_state.deed_count
        assert atom_int(conditions[6][5]) == spec.next_state.total_pool_token_supply
        assert atom_int(conditions[6][6]) == spec.next_state.treasury_reserve_tokens
        assert atom_int(conditions[6][7]) == spec.quote.fee_split.protocol_fee_tokens
        assert atom_int(conditions[6][8]) == spec.quote.fee_split.governance_fee_tokens

    def test_specific_deed_swap_rejects_invalid_rewards_root(self):
        nav_root = bytes32(b"\xc3" * 32)
        registry_version = 7
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                1_000_000_000,
                nav_root,
                registry_version,
                bytes32(b"\xc1" * 32),
                computed_nav_registry_puzzle_hash(nav_root, registry_version),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                bytes32(b"\xf1" * 32),
                bytes32(b"\xf2" * 32),
                bytes32(b"\xf3" * 32),
                b"\xf4" * 31,
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_specific_deed_swap_rejects_untrusted_nav_registry(self):
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                1_000_000_000,
                bytes32(b"\xc3" * 32),
                7,
                bytes32(b"\xc1" * 32),
                bytes32(b"\xc2" * 32),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                TRUSTED_TREASURY_RESERVE_PUZHASH,
                TRUSTED_PROTOCOL_TREASURY_PUZHASH,
                TRUSTED_GOVERNANCE_REWARDS_PUZHASH,
                TRUSTED_GOVERNANCE_REWARDS_ROOT,
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_specific_deed_swap_rejects_stale_nav_registry_version(self):
        nav_root = bytes32(b"\xc3" * 32)
        stale_version = MIN_NAV_REGISTRY_VERSION - 1
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                1_000_000_000,
                nav_root,
                stale_version,
                bytes32(b"\xc1" * 32),
                computed_nav_registry_puzzle_hash(nav_root, stale_version),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                TRUSTED_TREASURY_RESERVE_PUZHASH,
                TRUSTED_PROTOCOL_TREASURY_PUZHASH,
                TRUSTED_GOVERNANCE_REWARDS_PUZHASH,
                TRUSTED_GOVERNANCE_REWARDS_ROOT,
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_specific_deed_swap_rejects_untrusted_treasury_destination(self):
        nav_root = bytes32(b"\xc3" * 32)
        registry_version = 7
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                1_000_000_000,
                nav_root,
                registry_version,
                bytes32(b"\xc1" * 32),
                computed_nav_registry_puzzle_hash(nav_root, registry_version),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                bytes32(b"\xaf" * 32),
                TRUSTED_PROTOCOL_TREASURY_PUZHASH,
                TRUSTED_GOVERNANCE_REWARDS_PUZHASH,
                TRUSTED_GOVERNANCE_REWARDS_ROOT,
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestPoolV2TrueRedemption:
    """Test SPEND CASE 7 — Pool Economic V2 true redemption."""

    def test_true_redemption_binds_nav_deed_metadata_and_melt_authorization(self):
        state = PoolEconomicState(
            total_nav_locked_mojos=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=state.total_nav_locked_mojos,
            deed_count=state.deed_count,
            total_pool_token_supply=state.total_pool_token_supply,
            treasury_reserve_tokens=state.treasury_reserve_tokens,
        )
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xd1" * 32)
        collection_id = bytes32(b"\xa1" * 32)
        nav_root = bytes32(b"\xc3" * 32)
        nav_registry_coin_id = bytes32(b"\xc1" * 32)
        vault_launcher_id = bytes32(b"\xee" * 32)
        token_coin_id = bytes32(b"\xe1" * 32)
        share_ppm = 250_000
        collection_nav_mojos = 1_000_000_000
        registry_version = 7
        nav_registry_puzzle_hash = computed_nav_registry_puzzle_hash(nav_root, registry_version)
        p2_vault = computed_p2_vault_ph(vault_launcher_id)
        evidence = CollectionNavEvidence(
            registry_coin_id=nav_registry_coin_id,
            registry_puzzle_hash=nav_registry_puzzle_hash,
            collection_id_canon=collection_id,
            nav_value_mojos=collection_nav_mojos,
            collection_nav_root=nav_root,
            registry_version=registry_version,
        )
        spec = build_true_redemption_spec(
            state,
            deed_id=deed_id,
            deed_launcher_id=DEED_LAUNCHER_ID,
            par_value_mojos=DEED_PAR_VALUE,
            asset_class=DEED_ASSET_CLASS,
            property_id_canon=DEED_PROPERTY_ID,
            p2_vault_puzzle_hash=p2_vault,
            collection_id_canon=collection_id,
            share_ppm=share_ppm,
            nav_evidence=evidence,
            token_coin_id=token_coin_id,
        )

        sol = make_pool_solution(
            my_id,
            my_inner_puzhash,
            1,
            POOL_SPEND_V2_TRUE_REDEMPTION,
            [
                deed_id,
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                collection_id,
                share_ppm,
                collection_nav_mojos,
                nav_root,
                registry_version,
                nav_registry_coin_id,
                nav_registry_puzzle_hash,
                vault_launcher_id,
                LAUNCHER_PUZZLE_HASH,
                token_coin_id,
            ],
        )
        conditions = curried.run(sol).as_python()

        assert len(conditions) == 11
        assert atom_int(conditions[0][0]) == CREATE_COIN
        expected_next = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=spec.next_state.total_nav_locked_mojos,
            deed_count=spec.next_state.deed_count,
            total_pool_token_supply=spec.next_state.total_pool_token_supply,
            treasury_reserve_tokens=spec.next_state.treasury_reserve_tokens,
        )
        assert conditions[0][1] == expected_next.get_tree_hash()

        assert atom_int(conditions[1][0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        assert conditions[1][1] == hashlib.sha256(
            bytes(nav_registry_puzzle_hash) + spec.required_nav_evidence_message
        ).digest()

        assert atom_int(conditions[2][0]) == ASSERT_COIN_ANNOUNCEMENT
        assert conditions[2][1] == hashlib.sha256(bytes(deed_id) + spec.deed_message).digest()

        assert atom_int(conditions[3][0]) == CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[3][1] == spec.token_authorizations[0].announcement_message

        assert atom_int(conditions[4][0]) == CREATE_COIN_ANNOUNCEMENT
        assert conditions[4][1] == spec.token_authorizations[0].announcement_message

        assert atom_int(conditions[5][0]) == CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[5][1] == spec.pool_action_message

        assert atom_int(conditions[6][0]) == CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[6][1] == PROTOCOL_PREFIX + Program.to([
            my_id,
            deed_id,
            spec.deed_commitment,
            p2_vault,
        ]).get_tree_hash()

        assert atom_int(conditions[7][0]) == REMARK
        assert conditions[7][1] == PROTOCOL_PREFIX
        assert atom_int(conditions[7][2]) == POOL_V2_TRUE_REDEMPTION_TAG
        assert atom_int(conditions[7][3]) == spec.next_state.total_nav_locked_mojos
        assert atom_int(conditions[7][4]) == spec.next_state.deed_count
        assert atom_int(conditions[7][5]) == spec.next_state.total_pool_token_supply
        assert atom_int(conditions[7][6]) == spec.next_state.treasury_reserve_tokens

    def test_true_redemption_rejects_invalid_share(self):
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_TRUE_REDEMPTION,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                0,
                1_000_000_000,
                bytes32(b"\xc3" * 32),
                7,
                bytes32(b"\xc1" * 32),
                bytes32(b"\xc2" * 32),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                bytes32(b"\xe1" * 32),
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_true_redemption_rejects_reserve_above_total_supply(self):
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=900_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_TRUE_REDEMPTION,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                1_000_000_000,
                bytes32(b"\xc3" * 32),
                7,
                bytes32(b"\xc1" * 32),
                bytes32(b"\xc2" * 32),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                bytes32(b"\xe1" * 32),
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_true_redemption_rejects_untrusted_nav_registry(self):
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_TRUE_REDEMPTION,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                1_000_000_000,
                bytes32(b"\xc3" * 32),
                7,
                bytes32(b"\xc1" * 32),
                bytes32(b"\xc2" * 32),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                bytes32(b"\xe1" * 32),
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_true_redemption_rejects_stale_nav_registry_version(self):
        nav_root = bytes32(b"\xc3" * 32)
        stale_version = MIN_NAV_REGISTRY_VERSION - 1
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_TRUE_REDEMPTION,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                bytes32(b"\xa1" * 32),
                250_000,
                1_000_000_000,
                nav_root,
                stale_version,
                bytes32(b"\xc1" * 32),
                computed_nav_registry_puzzle_hash(nav_root, stale_version),
                bytes32(b"\xee" * 32),
                LAUNCHER_PUZZLE_HASH,
                bytes32(b"\xe1" * 32),
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestPoolV2ReserveAcquisition:
    """Test SPEND CASE 8 — Pool Economic V2 reserve-funded acquisition."""

    def test_reserve_acquisition_uses_reserve_and_mints_shortfall(self):
        state = PoolEconomicState(
            total_nav_locked_mojos=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=state.total_nav_locked_mojos,
            deed_count=state.deed_count,
            total_pool_token_supply=state.total_pool_token_supply,
            treasury_reserve_tokens=state.treasury_reserve_tokens,
        )
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xd1" * 32)
        property_id = bytes32(b"\xa2" * 32)
        collection_id = bytes32(b"\xa1" * 32)
        nav_root = bytes32(b"\xc3" * 32)
        nav_registry_coin_id = bytes32(b"\xc1" * 32)
        seller_puzhash = bytes32(b"\xb1" * 32)
        mint_token_coin_id = None
        par_value_mojos = 123_000
        asset_class = 1
        share_ppm = 500_000
        collection_nav_mojos = 400_000_000
        seller_token_price = 200_000_000
        registry_version = 7
        nav_registry_puzzle_hash = computed_nav_registry_puzzle_hash(nav_root, registry_version)
        evidence = CollectionNavEvidence(
            registry_coin_id=nav_registry_coin_id,
            registry_puzzle_hash=nav_registry_puzzle_hash,
            collection_id_canon=collection_id,
            nav_value_mojos=collection_nav_mojos,
            collection_nav_root=nav_root,
            registry_version=registry_version,
        )
        spec = build_reserve_acquisition_spec(
            state,
            deed_id=deed_id,
            deed_launcher_id=DEED_LAUNCHER_ID,
            property_id_canon=property_id,
            par_value_mojos=par_value_mojos,
            asset_class=asset_class,
            collection_id_canon=collection_id,
            share_ppm=share_ppm,
            nav_evidence=evidence,
            seller_puzhash=seller_puzhash,
            seller_token_price=seller_token_price,
            mint_token_coin_id=mint_token_coin_id,
        )

        sol = make_pool_solution(
            my_id,
            my_inner_puzhash,
            1,
            POOL_SPEND_V2_RESERVE_ACQUISITION,
            [
                deed_id,
                DEED_LAUNCHER_ID,
                property_id,
                par_value_mojos,
                asset_class,
                collection_id,
                share_ppm,
                collection_nav_mojos,
                nav_root,
                registry_version,
                nav_registry_coin_id,
                nav_registry_puzzle_hash,
                seller_puzhash,
                seller_token_price,
                mint_token_coin_id,
            ],
        )
        conditions = curried.run(sol).as_python()

        assert len(conditions) == 10
        assert atom_int(conditions[0][0]) == CREATE_COIN
        expected_next = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=spec.next_state.total_nav_locked_mojos,
            deed_count=spec.next_state.deed_count,
            total_pool_token_supply=spec.next_state.total_pool_token_supply,
            treasury_reserve_tokens=spec.next_state.treasury_reserve_tokens,
        )
        assert conditions[0][1] == expected_next.get_tree_hash()

        assert atom_int(conditions[1][0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        assert conditions[1][1] == hashlib.sha256(
            bytes(nav_registry_puzzle_hash) + spec.required_nav_evidence_message
        ).digest()

        assert atom_int(conditions[2][0]) == ASSERT_COIN_ANNOUNCEMENT
        assert conditions[2][1] == hashlib.sha256(bytes(deed_id) + spec.deed_message).digest()

        assert atom_int(conditions[3][0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        expected_payment_message = token_settlement_payment_message(my_id, spec.token_outputs)
        assert conditions[3][1] == hashlib.sha256(
            bytes(computed_cat_offer_puzzle_hash()) + bytes(expected_payment_message)
        ).digest()

        assert spec.token_authorizations == ()

        assert atom_int(conditions[4][0]) == CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[4][1] == spec.pool_action_message

        assert atom_int(conditions[5][0]) == SEND_MESSAGE
        assert conditions[5][1] == bytes([0x10])
        assert conditions[5][2] == PROTOCOL_PREFIX + Program.to([
            POOL_SPEND_DEPOSIT,
            deed_id,
            par_value_mojos,
        ]).get_tree_hash()

        assert atom_int(conditions[6][0]) == REMARK
        assert conditions[6][1] == PROTOCOL_PREFIX
        assert atom_int(conditions[6][2]) == POOL_V2_RESERVE_ACQUISITION_TAG
        assert atom_int(conditions[6][3]) == spec.next_state.total_nav_locked_mojos
        assert atom_int(conditions[6][4]) == spec.next_state.deed_count
        assert atom_int(conditions[6][5]) == spec.next_state.total_pool_token_supply
        assert atom_int(conditions[6][6]) == spec.next_state.treasury_reserve_tokens
        assert atom_int(conditions[6][7]) == spec.quote.reserve_tokens_paid
        assert atom_int(conditions[6][8]) == spec.quote.fresh_tokens_to_mint

    def test_reserve_acquisition_without_shortfall_omits_mint_authorization(self):
        state = PoolEconomicState(
            total_nav_locked_mojos=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=state.total_nav_locked_mojos,
            deed_count=state.deed_count,
            total_pool_token_supply=state.total_pool_token_supply,
            treasury_reserve_tokens=state.treasury_reserve_tokens,
        )
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xd1" * 32)
        property_id = bytes32(b"\xa2" * 32)
        collection_id = bytes32(b"\xa1" * 32)
        nav_root = bytes32(b"\xc3" * 32)
        nav_registry_coin_id = bytes32(b"\xc1" * 32)
        seller_puzhash = bytes32(b"\xb1" * 32)
        par_value_mojos = 123_000
        asset_class = 1
        share_ppm = 500_000
        collection_nav_mojos = 400_000_000
        seller_token_price = 100_000_000
        registry_version = 7
        nav_registry_puzzle_hash = computed_nav_registry_puzzle_hash(nav_root, registry_version)
        evidence = CollectionNavEvidence(
            registry_coin_id=nav_registry_coin_id,
            registry_puzzle_hash=nav_registry_puzzle_hash,
            collection_id_canon=collection_id,
            nav_value_mojos=collection_nav_mojos,
            collection_nav_root=nav_root,
            registry_version=registry_version,
        )
        spec = build_reserve_acquisition_spec(
            state,
            deed_id=deed_id,
            deed_launcher_id=DEED_LAUNCHER_ID,
            property_id_canon=property_id,
            par_value_mojos=par_value_mojos,
            asset_class=asset_class,
            collection_id_canon=collection_id,
            share_ppm=share_ppm,
            nav_evidence=evidence,
            seller_puzhash=seller_puzhash,
            seller_token_price=seller_token_price,
        )
        assert spec.token_authorizations == ()

        sol = make_pool_solution(
            my_id,
            my_inner_puzhash,
            1,
            POOL_SPEND_V2_RESERVE_ACQUISITION,
            [
                deed_id,
                DEED_LAUNCHER_ID,
                property_id,
                par_value_mojos,
                asset_class,
                collection_id,
                share_ppm,
                collection_nav_mojos,
                nav_root,
                registry_version,
                nav_registry_coin_id,
                nav_registry_puzzle_hash,
                seller_puzhash,
                seller_token_price,
                None,
            ],
        )
        conditions = curried.run(sol).as_python()

        assert len(conditions) == 10
        assert atom_int(conditions[3][0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        assert atom_int(conditions[4][0]) == CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[4][1] == spec.pool_action_message
        assert atom_int(conditions[5][0]) == SEND_MESSAGE
        assert atom_int(conditions[6][0]) == REMARK
        assert atom_int(conditions[6][7]) == spec.quote.reserve_tokens_paid
        assert atom_int(conditions[6][8]) == 0

    def test_reserve_acquisition_rejects_missing_mint_coin_for_shortfall(self):
        state = PoolEconomicState(
            total_nav_locked_mojos=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=0,
        )
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=state.total_nav_locked_mojos,
            deed_count=state.deed_count,
            total_pool_token_supply=state.total_pool_token_supply,
            treasury_reserve_tokens=state.treasury_reserve_tokens,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_RESERVE_ACQUISITION,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                bytes32(b"\xa2" * 32),
                123_000,
                1,
                bytes32(b"\xa1" * 32),
                500_000,
                400_000_000,
                bytes32(b"\xc3" * 32),
                7,
                bytes32(b"\xc1" * 32),
                computed_nav_registry_puzzle_hash(bytes32(b"\xc3" * 32), 7),
                bytes32(b"\xb1" * 32),
                200_000_000,
                None,
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_reserve_acquisition_rejects_stale_nav_registry_version(self):
        nav_root = bytes32(b"\xc3" * 32)
        stale_version = MIN_NAV_REGISTRY_VERSION - 1
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_RESERVE_ACQUISITION,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                bytes32(b"\xa2" * 32),
                123_000,
                1,
                bytes32(b"\xa1" * 32),
                500_000,
                400_000_000,
                nav_root,
                stale_version,
                bytes32(b"\xc1" * 32),
                computed_nav_registry_puzzle_hash(nav_root, stale_version),
                bytes32(b"\xb1" * 32),
                200_000_000,
                None,
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_reserve_acquisition_rejects_seller_price_above_nav(self):
        nav_root = bytes32(b"\xc3" * 32)
        registry_version = 7
        curried = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=1_000_000_000,
            deed_count=10,
            total_pool_token_supply=800_000_000,
            treasury_reserve_tokens=200_000_000,
        )
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_V2_RESERVE_ACQUISITION,
            [
                bytes32(b"\xd1" * 32),
                DEED_LAUNCHER_ID,
                bytes32(b"\xa2" * 32),
                123_000,
                1,
                bytes32(b"\xa1" * 32),
                500_000,
                400_000_000,
                nav_root,
                registry_version,
                bytes32(b"\xc1" * 32),
                computed_nav_registry_puzzle_hash(nav_root, registry_version),
                bytes32(b"\xb1" * 32),
                200_000_001,
                bytes32(b"\xe1" * 32),
            ],
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestPoolSettlementBinding:
    """Test SPEND CASE 3 — SETTLEMENT release-set binding."""

    splitxch_root = bytes32(b"\xab" * 32)
    gov_inner_puzhash = bytes32(b"\xac" * 32)
    releases = [
        [bytes32(b"\x21" * 32), bytes32(b"\x41" * 32), bytes32(b"\x31" * 32)],
        [bytes32(b"\x22" * 32), bytes32(b"\x42" * 32), bytes32(b"\x32" * 32)],
    ]

    def run_settlement(self, releases=None):
        releases = self.releases if releases is None else releases
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=200_000, deed_count=len(self.releases))
        sol = make_pool_solution(
            bytes32(b"\x11" * 32),
            curried.get_tree_hash(),
            1,
            POOL_SPEND_SETTLEMENT,
            [
                self.splitxch_root,
                99_999,
                releases,
                self.gov_inner_puzhash,
            ],
        )
        return curried.run(sol).as_python()

    def test_settlement_receive_message_binds_full_deed_releases_hash(self):
        conditions = self.run_settlement()
        receives = [c for c in conditions if atom_int(c[0]) == RECEIVE_MESSAGE]
        assert len(receives) == 1
        assert receives[0][1] == bytes([0x10])
        assert receives[0][2] == settlement_message(
            self.splitxch_root,
            99_999,
            len(self.releases),
            self.releases,
        )
        assert receives[0][2] != old_count_only_settlement_message(
            self.splitxch_root,
            99_999,
            len(self.releases),
        )

    def test_settlement_batch_announcement_binds_full_deed_releases_hash(self):
        conditions = self.run_settlement()
        announcements = [c for c in conditions if atom_int(c[0]) == CREATE_PUZZLE_ANNOUNCEMENT]
        batch = announcements[0]
        expected = PROTOCOL_PREFIX + Program.to([
            POOL_SPEND_SETTLEMENT,
            self.splitxch_root,
            99_999,
            len(self.releases),
            deed_releases_hash(self.releases),
        ]).get_tree_hash()
        assert batch[1] == expected

    def test_mutating_release_destination_changes_required_governance_message(self):
        mutated = [
            self.releases[0],
            [self.releases[1][0], self.releases[1][1], bytes32(b"\xfe" * 32)],
        ]
        assert settlement_message(self.splitxch_root, 99_999, len(self.releases), mutated) != settlement_message(
            self.splitxch_root,
            99_999,
            len(self.releases),
            self.releases,
        )
        conditions = self.run_settlement(mutated)
        receives = [c for c in conditions if atom_int(c[0]) == RECEIVE_MESSAGE]
        assert receives[0][2] == settlement_message(
            self.splitxch_root,
            99_999,
            len(self.releases),
            mutated,
        )

    def test_reordering_release_set_changes_required_governance_message(self):
        reordered = list(reversed(self.releases))
        assert settlement_message(self.splitxch_root, 99_999, len(self.releases), reordered) != settlement_message(
            self.splitxch_root,
            99_999,
            len(self.releases),
            self.releases,
        )

    def test_duplicate_deed_release_is_rejected_before_message_pairing(self):
        duplicate = [self.releases[0], self.releases[0]]
        with pytest.raises(ValueError):
            self.run_settlement(duplicate)


class TestPoolGovernance:
    """Test SPEND CASE 4 — GOVERNANCE."""

    def test_governance_returns_conditions(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        gov_singleton_struct = Program.to((SINGLETON_MOD_HASH, (bytes32(b"\xab" * 32), LAUNCHER_PUZZLE_HASH)))
        gov_inner_puzhash = bytes32(b"\xac" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GOVERNANCE, [POOL_FROZEN, gov_inner_puzhash],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 6 conditions
        assert len(conditions) == 6
        # CREATE_COIN (recreate with new status)
        assert conditions[0][0] == bytes([51])
        # RECEIVE_MESSAGE 0x10 (CHIP-25 message from governance)
        assert conditions[1][0] == bytes([67])
        assert conditions[1][1] == bytes([0x10])  # mode: sender commits puzzle_hash
        # REMARK
        assert conditions[2][0] == bytes([1])

        # State recreation: new pool should be FROZEN with same tvl/count
        expected_new = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        assert conditions[0][1] == expected_new.get_tree_hash()

    # ── LOW-10 regression tests ─────────────────────────────────────────
    # Pre-fix: spend_governance accepted any integer for new_status, so
    # governance could brick the pool by writing e.g. 2 (neither FROZEN
    # nor ACTIVE).  Post-fix: only {0, 1} are accepted.
    def test_governance_rejects_new_status_2(self):
        """LOW-10: out-of-range positive status rejected."""
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        gov_singleton_struct = Program.to(
            (SINGLETON_MOD_HASH, (bytes32(b"\xab" * 32), LAUNCHER_PUZZLE_HASH))
        )
        gov_inner_puzhash = bytes32(b"\xac" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GOVERNANCE, [2, gov_inner_puzhash],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_governance_rejects_new_status_99(self):
        """LOW-10: arbitrary non-{0,1} integer rejected."""
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        gov_singleton_struct = Program.to(
            (SINGLETON_MOD_HASH, (bytes32(b"\xab" * 32), LAUNCHER_PUZZLE_HASH))
        )
        gov_inner_puzhash = bytes32(b"\xac" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GOVERNANCE, [99, gov_inner_puzhash],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_governance_accepts_new_status_active(self):
        """LOW-10: status=1 (ACTIVE) is the canonical complement of FROZEN; must succeed."""
        curried = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        gov_singleton_struct = Program.to(
            (SINGLETON_MOD_HASH, (bytes32(b"\xab" * 32), LAUNCHER_PUZZLE_HASH))
        )
        gov_inner_puzhash = bytes32(b"\xac" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GOVERNANCE, [POOL_ACTIVE, gov_inner_puzhash],
        )
        # Should NOT raise; should produce 6 conditions including the
        # CREATE_COIN that recreates the pool with POOL_ACTIVE.
        result = curried.run(sol)
        conditions = result.as_python()
        assert len(conditions) == 6


class TestPoolGating:
    """Test that invalid spend cases fail."""

    def test_invalid_spend_case_fails(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            99, [],
        )
        with pytest.raises(ValueError):
            curried.run(sol)
