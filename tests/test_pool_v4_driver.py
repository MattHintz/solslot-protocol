from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs import G1Element
from chia_rs.sized_bytes import bytes32
import pytest

from solslot_puzzles import load_puzzle
from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
    deed_to_sols_inner_solution,
    deterministic_custody_coin_id,
    make_pool_v4_inner,
    pool_v4_inner_mod_hash,
    sols_to_deed_inner_solution,
)
from solslot_puzzles.protocol_statutes_driver import (
    protocol_statutes_inner_mod_hash,
)
from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    PermanentRules,
    ProtocolParameters,
    StatutesState,
    keyed_root,
)
from solslot_puzzles.sols_economics_v3 import SolsEconomicState
from solslot_puzzles.sols_pool_v4 import (
    SolsPoolStateV4,
    inventory_root,
    prepare_deed_to_sols,
    prepare_sols_to_deed,
)
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    ZKPASSPORT_EMPTY_ATTEST_ROOT,
    puzzle_hash_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import vault_v2_inner_mod_hash


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


POOL_LAUNCHER = b32(1)
STATUTES_LAUNCHER = b32(2)
GOVERNANCE_LAUNCHER = b32(3)
DEED_LAUNCHER = b32(4)
DEED_PARENT = b32(5)
POOL_COIN = b32(6)
VAULT_LAUNCHER = b32(7)
VAULT_COIN = b32(8)
IDENTITY_ROOT = b32(9)
MEMBERS_ROOT = b32(10)
SELLER_PUZZLE = b32(11)
PROPERTY_ID = b32(12)
MINT_TOKEN_COIN = b32(13)
QUOTE_EXPIRES = 1_800_080_000
PAR_VALUE = 100_000_000
ASSET_CLASS = 1
SHARE_PPM = 100_000

PARAMETERS = ProtocolParameters()
RULES = PermanentRules(
    sgt_tail_hash=b32(20),
    sgt_total_supply=1_000_000,
    sols_tail_hash=b32(21),
    zkpassport_policy_hash=b32(22),
    protocol_treasury_puzzle_hash=b32(23),
    network_id=b32(24),
)
COLLECTION = CollectionStatute(
    collection_id=b32(25),
    nav_micro_usd=999_000_000,
    allocation_ceiling_micro_usd=999_000_000,
    nav_version=1,
    valid_after=1_800_000_000,
    valid_until=1_800_086_400,
    status=1,
)
EMPTY_ROOT = bytes32(Program.to([]).get_tree_hash())
STATUTES_STATE = StatutesState(
    parameters_root=bytes32(
        Program.to(list(PARAMETERS.as_tuple())).get_tree_hash()
    ),
    collections_root=keyed_root([COLLECTION]),
    oracle_root=EMPTY_ROOT,
    routes_root=EMPTY_ROOT,
    liquidity_root=EMPTY_ROOT,
    pauses_root=EMPTY_ROOT,
    registry_version=3,
    permanent_rules_hash=RULES.commitment_hash,
)
EMPTY_POOL = SolsPoolStateV4(
    inventory_root=EMPTY_ROOT,
    economics=SolsEconomicState(
        bootstrap_complete=False,
        inventory_nav_micro_usd=0,
        treasury_assets_micro_usd=0,
        proven_liabilities_micro_usd=0,
        deed_count=0,
        total_sols_mojos=1,
        reserve_sols_mojos=1,
    ),
    state_version=1,
)


def singleton_struct(launcher_id: bytes32) -> Program:
    return Program.to(
        (SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH))
    )


CONFIG = PoolV4Config(
    pool_launcher_id=POOL_LAUNCHER,
    statutes_inner_mod_hash=protocol_statutes_inner_mod_hash(),
    statutes_singleton_struct=singleton_struct(STATUTES_LAUNCHER),
    governance_singleton_struct=singleton_struct(GOVERNANCE_LAUNCHER),
    permanent_rules=RULES,
    cat_mod_hash=b32(30),
    offer_mod_hash=b32(31),
    p2_vault_mod_hash=bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
    vault_v2_mod_hash=vault_v2_inner_mod_hash(),
    p2_pool_v2_mod_hash=bytes32(
        load_puzzle("p2_pool_v2.clsp").get_tree_hash()
    ),
    deed_launcher_puzzle_hash=b32(29),
    reserve_puzzle_hash=b32(32),
    sgt_rewards_puzzle_hash=b32(33),
)
OWNER_PUBKEY = bytes(G1Element.generator())
DEED_COMMITMENT = bytes32(
    Program.to(
        [
            DEED_LAUNCHER,
            PAR_VALUE,
            ASSET_CLASS,
            PROPERTY_ID,
            COLLECTION.collection_id,
            SHARE_PPM,
        ]
    ).get_tree_hash()
)
CUSTODY_COIN = deterministic_custody_coin_id(
    config=CONFIG,
    deed_parent_coin_id=DEED_PARENT,
    deed_launcher_id=DEED_LAUNCHER,
    deed_commitment=DEED_COMMITMENT,
)


def deposit_receipt():
    return prepare_deed_to_sols(
        pool_coin_id=POOL_COIN,
        state=EMPTY_POOL,
        inventory=(),
        deed_launcher_id=DEED_LAUNCHER,
        custody_coin_id=CUSTODY_COIN,
        deed_commitment=DEED_COMMITMENT,
        collection=COLLECTION,
        share_ppm=SHARE_PPM,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=VAULT_COIN,
        seller_sols_puzzle_hash=SELLER_PUZZLE,
        quote_expires_at=QUOTE_EXPIRES,
    )


def test_pool_v4_module_and_deterministic_custody_are_stable() -> None:
    assert len(pool_v4_inner_mod_hash()) == 32
    assert CUSTODY_COIN == deterministic_custody_coin_id(
        config=CONFIG,
        deed_parent_coin_id=DEED_PARENT,
        deed_launcher_id=DEED_LAUNCHER,
        deed_commitment=DEED_COMMITMENT,
    )


def test_deed_to_sols_solution_executes_exact_bootstrap_quote() -> None:
    receipt = deposit_receipt()
    inner = make_pool_v4_inner(CONFIG, EMPTY_POOL)
    solution = deed_to_sols_inner_solution(
        config=CONFIG,
        pool_coin_id=POOL_COIN,
        pool_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        pool_amount=1,
        receipt=receipt,
        parameters=PARAMETERS,
        collection=COLLECTION,
        pause=None,
        statutes_state=STATUTES_STATE,
        deed_parent_coin_id=DEED_PARENT,
        par_value=PAR_VALUE,
        asset_class=ASSET_CLASS,
        property_id=PROPERTY_ID,
        seller_sols_puzzle_hash=SELLER_PUZZLE,
        mint_token_coin_id=MINT_TOKEN_COIN,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=VAULT_COIN,
        owner_pubkey=OWNER_PUBKEY,
        auth_type=AUTH_TYPE_BLS,
        members_root=MEMBERS_ROOT,
        identity_root=IDENTITY_ROOT,
        bridge_policy=RULES.zkpassport_policy_hash,
        quote_expires_at=QUOTE_EXPIRES,
    )
    conditions = inner.run(solution).as_python()
    assert any(
        condition[0] == b"\x01"
        and receipt.operation_hash in [
            bytes32(item) for item in condition[1:] if len(item) == 32
        ]
        for condition in conditions
    )
    assert any(condition[0] == b"\x3c" for condition in conditions)
    assert any(condition[0] == b"\x3e" for condition in conditions)
    assert not any(condition[0] == b"\x34" for condition in conditions)

    altered = solution.as_python()
    altered[4][33] = b"\x01"
    with pytest.raises(Exception):
        inner.run(Program.to(altered))

    altered_custody = solution.as_python()
    altered_custody[4][13] = bytes(b32(0x45))
    with pytest.raises(Exception):
        inner.run(Program.to(altered_custody))

    unenrolled = solution.as_python()
    unenrolled[4][26] = bytes(ZKPASSPORT_EMPTY_ATTEST_ROOT)
    with pytest.raises(Exception):
        inner.run(Program.to(unenrolled))


def test_sols_to_deed_solution_pays_reserve_and_fees_without_melt() -> None:
    deposit = deposit_receipt()
    state = deposit.next_state
    pool_coin = b32(40)
    destination = puzzle_hash_for_p2_vault(VAULT_LAUNCHER)
    receipt = prepare_sols_to_deed(
        pool_coin_id=pool_coin,
        state=state,
        inventory=deposit.next_inventory,
        deed_launcher_id=DEED_LAUNCHER,
        collection=COLLECTION,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=VAULT_COIN,
        destination_p2_vault_hash=destination,
        quote_expires_at=QUOTE_EXPIRES,
    )
    inner = make_pool_v4_inner(CONFIG, state)
    solution = sols_to_deed_inner_solution(
        pool_coin_id=pool_coin,
        pool_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        pool_amount=1,
        receipt=receipt,
        parameters=PARAMETERS,
        collection=COLLECTION,
        pause=None,
        statutes_state=STATUTES_STATE,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=VAULT_COIN,
        owner_pubkey=OWNER_PUBKEY,
        auth_type=AUTH_TYPE_BLS,
        members_root=MEMBERS_ROOT,
        identity_root=IDENTITY_ROOT,
        bridge_policy=RULES.zkpassport_policy_hash,
        quote_expires_at=QUOTE_EXPIRES,
        destination_p2_vault_hash=destination,
    )
    conditions = inner.run(solution).as_python()
    assert any(condition[0] == b"\x3d" for condition in conditions)
    assert any(condition[0] == b"\x3e" for condition in conditions)
    assert not any(condition[0] == b"\x3c" for condition in conditions)
    assert receipt.next_state.inventory_root == inventory_root(())

    altered_fee = solution.as_python()
    altered_fee[4][26] = b"\x01"
    with pytest.raises(Exception):
        inner.run(Program.to(altered_fee))

    unsupported = solution.as_python()
    unsupported[3] = b"\x03"
    with pytest.raises(Exception):
        inner.run(Program.to(unsupported))
