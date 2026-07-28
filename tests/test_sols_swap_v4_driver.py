from __future__ import annotations

from dataclasses import dataclass, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
import pytest

from solslot_puzzles import load_puzzle
from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
    make_pool_v4_full,
    p2_pool_v2_inner_hash,
    pool_v4_inner_mod_hash,
)
from solslot_puzzles.mint_publish_driver import make_smart_deed_inner
from solslot_puzzles.protocol_deployment import pool_token_tail_hash
from solslot_puzzles.protocol_statutes_driver import (
    make_inner_puzzle as make_statutes_inner,
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
    SwapReceipt,
    inventory_root,
    prepare_deed_to_sols,
    prepare_sols_to_deed,
)
from solslot_puzzles.sols_swap_v4_driver import (
    SolsSwapOfferError,
    aggregate_sols_to_deed_swap,
    build_deed_to_sols_protocol_offer,
    build_sols_to_deed_protocol_offer,
    prepare_sols_buyer_offer,
    validate_sols_buyer_offer,
)
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, puzzle_hash_for_p2_vault
from solslot_puzzles.vault_v2_driver import (
    puzzle_for_vault_v2_full,
    vault_v2_inner_mod_hash,
)


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def singleton_struct(launcher_id: bytes32) -> Program:
    return Program.to(
        (SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH))
    )


def lineage(seed: int) -> LineageProof:
    return LineageProof(
        parent_name=b32(seed),
        inner_puzzle_hash=b32(seed + 1),
        amount=1,
    )


POOL_LAUNCHER = b32(1)
STATUTES_LAUNCHER = b32(2)
GOVERNANCE_LAUNCHER = b32(3)
DEED_LAUNCHER = b32(4)
VAULT_LAUNCHER = b32(6)
IDENTITY_ROOT = b32(7)
MEMBERS_ROOT = b32(8)
PROPERTY_ID = b32(9)
QUOTE_EXPIRES = 1_800_080_000
PAR_VALUE = 100_000_000
SHARE_PPM = 100_000
OWNER_SK = AugSchemeMPL.key_gen(bytes([42]) * 32)
OWNER_PK = bytes(OWNER_SK.get_g1())

PARAMETERS = ProtocolParameters()
RULES = PermanentRules(
    sgt_tail_hash=b32(20),
    sgt_total_supply=1_000_000,
    sols_tail_hash=pool_token_tail_hash(POOL_LAUNCHER),
    zkpassport_policy_hash=b32(22),
    protocol_treasury_puzzle_hash=b32(23),
    network_id=b32(24),
)
RESERVE_INNER = puzzle_for_pk(OWNER_SK.get_g1())
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
    inventory_root=inventory_root(()),
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
CONFIG = PoolV4Config(
    pool_launcher_id=POOL_LAUNCHER,
    statutes_inner_mod_hash=protocol_statutes_inner_mod_hash(),
    statutes_singleton_struct=singleton_struct(STATUTES_LAUNCHER),
    governance_singleton_struct=singleton_struct(GOVERNANCE_LAUNCHER),
    permanent_rules=RULES,
    cat_mod_hash=bytes32(CAT_MOD.get_tree_hash()),
    offer_mod_hash=OFFER_MOD_HASH,
    p2_vault_mod_hash=bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
    vault_v2_mod_hash=vault_v2_inner_mod_hash(),
    p2_pool_v2_mod_hash=bytes32(
        load_puzzle("p2_pool_v2.clsp").get_tree_hash()
    ),
    deed_launcher_puzzle_hash=b32(29),
    reserve_puzzle_hash=bytes32(RESERVE_INNER.get_tree_hash()),
    sgt_rewards_puzzle_hash=b32(31),
)
DEED_COMMITMENT = bytes32(
    Program.to(
        [
            DEED_LAUNCHER,
            PAR_VALUE,
            1,
            PROPERTY_ID,
            COLLECTION.collection_id,
            SHARE_PPM,
        ]
    ).get_tree_hash()
)


@dataclass(frozen=True)
class SwapFixture:
    receipt: SwapReceipt
    pool_coin: Coin
    pool_lineage: LineageProof
    custody_coin: Coin
    custody_lineage: LineageProof
    vault_coin: Coin
    vault_lineage: LineageProof
    statutes_coin: Coin
    statutes_lineage: LineageProof
    payment_coin: Coin
    payment_lineage: LineageProof


def _singleton_child(
    *,
    launcher_id: bytes32,
    parent_inner: Program,
    current_inner: Program,
    seed: int,
) -> tuple[Coin, LineageProof, Coin]:
    parent_coin = Coin(
        b32(seed),
        bytes32(
            puzzle_for_singleton(
                launcher_id,
                parent_inner,
            ).get_tree_hash()
        ),
        1,
    )
    child = Coin(
        parent_coin.name(),
        bytes32(
            puzzle_for_singleton(
                launcher_id,
                current_inner,
            ).get_tree_hash()
        ),
        1,
    )
    return (
        child,
        LineageProof(
            parent_name=parent_coin.parent_coin_info,
            inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
            amount=parent_coin.amount,
        ),
        parent_coin,
    )


def _deed_singleton_child(
    *,
    parent_inner: Program,
    current_inner: Program,
    seed: int,
) -> tuple[Coin, LineageProof, Coin]:
    deed_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (DEED_LAUNCHER, CONFIG.deed_launcher_puzzle_hash),
        )
    )
    parent_coin = Coin(
        b32(seed),
        bytes32(SINGLETON_MOD.curry(deed_struct, parent_inner).get_tree_hash()),
        1,
    )
    child = Coin(
        parent_coin.name(),
        bytes32(SINGLETON_MOD.curry(deed_struct, current_inner).get_tree_hash()),
        1,
    )
    return (
        child,
        LineageProof(
            parent_name=parent_coin.parent_coin_info,
            inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
            amount=parent_coin.amount,
        ),
        parent_coin,
    )


def _fixture() -> SwapFixture:
    empty_pool_inner = make_pool_v4_full(CONFIG, EMPTY_POOL).uncurry()
    assert empty_pool_inner is not None
    _, empty_pool_args = empty_pool_inner
    empty_pool_inner_puzzle = list(empty_pool_args.as_iter())[1]
    empty_pool_coin = Coin(
        b32(40),
        bytes32(make_pool_v4_full(CONFIG, EMPTY_POOL).get_tree_hash()),
        1,
    )
    custody_inner = load_puzzle("p2_pool_v2.clsp").curry(
        CONFIG.p2_pool_v2_mod_hash,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER,
        SINGLETON_LAUNCHER_HASH,
        DEED_COMMITMENT,
    )
    assert bytes32(custody_inner.get_tree_hash()) == p2_pool_v2_inner_hash(
        config=CONFIG,
        deed_commitment=DEED_COMMITMENT,
    )
    custody_coin, custody_lineage, deed_parent_coin = _deed_singleton_child(
        parent_inner=Program.to(1),
        current_inner=custody_inner,
        seed=41,
    )
    deposit = prepare_deed_to_sols(
        pool_coin_id=empty_pool_coin.name(),
        state=EMPTY_POOL,
        inventory=(),
        deed_launcher_id=DEED_LAUNCHER,
        custody_coin_id=custody_coin.name(),
        deed_commitment=DEED_COMMITMENT,
        collection=COLLECTION,
        share_ppm=SHARE_PPM,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=b32(41),
        seller_sols_puzzle_hash=b32(42),
        quote_expires_at=QUOTE_EXPIRES,
    )
    current_pool_inner = make_pool_v4_full(
        CONFIG,
        deposit.next_state,
    ).uncurry()
    assert current_pool_inner is not None
    _, current_pool_args = current_pool_inner
    current_pool_inner_puzzle = list(current_pool_args.as_iter())[1]
    pool_coin, pool_lineage, parent_pool_coin = _singleton_child(
        launcher_id=POOL_LAUNCHER,
        parent_inner=empty_pool_inner_puzzle,
        current_inner=current_pool_inner_puzzle,
        seed=40,
    )
    assert parent_pool_coin == empty_pool_coin
    vault_full = puzzle_for_vault_v2_full(
        vault_launcher_id=VAULT_LAUNCHER,
        owner_pubkey=OWNER_PK,
        auth_type=AUTH_TYPE_BLS,
        members_merkle_root=MEMBERS_ROOT,
        pool_launcher_id=POOL_LAUNCHER,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=RULES.zkpassport_policy_hash,
    )
    vault_uncurry = vault_full.uncurry()
    assert vault_uncurry is not None
    _, vault_args = vault_uncurry
    vault_inner = list(vault_args.as_iter())[1]
    vault_coin, vault_lineage, _ = _singleton_child(
        launcher_id=VAULT_LAUNCHER,
        parent_inner=vault_inner,
        current_inner=vault_inner,
        seed=43,
    )
    receipt = prepare_sols_to_deed(
        pool_coin_id=pool_coin.name(),
        state=deposit.next_state,
        inventory=deposit.next_inventory,
        deed_launcher_id=DEED_LAUNCHER,
        collection=COLLECTION,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=vault_coin.name(),
        destination_p2_vault_hash=puzzle_hash_for_p2_vault(VAULT_LAUNCHER),
        quote_expires_at=QUOTE_EXPIRES,
    )
    statutes_inner = make_statutes_inner(
        singleton_struct=CONFIG.statutes_singleton_struct,
        governance_singleton_struct=CONFIG.governance_singleton_struct,
        permanent_rules=RULES,
        state=STATUTES_STATE,
    )
    statutes_coin, statutes_lineage, _ = _singleton_child(
        launcher_id=STATUTES_LAUNCHER,
        parent_inner=statutes_inner,
        current_inner=statutes_inner,
        seed=44,
    )
    payment_puzzle = puzzle_for_pk(OWNER_SK.get_g1())
    payment_parent = Coin(
        b32(45),
        bytes32(
            construct_cat_puzzle(
                CAT_MOD,
                RULES.sols_tail_hash,
                payment_puzzle,
            ).get_tree_hash()
        ),
        receipt.sols_to_deed_quote.buyer_total_sols_mojos + 10,
    )
    payment_coin = Coin(
        payment_parent.name(),
        payment_parent.puzzle_hash,
        payment_parent.amount,
    )
    payment_lineage = LineageProof(
        parent_name=payment_parent.parent_coin_info,
        inner_puzzle_hash=bytes32(payment_puzzle.get_tree_hash()),
        amount=payment_parent.amount,
    )
    assert custody_coin.parent_coin_info == deed_parent_coin.name()
    return SwapFixture(
        receipt=receipt,
        pool_coin=pool_coin,
        pool_lineage=pool_lineage,
        custody_coin=custody_coin,
        custody_lineage=custody_lineage,
        vault_coin=vault_coin,
        vault_lineage=vault_lineage,
        statutes_coin=statutes_coin,
        statutes_lineage=statutes_lineage,
        payment_coin=payment_coin,
        payment_lineage=payment_lineage,
    )


def test_sols_to_deed_offer_balances_exact_protocol_spends() -> None:
    fixture = _fixture()
    buyer = prepare_sols_buyer_offer(
        payment_coin=fixture.payment_coin,
        payment_public_key=OWNER_PK,
        payment_lineage_proof=fixture.payment_lineage,
        receipt=fixture.receipt,
        config=CONFIG,
        vault_launcher_id=VAULT_LAUNCHER,
    )
    protocol = build_sols_to_deed_protocol_offer(
        receipt=fixture.receipt,
        config=CONFIG,
        parameters=PARAMETERS,
        collection=COLLECTION,
        pause=None,
        statutes_state=STATUTES_STATE,
        statutes_coin=fixture.statutes_coin,
        statutes_launcher_id=STATUTES_LAUNCHER,
        statutes_lineage_proof=fixture.statutes_lineage,
        collections=[COLLECTION],
        pauses=[],
        vault_coin=fixture.vault_coin,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_lineage_proof=fixture.vault_lineage,
        vault_owner_pubkey=OWNER_PK,
        vault_auth_type=AUTH_TYPE_BLS,
        vault_members_merkle_root=MEMBERS_ROOT,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=RULES.zkpassport_policy_hash,
        vault_signature_data=None,
        pool_coin=fixture.pool_coin,
        pool_lineage_proof=fixture.pool_lineage,
        custody_coin=fixture.custody_coin,
        custody_lineage_proof=fixture.custody_lineage,
        quote_expires_at=QUOTE_EXPIRES,
    )
    aggregate = aggregate_sols_to_deed_swap(
        buyer_offer=buyer.offer,
        protocol_offer=protocol,
        receipt=fixture.receipt,
        config=CONFIG,
        vault_launcher_id=VAULT_LAUNCHER,
    )
    assert aggregate.aggregate_offer.is_valid()
    assert len(aggregate.aggregate_offer.to_valid_spend().coin_spends) == 6
    assert len(
        (
            protocol.statutes_spend,
            protocol.vault_spend,
            protocol.pool_spend,
            protocol.custody_spend,
        )
    ) == 4
    assert set(protocol.offer.requested_payments) == {RULES.sols_tail_hash}
    quote = fixture.receipt.sols_to_deed_quote
    assert quote is not None
    payments = protocol.offer.requested_payments[RULES.sols_tail_hash]
    assert [
        (payment.puzzle_hash, int(payment.amount))
        for payment in payments
    ] == [
        (CONFIG.reserve_puzzle_hash, quote.principal_sols_mojos),
        (
            RULES.protocol_treasury_puzzle_hash,
            quote.fee_split.protocol_fee_sols_mojos,
        ),
        (
            CONFIG.sgt_rewards_puzzle_hash,
            quote.fee_split.sgt_rewards_fee_sols_mojos,
        ),
    ]


def test_sols_buyer_offer_rejects_wrong_vault_and_amount() -> None:
    fixture = _fixture()
    buyer = prepare_sols_buyer_offer(
        payment_coin=fixture.payment_coin,
        payment_public_key=OWNER_PK,
        payment_lineage_proof=fixture.payment_lineage,
        receipt=fixture.receipt,
        config=CONFIG,
        vault_launcher_id=VAULT_LAUNCHER,
    )
    with pytest.raises(SolsSwapOfferError, match="different vault"):
        validate_sols_buyer_offer(
            buyer_offer=buyer.offer,
            receipt=fixture.receipt,
            config=CONFIG,
            vault_launcher_id=b32(101),
        )

    wrong_quote = fixture.receipt.sols_to_deed_quote
    assert wrong_quote is not None
    altered = replace(
        fixture.receipt,
        sols_to_deed_quote=replace(
            wrong_quote,
            buyer_total_sols_mojos=wrong_quote.buyer_total_sols_mojos + 1,
        ),
    )
    with pytest.raises(SolsSwapOfferError, match="amount"):
        validate_sols_buyer_offer(
            buyer_offer=buyer.offer,
            receipt=altered,
            config=CONFIG,
            vault_launcher_id=VAULT_LAUNCHER,
        )

    replayed = replace(
        fixture.receipt,
        operation_hash=b32(102),
    )
    with pytest.raises(SolsSwapOfferError, match="pool operation"):
        validate_sols_buyer_offer(
            buyer_offer=buyer.offer,
            receipt=replayed,
            config=CONFIG,
            vault_launcher_id=VAULT_LAUNCHER,
        )


def test_protocol_offer_rejects_stale_pool_coin() -> None:
    fixture = _fixture()
    stale_pool = Coin(
        b32(110),
        fixture.pool_coin.puzzle_hash,
        fixture.pool_coin.amount,
    )
    with pytest.raises(SolsSwapOfferError, match="pool coin"):
        build_sols_to_deed_protocol_offer(
            receipt=fixture.receipt,
            config=CONFIG,
            parameters=PARAMETERS,
            collection=COLLECTION,
            pause=None,
            statutes_state=STATUTES_STATE,
            statutes_coin=fixture.statutes_coin,
            statutes_launcher_id=STATUTES_LAUNCHER,
            statutes_lineage_proof=lineage(111),
            collections=[COLLECTION],
            pauses=[],
            vault_coin=fixture.vault_coin,
            vault_launcher_id=VAULT_LAUNCHER,
            vault_lineage_proof=lineage(113),
            vault_owner_pubkey=OWNER_PK,
            vault_auth_type=AUTH_TYPE_BLS,
            vault_members_merkle_root=MEMBERS_ROOT,
            identity_attest_root=IDENTITY_ROOT,
            zkpassport_bridge_policy_hash=RULES.zkpassport_policy_hash,
            vault_signature_data=None,
            pool_coin=stale_pool,
            pool_lineage_proof=lineage(115),
            custody_coin=fixture.custody_coin,
            custody_lineage_proof=lineage(117),
            quote_expires_at=QUOTE_EXPIRES,
        )


def test_deed_to_sols_offer_bootstraps_atomically_and_preserves_anchor() -> None:
    empty_pool_full = make_pool_v4_full(CONFIG, EMPTY_POOL)
    uncurried_pool = empty_pool_full.uncurry()
    assert uncurried_pool is not None
    _, pool_args = uncurried_pool
    empty_pool_inner = list(pool_args.as_iter())[1]
    pool_coin, pool_lineage, _ = _singleton_child(
        launcher_id=POOL_LAUNCHER,
        parent_inner=empty_pool_inner,
        current_inner=empty_pool_inner,
        seed=120,
    )

    vault_full = puzzle_for_vault_v2_full(
        vault_launcher_id=VAULT_LAUNCHER,
        owner_pubkey=OWNER_PK,
        auth_type=AUTH_TYPE_BLS,
        members_merkle_root=MEMBERS_ROOT,
        pool_launcher_id=POOL_LAUNCHER,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=RULES.zkpassport_policy_hash,
    )
    vault_uncurried = vault_full.uncurry()
    assert vault_uncurried is not None
    _, vault_args = vault_uncurried
    vault_inner = list(vault_args.as_iter())[1]
    vault_coin, vault_lineage, _ = _singleton_child(
        launcher_id=VAULT_LAUNCHER,
        parent_inner=vault_inner,
        current_inner=vault_inner,
        seed=121,
    )

    deed_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (DEED_LAUNCHER, CONFIG.deed_launcher_puzzle_hash),
        )
    )
    smart_deed_inner = make_smart_deed_inner(
        deed_singleton_struct_program=deed_struct,
        protocol_did_puzhash=b32(122),
        par_value_mojos=PAR_VALUE,
        asset_class=1,
        property_id_canon=PROPERTY_ID,
        collection_id_canon=COLLECTION.collection_id,
        share_ppm=SHARE_PPM,
        jurisdiction=b"US-MI",
        royalty_puzhash=b32(123),
        royalty_bps=0,
        pool_singleton_launcher_id=POOL_LAUNCHER,
        pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
        p2_pool_mod_hash=CONFIG.p2_pool_v2_mod_hash,
        p2_vault_mod_hash=CONFIG.p2_vault_mod_hash,
    )
    p2_vault_inner = puzzle_hash_for_p2_vault(VAULT_LAUNCHER)
    current_deed_inner = Program.to(
        load_puzzle("p2_vault.clsp").curry(
            SINGLETON_MOD_HASH,
            VAULT_LAUNCHER,
            SINGLETON_LAUNCHER_HASH,
        )
    )
    assert bytes32(current_deed_inner.get_tree_hash()) == p2_vault_inner
    held_deed_coin, held_deed_lineage, _ = _deed_singleton_child(
        parent_inner=Program.to(1),
        current_inner=current_deed_inner,
        seed=124,
    )
    ephemeral = Coin(
        held_deed_coin.name(),
        bytes32(
            SINGLETON_MOD.curry(
                deed_struct,
                smart_deed_inner,
            ).get_tree_hash()
        ),
        1,
    )
    custody_inner = load_puzzle("p2_pool_v2.clsp").curry(
        CONFIG.p2_pool_v2_mod_hash,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER,
        SINGLETON_LAUNCHER_HASH,
        DEED_COMMITMENT,
    )
    custody_id = Coin(
        ephemeral.name(),
        bytes32(
            SINGLETON_MOD.curry(
                deed_struct,
                custody_inner,
            ).get_tree_hash()
        ),
        1,
    ).name()
    seller_inner_hash = b32(125)
    receipt = prepare_deed_to_sols(
        pool_coin_id=pool_coin.name(),
        state=EMPTY_POOL,
        inventory=(),
        deed_launcher_id=DEED_LAUNCHER,
        custody_coin_id=custody_id,
        deed_commitment=DEED_COMMITMENT,
        collection=COLLECTION,
        share_ppm=SHARE_PPM,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=vault_coin.name(),
        seller_sols_puzzle_hash=seller_inner_hash,
        quote_expires_at=QUOTE_EXPIRES,
    )
    statutes_inner = make_statutes_inner(
        singleton_struct=CONFIG.statutes_singleton_struct,
        governance_singleton_struct=CONFIG.governance_singleton_struct,
        permanent_rules=RULES,
        state=STATUTES_STATE,
    )
    statutes_coin, statutes_lineage, _ = _singleton_child(
        launcher_id=STATUTES_LAUNCHER,
        parent_inner=statutes_inner,
        current_inner=statutes_inner,
        seed=126,
    )
    reserve_cat = construct_cat_puzzle(
        CAT_MOD,
        RULES.sols_tail_hash,
        RESERVE_INNER,
    )
    reserve_coin = Coin(b32(127), bytes32(reserve_cat.get_tree_hash()), 1)
    protocol = build_deed_to_sols_protocol_offer(
        receipt=receipt,
        config=CONFIG,
        parameters=PARAMETERS,
        collection=COLLECTION,
        pause=None,
        statutes_state=STATUTES_STATE,
        statutes_coin=statutes_coin,
        statutes_launcher_id=STATUTES_LAUNCHER,
        statutes_lineage_proof=statutes_lineage,
        collections=[COLLECTION],
        pauses=[],
        vault_coin=vault_coin,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_lineage_proof=vault_lineage,
        vault_owner_pubkey=OWNER_PK,
        vault_auth_type=AUTH_TYPE_BLS,
        vault_members_merkle_root=MEMBERS_ROOT,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=RULES.zkpassport_policy_hash,
        vault_signature_data=None,
        pool_coin=pool_coin,
        pool_lineage_proof=pool_lineage,
        p2_vault_deed_coin=held_deed_coin,
        p2_vault_deed_lineage_proof=held_deed_lineage,
        smart_deed_inner=smart_deed_inner,
        par_value=PAR_VALUE,
        asset_class=1,
        property_id=PROPERTY_ID,
        reserve_cat_coin=reserve_coin,
        reserve_cat_lineage_proof=LineageProof(),
        reserve_inner_puzzle=RESERVE_INNER,
        quote_expires_at=QUOTE_EXPIRES,
    )
    quote = receipt.deed_to_sols_quote
    assert quote is not None
    assert quote.reserve_sols_mojos_paid == 0
    assert quote.fresh_sols_mojos_minted == quote.seller_sols_mojos
    assert receipt.next_state.economics.reserve_sols_mojos == 1
    assert protocol.offer.is_valid()
    spend = protocol.offer.to_valid_spend()
    assert len(spend.coin_spends) == 7
    assert protocol.reserve_cat_spend.coin == reserve_coin
    assert set(protocol.offer.requested_payments) == {RULES.sols_tail_hash}
    seller_payment = protocol.offer.requested_payments[
        RULES.sols_tail_hash
    ][0]
    assert seller_payment.puzzle_hash == seller_inner_hash
    assert int(seller_payment.amount) == quote.seller_sols_mojos
