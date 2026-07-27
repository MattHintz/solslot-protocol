from __future__ import annotations

from dataclasses import replace

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
import pytest

from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    PermanentRules,
    ProtocolParameters,
    ScopedPause,
    StatutesState,
    keyed_root,
)
from solslot_puzzles.sols_economics_v3 import SolsEconomicState
from solslot_puzzles.sols_pool_v4 import (
    PoolInventoryRecord,
    SolsPoolStateV4,
    canonical_inventory,
    inventory_root,
    prepare_deed_to_sols,
    prepare_sols_to_deed,
)


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


PARAMETERS = ProtocolParameters()
RULES = PermanentRules(
    sgt_tail_hash=b32(1),
    sgt_total_supply=1_000_000,
    sols_tail_hash=b32(2),
    zkpassport_policy_hash=b32(3),
    protocol_treasury_puzzle_hash=b32(4),
    network_id=b32(5),
)
COLLECTION = CollectionStatute(
    collection_id=b32(6),
    nav_micro_usd=999_000_000,
    allocation_ceiling_micro_usd=999_000_000,
    nav_version=1,
    valid_after=1_800_000_000,
    valid_until=1_800_086_400,
    status=1,
)
EMPTY = bytes32(Program.to([]).get_tree_hash())
STATUTES = StatutesState(
    parameters_root=bytes32(
        Program.to(list(PARAMETERS.as_tuple())).get_tree_hash()
    ),
    collections_root=keyed_root([COLLECTION]),
    oracle_root=EMPTY,
    routes_root=EMPTY,
    pauses_root=EMPTY,
    registry_version=4,
    permanent_rules_hash=RULES.commitment_hash,
)
EMPTY_STATE = SolsPoolStateV4(
    inventory_root=EMPTY,
    economics=SolsEconomicState(
        bootstrap_complete=False,
        inventory_nav_micro_usd=0,
        treasury_assets_micro_usd=0,
        proven_liabilities_micro_usd=0,
        deed_count=0,
        total_sols_mojos=0,
        reserve_sols_mojos=0,
    ),
    state_version=1,
)


def _deposit(
    *,
    state: SolsPoolStateV4 = EMPTY_STATE,
    inventory: tuple[PoolInventoryRecord, ...] = (),
    collection: CollectionStatute = COLLECTION,
    deed: bytes32 = b32(10),
    share_ppm: int = 100_000,
):
    return prepare_deed_to_sols(
        pool_coin_id=b32(11),
        state=state,
        inventory=inventory,
        deed_launcher_id=deed,
        custody_coin_id=b32((deed[0] + 2) % 256),
        deed_commitment=b32((deed[0] + 1) % 256),
        collection=collection,
        share_ppm=share_ppm,
        parameters=PARAMETERS,
        statutes_state=STATUTES,
        pause=None,
        vault_launcher_id=b32(13),
        vault_coin_id=b32(14),
        seller_sols_puzzle_hash=b32(15),
        quote_expires_at=1_800_080_000,
    )


def test_first_deed_bootstraps_at_three_dollars_thirty_three() -> None:
    receipt = _deposit()
    quote = receipt.deed_to_sols_quote
    assert quote is not None
    assert receipt.record.deed_value_micro_usd == 99_900_000
    assert quote.seller_sols_mojos == 30_000
    assert quote.reserve_sols_mojos_paid == 0
    assert quote.fresh_sols_mojos_minted == 30_000
    assert quote.next_state.total_sols_mojos == 30_000
    assert receipt.next_state.economics.inventory_nav_micro_usd == 99_900_000


def test_reserve_pays_first_and_only_exact_shortfall_is_minted() -> None:
    first = _deposit()
    second = _deposit(
        state=first.next_state,
        inventory=first.next_inventory,
        deed=b32(20),
    )
    reserve_receipt = prepare_sols_to_deed(
        pool_coin_id=b32(25),
        state=second.next_state,
        inventory=second.next_inventory,
        deed_launcher_id=first.record.deed_launcher_id,
        collection=COLLECTION,
        parameters=PARAMETERS,
        statutes_state=STATUTES,
        pause=None,
        vault_launcher_id=b32(26),
        vault_coin_id=b32(27),
        destination_p2_vault_hash=b32(28),
        quote_expires_at=1_800_080_000,
    )
    third = _deposit(
        state=reserve_receipt.next_state,
        inventory=reserve_receipt.next_inventory,
        deed=b32(30),
        share_ppm=200_000,
    )
    quote = third.deed_to_sols_quote
    assert quote is not None
    assert quote.seller_sols_mojos == 60_000
    assert quote.reserve_sols_mojos_paid == 30_000
    assert quote.fresh_sols_mojos_minted == 30_000


def test_sols_purchase_returns_principal_to_reserve_without_melt() -> None:
    deposit = _deposit()
    receipt = prepare_sols_to_deed(
        pool_coin_id=b32(21),
        state=deposit.next_state,
        inventory=deposit.next_inventory,
        deed_launcher_id=deposit.record.deed_launcher_id,
        collection=COLLECTION,
        parameters=PARAMETERS,
        statutes_state=STATUTES,
        pause=None,
        vault_launcher_id=b32(22),
        vault_coin_id=b32(23),
        destination_p2_vault_hash=b32(24),
        quote_expires_at=1_800_080_000,
    )
    quote = receipt.sols_to_deed_quote
    assert quote is not None
    assert quote.principal_sols_mojos == 30_000
    assert quote.fee_split.total_fee_sols_mojos == 300
    assert quote.fee_split.protocol_fee_sols_mojos == 90
    assert quote.fee_split.sgt_rewards_fee_sols_mojos == 210
    assert receipt.next_state.economics.total_sols_mojos == 30_000
    assert receipt.next_state.economics.reserve_sols_mojos == 30_000
    assert receipt.next_state.economics.deed_count == 0


def test_inventory_rejects_duplicates_reordering_and_summary_mismatch() -> None:
    deposit = _deposit()
    record = deposit.record
    with pytest.raises(ValueError, match="launcher IDs"):
        canonical_inventory([record, replace(record, deed_commitment=b32(30))])
    with pytest.raises(ValueError, match="commitments"):
        canonical_inventory(
            [
                record,
                replace(
                    record,
                    deed_launcher_id=b32(31),
                    custody_coin_id=b32(32),
                ),
            ]
        )
    bad = replace(
        deposit.next_state,
        economics=replace(
            deposit.next_state.economics,
            inventory_nav_micro_usd=1,
        ),
    )
    with pytest.raises(ValueError, match="inventory NAV"):
        bad.validate(deposit.next_inventory)


def test_allocation_pause_stale_nav_and_quote_expiry_fail_closed() -> None:
    constrained = replace(
        COLLECTION,
        allocation_ceiling_micro_usd=50_000_000,
    )
    with pytest.raises(ValueError, match="allocation ceiling"):
        _deposit(collection=constrained)

    pause = ScopedPause(
        scope_id=COLLECTION.collection_id,
        paused=1,
        expires_at=1_800_040_000,
        reason_hash=b32(40),
    )
    with pytest.raises(ValueError, match="paused"):
        prepare_deed_to_sols(
            pool_coin_id=b32(41),
            state=EMPTY_STATE,
            inventory=(),
            deed_launcher_id=b32(42),
            custody_coin_id=b32(57),
            deed_commitment=b32(43),
            collection=COLLECTION,
            share_ppm=100_000,
            parameters=PARAMETERS,
            statutes_state=STATUTES,
            pause=pause,
            vault_launcher_id=b32(44),
            vault_coin_id=b32(45),
            seller_sols_puzzle_hash=b32(46),
            quote_expires_at=1_800_080_000,
        )

    deposit = _deposit()
    revalued = replace(
        COLLECTION,
        nav_micro_usd=1_100_000_000,
        allocation_ceiling_micro_usd=1_200_000_000,
        nav_version=2,
    )
    with pytest.raises(ValueError, match="revaluation"):
        prepare_sols_to_deed(
            pool_coin_id=b32(47),
            state=deposit.next_state,
            inventory=deposit.next_inventory,
            deed_launcher_id=deposit.record.deed_launcher_id,
            collection=revalued,
            parameters=PARAMETERS,
            statutes_state=STATUTES,
            pause=None,
            vault_launcher_id=b32(48),
            vault_coin_id=b32(49),
            destination_p2_vault_hash=b32(50),
            quote_expires_at=1_800_080_000,
        )

    with pytest.raises(ValueError, match="outlives"):
        prepare_deed_to_sols(
            pool_coin_id=b32(51),
            state=EMPTY_STATE,
            inventory=(),
            deed_launcher_id=b32(52),
            custody_coin_id=b32(58),
            deed_commitment=b32(53),
            collection=COLLECTION,
            share_ppm=100_000,
            parameters=PARAMETERS,
            statutes_state=STATUTES,
            pause=None,
            vault_launcher_id=b32(54),
            vault_coin_id=b32(55),
            seller_sols_puzzle_hash=b32(56),
            quote_expires_at=COLLECTION.valid_until + 1,
        )


def test_operation_hash_changes_with_pool_coin_vault_and_destination() -> None:
    first = _deposit()
    second = prepare_deed_to_sols(
        pool_coin_id=b32(60),
        state=EMPTY_STATE,
        inventory=(),
        deed_launcher_id=b32(10),
        custody_coin_id=b32(12),
        deed_commitment=b32(12),
        collection=COLLECTION,
        share_ppm=100_000,
        parameters=PARAMETERS,
        statutes_state=STATUTES,
        pause=None,
        vault_launcher_id=b32(13),
        vault_coin_id=b32(14),
        seller_sols_puzzle_hash=b32(15),
        quote_expires_at=1_800_080_000,
    )
    third = prepare_deed_to_sols(
        pool_coin_id=b32(11),
        state=EMPTY_STATE,
        inventory=(),
        deed_launcher_id=b32(10),
        custody_coin_id=b32(12),
        deed_commitment=b32(12),
        collection=COLLECTION,
        share_ppm=100_000,
        parameters=PARAMETERS,
        statutes_state=STATUTES,
        pause=None,
        vault_launcher_id=b32(13),
        vault_coin_id=b32(61),
        seller_sols_puzzle_hash=b32(15),
        quote_expires_at=1_800_080_000,
    )
    assert first.operation_hash != second.operation_hash
    assert first.operation_hash != third.operation_hash
    assert inventory_root(first.next_inventory) == first.next_state.inventory_root
