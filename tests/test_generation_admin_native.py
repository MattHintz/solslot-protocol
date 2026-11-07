"""New registry paired with real recovery-aware MIPS/EIP-712 administrators.

Keys are deterministic simulator-only fixtures, never user credentials.
"""
import pytest
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles.admin_authority_v3_driver import (
    ADMIN_AUTHORITY_FUNDING_AMOUNT, AUTHORITY_LAUNCHER_AMOUNT,
    build_genesis_admin_authority_v3, build_authority_operational_mips_spend,
    build_identity_operational_action, build_identity_operational_solution, build_operational_solution,
)
from solslot_puzzles.generation_admin import pause_action, publication_action
from solslot_puzzles.generation_registry import Registry, inner_solution
from tests.test_admin_authority_v3 import _compressed_pubkey, _eip_member_solution, _singleton_spend
from tests.test_generation_registry_native import Singleton, b32


@pytest.mark.asyncio
@pytest.mark.parametrize('coadmin_slot', [1, 2])
async def test_pause_requires_exact_scope_and_both_administrator_identities(coadmin_slot):
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client, acs = SimClient(sim), Program.to(1)
        await sim.farm_block(acs.get_tree_hash())
        origins = [r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())]
        parent, registry_parent = origins[:2]
        daily = tuple(keys.PrivateKey(bytes([v]) * 32) for v in (0x11, 0x22, 0x33))
        recovery = tuple(AugSchemeMPL.key_gen(bytes([v]) * 32) for v in (0x41, 0x42, 0x43))
        authority = build_genesis_admin_authority_v3(parent_coin_id=parent.name(), network='testnet11',
            daily_compressed_pubkeys=tuple(_compressed_pubkey(k) for k in daily),
            recovery_bls_pubkeys=tuple(bytes(k.get_g1()) for k in recovery),
            source_manifest_hash=b32(88), authority_puzzle_version=4)
        targets = [(authority.inner_puzzle, AUTHORITY_LAUNCHER_AMOUNT)] + [
            (i.custody_reveal, i.launcher_amount) for i in authority.identity_vaults]
        conditions, launches = [], []
        for inner, amount in targets:
            more, launch = launch_conditions_and_coinsol(parent, inner, [], uint64(amount))
            conditions.extend(more); launches.append(launch)
        conditions.append(Program.to([51, acs.get_tree_hash(), int(parent.amount) - ADMIN_AUTHORITY_FUNDING_AMOUNT]))
        registry_id = Coin(registry_parent.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        registry = Registry(b32(1), registry_id, b32(2), authority.authority_launcher_id, ())
        reg_conditions, reg_launch = launch_conditions_and_coinsol(registry_parent, registry.inner(), [], uint64(1))
        reg_conditions.append(Program.to([51, acs.get_tree_hash(), int(registry_parent.amount) - 1]))
        genesis = [make_spend(parent, acs, Program.to(conditions)), *launches,
            make_spend(registry_parent, acs, Program.to(reg_conditions)), reg_launch]
        assert (await client.push_tx(SpendBundle(genesis, G2Element())))[0] == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        reg = Singleton(registry.inner(), reg_launch)
        coins = [compute_additions(s)[0] for s in launches]
        action = pause_action(registry.generation, reg.coin.puzzle_hash, 0, 3)
        mips = build_authority_operational_mips_spend(authority=authority,
            current_authority_inner_puzzle=authority.inner_puzzle,
            current_identities=authority.identity_vaults,
            current_identity_coin_ids=tuple(c.name() for c in coins[1:]),
            authority_delegated_puzzle=action, coadmin_slot=coadmin_slot)
        auth_spend = _singleton_spend(coin=coins[0], launcher_id=authority.authority_launcher_id,
            inner_puzzle=authority.inner_puzzle, launcher_spend=launches[0], amount=AUTHORITY_LAUNCHER_AMOUNT,
            inner_solution=build_operational_solution(my_amount=AUTHORITY_LAUNCHER_AMOUNT,
                new_authority_version=2, mips_reveal=mips.reveal, mips_solution=mips.solution,
                authority_delegated_puzzle=action, identity_records=mips.identity_records))
        identity_spends = []
        for slot in mips.selected_slots:
            identity = authority.identity_vaults[slot]
            signed_action = build_identity_operational_action(identity=identity,
                current_authority_inner_puzzle=authority.inner_puzzle, authority_delegated_puzzle=action)
            identity_spends.append(_singleton_spend(coin=coins[slot+1], launcher_id=identity.launcher_id,
                inner_puzzle=identity.custody_reveal, launcher_spend=launches[slot+1], amount=identity.launcher_amount,
                inner_solution=build_identity_operational_solution(identity=identity,
                    current_authority_inner_puzzle=authority.inner_puzzle, current_identity_coin_id=coins[slot+1].name(),
                    daily_member_solution=_eip_member_solution(daily[slot], coins[slot+1].name(), signed_action.get_tree_hash()),
                    authority_delegated_puzzle=action)))
        pause = reg.spend(inner_solution('PAUSE', reg.coin, [authority.inner_puzzle.get_tree_hash(), 3]))
        spends = [pause, auth_spend, *identity_spends]
        for omitted in range(len(spends)):
            assert (await client.push_tx(SpendBundle(spends[:omitted]+spends[omitted+1:], G2Element())))[0] == MempoolInclusionStatus.FAILED
        # A signature for scope 3 cannot be repurposed into scope 16.
        changed = reg.spend(inner_solution('PAUSE', reg.coin, [authority.inner_puzzle.get_tree_hash(), 16]))
        assert (await client.push_tx(SpendBundle([changed, *spends[1:]], G2Element())))[0] == MempoolInclusionStatus.FAILED
        assert (await client.push_tx(SpendBundle(spends, G2Element())))[0] == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        reg.advance(pause, registry.paused(3).inner())
        assert (await client.get_coin_record_by_name(reg.coin.name())).spent is False


def test_exact_publication_action_has_24_hour_window_and_generation_binding():
    first = publication_action(b32(1), b32(2), b32(3), 123456)
    assert first != publication_action(b32(4), b32(2), b32(3), 123456)
    conditions = [list(c.as_iter()) for c in first.run(Program.to([])).as_iter()]
    assert [c[1].as_int() for c in conditions[:2]] == [123456, 123456 + 86400]
    for scope in (0, 32, 64, -1, True):
        with pytest.raises(ValueError): pause_action(b32(1), b32(2), 0, scope)
