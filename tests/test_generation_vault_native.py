"""Confirmed custody vaults hold the real fixed-supply CAT in SpendSim.

All keys, coins and signatures are synthetic. These are consensus tests, not
claims that an installed Sage/Goby/MetaMask client has approved the new action.
"""
from dataclasses import replace

import pytest
import pytest_asyncio
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles.generation_sgt import GenesisIssuancePlan, build_initial_issuance, ledger_inner, transition_digest, transition_witness
from solslot_puzzles.generation_vault import vault_inner, sgt_owner, authorization_hash, authorization_solution, owner_solution, signing_digest
from solslot_puzzles.vault_driver import DEFAULT_IDENTITY_ATTEST_ROOT
from tests.test_admin_authority_v3 import _compressed_pubkey
from tests.test_generation_registry_native import Singleton, b32


@pytest_asyncio.fixture
async def custody_chain():
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client, acs = SimClient(sim), Program.to(1)
        for _ in range(4): await sim.farm_block(acs.get_tree_hash())
        origins = [r.coin for r in await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())]
        generation = b32(1)
        secret = [AugSchemeMPL.key_gen(bytes([71])*32), keys.PrivateKey(bytes([72])*32),
                  AugSchemeMPL.key_gen(bytes([73])*32)]
        kinds = [1, 3, 1]
        vaults, owners, launch_spends = [], [], []
        for origin, sk, kind in zip(origins[:3], secret, kinds):
            launcher = Coin(origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
            pk = bytes(sk.get_g1()) if kind == 1 else _compressed_pubkey(sk)
            inner = vault_inner(vault_launcher_id=launcher, owner_pubkey=pk, auth_type=kind,
                members_merkle_root=Program.to(pk).get_tree_hash(), pool_launcher_id=b32(10))
            conditions, launch = launch_conditions_and_coinsol(origin, inner, [], uint64(1))
            conditions.append(Program.to([51, acs.get_tree_hash(), int(origin.amount)-1]))
            launch_spends += [make_spend(origin, acs, Program.to(conditions)), launch]
            vaults.append(Singleton(inner, launch)); owners.append(sgt_owner(generation, launcher))
        assert (await client.push_tx(SpendBundle(launch_spends, G2Element())))[0] == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()
        # Confirmed custody first, before the final issuance plan is built.
        for v in vaults:
            record = await client.get_coin_record_by_name(v.coin.name())
            assert record.confirmed_block_index > 0 and not record.spent
            assert list(v.inner.uncurry()[1].as_iter())[4].as_atom() == DEFAULT_IDENTITY_ATTEST_ROOT
        origin, ledger_origin = origins[3:5]
        ledger_id = Coin(ledger_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        plan = GenesisIssuancePlan(origin.name(), generation, ledger_id, b32(2), b32(3),
                                  tuple(o.get_tree_hash() for o in owners), b32(44))
        bindings, issue = plan.bindings(), build_initial_issuance(plan)
        inner = ledger_inner(bindings, issue.holdings, 0)
        conditions, launch = launch_conditions_and_coinsol(ledger_origin, inner, [], uint64(1))
        conditions.append(Program.to([51, acs.get_tree_hash(), int(ledger_origin.amount)-1]))
        ledger = Singleton(inner, launch)
        init = ledger.spend(issue.ledger_initialization())
        genesis = [make_spend(origin, acs, Program.to([[51, issue.eve_coin.puzzle_hash, 1_000_000],
                [51, acs.get_tree_hash(), int(origin.amount)-1_000_000]])), issue.eve_spend,
            make_spend(ledger_origin, acs, Program.to(conditions)), launch, init]
        assert (await client.push_tx(SpendBundle(genesis, G2Element())))[0] == MempoolInclusionStatus.SUCCESS
        await sim.farm_block(); ledger.advance(init, inner)
        yield dict(sim=sim, client=client, bindings=bindings, issue=issue, owners=owners, vaults=vaults,
                   secret=secret, kinds=kinds, ledger=ledger)


def transfer(c, slot=0, attack=None):
    b, issue, vault, ledger = c['bindings'], c['issue'], c['vaults'][slot], c['ledger']
    coin, source = issue.coins[slot], issue.outputs[slot]
    original_outputs = (replace(source, owner=c['owners'][(slot+1)%3].get_tree_hash()),)
    outputs = original_outputs
    digest = transition_digest(b, coin, 'TRANSFER', original_outputs)
    expiry = int(c['sim'].timestamp)+600
    operation = authorization_hash(b.generation, vault.coin.name(), coin.name(), digest, expiry)
    sk = c['secret'][slot]
    if c['kinds'][slot] == 1:
        aggregate = AugSchemeMPL.sign(sk, bytes(operation)+vault.coin.name()+DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
        compact = b''
    else:
        compact = sk.sign_msg_hash(signing_digest(b.generation,vault.coin.name(),coin.name(),digest,expiry)).to_bytes()[:64]
        aggregate = G2Element()
    if attack == 'unsigned': compact, aggregate = bytes(64), G2Element()
    if attack == 'changed_destination': outputs = (replace(source, owner=b32(88)),)
    if attack == 'changed_amount': outputs = (replace(original_outputs[0], amount=9999), replace(source, amount=1))
    if attack in {'changed_destination','changed_amount'}: digest = transition_digest(b, coin, 'TRANSFER', outputs)
    witness, tree = transition_witness(b, issue.holdings, coin, source, 'TRANSFER', outputs)
    generation = b32(89) if attack == 'wrong_generation' else b.generation
    expires = expiry+1 if attack == 'changed_expiry' else expiry
    vault_spend = vault.spend(authorization_solution(generation, vault.coin, vault.inner, coin.name(), digest, expires, compact))
    owning_vault = c['vaults'][(slot+1)%3] if attack == 'wrong_vault' else vault
    solution = Program.to([b'TRANSFER', coin.name(), coin.amount, ledger.inner.get_tree_hash(), c['owners'][slot],
        owner_solution(owning_vault.coin, owning_vault.inner, coin.name(), 'TRANSFER', outputs, expires), b'',
        [v.descriptor() for v in outputs]])
    eve_inner = list(Program.from_bytes(bytes(issue.eve_spend.puzzle_reveal)).uncurry()[1].as_iter())[2]
    cat = SpendableCAT(coin=coin, limitations_program_hash=b.tail_hash, inner_puzzle=source.inner(b),
        inner_solution=solution, lineage_proof=LineageProof(issue.eve_coin.parent_coin_info,eve_inner.get_tree_hash(),issue.eve_coin.amount))
    cats = unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat])
    ledger_spend = ledger.spend(Program.to([b'UPDATE',[witness]]))
    spends = [*cats.coin_spends,ledger_spend,vault_spend]
    if attack == 'missing_vault': spends.pop()
    if attack == 'missing_cat': spends=spends[1:]
    return SpendBundle(spends,aggregate), outputs, tree, ledger_spend, vault_spend


@pytest.mark.asyncio
@pytest.mark.parametrize('slot',[0,1])
async def test_confirmed_bls_and_evm_custody_receives_then_transfers_without_id(custody_chain,slot):
    c=custody_chain; bundle, outputs, tree, led_spend, vault_spend=transfer(c,slot)
    assert await c['client'].push_tx(bundle) == (MempoolInclusionStatus.SUCCESS,None)
    await c['sim'].farm_block()
    c['ledger'].advance(led_spend,ledger_inner(c['bindings'],tree,1))
    c['vaults'][slot].advance(vault_spend,c['vaults'][slot].inner)
    received=outputs[0].coin(c['bindings'],c['issue'].coins[slot].name())
    assert not (await c['client'].get_coin_record_by_name(received.name())).spent
    assert tree.root.total==1_000_000 and tree.root.eligible==30_000
    assert (await c['client'].push_tx(bundle))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('slot',[0,1])
@pytest.mark.parametrize('attack',['missing_vault','missing_cat','unsigned','changed_destination','changed_amount',
                                  'changed_expiry','wrong_generation','wrong_vault'])
async def test_custody_rejects_substitution_and_missing_cospend(custody_chain,slot,attack):
    c=custody_chain
    # Some malformed EVM signatures are rejected during direct construction;
    # otherwise SpendSim must reject the submitted complete native bundle.
    try: bundle,*_=transfer(c,slot,attack)
    except ValueError:
        assert slot==1 and attack in {'unsigned','changed_destination','changed_amount','changed_expiry','wrong_generation'}
    else: assert (await c['client'].push_tx(bundle))[0] == MempoolInclusionStatus.FAILED
