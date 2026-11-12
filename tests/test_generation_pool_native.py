"""Actual CAT/deed swaps plus a real holder-ratified stable pool upgrade.

Synthetic economic witnesses isolate asset settlement. Native governance uses
real issued holders and clocks. Legacy statutes are NOT whole-genesis evidence.
"""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_ints import uint64
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_registry import CodeChange, UpgradePlan
from solslot_puzzles.generation_transactions import ratify_upgrade, activate_upgrade, NativeOperation
from solslot_puzzles.sols_swap_v4_driver import (
    aggregate_sols_to_deed_swap, build_sols_to_deed_protocol_offer, prepare_vault_sols_buyer_offer,
    build_deed_to_sols_protocol_offer,
)
from tests.test_generation_governance_native import generation, unlock_all
from tests.test_generation_transactions_native import close_bill, tip, apply
from tests.test_sols_swap_v4_driver import (
    CONFIG, EMPTY_POOL, STATUTES_STATE, VAULT_LAUNCHER, b32,
    _fixture, _forward_arguments, _reverse_arguments, _assert_signed_consensus,
)


def generation_permanent():
    from solslot_puzzles.generation_sols_tail import pool_token_tail_hash
    return replace(CONFIG,vault_v2_mod_hash=load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash(),
        permanent_rules=replace(CONFIG.permanent_rules,sols_tail_hash=pool_token_tail_hash(CONFIG.pool_launcher_id)))


def swap(version=1, *, policy_hash=None):
    parameters = GenerationParameters(*(b32(n) for n in range(210, 215))).economic_parameters()
    permanent = generation_permanent()
    pool = GenerationPool(b32(201), b32(202), b32(203), permanent, replace(EMPTY_POOL,state_version=2), version=version,
        module_hash=policy_hash or load_puzzle(f'generation_pool_logic_v{version}.clsp').get_tree_hash())
    config = pool.config()
    statutes = replace(STATUTES_STATE, parameters_root=Program.to(list(parameters.as_tuple())).get_tree_hash(), permanent_rules_hash=permanent.permanent_rules.commitment_hash)
    fixture = _fixture(parameters=parameters, config=config, statutes_state=statutes)
    buyer = prepare_vault_sols_buyer_offer(payment_coin=fixture.payment_coin,
        payment_lineage_proof=fixture.payment_lineage, receipt=fixture.receipt,
        config=config, vault_launcher_id=VAULT_LAUNCHER)
    protocol = build_sols_to_deed_protocol_offer(**_forward_arguments(fixture,
        parameters=parameters, config=config, statutes_state=statutes), vault_signature_data=None)
    aggregate = aggregate_sols_to_deed_swap(buyer_offer=buyer.offer, protocol_offer=protocol,
        receipt=fixture.receipt, config=config, vault_launcher_id=VAULT_LAUNCHER)
    return fixture, pool.with_economics(fixture.receipt.current_state), protocol, aggregate.aggregate_offer.to_valid_spend()


@pytest.mark.parametrize('version', [1, 2])
def test_generation_pool_performs_native_swap_before_and_after_policy_upgrade(version):
    fixture, pool, protocol, bundle = swap(version)
    _assert_signed_consensus(bundle)
    from chia.wallet.util.compute_additions import compute_additions
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
    next_pool = pool.with_economics(fixture.receipt.next_state)
    outputs = compute_additions(protocol.pool_spend)
    assert len(outputs) == 1 and outputs[0].puzzle_hash == puzzle_for_singleton(pool.launcher_id, next_pool.inner()).get_tree_hash()
    quote = fixture.receipt.sols_to_deed_quote.fee_split
    assert (quote.total_fee_sols_mojos, quote.protocol_fee_sols_mojos, quote.sgt_rewards_fee_sols_mojos) == (300, 210, 90)
    assert pool.config().permanent_rules.sols_tail_hash == next_pool.config().permanent_rules.sols_tail_hash
    from chia.wallet.cat_wallet.cat_utils import CAT_MOD
    from chia.wallet.util.curry_and_treehash import curry_and_treehash, calculate_hash_of_quoted_mod_hash
    def cat_hash(inner_hash):
        return curry_and_treehash(calculate_hash_of_quoted_mod_hash(CAT_MOD.get_tree_hash()),
            Program.to(CAT_MOD.get_tree_hash()).get_tree_hash(),
            Program.to(pool.permanent.permanent_rules.sols_tail_hash).get_tree_hash(), inner_hash)
    all_outputs = [coin for spend in bundle.coin_spends for coin in compute_additions(spend)]
    for inner, amount in ((pool.permanent.reserve_puzzle_hash, 30000),
        (pool.permanent.permanent_rules.protocol_treasury_puzzle_hash, 210),
        (pool.permanent.sgt_rewards_puzzle_hash, 90)):
        assert [int(coin.amount) for coin in all_outputs if coin.puzzle_hash == cat_hash(inner)] == [amount]
    from solslot_puzzles.generation_economic_reader import reconstruct_economic_successor
    transition = reconstruct_economic_successor(protocol.pool_spend, pool)
    assert transition.after.inner() == next_pool.inner() and transition.action == 'SOLS_TO_DEED'
    with pytest.raises(ValueError): reconstruct_economic_successor(protocol.pool_spend, next_pool)


def test_existing_sols_custody_and_deed_destinations_survive_pool_policy_activation():
    from solslot_puzzles.vault_sols_v1 import puzzle_for_vault_sols_cat
    from solslot_puzzles.pool_v4_driver import p2_pool_v2_inner_hash
    pool = GenerationPool(b32(201), b32(202), b32(203), CONFIG, EMPTY_POOL)
    upgraded = replace(pool, module_hash=load_puzzle('generation_pool_logic_v2.clsp').get_tree_hash(), version=2)
    assert pool.inner() != upgraded.inner()
    assert puzzle_for_vault_sols_cat(config=pool.config(), vault_launcher_id=VAULT_LAUNCHER) == puzzle_for_vault_sols_cat(
        config=upgraded.config(), vault_launcher_id=VAULT_LAUNCHER)
    assert p2_pool_v2_inner_hash(config=pool.config(), deed_commitment=b32(90)) == p2_pool_v2_inner_hash(
        config=upgraded.config(), deed_commitment=b32(90))


@pytest.mark.parametrize('version', [1, 2])
def test_generation_pool_deed_deposit_issues_sols_and_reader_proves_successor(version):
    parameters = GenerationParameters(*(b32(n) for n in range(210, 215))).economic_parameters()
    permanent = generation_permanent()
    pool = GenerationPool(b32(201), b32(202), b32(203), permanent, replace(EMPTY_POOL,state_version=2), version=version,
        module_hash=load_puzzle(f'generation_pool_logic_v{version}.clsp').get_tree_hash())
    statutes = replace(STATUTES_STATE, parameters_root=Program.to(list(parameters.as_tuple())).get_tree_hash(), permanent_rules_hash=permanent.permanent_rules.commitment_hash)
    args = _reverse_arguments(parameters=parameters, config=pool.config(), statutes_state=statutes)
    protocol = build_deed_to_sols_protocol_offer(**args, vault_signature_data=None)
    bundle = protocol.offer.to_valid_spend()
    _assert_signed_consensus(bundle)
    from solslot_puzzles.generation_economic_reader import reconstruct_economic_successor
    transition = reconstruct_economic_successor(protocol.pool_spend, pool)
    assert transition.after.economics == args['receipt'].next_state
    assert transition.action == 'DEED_TO_SOLS' and transition.after.version == version


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('reverse', [False, True])
def test_generation_pool_native_evm_vault_signature_is_bound_to_exact_swap(version, reverse):
    from eth_keys import keys
    from solslot_puzzles.sols_swap_v4_driver import prepare_unsigned_deed_to_sols_swap, prepare_unsigned_sols_to_deed_swap
    from solslot_puzzles.vault_v2_driver import signing_digest_for_sols_swap
    key=keys.PrivateKey(bytes([91])*32);owner=key.public_key.to_compressed_bytes()
    parameters=GenerationParameters(*(b32(n) for n in range(210,215))).economic_parameters()
    permanent=generation_permanent()
    pool=GenerationPool(b32(201),b32(202),b32(203),permanent,replace(EMPTY_POOL,state_version=2),version=version,
        module_hash=load_puzzle(f'generation_pool_logic_v{version}.clsp').get_tree_hash())
    config=pool.config();statutes=replace(STATUTES_STATE,parameters_root=Program.to(list(parameters.as_tuple())).get_tree_hash(),permanent_rules_hash=permanent.permanent_rules.commitment_hash)
    if reverse:
        args=_reverse_arguments(auth_type=3,owner_pubkey=owner,parameters=parameters,config=config,statutes_state=statutes)
        evidence=prepare_unsigned_deed_to_sols_swap(**args);buyer=None
    else:
        fixture=_fixture(auth_type=3,owner_pubkey=owner,parameters=parameters,config=config,statutes_state=statutes)
        args=_forward_arguments(fixture,auth_type=3,owner_pubkey=owner,parameters=parameters,config=config,statutes_state=statutes)
        buyer=prepare_vault_sols_buyer_offer(payment_coin=fixture.payment_coin,payment_lineage_proof=fixture.payment_lineage,
            receipt=fixture.receipt,config=config,vault_launcher_id=VAULT_LAUNCHER).offer
        evidence=prepare_unsigned_sols_to_deed_swap(buyer_offer=buyer,**args)
    vault=next(s for s in evidence.coin_spends if s.coin.name()==evidence.vault_coin_id)
    intent=list(list(list(Program.from_bytes(bytes(vault.solution)).as_iter())[2].as_iter())[4].as_iter())
    authority=list(intent[4].as_iter());transfer=list(intent[3].as_iter())
    kwargs=dict(pool_coin_id=type(pool.generation)(authority[0].as_atom()),
        pool_inner_puzzle_hash=type(pool.generation)(authority[1].as_atom()),quote_expires_at=intent[1].as_int())
    if transfer:
        kwargs.update(deed_launcher_id=type(pool.generation)(transfer[0].as_atom()),
            p2_vault_coin_id=type(pool.generation)(transfer[1].as_atom()),smart_deed_inner_puzzle_hash=type(pool.generation)(transfer[2].as_atom()))
    signature=key.sign_msg_hash(signing_digest_for_sols_swap(args['receipt'].operation_hash,evidence.vault_coin_id,**kwargs)).to_bytes()[:64]
    if reverse:
        protocol=build_deed_to_sols_protocol_offer(**args,vault_signature_data=signature)
        bundle=protocol.offer.to_valid_spend()
    else:
        protocol=build_sols_to_deed_protocol_offer(**args,vault_signature_data=signature)
        bundle=aggregate_sols_to_deed_swap(buyer_offer=buyer,protocol_offer=protocol,receipt=args['receipt'],
            config=config,vault_launcher_id=VAULT_LAUNCHER).aggregate_offer.to_valid_spend()
    _assert_signed_consensus(bundle)
    raw=Program.from_bytes(bytes(protocol.vault_spend.solution)).as_python()
    raw[2][4][2]=bytes([0])*64
    changed=make_spend(protocol.vault_spend.coin,Program.from_bytes(bytes(protocol.vault_spend.puzzle_reveal)),Program.to(raw))
    tampered=SpendBundle([changed if s.coin==changed.coin else s for s in bundle.coin_spends],bundle.aggregated_signature)
    with pytest.raises(Exception):_assert_signed_consensus(tampered)


@pytest.mark.parametrize('mutation', ['fees', 'policy', 'version', 'treasury', 'identity', 'inventory', 'supply', 'statutes'])
def test_generation_pool_rejects_asset_or_policy_substitution(mutation):
    _, pool, protocol, bundle = swap()
    spend = protocol.pool_spend
    raw = Program.from_bytes(bytes(spend.solution)).as_python()
    reveal = Program.from_bytes(bytes(spend.puzzle_reveal))
    if mutation == 'fees': raw[2][4][26], raw[2][4][27] = 90, 210
    elif mutation == 'policy': raw[2][5] = Program.to((1, 1)).as_python()
    elif mutation == 'version':
        reveal = puzzle_for_singleton(
            pool.launcher_id, replace(pool, version=2).inner())
    elif mutation == 'treasury':
        reveal = puzzle_for_singleton(
            pool.launcher_id, replace(pool, permanent=replace(pool.permanent, sgt_rewards_puzzle_hash=b32(91))).inner())
    elif mutation == 'identity': raw[2][4][19] = bytes(load_puzzle('generation_pool_logic_v1.clsp').get_tree_hash())
    elif mutation == 'inventory': raw[2][4][28] = bytes(b32(92))
    elif mutation == 'statutes': raw[2][6] = bytes(b32(93))
    else: raw[2][4][25] = 1
    changed = make_spend(spend.coin, reveal, Program.to(raw))
    corrupted = SpendBundle([changed if s.coin == spend.coin else s for s in bundle.coin_spends], bundle.aggregated_signature)
    with pytest.raises(Exception): _assert_signed_consensus(corrupted)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation', ['pool','pool-reserve'], indirect=True)
async def test_holder_vote_delayed_pool_upgrade_preserves_all_bindings_and_economics(generation):
    c = generation; pool = c['pool']; pc = c['pool_coin']
    initial_pool = pool
    from tests.test_generation_sols_genesis_native import prepare_signed_sols_seed
    issuance, pool, seed, _, _ = await prepare_signed_sols_seed(c)
    assert await c['client'].push_tx(issuance.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c['sim'].farm_block()
    pc.advance(issuance.spends[1], pool.inner()); c['pool'] = pool
    v2 = load_puzzle('generation_pool_logic_v2.clsp')
    old_read = pc.spend(pool.solution(pc.coin, 'READ', b'PROVE_STATE'))
    assert (await c['client'].push_tx(SpendBundle([old_read], G2Element())))[0] != MempoolInclusionStatus.SUCCESS
    unauthorized = pc.spend(pool.solution(pc.coin, 'UPGRADE', [c['registry'].inner().get_tree_hash(), b32(57),
        v2.get_tree_hash(), 2, 1]))
    assert (await c['client'].push_tx(SpendBundle([unauthorized], G2Element())))[0] != MempoolInclusionStatus.SUCCESS
    plan = UpgradePlan(b32(54), (CodeChange(pool.component_id, pool.logic_hash(), v2.get_tree_hash(), 2, 1),))
    proposal = await close_bill(c, Program.to([b'UPGRADE', c['registry'].nonce, plan.program()]))
    operation, gov, registry = ratify_upgrade(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']), proposal, plan)
    ticket = operation.auxiliary_outputs[0]
    await apply(c, operation); c.update(gov=gov, registry=registry)
    args = (gov, tip(c['gov_coin']), registry, tip(c['registry_coin']), plan, ticket, ((pool, tip(pc)),))
    operation, activated, states = activate_upgrade(*args)
    assert (await c['client'].push_tx(operation.bundle()))[0] != MempoolInclusionStatus.SUCCESS
    c['sim'].pass_time(uint64(86401)); await c['sim'].farm_block()
    for index in range(len(operation.spends)):
        partial = SpendBundle(list(operation.spends[:index] + operation.spends[index+1:]), G2Element())
        assert (await c['client'].push_tx(partial))[0] != MempoolInclusionStatus.SUCCESS
    change = next(s for s in operation.spends if s.coin == pc.coin)
    # A reveal that tries to mutate the preserved reserve/economic state cannot
    # consume the actual current coin even with the real ratification ticket.
    wrong = replace(pool, economics=replace(pool.economics, state_version=3))
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
    counterfeit = make_spend(change.coin, puzzle_for_singleton(pool.launcher_id, wrong.inner()),
                             Program.from_bytes(bytes(change.solution)))
    tampered = SpendBundle([counterfeit if s.coin == pc.coin else s for s in operation.spends], G2Element())
    assert (await c['client'].push_tx(tampered))[0] != MempoolInclusionStatus.SUCCESS
    await apply(c, operation)
    pc.advance(change, states[0].inner()); c.update(pool=states[0], registry=activated)
    assert states[0].state() == pool.state() and states[0].launcher_id == pool.launcher_id
    assert states[0].version == 2 and states[0].component() in activated.components
    read = pc.spend(states[0].solution(pc.coin, 'READ', b'PROVE_STATE'))
    await apply(c, NativeOperation(pool.generation, 'POOL_STATE_PROOF', (read,),
        (tip(pc).advanced(read, states[0].inner()),)))
    assert (await c['client'].push_tx(operation.bundle()))[0] != MempoolInclusionStatus.SUCCESS
    await unlock_all(c, proposal)
    assert c['tree'].root.total == 1_000_000 and c['tree'].root.eligible == 30_000
    from solslot_puzzles.generation_economic_reader import decode_initial_economic_inner, reconstruct_economic_successor
    decoded = decode_initial_economic_inner(initial_pool.inner(), generation=pool.generation, registry_id=pool.registry_id,
        governance_id=pool.governance_id, launcher_id=pool.launcher_id)
    decoded = reconstruct_economic_successor(issuance.spends[1], decoded).after
    assert decoded.inner() == pool.inner()
    replayed = reconstruct_economic_successor(change, decoded)
    assert replayed.after.inner() == states[0].inner() and replayed.after.state() == pool.state()
    assert reconstruct_economic_successor(read, replayed.after).after.inner() == states[0].inner()
    assert (await c['client'].get_coin_record_by_name(seed.reserve.name())).spent is False
    assert (await c['client'].get_coin_record_by_name(seed.reserve.name())).coin == seed.reserve
