"""Actual funded primary NFT -> reserve -> signed buyer offers in consensus.

Prices, property facts and keys are labeled simulator fixtures. No ACS receipt
stands in for a primary NFT, and no ID-stamped human intermediary is fabricated.
The payment CAT is synthetic, not an assertion of a live USDC representation.
"""
from dataclasses import replace

import pytest
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.conditions import CreateCoin
from chia.wallet.trading.offer import Offer, OFFER_MOD_HASH
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk, solution_for_conditions, calculate_synthetic_secret_key, DEFAULT_HIDDEN_PUZZLE_HASH)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_batch_orders import inspect_buyer_offer
from solslot_puzzles.generation_batch_settlement import build_primary_batch, build_primary_batches, XCH_ORACLE_ASSET
from solslot_puzzles.generation_economic_reader import reconstruct_economic_successor
from solslot_puzzles.generation_transactions import apply_statutes
from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver
from solslot_puzzles.protocol_statutes_v1 import CollectionStatute, OracleRound, BridgeRoute
from tests.test_generation_governance_native import generation, push, unlock_all
from tests.test_generation_mint_native import edition_for, approve, mint_spends
from tests.test_generation_transactions_native import close_bill, tip, apply
from tests.test_generation_sols_genesis_native import prepare_signed_sols_seed
from tests.test_generation_registry_native import b32


def sign_bundle(bundle, keys):
    indexed = {bytes(k.get_g1()): k for k in keys}
    signatures = []
    for spend in bundle.coin_spends:
        cd = conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 11_000_000_000)
        for public, message in pkm_pairs_for_conditions_dict(cd, spend.coin, DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA):
            signatures.append(AugSchemeMPL.sign(indexed[bytes(public)], message))
    return SpendBundle(bundle.coin_spends, AugSchemeMPL.aggregate(signatures))


async def publish(c, kind, record):
    s = c['parameters']; bill, _, _ = s.record_change(kind, (), record)
    proposal = await close_bill(c, bill)
    operation, gov, after, records = apply_statutes(c['gov'], tip(c['gov_coin']), c['registry'],
        tip(c['registry_coin']), s, tip(c['parameters_coin']), proposal, kind, (), record)
    await apply(c, operation); c.update(gov=gov, parameters=after)
    await unlock_all(c, proposal)
    return records


async def prepare(c, native, deeds=1, wanted_offset=0):
    acs = Program.to(1)
    edition = edition_for(c); proposal = await approve(c, edition)
    spends, inventories = mint_spends(c, edition, proposal)
    await push(c, spends)
    c['mint_coin'].advance(spends[2], c['mint'].minted(edition).inner())
    c['gov'] = c['gov'].executed(proposal, edition.bill())
    c['gov_coin'].advance(spends[0], c['gov'].inner())
    c['registry_coin'].advance(spends[1], c['registry'].inner())
    await unlock_all(c, proposal)
    seed_op, pool, seed, _, _ = await prepare_signed_sols_seed(c)
    assert await c['client'].push_tx(seed_op.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c['sim'].farm_block(); c['pool_coin'].advance(seed_op.spends[1], pool.inner()); c['pool'] = pool
    now = int(c['sim'].timestamp)
    collections = await publish(c, 'COLLECTION', CollectionStatute(edition.collection,
        75_000_000_000, 75_000_000_000, 1, now - 1, now + 80000, 1))
    # Real BLS buyer spends, including the CAT owner signature. No fake
    # requested-payment metadata or assumed successful wallet signature.
    key = AugSchemeMPL.key_gen(b'B' * 32); wallet = puzzle_for_pk(key.get_g1())
    synthetic = calculate_synthetic_secret_key(key, DEFAULT_HIDDEN_PUZZLE_HASH)
    origin = (await c['client'].get_coin_records_by_puzzle_hash(acs.get_tree_hash(), include_spent_coins=False))[0].coin
    amounts = (101000, 202000) if deeds==1 else (303000*deeds,)
    parent_spends = {}; coins = []; lineages = []
    if native:
        fund = make_spend(origin, acs, Program.to([[51, wallet.get_tree_hash(), a] for a in amounts]
            + [[51, acs.get_tree_hash(), int(origin.amount) - sum(amounts)]]))
        await push(c, [fund]); asset = None
        coins = [Coin(origin.name(), wallet.get_tree_hash(), uint64(a)) for a in amounts]
    else:
        tail = GENESIS_BY_ID_MOD.curry(origin.name()); asset = tail.get_tree_hash()
        eve = Coin(origin.name(), construct_cat_puzzle(CAT_MOD, asset, acs).get_tree_hash(), uint64(sum(amounts)))
        parent = make_spend(origin, acs, Program.to([[51, eve.puzzle_hash, int(eve.amount)],
            [51, acs.get_tree_hash(), int(origin.amount) - int(eve.amount)]]))
        issued = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(eve, asset, acs,
            Program.to([[51, wallet.get_tree_hash(), a] for a in amounts] + [[51, [], -113, tail, []]]),
            limitations_program_reveal=tail)])
        await push(c, [parent, *issued.coin_spends])
        coins = [Coin(eve.name(), construct_cat_puzzle(CAT_MOD, asset, wallet).get_tree_hash(), uint64(a)) for a in amounts]
        lineages = [LineageProof(eve.parent_coin_info, acs.get_tree_hash(), eve.amount)] * len(coins)
    routes = ()
    if asset:
        routes = await publish(c, 'ROUTE', BridgeRoute(b32(149), pool.generation, pool.generation, asset, asset, 2, 1))
    # Reuse the real H-system signature domain with two synthetic independent
    # source observations/operators. No future governance-price commitment.
    from solslot_puzzles.payment_artifacts_v2 import (OracleObservationV1,build_oracle_round,
        oracle_operator_set_root,oracle_round_signature_message)
    from solslot_puzzles.generation_primary_price import SignedPrimaryPrice
    observed=int(c['sim'].timestamp)
    price_keys=[AugSchemeMPL.key_gen(bytes([n])*32) for n in (81,82,83)]
    price_round=build_oracle_round(network='testnet11',sequence=1,asset_id=bytes32.zeros if native else asset,
        asset_decimals=12 if native else 2,operator_set_root=oracle_operator_set_root([bytes(k.get_g1()) for k in price_keys]),
        observations=tuple(OracleObservationV1(b32(n),bytes32.zeros if native else asset,12 if native else 2,
            10**12 if native else 100,observed,observed+600,b32(n+2)) for n in (145,146)))
    signed_price=SignedPrimaryPrice(price_round,tuple((i,bytes(AugSchemeMPL.sign(price_keys[i],
        oracle_round_signature_message(price_round.round_hash)))) for i in (0,1)))
    oracles=()
    sols = pool.permanent.permanent_rules.sols_tail_hash
    driver = chia_cat_driver(sols); orders = []
    for i, (coin, amount, wanted) in enumerate(zip(coins, amounts, (300300, 600600) if deeds==1 else (900900*deeds-wanted_offset,))):
        requested = Offer.notarize_payments({sols: [CreateCoin(b32(160 + i), uint64(wanted))]}, [coin])
        drivers = {sols: driver} | ({asset: chia_cat_driver(asset)} if asset else {})
        conditions = [[51, OFFER_MOD_HASH, amount],
            *[v.to_program() for v in Offer.calculate_announcements(requested, drivers)], [85, observed + 400]]
        if asset:
            bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(coin, asset, wallet,
                solution_for_conditions(conditions), lineage_proof=lineages[i])])
        else: bundle = SpendBundle([make_spend(coin, wallet, solution_for_conditions(conditions))], G2Element())
        signed = sign_bundle(bundle, [synthetic])
        offer = Offer(requested, WalletSpendBundle(signed.coin_spends, signed.aggregated_signature), drivers)
        orders.append(inspect_buyer_offer(offer, generation=pool.generation, sols_asset=sols, sols_driver=driver,
            payment_asset=asset, destination_inner_hash=b32(160 + i), approved_payment_assets=frozenset([asset] if asset else [])))
    # Lineage is the actual governed DID launcher, not an invented NFT source.
    item = inventories[0]
    kwargs = dict(orders=orders, inventory_item=item,
        inventory_lineage=LineageProof(item.launcher_spend.coin.parent_coin_info, amount=uint64(1)),
        pool=pool, pool_tip=tip(c['pool_coin']), statutes=c['parameters'], statutes_tip=tip(c['parameters_coin']),
        registry=c['registry'], registry_tip=tip(c['registry_coin']), sgt_bindings=c['bindings'],
        collections=collections, oracles=oracles, routes=routes, inventory=(), reserve_coin=seed.reserve,
        signed_price=signed_price, reserve_lineage=LineageProof(seed.eve.parent_coin_info,
            seed.inner.get_tree_hash(),seed.eve.amount), decimals=12 if native else 2, expires_at=observed + 300)
    if deeds==1:
        settlement = build_primary_batch(**kwargs)
    else:
        contexts=dict(kwargs);contexts.pop('inventory_item');contexts.pop('inventory_lineage')
        settlement=build_primary_batches(inventory_items=inventories[:deeds],
            inventory_lineages=(kwargs['inventory_lineage'],)+tuple(LineageProof(
                v.launcher_spend.coin.parent_coin_info,amount=uint64(1)) for v in inventories[1:deeds]),**contexts)
    # Fresh Sols issuance has exactly matching XCH backing, paid from a real
    # simulator input; it cannot steal a fee recipient's promised payment.
    origin = (await c['client'].get_coin_records_by_puzzle_hash(acs.get_tree_hash(), include_spent_coins=False))[0].coin
    backing = sum(r.deed_to_sols_quote.fresh_sols_mojos_minted for r in settlement.receipts)
    fund = make_spend(origin, acs, Program.to([[51, acs.get_tree_hash(), int(origin.amount) - backing]]))
    validator_keys = [AugSchemeMPL.key_gen(bytes([n]) * 32) for n in (71, 72, 73)]
    final = sign_bundle(SpendBundle([*settlement.bundle.coin_spends, fund], G2Element()), [synthetic, *validator_keys,*price_keys])
    return settlement, final, kwargs, coins, key, synthetic


@pytest.mark.asyncio
@pytest.mark.parametrize('generation', ['batch','batch-revenue'], indirect=True)
@pytest.mark.parametrize('native', [True, False], ids=['TXCH', 'synthetic-CAT'])
async def test_whole_signed_orders_acquire_real_primary_deed_and_back_exact_sols(generation, native, tmp_path):
    c = generation
    settlement, bundle, kwargs, _, _, _ = await prepare(c, native)
    # Persist the ACTUAL native primary/buyer/reserve intent, not an ACS
    # operation fixture. API status reads retain it across process restart.
    from solslot_api.generation_sols_batches import GenerationSolsOrderBook
    from solslot_api.generation_operations import GenerationOperationJournal
    from solslot_api.protocol_submission import PreparedProtocolBundle
    gen_id = '0x' + settlement.generation.hex()
    sols_asset = kwargs['pool'].permanent.permanent_rules.sols_tail_hash
    assets = frozenset([kwargs['orders'][0].payment_asset]) if not native else frozenset()
    book = GenerationSolsOrderBook(str(tmp_path/'orders.sqlite3'), gen_id, sols_asset, assets, signature_data=DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    journal = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), gen_id)
    for order in kwargs['orders']:
        book.place(order.offer(), payment_asset=order.payment_asset,
            destination=order.destination_inner_hash, now=int(c['sim'].timestamp))
    signed_protocol = replace(settlement, bundle=SpendBundle(settlement.bundle.coin_spends, bundle.aggregated_signature))
    retained = book.retain_settlement(signed_protocol, journal=journal, pool_tip=kwargs['pool_tip'],
        statutes_tip=kwargs['statutes_tip'], registry_tip=kwargs['registry_tip'], fee_cap=0, now=int(c['sim'].timestamp))
    identity = retained['operationId']
    assert retained['review']['issuanceBackingMojos'] == '900900'
    prepared = PreparedProtocolBundle(bundle, 0, '0x'+bundle.coin_spends[-1].coin.name().hex(), 900900)
    with pytest.raises(ValueError): journal.save_funded(identity, replace(prepared, backing_mojos=900901), int(c['sim'].timestamp))
    journal.save_funded(identity, prepared, int(c['sim'].timestamp))
    reopened_book = GenerationSolsOrderBook(str(tmp_path/'orders.sqlite3'), gen_id, sols_asset, assets, signature_data=DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    reopened_journal = GenerationOperationJournal(str(tmp_path/'ops.sqlite3'), gen_id)
    assert reopened_journal.protocol_bundle(identity) == signed_protocol.bundle
    assert reopened_journal.saved_funding(identity)['spendBundleId'] == prepared.spend_bundle_id
    original_inputs = reopened_journal.reserved_input_coin_ids()
    for order in kwargs['orders']:
        assert reopened_book.status('0x'+order.order_id.hex())['operationId'] == identity
    assert original_inputs == journal.reserved_input_coin_ids()
    assert settlement.routing.allocations() == (300000, 2100, 900)
    if c['pool'].company_revenue_puzzle_hash is not None:
        assert settlement.routing.treasury_destination == c['pool'].company_revenue_puzzle_hash
        assert settlement.routing.treasury_destination != c['pool'].permanent.permanent_rules.protocol_treasury_puzzle_hash
        assert settlement.routing.principal_destination == kwargs['inventory_item'].terms.protocol_puzhash
        assert settlement.routing.principal_destination != settlement.routing.treasury_destination
    assert (await c['client'].push_tx(SpendBundle(bundle.coin_spends, G2Element())))[0] != MempoolInclusionStatus.SUCCESS
    # Removing ANY independent leg fails, including any buyer or fee/backing.
    for index in range(len(bundle.coin_spends)):
        bad = SpendBundle(bundle.coin_spends[:index] + bundle.coin_spends[index+1:], bundle.aggregated_signature)
        assert (await c['client'].push_tx(bad))[0] != MempoolInclusionStatus.SUCCESS
    assert await c['client'].push_tx(bundle) == (MempoolInclusionStatus.SUCCESS, None)
    await c['sim'].farm_block()
    height = (await c['client'].get_coin_record_by_name(settlement.backing_coin.name())).confirmed_block_index
    reopened_journal.observed(identity, transaction_id=prepared.spend_bundle_id, status='CONFIRMED',
        now=int(c['sim'].timestamp), confirmed_height=int(height))
    for order in kwargs['orders']:
        status = await reopened_book.check_inputs('0x'+order.order_id.hex(), provider=None,
            journal=reopened_journal, now=int(c['sim'].timestamp))
        assert status['stage'] == 'FILLED'
    assert (await c['client'].get_coin_record_by_name(settlement.backing_coin.name())).spent is False
    assert (await c['client'].get_coin_record_by_name(kwargs['inventory_item'].coin.name())).spent
    replay = reconstruct_economic_successor(settlement.pool_spend, kwargs['pool'])
    assert replay.action == 'PRIMARY_SOLS_BATCH' and replay.after.inner() == settlement.next_pool.inner()
    assert replay.after.economics.economics.deed_count == 1
    assert replay.after.economics.economics.reserve_sols_mojos == 1
    assert replay.after.economics.economics.total_sols_mojos == 900901
    assert reconstruct_economic_successor(settlement.statutes_spend, kwargs['statutes']).after == kwargs['statutes']
    from chia.wallet.util.curry_and_treehash import curry_and_treehash, calculate_hash_of_quoted_mod_hash
    sols = kwargs['pool'].permanent.permanent_rules.sols_tail_hash
    for order in settlement.batch.orders:
        ph = curry_and_treehash(calculate_hash_of_quoted_mod_hash(CAT_MOD.get_tree_hash()),
            Program.to(CAT_MOD.get_tree_hash()).get_tree_hash(), Program.to(sols).get_tree_hash(), order.destination_inner_hash)
        records = await c['client'].get_coin_records_by_puzzle_hash(ph, include_spent_coins=False)
        assert sum(r.coin.amount for r in records) == order.sols_amount
    assert (await c['client'].push_tx(bundle))[0] != MempoolInclusionStatus.SUCCESS


@pytest.mark.asyncio
@pytest.mark.parametrize('generation', ['batch','batch-revenue'], indirect=True)
@pytest.mark.parametrize('native', [True, False], ids=['TXCH', 'synthetic-CAT'])
async def test_batch_rejects_changed_price_payout_identity_bypass_and_cancelled_offer(generation, native):
    c = generation
    settlement, bundle, kwargs, coins, _, synthetic = await prepare(c, native)
    keys = [synthetic, *[AugSchemeMPL.key_gen(bytes([n]) * 32) for n in (71, 72, 73,81,82,83)]]
    # Re-sign modified source requests, so rejection demonstrates the native
    # boundary rather than only a stale validator signature.
    for fault in ('price', 'expiry', 'fee-coin', 'deed-reveal', 'generation'):
        spend = settlement.source_spend
        raw = Program.from_bytes(bytes(spend.solution)).as_python()
        args = raw[2][1]
        if fault == 'price': args[10] = int.from_bytes(args[10], 'big') + 1
        elif fault == 'expiry': args[12] = int.from_bytes(args[12], 'big') + 1
        elif fault == 'fee-coin': args[14] = bytes(b32(151))
        elif fault == 'deed-reveal': args[5] = Program.to(1).as_python()
        elif fault == 'generation': args[13] = bytes(b32(152))
        changed = make_spend(spend.coin, Program.from_bytes(bytes(spend.puzzle_reveal)), Program.to(raw))
        bad = SpendBundle([changed if s.coin == spend.coin else s for s in bundle.coin_spends], G2Element())
        try: bad = sign_bundle(bad, keys)
        except ValueError: continue  # immutable source rejected before signatures
        assert (await c['client'].push_tx(bad))[0] != MempoolInclusionStatus.SUCCESS
    for fault in ('human-direction', 'redirect-payout', 'wrong-primary-ancestor', 'counterfeit-source'):
        spend = settlement.pool_spend
        raw = Program.from_bytes(bytes(spend.solution)).as_python()
        if fault == 'human-direction': raw[2][3] = 1
        elif fault == 'redirect-payout': raw[2][4][39][0][1][0][0] = bytes(b32(153))
        elif fault == 'wrong-primary-ancestor': raw[2][4][21] = bytes(b32(154))
        else: raw[2][4][23][0] = bytes(Program.to(1).get_tree_hash())
        changed = make_spend(spend.coin, Program.from_bytes(bytes(spend.puzzle_reveal)), Program.to(raw))
        assert (await c['client'].push_tx(SpendBundle([
            changed if s.coin == spend.coin else s for s in bundle.coin_spends], bundle.aggregated_signature)))[0] != MempoolInclusionStatus.SUCCESS
    for mask in (4, 8, 12):
        with pytest.raises(ValueError): build_primary_batch(**(kwargs | {'registry': replace(kwargs['registry'], pause_mask=mask)}))
    # Secure cancellation spends the ORIGINAL wallet input. Removing a web
    # listing would not invalidate the original signed offer; this does.
    original_spend = next(s for s in bundle.coin_spends if s.coin == coins[0])
    full = Program.from_bytes(bytes(original_spend.puzzle_reveal))
    if native:
        cancelled = SpendBundle([make_spend(coins[0], full, solution_for_conditions([
            [51, full.get_tree_hash(), int(coins[0].amount)]]))], G2Element())
    else:
        _, args = full.uncurry(); wallet = args.at('rrf')
        original_solution = Program.from_bytes(bytes(original_spend.solution))
        cancelled = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(coins[0], kwargs['orders'][0].payment_asset,
            wallet, solution_for_conditions([[51, wallet.get_tree_hash(), int(coins[0].amount)]]),
            lineage_proof=LineageProof(*[v.as_atom() if i<2 else v.as_int() for i,v in enumerate(original_solution.at('rf').as_iter())]))])
    cancelled = sign_bundle(cancelled, [synthetic])
    assert await c['client'].push_tx(cancelled) == (MempoolInclusionStatus.SUCCESS, None)
    await c['sim'].farm_block()
    assert (await c['client'].push_tx(bundle))[0] != MempoolInclusionStatus.SUCCESS
    assert not (await c['client'].get_coin_record_by_name(kwargs['inventory_item'].coin.name())).spent


@pytest.mark.asyncio
@pytest.mark.parametrize('generation', ['batch','batch-revenue'], indirect=True)
@pytest.mark.parametrize('native', [True, False], ids=['TXCH', 'synthetic-CAT'])
async def test_one_whole_signed_order_spans_two_primary_deeds_and_preserves_its_minimum(generation, native):
    c = generation
    settlement, bundle, kwargs, _, _, _ = await prepare(c, native, deeds=2, wanted_offset=1)
    assert len(settlement.backing_coins) == len(settlement.receipts) == 2
    assert sum(r.deed_to_sols_quote.seller_sols_mojos for r in settlement.receipts) == 1_801_800
    original = kwargs['orders'][0]
    assert original.sols_amount == 1_801_799
    assert bytes(original.offer()) == original.offer_bytes
    for i in range(len(bundle.coin_spends)):
        bad = SpendBundle(bundle.coin_spends[:i] + bundle.coin_spends[i+1:], bundle.aggregated_signature)
        assert (await c['client'].push_tx(bad))[0] != MempoolInclusionStatus.SUCCESS
    assert await c['client'].push_tx(bundle) == (MempoolInclusionStatus.SUCCESS, None)
    await c['sim'].farm_block()
    for backing in settlement.backing_coins:
        assert not (await c['client'].get_coin_record_by_name(backing.name())).spent
    assert settlement.next_pool.economics.economics.deed_count == 2
    assert settlement.next_pool.economics.economics.total_sols_mojos == 1_801_801
    assert settlement.next_pool.economics.economics.reserve_sols_mojos == 1
    assert (await c['client'].push_tx(bundle))[0] != MempoolInclusionStatus.SUCCESS
