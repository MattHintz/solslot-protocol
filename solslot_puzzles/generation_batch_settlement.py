"""Whole signed offers -> primary inventory -> pool backing -> exact Sols.

Deterministic construction only. No wallet keys, network or dispatch. Admission
must recheck every external input and the native signature before broadcasting.
It cannot resize an offer, choose an arbitrage recipient or invent an ID stamp.
"""
from dataclasses import dataclass
from hashlib import sha256

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH, solution_for_singleton
from chia.wallet.trading.offer import Offer, NotarizedPayment, OFFER_MOD_HASH
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL,Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_batch_orders import combine_buyer_orders, primary_route_sols_distribution
from solslot_puzzles.generation_primary_inventory import batch_bindings, inventory_inner
from solslot_puzzles.generation_primary_payment import PrimaryFeeRouting
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles.generation_sols_reserve import reserve_inner, reserve_solution
from solslot_puzzles.pool_v4_driver import deed_to_sols_inner_solution, p2_pool_v2_inner_hash
from solslot_puzzles.primary_purchase_v2_driver import chia_cat_driver
from solslot_puzzles.sols_pool_v4 import prepare_deed_to_sols

XCH_ORACLE_ASSET = bytes32(sha256(b'XCH').digest())


@dataclass(frozen=True)
class PrimaryBatchSettlement:
    generation: bytes32
    batch: object
    routing: PrimaryFeeRouting
    receipt: object
    next_pool: object
    protocol_offer: Offer
    aggregate_offer: Offer
    bundle: SpendBundle
    roles: tuple[str, ...]
    source_spend: object
    pool_spend: object
    statutes_spend: object
    registry_spend: object
    backing_coin: Coin
    fee_coin: Coin
    payout_spend: object | None = None
    successors: tuple = ()
    receipts: tuple = ()
    backing_coins: tuple = ()
    routings: tuple = ()
    primary_spends: tuple = ()


def build_primary_batch(*, orders, inventory_item, inventory_lineage, pool, pool_tip,
                       statutes, statutes_tip, registry, registry_tip, sgt_bindings,
                       collections, oracles, routes, inventory, reserve_coin,
                       reserve_lineage, decimals, expires_at, signer_indices=(0, 1),
                       validator_signature=None, signed_price=None, _shared=None):
    batch = combine_buyer_orders(tuple(orders))
    config = pool.config(); terms = inventory_item.terms
    if (batch.generation != pool.generation or statutes.generation != pool.generation
            or registry.generation != pool.generation or sgt_bindings.generation != pool.generation
            or pool.component() not in registry.components or statutes.component() not in registry.components
            or pool_tip.inner != pool.inner() or statutes_tip.inner != statutes.inner()
            or registry_tip.inner != registry.inner() or pool_tip.launcher_id != pool.launcher_id
            or statutes_tip.launcher_id != statutes.launcher_id or registry_tip.launcher_id != registry.launcher_id
            or registry.launcher_id != pool.registry_id or statutes.registry_id != registry.launcher_id
            or statutes.permanent_rules != pool.permanent.permanent_rules
            or registry.pause_mask & 12):
        raise ValueError('batch requires current compatible generation authorities and both open operation scopes')
    for tip in (pool_tip, statutes_tip, registry_tip): tip.validate()
    bindings = batch_bindings(generation=pool.generation, pool_id=pool.launcher_id,
        sgt=sgt_bindings, statutes_id=statutes.launcher_id,
        treasury=pool.permanent.permanent_rules.protocol_treasury_puzzle_hash,
        oracle_pubkeys=tuple(v.as_atom() for v in list(inventory_item.inner.uncurry()[1].as_iter())[-1].at('rrrrrrrf').as_iter()))
    source_inner = inventory_inner(terms, bindings)
    if source_inner != inventory_item.inner:
        raise ValueError('primary inventory does not carry the actual immutable generation bindings')
    structure = Program.to((SINGLETON_MOD_HASH, (terms.deed_launcher_id, terms.deed_launcher_puzzle_hash)))
    source_full = SINGLETON_MOD.curry(structure, source_inner)
    source_coin = inventory_item.coin
    if source_coin.puzzle_hash != source_full.get_tree_hash() or source_coin.amount != 1:
        raise ValueError('primary source differs from its exact governed one-deed inventory')
    asset = batch.payment_asset or bytes32.zeros
    from solslot_puzzles.generation_primary_price import SignedPrimaryPrice
    if not isinstance(signed_price,SignedPrimaryPrice):
        raise ValueError('primary settlement requires the existing two-source, two-signer live price')
    price_keys=tuple(v.as_atom() for v in bindings.at('rrrrrrrf').as_iter())
    signed_price.verify(price_keys,asset=asset,decimals=decimals,expires_at=expires_at,maximum_age=statutes.values[1])
    oracle=signed_price.round
    price=oracle.price_usd_minor_per_asset
    if statutes.values[2:5]!=(100,70,30):
        raise ValueError('the one-percent primary route requires a new review after a fee-policy change')
    if terms.technology_fee_bps!=100 or (_shared is None and batch.payment_amount !=
            (terms.subtotal_minor*10**decimals+price-1)//price):
        raise ValueError('whole signed offers must exactly fund the immutable, fee-inclusive primary quote')
    if batch.payment_asset is not None and not any(
            r.source_chain_id==pool.generation and r.destination_chain_id==pool.generation
            and r.asset_id==asset and r.remote_asset_id==asset and r.decimals==decimals and r.active==1 for r in routes):
        raise ValueError('CAT payments require a governed active same-chain representation')
    local_payment = (terms.subtotal_minor * 10**decimals + price - 1) // price
    collection = next((v for v in collections if v.collection_id == terms.collection_id), None)
    if collection is None: raise ValueError('primary collection has no governed valuation')
    sd = inventory_item.smart_deed
    _, sd_args = sd.uncurry(); values = list(sd_args.as_iter())
    if sd.get_tree_hash() != terms.smart_deed_inner_hash:
        raise ValueError('primary deed reveal differs from its immutable inventory commitment')
    par, asset_class, property_id = values[2].as_int(), values[3].as_int(), bytes32(values[4].as_atom())
    commitment = Program.to([terms.deed_launcher_id, par, asset_class, property_id,
        terms.collection_id, terms.share_ppm]).get_tree_hash()
    ephemeral = Coin(source_coin.name(), SINGLETON_MOD.curry(structure, sd).get_tree_hash(), uint64(1))
    custody = Coin(ephemeral.name(), SINGLETON_MOD.curry(structure,
        load_puzzle('p2_pool_v2.clsp').curry(config.p2_pool_v2_mod_hash, SINGLETON_MOD_HASH,
            pool.launcher_id, SINGLETON_LAUNCHER_HASH, commitment)).get_tree_hash(), uint64(1))
    original = Offer.from_bytes(batch.aggregate_bytes)
    sols = config.permanent_rules.sols_tail_hash
    requested = original.requested_payments.get(sols)
    if requested is None: raise ValueError('offers request another generation Sols identity')
    groups = [[nonce, [p.as_condition_args() for p in requested if p.nonce == nonce]]
        for nonce in dict.fromkeys(p.nonce for p in requested)]
    if _shared is not None: groups = _shared['groups']
    payout_root = Program.to(groups).get_tree_hash()
    receipt = prepare_deed_to_sols(pool_coin_id=pool_tip.coin.name(), state=pool.economics,
        inventory=inventory, deed_launcher_id=terms.deed_launcher_id, custody_coin_id=custody.name(),
        deed_commitment=commitment, collection=collection, share_ppm=terms.share_ppm,
        parameters=statutes.economic_parameters(), statutes_state=statutes.economic_view(), pause=None,
        vault_launcher_id=source_coin.parent_coin_info, vault_coin_id=source_coin.name(),
        seller_sols_puzzle_hash=payout_root, quote_expires_at=expires_at)
    quote = receipt.deed_to_sols_quote
    allocations = primary_route_sols_distribution(int(quote.seller_sols_mojos), tuple(int(o.payment_amount) for o in batch.orders))
    if _shared is None and tuple(o.sols_amount for o in batch.orders) != allocations:
        raise ValueError('signed Sols outputs differ from governed proportional valuation; obtain new offers')
    round_hash = oracle.round_hash
    operation = receipt.operation_hash
    route = Program.to([b'PRIMARY_SOLS_V1', pool.generation, source_coin.name(), pool_tip.coin.name(),
        batch.commitment, asset, local_payment, decimals, round_hash, price,
        oracle.source_evidence_root, expires_at, sd.get_tree_hash(), operation]).get_tree_hash()
    routing = PrimaryFeeRouting(sgt_bindings, statutes.launcher_id, asset, source_full.get_tree_hash(),
        route, terms.base_amount_minor, local_payment, terms.protocol_treasury_puzzle_hash,
        config.permanent_rules.protocol_treasury_puzzle_hash, statutes.inner().get_tree_hash(), statutes.values)
    payment_parent = original.get_offered_coins()[batch.payment_asset][0]
    fee_coin = Coin(payment_parent.name(), routing.full().get_tree_hash(), uint64(local_payment))
    source_args = [source_coin.name(), source_coin.parent_coin_info, source_full.get_tree_hash(),
        pool_tip.coin.name(), pool.inner().get_tree_hash(), sd, asset, local_payment,
        decimals, round_hash, price, oracle.source_evidence_root, expires_at, batch.commitment,
        fee_coin.name(), statutes.inner().get_tree_hash(), list(statutes.values), operation, list(signer_indices), oracle.to_program(),
        [i for i,_ in signed_price.signatures]]
    # Same 23-field solution shape as direct purchases; a typed first field
    # selects the new native branch. Other fields cannot supply conditions.
    source_spend = make_spend(source_coin, source_full,
        solution_for_singleton(inventory_lineage, uint64(1),
            Program.to([b'PRIMARY_SOLS', source_args, *([b''] * 20)])))
    raw = list(deed_to_sols_inner_solution(config=config, pool_coin_id=pool_tip.coin.name(),
        pool_inner_puzzle_hash=pool.inner().get_tree_hash(), pool_amount=1, receipt=receipt,
        parameters=statutes.economic_parameters(), collection=collection, pause=None,
        statutes_state=statutes.economic_view(), deed_parent_coin_id=ephemeral.name(), par_value=par,
        asset_class=asset_class, property_id=property_id, seller_sols_puzzle_hash=payout_root,
        mint_token_coin_id=reserve_coin.name() if quote.fresh_sols_mojos_minted else None,
        vault_launcher_id=source_coin.parent_coin_info, vault_coin_id=source_coin.name(), owner_pubkey=b'',
        auth_type=4, members_root=batch.commitment, identity_root=route,
        bridge_policy=config.permanent_rules.zkpassport_policy_hash, quote_expires_at=expires_at).as_iter())
    params = list(raw[4].as_iter()); params[23] = source_inner.uncurry()[1]
    plan = _shared['plan'] if _shared is not None and _shared.get('plan') is not None else [[pool_tip.coin.name(), pool_tip.coin.puzzle_hash, operation, int(quote.seller_sols_mojos)]]
    payout_mod = load_puzzle('generation_batch_payout_v1.clsp')
    payout = payout_mod.curry(payout_mod.get_tree_hash(), pool.generation, CAT_MOD.get_tree_hash(), sols, OFFER_MOD_HASH,
        plan[0][0], plan, groups)
    payout_coin = Coin(plan[0][0], payout.get_tree_hash(), uint64(0))
    payout_spend = make_spend(payout_coin, payout, Program.to([]))
    pool_spend = pool_tip.spend(Program.to([*raw[:3], 3, [*params, groups, plan],
        config.policy(), statutes.inner().get_tree_hash()]))
    deed_spend = make_spend(ephemeral, SINGLETON_MOD.curry(structure, sd),
        solution_for_singleton(LineageProof(source_coin.parent_coin_info, source_inner.get_tree_hash(), uint64(1)),
            uint64(1), Program.to([ephemeral.name(), sd.get_tree_hash(), 1, 0x64, [pool.inner().get_tree_hash()]])))
    statute_args = [pool_tip.coin.name(), terms.collection_id, [r.as_program_value() for r in collections],
        registry.inner().get_tree_hash(), operation, source_coin.puzzle_hash, route,
        fee_coin.puzzle_hash, asset, [r.as_program_value() for r in oracles], decimals,
        round_hash, price, oracle.source_evidence_root, expires_at, [r.as_program_value() for r in routes]]
    statutes_spend = statutes_tip.spend(Program.to([b'PRIMARY_EVIDENCE', statute_args]))
    registry_spend = registry_tip.spend(inner_solution('AUTHORIZE_NEW', registry_tip.coin,
        [12, statutes_tip.coin.puzzle_hash, operation,
            [b'PRIMARY_SOLS', pool_tip.coin.name(), terms.collection_id, route, source_coin.puzzle_hash, fee_coin.puzzle_hash]]))
    if batch.payment_asset is None:
        fee_spends = (make_spend(fee_coin, routing.inner(), routing.solution(fee_coin.name())),)
    else:
        fee_spends = tuple(unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(fee_coin, asset,
            routing.inner(), routing.solution(fee_coin.name()), lineage_proof=LineageProof(
                payment_parent.parent_coin_info, OFFER_MOD_HASH, payment_parent.amount))]).coin_spends)
    reserve = reserve_inner(generation=pool.generation, registry_id=pool.registry_id,
        pool_id=pool.launcher_id, component_id=pool.component_id)
    reserve_params = Program.to(params)
    tail = load_puzzle('generation_sols_tail_v1.clsp').curry(SINGLETON_MOD_HASH, pool.launcher_id, SINGLETON_LAUNCHER_HASH)
    tail_solution = Program.to([pool_tip.coin.puzzle_hash, pool.inner().get_tree_hash(), pool_tip.coin.name(),
        reserve_coin.name(), 1, quote.fresh_sols_mojos_minted])
    reserve_spends = tuple(unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [SpendableCAT(reserve_coin, sols,
        reserve, reserve_solution(config=config, state=pool.economics, pool_coin=pool_tip.coin,
            reserve_coin=reserve_coin, pool_params=reserve_params), lineage_proof=reserve_lineage,
        limitations_solution=tail_solution if quote.fresh_sols_mojos_minted else Program.to(0),
        limitations_program_reveal=tail if quote.fresh_sols_mojos_minted else Program.to(0),
        extra_delta=quote.fresh_sols_mojos_minted)]).coin_spends)
    spends = (source_spend, deed_spend, pool_spend, statutes_spend, registry_spend,
        *(() if _shared is not None else (payout_spend,)), *fee_spends, *reserve_spends)
    drivers = {sols: chia_cat_driver(sols)}
    if batch.payment_asset is not None:
        drivers[batch.payment_asset] = original.driver_dict[batch.payment_asset]
    protocol = Offer({batch.payment_asset: [NotarizedPayment(routing.inner().get_tree_hash(),
        uint64(local_payment), nonce=source_coin.name())]},
        WalletSpendBundle(list(spends), AugSchemeMPL.aggregate([validator_signature or G2Element(),signed_price.aggregate()])), drivers)
    aggregate = Offer.aggregate([original, protocol])
    if _shared is None and any(aggregate.arbitrage().values()):
        raise ValueError('batch must balance exactly without an operator surplus')
    native = aggregate.to_valid_spend() if _shared is None else protocol._bundle
    return PrimaryBatchSettlement(pool.generation, batch, routing, receipt,
        pool.with_economics(receipt.next_state), protocol, aggregate,
        SpendBundle(native.coin_spends, native.aggregated_signature),
        ('primary', 'deed-deposit', 'pool', 'statutes', 'registry', 'primary-fee', 'sols-reserve'),
        source_spend, pool_spend, statutes_spend, registry_spend, custody, fee_coin, payout_spend,
        (pool_tip.advanced(pool_spend,pool.with_economics(receipt.next_state).inner()),
         statutes_tip.advanced(statutes_spend,statutes_tip.inner),registry_tip.advanced(registry_spend,registry_tip.inner)),
        (receipt,), (custody,), (routing,), (source_spend,))


def build_primary_batches(*, inventory_items, inventory_lineages, validator_signatures=None, **context):
    """One whole signed order may span several whole primary SmartDeeds.

    Eight deeds/32 buyer offers bound the candidate. Every pool, statutes and
    registry transition continues its predecessor atomically, and one native
    payout witness proves the sum across ALL deposits. No custody is pooled
    off chain and no selected buyer offer is split or repriced.
    """
    from dataclasses import replace
    from chia.wallet.util.compute_additions import compute_additions
    if (not 1 <= len(inventory_items) <= 8 or len(inventory_items) != len(inventory_lineages)
            or len({v.coin.name() for v in inventory_items}) != len(inventory_items)):
        raise ValueError('batch requires one to eight distinct whole primary deeds and exact lineage')
    batch = combine_buyer_orders(tuple(context['orders']))
    original = Offer.from_bytes(batch.aggregate_bytes)
    sols = context['pool'].permanent.permanent_rules.sols_tail_hash
    payments = original.requested_payments[sols]
    groups = [[nonce, [p.as_condition_args() for p in payments if p.nonce == nonce]]
        for nonce in dict.fromkeys(p.nonce for p in payments)]
    if validator_signatures is not None and len(validator_signatures) != len(inventory_items):
        raise ValueError('each primary source requires its own exact validator authorization')

    def legs_for(group_list, plan):
        selected = []; ctx = dict(context)
        for index, (item, lineage) in enumerate(zip(inventory_items, inventory_lineages, strict=True)):
            leg = build_primary_batch(inventory_item=item, inventory_lineage=lineage,
                validator_signature=validator_signatures[index] if validator_signatures else None,
                _shared={'groups': group_list, 'plan': plan}, **ctx)
            selected.append(leg)
            reserve_spend = next(s for s in leg.protocol_offer._bundle.coin_spends
                if s.coin.name() == ctx['reserve_coin'].name())
            reserve = reserve_inner(generation=ctx['pool'].generation, registry_id=ctx['pool'].registry_id,
                pool_id=ctx['pool'].launcher_id, component_id=ctx['pool'].component_id)
            next_reserve = [c for c in compute_additions(reserve_spend)
                if c.puzzle_hash == ctx['reserve_coin'].puzzle_hash]
            if len(next_reserve) != 1: raise ValueError('batch loses its exact remaining protocol reserve')
            ctx.update(pool=leg.next_pool, pool_tip=leg.successors[0],
                statutes_tip=leg.successors[1], registry_tip=leg.successors[2],
                inventory=leg.receipt.next_inventory, reserve_coin=next_reserve[0],
                reserve_lineage=LineageProof(reserve_spend.coin.parent_coin_info,
                    reserve.get_tree_hash(), reserve_spend.coin.amount))
        return selected

    # Projection does not contact a node, reserve inputs or request signatures.
    # State/coin destinations are independent of the later payout witness.
    preview = legs_for(groups, None)
    if sum(v.routing.total_payment for v in preview) != batch.payment_amount:
        raise ValueError('whole offers must exactly fund the selected whole primary inventory')
    gross = sum(int(v.receipt.deed_to_sols_quote.seller_sols_mojos) for v in preview)
    allocations = primary_route_sols_distribution(gross, tuple(int(o.payment_amount) for o in batch.orders))
    if any(o.sols_amount > amount for o, amount in zip(batch.orders, allocations, strict=True)):
        raise ValueError('a signed minimum exceeds current governed proportional Sols valuation')
    # Original payments stay byte-for-byte intact. A favourable rounding/value
    # change pays the extra only to that buyer's ORIGINAL signed destination.
    extras = [(order.destination_inner_hash, amount - order.sols_amount)
        for order, amount in zip(batch.orders, allocations, strict=True) if amount > order.sols_amount]
    extra_payments = []
    if extras:
        nonce = Program.to([b'SOLS_BATCH_TOPUP', batch.generation, batch.commitment,
            context['pool_tip'].coin.name()]).get_tree_hash()
        extra_payments = [NotarizedPayment(dest, uint64(amount), [dest], nonce=nonce) for dest, amount in extras]
        groups.append([nonce, [p.as_condition_args() for p in extra_payments]])
    pairs = [(p[0], p[1]) for _, ps in groups for p in ps]
    if len(pairs) != len(set(pairs)):
        raise ValueError('duplicate native payment outputs require separately matched batches or a new combined wallet offer')
    projected = legs_for(groups, None)
    plan = [[leg.pool_spend.coin.name(), leg.pool_spend.coin.puzzle_hash,
        leg.receipt.operation_hash, int(leg.receipt.deed_to_sols_quote.seller_sols_mojos)] for leg in projected]
    legs = legs_for(groups, plan)
    witness = legs[0].payout_spend
    protocol = Offer.aggregate([leg.protocol_offer for leg in legs] + [Offer(
        {sols: extra_payments} if extra_payments else {}, WalletSpendBundle([witness], G2Element()),
        {sols: chia_cat_driver(sols)})])
    aggregate = Offer.aggregate([original, protocol])
    if any(aggregate.arbitrage().values()):
        raise ValueError('multi-deed settlement cannot create an operator surplus')
    native = aggregate.to_valid_spend()
    first, last = legs[0], legs[-1]
    return replace(first, protocol_offer=protocol, aggregate_offer=aggregate,
        bundle=SpendBundle(native.coin_spends, native.aggregated_signature),
        next_pool=last.next_pool, successors=last.successors, receipts=tuple(v.receipt for v in legs),
        backing_coins=tuple(v.backing_coin for v in legs),
        routings=tuple(v.routing for v in legs),primary_spends=tuple(v.source_spend for v in legs),
        roles=tuple(role for leg in legs for role in leg.roles))
