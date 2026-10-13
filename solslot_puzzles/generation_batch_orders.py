"""Read-only matching of signed Chia offers for the proposed Sols route.

This module never signs, takes custody, broadcasts or grants mint authority.
An economically balanced Offer is not proof that a primary SmartDeed entered
the reserve. The permanent batch-settlement boundary must prove both legs.
"""
from dataclasses import dataclass,replace
from hashlib import sha256

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.wallet.outer_puzzles import create_asset_id
from chia.wallet.trading.offer import Offer
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.generation_parameters import GenerationParameters

MAX_ORDER_BYTES = 1_000_000
MAX_BATCH_ORDERS = 32


@dataclass(frozen=True)
class BuyerOrder:
    generation: bytes32
    offer_bytes: bytes
    payment_asset: bytes32 | None
    payment_amount: int
    sols_amount: int
    destination_inner_hash: bytes32

    @property
    def order_id(self):
        return bytes32(sha256(bytes(self.generation)+self.offer_bytes).digest())

    def offer(self):
        return Offer.from_bytes(self.offer_bytes)


def inspect_buyer_offer(offer: Offer, *, generation: bytes32, sols_asset: bytes32,
                        sols_driver: PuzzleInfo, payment_asset: bytes32 | None,
                        destination_inner_hash: bytes32, approved_payment_assets: frozenset[bytes32]) -> BuyerOrder:
    """Read exact signed amounts; a matcher cannot reprice or partially fill."""
    for value in (generation, sols_asset, destination_inner_hash):
        if not isinstance(value,bytes32) or value==bytes32.zeros:
            raise ValueError('batch order requires exact generation, asset and recipient bindings')
    if payment_asset is not None and (payment_asset not in approved_payment_assets or payment_asset==sols_asset):
        raise ValueError('payment must be XCH or an explicitly approved Chia CAT')
    raw=bytes(offer)
    if not 0<len(raw)<=MAX_ORDER_BYTES or len(offer._bundle.coin_spends)>64:
        raise ValueError('buyer offer exceeds its native inspection bound')
    # Copy serialized signed data before inspection. Caller-owned dictionaries
    # cannot change the request later, and no cached Offer object is retained.
    source=Offer.from_bytes(raw)
    if create_asset_id(sols_driver)!=sols_asset:
        raise ValueError('Sols driver must identify the actual current-generation asset')
    offered=source.get_offered_amounts();requested=source.get_requested_amounts()
    if (set(offered)!={payment_asset} or set(requested)!={sols_asset}
            or not 0<offered[payment_asset]<2**64 or not 0<requested[sols_asset]<2**64
            or source.driver_dict.get(sols_asset)!=sols_driver
            or set(source.driver_dict)!={sols_asset,*(() if payment_asset is None else (payment_asset,))}):
        raise ValueError('buyer offer must give exactly one approved asset and request only current-generation Sols')
    payments=source.requested_payments[sols_asset]
    if (len(payments)!=1 or payments[0].puzzle_hash!=destination_inner_hash
            or payments[0].amount!=requested[sols_asset]):
        raise ValueError('buyer offer changes its exact Sols destination or output amount')
    remaining_cost=100_000_000;conditions=[];inputs=set()
    for spend in source._bundle.coin_spends:
        if (spend.coin.name() in inputs or spend.puzzle_reveal.get_tree_hash()!=spend.coin.puzzle_hash):
            raise ValueError('buyer offer repeats an input or substitutes its reveal')
        inputs.add(spend.coin.name())
        cost,result=Program.from_bytes(bytes(spend.puzzle_reveal)).run_with_cost(remaining_cost,
            Program.from_bytes(bytes(spend.solution)))
        remaining_cost-=cost
        values=list(result.as_iter())
        if len(values)>4096:raise ValueError('buyer offer emits too many conditions')
        conditions.extend(bytes(v) for v in values)
    # Requested-payment metadata must be committed by native assertions; an
    # unsigned display field alone is not a buyer's requested Sols output.
    for announcement in Offer.calculate_announcements(source.requested_payments,source.driver_dict):
        if bytes(announcement.to_program()) not in conditions:
            raise ValueError('native buyer spend does not commit its requested Sols payment')
    return BuyerOrder(generation,raw,payment_asset,offered[payment_asset],requested[sols_asset],destination_inner_hash)


@dataclass(frozen=True)
class BuyerBatch:
    generation: bytes32
    payment_asset: bytes32 | None
    orders: tuple[BuyerOrder,...]
    payment_amount: int
    requested_sols: int
    aggregate_bytes: bytes

    def offers(self):
        return tuple(o.offer() for o in self.orders)

    @property
    def commitment(self):
        return Program.to([b'SOLS_BUYER_BATCH_V1',self.generation,
            self.payment_asset or b'',[[o.order_id,o.destination_inner_hash,o.payment_amount,o.sols_amount]
                for o in self.orders]]).get_tree_hash()


def combine_buyer_orders(orders: tuple[BuyerOrder,...]) -> BuyerBatch:
    """Aggregate whole files, rejecting duplicate inputs and mixed asset lanes.

Native USDC on another chain is not a Chia coin. A governed bridge/conversion
must produce the approved payment CAT or supply a separately validated route.
    """
    if not 0<len(orders)<=MAX_BATCH_ORDERS or len({o.order_id for o in orders})!=len(orders):
        raise ValueError('batch requires distinct bounded whole offers')
    first=orders[0]
    if any(o.generation!=first.generation or o.payment_asset!=first.payment_asset for o in orders):
        raise ValueError('buyer batch cannot mix deployment generations or payment assets')
    aggregate=Offer.aggregate([o.offer() for o in orders])
    for order in orders:
        native=order.offer()
        if (native.get_offered_amounts()!={order.payment_asset:order.payment_amount}
                or list(native.get_requested_amounts().values())!=[order.sols_amount]
                or len(native.requested_payments)!=1
                or next(iter(native.requested_payments.values()))[0].puzzle_hash!=order.destination_inner_hash):
            raise ValueError('batch order fields differ from its original offer file')
    paid=sum(o.payment_amount for o in orders);received=sum(o.sols_amount for o in orders)
    if not max(paid,received)<2**64:
        raise ValueError('batch amounts exceed uint64 settlement bounds')
    return BuyerBatch(first.generation,first.payment_asset,tuple(orders),paid,received,bytes(aggregate))


def funding_progress(batch: BuyerBatch, primary_price: int) -> dict:
    if type(primary_price) is not int or not 0<primary_price<2**64:
        raise ValueError('primary offering price must be positive atomic units')
    return {'orderCount':len(batch.orders),'availableAmount':batch.payment_amount,
        'requiredAmount':primary_price,'remainingAmount':max(0,primary_price-batch.payment_amount),
        'cashThresholdMet':batch.payment_amount>=primary_price,
        # Cash alone does not authorize creation, fill or reserve accounting.
        'settlementReady':False,'signatureValidated':False,'inputsRechecked':False,
        'stage':'AWAITING_ATOMIC_PRIMARY_AND_RESERVE_PROOF'}


def batch_sols_distribution(parameters: GenerationParameters, gross_sols: int,
                            payment_weights: tuple[int,...]) -> tuple[tuple[int,...],object]:
    """Quote a Sols-denominated fee leg, separately from the primary route.

Integer remainders use largest fractional shares, with original-order ties.
This quote never replaces amounts or destinations in signed offer files.
The primary-to-Sols route already pays its sealed purchase fee; it must use
primary_route_sols_distribution instead of charging this second fee.
    """
    if (not 0<len(payment_weights)<=MAX_BATCH_ORDERS
            or any(type(w) is not int or not 0<w<2**64 for w in payment_weights)
            or sum(payment_weights)>=2**64):
        raise ValueError('batch allocation requires bounded positive payment weights')
    fees=parameters.fee_split(gross_sols);net=gross_sols-fees.total_fee_sols_mojos
    denominator=sum(payment_weights)
    values=[net*w//denominator for w in payment_weights]
    ranks=sorted(range(len(values)),key=lambda i: (-(net*payment_weights[i]%denominator),i))
    for i in ranks[:net-sum(values)]:values[i]+=1
    if any(v<=0 for v in values):raise ValueError('an order is too small to receive one Sols atomic unit')
    assert sum(values)+fees.protocol_fee_sols_mojos+fees.sgt_rewards_fee_sols_mojos==gross_sols
    return tuple(values),fees


def primary_route_sols_distribution(gross_sols: int, payment_weights: tuple[int,...]) -> tuple[int,...]:
    """Allocate the existing fee-free deed-deposit result after the primary fee.

No additional Sols exchange or aggregator fee is introduced on this leg.
The primary payment itself must still satisfy its original native subtotal.
    """
    if (type(gross_sols) is not int or not 0<gross_sols<2**64
            or not 0<len(payment_weights)<=MAX_BATCH_ORDERS
            or any(type(w) is not int or not 0<w<2**64 for w in payment_weights)
            or sum(payment_weights)>=2**64):
        raise ValueError('primary batch requires bounded positive amounts')
    denominator=sum(payment_weights)
    values=[gross_sols*w//denominator for w in payment_weights]
    ranks=sorted(range(len(values)),key=lambda i:(-(gross_sols*payment_weights[i]%denominator),i))
    for i in ranks[:gross_sols-sum(values)]:values[i]+=1
    if any(v<=0 for v in values):raise ValueError('an order is too small to receive one Sols atomic unit')
    assert sum(values)==gross_sols
    return tuple(values)


def inspect_primary_route_fees(terms) -> dict:
    """Assess frozen primary terms without changing a mandatory fee or payee.

The existing primary inventory pays its encoded treasury, not separate SGT
and protocol outputs. Split figures below are a requested allocation target,
never evidence that this contract already performs that distribution.
    """
    from solslot_puzzles.stripe_settlement_v1_driver import PrimaryMintTermsV3
    if not isinstance(terms,PrimaryMintTermsV3):
        raise ValueError('fee assessment requires the exact reviewed primary inventory terms')
    terms=replace(terms)
    if terms.network!='testnet11' or terms.inventory_version not in (2,3,4):
        raise ValueError('batch fee assessment is limited to explicit-subtotal Testnet inventory')
    if (any(type(v) is not int or not 0<=v<2**64 for v in (terms.base_amount_minor,terms.technology_fee_bps,
            terms.technology_fee_minor,terms.subtotal_minor)) or not terms.base_amount_minor
            or terms.technology_fee_bps>1000):
        raise ValueError('primary economics exceed their native integer bounds')
    amount=terms.technology_fee_minor
    expected=(terms.base_amount_minor*terms.technology_fee_bps+9999)//10000
    if amount!=expected or terms.subtotal_minor!=terms.base_amount_minor+amount:
        raise ValueError('primary fee or subtotal differs from its immutable terms')
    # Preserve a differently sealed offering. It needs a new review rather
    # than an invisible discount or a second fee disguised as routing cost.
    exact_split=terms.technology_fee_bps==100
    protocol=min(amount,(terms.base_amount_minor*70+9999)//10000) if exact_split else None
    return {'primaryBaseMinor':terms.base_amount_minor,'primaryFeeBps':terms.technology_fee_bps,
        'primaryFeeMinor':amount,'primarySubtotalMinor':terms.subtotal_minor,
        'additionalSolsFeeBps':0,'aggregatorFeeBps':0,
        'currentTreasuryPuzzleHash':'0x'+terms.protocol_treasury_puzzle_hash.hex(),
        'requestedProtocolFeeMinor':protocol,'requestedSgtFeeMinor':amount-protocol if exact_split else None,
        'nativeSplitVerified':False,'requiresGovernedPrimarySplit':exact_split,
        'requiresOfferingReview':not exact_split}
