"""Pool Economic V2 calculations.

Pool tokens are an ETF-like pro-rata claim on the global smart-deed pool.
The market can trade above or below NAV, but protocol redemption/specific-deed
quotes use governed collection NAV as the accounting reference.
"""
from __future__ import annotations

from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.collection_nav_registry_driver import compute_nav_evidence_message


SHARE_PPM_DENOMINATOR = 1_000_000
FEE_BPS_DENOMINATOR = 10_000
DEFAULT_SWAP_FEE_BPS = 100
DEFAULT_PROTOCOL_FEE_BPS = 30
DEFAULT_GOVERNANCE_FEE_BPS = 70
MAX_POOL_V2_TOKEN_OUTPUTS = 3
PROTOCOL_PREFIX = b"\x53"

TOKEN_MINT = 1
TOKEN_MELT = -1

DEED_SPEND_POOL_DEPOSIT = 0x64
DEED_SPEND_POOL_REDEEM = 0x72

POOL_V2_SPECIFIC_DEED_SWAP_TAG = 0x53574150  # "SWAP"
POOL_V2_TRUE_REDEMPTION_TAG = 0x5244454D  # "RDEM"
POOL_V2_RESERVE_ACQUISITION_TAG = 0x41435152  # "ACQR"


def ceil_div(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    if numerator < 0:
        raise ValueError("numerator must be non-negative")
    return (numerator + denominator - 1) // denominator


def deed_nav_mojos(collection_nav_mojos: int, share_ppm: int) -> int:
    """NAV assigned to one smart deed by collection value and share."""
    if collection_nav_mojos <= 0:
        raise ValueError("collection_nav_mojos must be positive")
    if share_ppm <= 0 or share_ppm > SHARE_PPM_DENOMINATOR:
        raise ValueError("share_ppm must be in 1..1_000_000")
    return ceil_div(collection_nav_mojos * share_ppm, SHARE_PPM_DENOMINATOR)


@dataclass(frozen=True)
class PoolEconomicState:
    total_nav_locked_mojos: int
    deed_count: int
    total_pool_token_supply: int
    treasury_reserve_tokens: int

    def circulating_supply(self) -> int:
        if self.total_nav_locked_mojos < 0:
            raise ValueError("total_nav_locked_mojos must be non-negative")
        if self.deed_count < 0:
            raise ValueError("deed_count must be non-negative")
        if self.total_pool_token_supply < 0:
            raise ValueError("total_pool_token_supply must be non-negative")
        if self.treasury_reserve_tokens < 0:
            raise ValueError("treasury_reserve_tokens must be non-negative")
        if self.treasury_reserve_tokens > self.total_pool_token_supply:
            raise ValueError("treasury_reserve_tokens cannot exceed total supply")
        return self.total_pool_token_supply - self.treasury_reserve_tokens


@dataclass(frozen=True)
class FeeSplit:
    protocol_fee_tokens: int
    governance_fee_tokens: int
    total_fee_tokens: int


@dataclass(frozen=True)
class SpecificDeedSwapQuote:
    deed_nav_mojos: int
    principal_tokens: int
    fee_split: FeeSplit
    buyer_total_tokens: int
    next_total_nav_locked_mojos: int
    next_deed_count: int
    next_total_pool_token_supply: int
    next_treasury_reserve_tokens: int

    @property
    def next_circulating_supply(self) -> int:
        return self.next_total_pool_token_supply - self.next_treasury_reserve_tokens


@dataclass(frozen=True)
class RedemptionQuote:
    deed_nav_mojos: int
    principal_tokens: int
    next_total_nav_locked_mojos: int
    next_deed_count: int
    next_total_pool_token_supply: int
    next_treasury_reserve_tokens: int

    @property
    def next_circulating_supply(self) -> int:
        return self.next_total_pool_token_supply - self.next_treasury_reserve_tokens


@dataclass(frozen=True)
class ReserveAcquisitionQuote:
    deed_nav_mojos: int
    reserve_tokens_paid: int
    fresh_tokens_to_mint: int
    next_total_nav_locked_mojos: int
    next_deed_count: int
    next_total_pool_token_supply: int
    next_treasury_reserve_tokens: int

    @property
    def next_circulating_supply(self) -> int:
        return self.next_total_pool_token_supply - self.next_treasury_reserve_tokens


@dataclass(frozen=True)
class CollectionNavEvidence:
    registry_coin_id: bytes32
    registry_puzzle_hash: bytes32
    collection_id_canon: bytes32
    nav_value_mojos: int
    collection_nav_root: bytes32
    registry_version: int

    @property
    def evidence_message(self) -> bytes32:
        return compute_nav_evidence_message(
            self.collection_id_canon,
            self.nav_value_mojos,
            self.collection_nav_root,
            self.registry_version,
        )

    @property
    def announcement_message(self) -> bytes:
        return PROTOCOL_PREFIX + self.evidence_message


@dataclass(frozen=True)
class TokenOutput:
    puzzle_hash: bytes32
    amount: int
    role: str
    memos: tuple[bytes32, ...] = ()

    def settlement_payment(self) -> list[object]:
        if self.amount <= 0:
            raise ValueError("token output amount must be positive")
        memos = self.memos if self.memos else (self.puzzle_hash,)
        return [self.puzzle_hash, int(self.amount), list(memos)]


@dataclass(frozen=True)
class TokenAuthorization:
    mint_or_melt: int
    token_coin_id: bytes32
    amount: int

    @property
    def announcement_message(self) -> bytes:
        return token_authorization_message(
            self.mint_or_melt,
            self.token_coin_id,
            self.amount,
        )


@dataclass(frozen=True)
class PoolV2ActionSpec:
    action_tag: int
    quote: SpecificDeedSwapQuote | RedemptionQuote | ReserveAcquisitionQuote
    next_state: PoolEconomicState
    nav_evidence: CollectionNavEvidence
    required_nav_evidence_message: bytes
    deed_commitment: bytes32
    pool_action_message: bytes
    deed_message: bytes
    token_outputs: tuple[TokenOutput, ...]
    token_authorizations: tuple[TokenAuthorization, ...] = ()


def principal_tokens_for_nav(deed_nav: int, state: PoolEconomicState) -> int:
    """Return token principal required for a NAV-pro-rata deed exit."""
    circulating = state.circulating_supply()
    if state.total_nav_locked_mojos <= 0:
        raise ValueError("total_nav_locked_mojos must be positive")
    if circulating <= 0:
        raise ValueError("circulating supply must be positive")
    if deed_nav <= 0:
        raise ValueError("deed_nav must be positive")
    if deed_nav > state.total_nav_locked_mojos:
        raise ValueError("deed_nav cannot exceed total NAV locked")
    return ceil_div(deed_nav * circulating, state.total_nav_locked_mojos)


def fee_split_for_principal(
    principal_tokens: int,
    *,
    swap_fee_bps: int = DEFAULT_SWAP_FEE_BPS,
    protocol_fee_bps: int = DEFAULT_PROTOCOL_FEE_BPS,
    governance_fee_bps: int = DEFAULT_GOVERNANCE_FEE_BPS,
) -> FeeSplit:
    if principal_tokens <= 0:
        raise ValueError("principal_tokens must be positive")
    if swap_fee_bps < 0:
        raise ValueError("swap_fee_bps must be non-negative")
    if protocol_fee_bps < 0 or governance_fee_bps < 0:
        raise ValueError("fee split bps must be non-negative")
    if protocol_fee_bps + governance_fee_bps != swap_fee_bps:
        raise ValueError("protocol + governance fee bps must equal swap_fee_bps")
    total_fee = ceil_div(principal_tokens * swap_fee_bps, FEE_BPS_DENOMINATOR)
    protocol_fee = ceil_div(principal_tokens * protocol_fee_bps, FEE_BPS_DENOMINATOR)
    governance_fee = total_fee - protocol_fee
    return FeeSplit(
        protocol_fee_tokens=protocol_fee,
        governance_fee_tokens=governance_fee,
        total_fee_tokens=total_fee,
    )


def quote_specific_deed_swap(
    state: PoolEconomicState,
    *,
    collection_nav_mojos: int,
    share_ppm: int,
    swap_fee_bps: int = DEFAULT_SWAP_FEE_BPS,
    protocol_fee_bps: int = DEFAULT_PROTOCOL_FEE_BPS,
    governance_fee_bps: int = DEFAULT_GOVERNANCE_FEE_BPS,
) -> SpecificDeedSwapQuote:
    """Quote a specific deed purchase paid in pool tokens.

    Principal goes into locked treasury reserve.  Total supply is unchanged;
    circulating supply decreases by the principal because those reserve tokens
    stop participating in NAV-per-circulating-token displays.
    """
    nav = deed_nav_mojos(collection_nav_mojos, share_ppm)
    if state.deed_count <= 0:
        raise ValueError("deed_count must be positive")
    principal = principal_tokens_for_nav(nav, state)
    fees = fee_split_for_principal(
        principal,
        swap_fee_bps=swap_fee_bps,
        protocol_fee_bps=protocol_fee_bps,
        governance_fee_bps=governance_fee_bps,
    )
    return SpecificDeedSwapQuote(
        deed_nav_mojos=nav,
        principal_tokens=principal,
        fee_split=fees,
        buyer_total_tokens=principal + fees.total_fee_tokens,
        next_total_nav_locked_mojos=state.total_nav_locked_mojos - nav,
        next_deed_count=state.deed_count - 1,
        next_total_pool_token_supply=state.total_pool_token_supply,
        next_treasury_reserve_tokens=state.treasury_reserve_tokens + principal,
    )


def quote_true_redemption(
    state: PoolEconomicState,
    *,
    collection_nav_mojos: int,
    share_ppm: int,
) -> RedemptionQuote:
    """Quote a true redemption: holder melts principal tokens for the deed."""
    nav = deed_nav_mojos(collection_nav_mojos, share_ppm)
    if state.deed_count <= 0:
        raise ValueError("deed_count must be positive")
    principal = principal_tokens_for_nav(nav, state)
    if principal > state.total_pool_token_supply:
        raise ValueError("principal exceeds total pool token supply")
    return RedemptionQuote(
        deed_nav_mojos=nav,
        principal_tokens=principal,
        next_total_nav_locked_mojos=state.total_nav_locked_mojos - nav,
        next_deed_count=state.deed_count - 1,
        next_total_pool_token_supply=state.total_pool_token_supply - principal,
        next_treasury_reserve_tokens=state.treasury_reserve_tokens,
    )


def quote_reserve_acquisition(
    state: PoolEconomicState,
    *,
    collection_nav_mojos: int,
    share_ppm: int,
    seller_token_price: int,
) -> ReserveAcquisitionQuote:
    """Quote acquisition of a new deed, using treasury reserve first."""
    if seller_token_price <= 0:
        raise ValueError("seller_token_price must be positive")
    nav = deed_nav_mojos(collection_nav_mojos, share_ppm)
    if seller_token_price > nav:
        raise ValueError("seller_token_price cannot exceed deed NAV")
    reserve_paid = min(state.treasury_reserve_tokens, seller_token_price)
    fresh_mint = seller_token_price - reserve_paid
    return ReserveAcquisitionQuote(
        deed_nav_mojos=nav,
        reserve_tokens_paid=reserve_paid,
        fresh_tokens_to_mint=fresh_mint,
        next_total_nav_locked_mojos=state.total_nav_locked_mojos + nav,
        next_deed_count=state.deed_count + 1,
        next_total_pool_token_supply=state.total_pool_token_supply + fresh_mint,
        next_treasury_reserve_tokens=state.treasury_reserve_tokens - reserve_paid,
    )


def _as_b32(value: bytes | bytes32, label: str) -> bytes32:
    b = bytes(value)
    if len(b) != 32:
        raise ValueError(f"{label} must be 32 bytes, got {len(b)}")
    return bytes32(b)


def _validate_uint64(value: int, label: str) -> int:
    if value < 0 or value >= 2**64:
        raise ValueError(f"{label} must fit uint64")
    return int(value)


def prefixed_tree_message(items: list[object]) -> bytes:
    return PROTOCOL_PREFIX + Program.to(items).get_tree_hash()


def token_authorization_message(
    mint_or_melt: int,
    token_coin_id: bytes | bytes32,
    amount: int,
) -> bytes:
    if mint_or_melt not in (TOKEN_MINT, TOKEN_MELT):
        raise ValueError("mint_or_melt must be TOKEN_MINT or TOKEN_MELT")
    token_id = _as_b32(token_coin_id, "token_coin_id")
    if amount <= 0:
        raise ValueError("amount must be positive")
    return prefixed_tree_message([mint_or_melt, token_id, int(amount)])


def token_settlement_payment_message(
    pool_coin_id: bytes | bytes32,
    outputs: tuple[TokenOutput, ...],
) -> bytes32:
    """Message asserted against CAT(TOKEN_TAIL, settlement_payments).

    Mirrors pool_singleton_inner_v3.clsp's ``sha256tree(c my_id payments)`` shape.
    ``pool_coin_id`` is the pool coin id performing the swap spend.
    """
    coin_id = _as_b32(pool_coin_id, "pool_coin_id")
    if not outputs:
        raise ValueError("outputs must not be empty")
    if len(outputs) > MAX_POOL_V2_TOKEN_OUTPUTS:
        raise ValueError(f"outputs cannot exceed {MAX_POOL_V2_TOKEN_OUTPUTS}")
    payments = [output.settlement_payment() for output in outputs]
    return bytes32(Program.to(coin_id).cons(Program.to(payments)).get_tree_hash())


def deed_metadata_commitment(
    deed_launcher_id: bytes | bytes32,
    par_value_mojos: int,
    asset_class: int,
    property_id_canon: bytes | bytes32,
    collection_id_canon: bytes | bytes32,
    share_ppm: int,
) -> bytes32:
    launcher_id = _as_b32(deed_launcher_id, "deed_launcher_id")
    property_id = _as_b32(property_id_canon, "property_id_canon")
    collection = _as_b32(collection_id_canon, "collection_id_canon")
    if par_value_mojos <= 0:
        raise ValueError("par_value_mojos must be positive")
    _validate_uint64(par_value_mojos, "par_value_mojos")
    _validate_uint64(asset_class, "asset_class")
    if share_ppm <= 0 or share_ppm > SHARE_PPM_DENOMINATOR:
        raise ValueError("share_ppm must be in 1..1_000_000")
    return bytes32(
        Program.to(
            [launcher_id, par_value_mojos, asset_class, property_id, collection, share_ppm]
        ).get_tree_hash()
    )


def deed_pool_redeem_message(
    deed_commitment: bytes | bytes32,
    p2_vault_puzzle_hash: bytes | bytes32,
) -> bytes:
    commitment = _as_b32(deed_commitment, "deed_commitment")
    p2_vault = _as_b32(p2_vault_puzzle_hash, "p2_vault_puzzle_hash")
    return prefixed_tree_message([DEED_SPEND_POOL_REDEEM, commitment, p2_vault])


def deed_pool_deposit_message(
    deed_id: bytes | bytes32,
    deed_launcher_id: bytes | bytes32,
    par_value_mojos: int,
    asset_class: int,
    property_id_canon: bytes | bytes32,
    collection_id_canon: bytes | bytes32,
    share_ppm: int,
) -> bytes:
    deed = _as_b32(deed_id, "deed_id")
    property_id = _as_b32(property_id_canon, "property_id_canon")
    collection = _as_b32(collection_id_canon, "collection_id_canon")
    commitment = deed_metadata_commitment(
        deed_launcher_id,
        par_value_mojos,
        asset_class,
        property_id,
        collection,
        share_ppm,
    )
    return prefixed_tree_message(
        [
            DEED_SPEND_POOL_DEPOSIT,
            deed,
            commitment,
            int(par_value_mojos),
            int(asset_class),
            property_id,
            collection,
            int(share_ppm),
        ]
    )


def _validate_nav_evidence(
    evidence: CollectionNavEvidence,
    collection_id_canon: bytes32,
) -> None:
    _as_b32(evidence.registry_coin_id, "nav_evidence.registry_coin_id")
    _as_b32(evidence.registry_puzzle_hash, "nav_evidence.registry_puzzle_hash")
    _as_b32(evidence.collection_nav_root, "nav_evidence.collection_nav_root")
    if evidence.collection_id_canon != collection_id_canon:
        raise ValueError("NAV evidence collection_id_canon mismatch")
    if evidence.nav_value_mojos <= 0:
        raise ValueError("NAV evidence nav_value_mojos must be positive")
    if evidence.registry_version < 0:
        raise ValueError("NAV evidence registry_version must be non-negative")


def _next_state_from_quote(
    quote: SpecificDeedSwapQuote | RedemptionQuote | ReserveAcquisitionQuote,
) -> PoolEconomicState:
    return PoolEconomicState(
        total_nav_locked_mojos=quote.next_total_nav_locked_mojos,
        deed_count=quote.next_deed_count,
        total_pool_token_supply=quote.next_total_pool_token_supply,
        treasury_reserve_tokens=quote.next_treasury_reserve_tokens,
    )


def build_specific_deed_swap_spec(
    state: PoolEconomicState,
    *,
    deed_id: bytes | bytes32,
    deed_launcher_id: bytes | bytes32,
    par_value_mojos: int,
    asset_class: int,
    property_id_canon: bytes | bytes32,
    p2_vault_puzzle_hash: bytes | bytes32,
    collection_id_canon: bytes | bytes32,
    share_ppm: int,
    nav_evidence: CollectionNavEvidence,
    treasury_reserve_puzhash: bytes | bytes32,
    protocol_treasury_puzhash: bytes | bytes32,
    governance_rewards_puzhash: bytes | bytes32,
    governance_rewards_root: bytes | bytes32,
) -> PoolV2ActionSpec:
    deed = _as_b32(deed_id, "deed_id")
    p2_vault = _as_b32(p2_vault_puzzle_hash, "p2_vault_puzzle_hash")
    collection = _as_b32(collection_id_canon, "collection_id_canon")
    commitment = deed_metadata_commitment(
        deed_launcher_id,
        par_value_mojos,
        asset_class,
        property_id_canon,
        collection,
        share_ppm,
    )
    reserve_ph = _as_b32(treasury_reserve_puzhash, "treasury_reserve_puzhash")
    protocol_ph = _as_b32(protocol_treasury_puzhash, "protocol_treasury_puzhash")
    rewards_ph = _as_b32(governance_rewards_puzhash, "governance_rewards_puzhash")
    rewards_root = _as_b32(governance_rewards_root, "governance_rewards_root")
    _validate_nav_evidence(nav_evidence, collection)
    quote = quote_specific_deed_swap(
        state,
        collection_nav_mojos=nav_evidence.nav_value_mojos,
        share_ppm=share_ppm,
    )
    deed_message = deed_pool_redeem_message(commitment, p2_vault)
    pool_action_message = prefixed_tree_message(
        [
            POOL_V2_SPECIFIC_DEED_SWAP_TAG,
            deed,
            commitment,
            p2_vault,
            collection,
            int(share_ppm),
            nav_evidence.nav_value_mojos,
            nav_evidence.collection_nav_root,
            nav_evidence.registry_version,
            nav_evidence.registry_coin_id,
            nav_evidence.registry_puzzle_hash,
            quote.deed_nav_mojos,
            quote.principal_tokens,
            quote.fee_split.protocol_fee_tokens,
            quote.fee_split.governance_fee_tokens,
            reserve_ph,
            protocol_ph,
            rewards_ph,
            rewards_root,
        ]
    )
    return PoolV2ActionSpec(
        action_tag=POOL_V2_SPECIFIC_DEED_SWAP_TAG,
        quote=quote,
        next_state=_next_state_from_quote(quote),
        nav_evidence=nav_evidence,
        required_nav_evidence_message=nav_evidence.announcement_message,
        deed_commitment=commitment,
        pool_action_message=pool_action_message,
        deed_message=deed_message,
        token_outputs=(
            TokenOutput(
                reserve_ph,
                quote.principal_tokens,
                "treasury_reserve_principal",
                (reserve_ph,),
            ),
            TokenOutput(
                protocol_ph,
                quote.fee_split.protocol_fee_tokens,
                "protocol_treasury_fee",
                (protocol_ph,),
            ),
            TokenOutput(
                rewards_ph,
                quote.fee_split.governance_fee_tokens,
                "sgt_rewards_fee",
                (rewards_ph, rewards_root),
            ),
        ),
    )


def build_true_redemption_spec(
    state: PoolEconomicState,
    *,
    deed_id: bytes | bytes32,
    deed_launcher_id: bytes | bytes32,
    par_value_mojos: int,
    asset_class: int,
    property_id_canon: bytes | bytes32,
    p2_vault_puzzle_hash: bytes | bytes32,
    collection_id_canon: bytes | bytes32,
    share_ppm: int,
    nav_evidence: CollectionNavEvidence,
    token_coin_id: bytes | bytes32,
) -> PoolV2ActionSpec:
    deed = _as_b32(deed_id, "deed_id")
    p2_vault = _as_b32(p2_vault_puzzle_hash, "p2_vault_puzzle_hash")
    collection = _as_b32(collection_id_canon, "collection_id_canon")
    token_id = _as_b32(token_coin_id, "token_coin_id")
    commitment = deed_metadata_commitment(
        deed_launcher_id,
        par_value_mojos,
        asset_class,
        property_id_canon,
        collection,
        share_ppm,
    )
    _validate_nav_evidence(nav_evidence, collection)
    quote = quote_true_redemption(
        state,
        collection_nav_mojos=nav_evidence.nav_value_mojos,
        share_ppm=share_ppm,
    )
    deed_message = deed_pool_redeem_message(commitment, p2_vault)
    pool_action_message = prefixed_tree_message(
        [
            POOL_V2_TRUE_REDEMPTION_TAG,
            deed,
            commitment,
            p2_vault,
            collection,
            int(share_ppm),
            nav_evidence.nav_value_mojos,
            nav_evidence.collection_nav_root,
            nav_evidence.registry_version,
            nav_evidence.registry_coin_id,
            nav_evidence.registry_puzzle_hash,
            quote.deed_nav_mojos,
            quote.principal_tokens,
            token_id,
        ]
    )
    return PoolV2ActionSpec(
        action_tag=POOL_V2_TRUE_REDEMPTION_TAG,
        quote=quote,
        next_state=_next_state_from_quote(quote),
        nav_evidence=nav_evidence,
        required_nav_evidence_message=nav_evidence.announcement_message,
        deed_commitment=commitment,
        pool_action_message=pool_action_message,
        deed_message=deed_message,
        token_outputs=(),
        token_authorizations=(
            TokenAuthorization(TOKEN_MELT, token_id, quote.principal_tokens),
        ),
    )


def build_reserve_acquisition_spec(
    state: PoolEconomicState,
    *,
    deed_id: bytes | bytes32,
    deed_launcher_id: bytes | bytes32,
    property_id_canon: bytes | bytes32,
    par_value_mojos: int,
    asset_class: int,
    collection_id_canon: bytes | bytes32,
    share_ppm: int,
    nav_evidence: CollectionNavEvidence,
    seller_puzhash: bytes | bytes32,
    seller_token_price: int,
    mint_token_coin_id: bytes | bytes32 | None = None,
) -> PoolV2ActionSpec:
    deed = _as_b32(deed_id, "deed_id")
    property_id = _as_b32(property_id_canon, "property_id_canon")
    collection = _as_b32(collection_id_canon, "collection_id_canon")
    seller_ph = _as_b32(seller_puzhash, "seller_puzhash")
    _validate_nav_evidence(nav_evidence, collection)
    quote = quote_reserve_acquisition(
        state,
        collection_nav_mojos=nav_evidence.nav_value_mojos,
        share_ppm=share_ppm,
        seller_token_price=seller_token_price,
    )
    mint_token_id: bytes32 | None = None
    if quote.fresh_tokens_to_mint > 0 and mint_token_coin_id is None:
        raise ValueError("mint_token_coin_id is required when reserve has a fresh mint shortfall")
    token_authorizations: tuple[TokenAuthorization, ...] = ()
    if quote.fresh_tokens_to_mint > 0:
        mint_token_id = _as_b32(mint_token_coin_id, "mint_token_coin_id")
        token_authorizations = (
            TokenAuthorization(
                TOKEN_MINT,
                mint_token_id,
                quote.fresh_tokens_to_mint,
            ),
        )
    commitment = deed_metadata_commitment(
        deed_launcher_id,
        par_value_mojos,
        asset_class,
        property_id,
        collection,
        share_ppm,
    )
    deed_message = deed_pool_deposit_message(
        deed,
        deed_launcher_id,
        par_value_mojos,
        asset_class,
        property_id,
        collection,
        share_ppm,
    )
    pool_action_message = prefixed_tree_message(
        [
            POOL_V2_RESERVE_ACQUISITION_TAG,
            deed,
            commitment,
            property_id,
            int(par_value_mojos),
            int(asset_class),
            collection,
            int(share_ppm),
            nav_evidence.nav_value_mojos,
            nav_evidence.collection_nav_root,
            nav_evidence.registry_version,
            nav_evidence.registry_coin_id,
            nav_evidence.registry_puzzle_hash,
            quote.deed_nav_mojos,
            int(seller_token_price),
            quote.reserve_tokens_paid,
            quote.fresh_tokens_to_mint,
            seller_ph,
            mint_token_id,
        ]
    )
    outputs: tuple[TokenOutput, ...] = ()
    if quote.reserve_tokens_paid > 0:
        outputs = (
            TokenOutput(seller_ph, quote.reserve_tokens_paid, "seller_reserve_payment", (seller_ph,)),
        )
    return PoolV2ActionSpec(
        action_tag=POOL_V2_RESERVE_ACQUISITION_TAG,
        quote=quote,
        next_state=_next_state_from_quote(quote),
        nav_evidence=nav_evidence,
        required_nav_evidence_message=nav_evidence.announcement_message,
        deed_commitment=commitment,
        pool_action_message=pool_action_message,
        deed_message=deed_message,
        token_outputs=outputs,
        token_authorizations=token_authorizations,
    )


__all__ = [
    "SHARE_PPM_DENOMINATOR",
    "DEFAULT_SWAP_FEE_BPS",
    "DEFAULT_PROTOCOL_FEE_BPS",
    "DEFAULT_GOVERNANCE_FEE_BPS",
    "MAX_POOL_V2_TOKEN_OUTPUTS",
    "PROTOCOL_PREFIX",
    "TOKEN_MINT",
    "TOKEN_MELT",
    "DEED_SPEND_POOL_DEPOSIT",
    "DEED_SPEND_POOL_REDEEM",
    "POOL_V2_SPECIFIC_DEED_SWAP_TAG",
    "POOL_V2_TRUE_REDEMPTION_TAG",
    "POOL_V2_RESERVE_ACQUISITION_TAG",
    "PoolEconomicState",
    "FeeSplit",
    "SpecificDeedSwapQuote",
    "RedemptionQuote",
    "ReserveAcquisitionQuote",
    "CollectionNavEvidence",
    "TokenOutput",
    "TokenAuthorization",
    "PoolV2ActionSpec",
    "ceil_div",
    "deed_nav_mojos",
    "principal_tokens_for_nav",
    "fee_split_for_principal",
    "quote_specific_deed_swap",
    "quote_true_redemption",
    "quote_reserve_acquisition",
    "prefixed_tree_message",
    "token_authorization_message",
    "token_settlement_payment_message",
    "deed_metadata_commitment",
    "deed_pool_redeem_message",
    "deed_pool_deposit_message",
    "build_specific_deed_swap_spec",
    "build_true_redemption_spec",
    "build_reserve_acquisition_spec",
]
