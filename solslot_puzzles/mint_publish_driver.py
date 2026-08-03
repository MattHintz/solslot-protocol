"""Python driver for the Phase 4 mint-proposal **publish** flow.

The mint-detail page's ``Publish`` action atomically lands two
on-chain artifacts:

  * **Artifact A** — the V2 per-proposal singleton
    (:file:`mint_proposal_inner_v2.clsp`) launched in ``DRAFT`` via
    a standard chia singleton launcher.  Pins authorship + metadata
    at publish time (CHIP-0043 ``OWNER_MEMBER_HASH`` = Eip712Member
    of the proposer's EVM address) plus immutable
    ``PROPOSAL_DATA_HASH``.

  * **Artifact B** — the governance tracker singleton
    (:file:`governance_singleton_inner.clsp`) spent in ``PROPOSE``
    mode with ``bill_op = (BILL_MINT, deed_full_puzhash,
    property_id_canon, property_registry_puzzle_hash)`` and the proposer's
    first SGT lock.

In the same bundle, the publisher pre-spawns the **deed
launcher coin** at the *DID-curried* launcher puzzle hash
(``singleton_launcher_with_did.curry(PROTOCOL_DID_SINGLETON_STRUCT)``)
so that ``deed_full_puzhash`` is deterministic from the parent
coin id at publish time.  The deed launcher coin sits unspent
until ``governance_singleton_inner.EXECUTE_MINT`` produces the
authorising DID announcement — there is **no launcher-coin race**
because the curried ``DID_SINGLETON_STRUCT`` constrains the
authorising puzzle to the protocol DID singleton lineage.

This module exposes **only** the deterministic
``build_mint_publish_artifacts`` computation that pins the four
``computed.*_puzhash`` fields surfaced by the admin desk API.
Spend-bundle assembly (parent → launcher → eve, tracker.PROPOSE,
SGT lock) lives in callers — the portal's
``MintPublishSpendBuilderService`` mirrors the artifacts produced
here byte-for-byte and threads them into ``CoinSpend`` objects
the wallet can sign.

Cross-repo binding:

  * The Solslot portal mint-proposal service mirrors
    every hash computation in TypeScript; the fixture dump in
    :file:`scripts/dump_mint_publish_fixtures.py` (sub-brick 4b)
    is the canonical reference both sides regression against.

  * The Solslot API mint endpoint's
    ``POST /admin/committee/propose`` (sub-brick 4e) re-runs this
    driver server-side to validate the spend bundle the portal
    submits — the API never trusts the portal's hash claims.

Design rationale and the deferred ``APPROVED → EXECUTED``
cross-coin coordination link are documented in
:file:`docs/PHASE_4_MINT_PUBLISH_FINAL.md`.
"""
from __future__ import annotations

from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    launch_conditions_and_coinsol,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.wallet.util.curry_and_treehash import (
    calculate_hash_of_quoted_mod_hash,
    curry_and_treehash,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.mint_proposal_v2_driver import (
    STATE_DRAFT,
    compute_proposal_data_hash,
    make_inner_puzzle_hash,
)
from solslot_puzzles.payment_artifacts_v3 import technology_fee_minor
from solslot_puzzles.stripe_settlement_v1_driver import (
    PrimaryMintTermsV3,
    make_inventory_available_inner,
)
from solslot_puzzles.sgt_driver import (
    TRK_PROPOSE,
    build_sgt_lock_coin_spend,
)

# ─── Constants pinned to puzzle source ─────────────────────────────────────

#: Bill operation tag for a MINT proposal on the governance tracker.
#: Matches :file:`governance_singleton_inner.clsp`'s ``BILL_MINT``
#: defconstant (``'M' = 0x4d``).
BILL_MINT_TAG = 0x4D

#: Singleton coin amount (mojos).  All Solslot singletons are
#: odd-amount singletons per chia singleton_top_layer_v1_1.
SINGLETON_AMOUNT = 1


# ─── Puzzle loaders ────────────────────────────────────────────────────────

_SMART_DEED_INNER_MOD: Program | None = None
_MINT_OFFER_DELEGATE_MOD: Program | None = None
_PURCHASE_PAYMENT_MOD: Program | None = None
_SINGLETON_LAUNCHER_WITH_DID_MOD: Program | None = None


def _smart_deed_inner_mod() -> Program:
    global _SMART_DEED_INNER_MOD
    if _SMART_DEED_INNER_MOD is None:
        _SMART_DEED_INNER_MOD = load_puzzle("smart_deed_inner_v2.clsp")
    return _SMART_DEED_INNER_MOD


def canonical_p2_pool_mod_hash() -> bytes32:
    """Return the only escrow module accepted by Solslot protocol v2."""
    return bytes32(load_puzzle("p2_pool_v2.clsp").get_tree_hash())


def _mint_offer_delegate_mod() -> Program:
    global _MINT_OFFER_DELEGATE_MOD
    if _MINT_OFFER_DELEGATE_MOD is None:
        _MINT_OFFER_DELEGATE_MOD = load_puzzle("mint_offer_delegate.clsp")
    return _MINT_OFFER_DELEGATE_MOD


def _purchase_payment_mod() -> Program:
    global _PURCHASE_PAYMENT_MOD
    if _PURCHASE_PAYMENT_MOD is None:
        _PURCHASE_PAYMENT_MOD = load_puzzle("purchase_payment.clsp")
    return _PURCHASE_PAYMENT_MOD


def _singleton_launcher_with_did_mod() -> Program:
    global _SINGLETON_LAUNCHER_WITH_DID_MOD
    if _SINGLETON_LAUNCHER_WITH_DID_MOD is None:
        _SINGLETON_LAUNCHER_WITH_DID_MOD = load_puzzle("singleton_launcher_with_did.clsp")
    return _SINGLETON_LAUNCHER_WITH_DID_MOD


def _purchase_payment_mod_hash() -> bytes32:
    return bytes32(_purchase_payment_mod().get_tree_hash())


# ─── Singleton-struct helpers ──────────────────────────────────────────────


def _standard_singleton_struct(launcher_id: bytes32) -> Program:
    """Standard chia singleton struct using ``SINGLETON_LAUNCHER_HASH``.

    Used for Artifact A (the V2 mint-proposal singleton), which
    launches via a plain chia singleton_launcher because it carries
    no DID-gated semantics.
    """
    return Program.to((SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH)))


def deed_launcher_puzzle_hash(
    *,
    protocol_did_singleton_struct: Program,
) -> bytes32:
    """Compute the deed launcher coin's puzzle hash.

    The deed launcher uses :file:`singleton_launcher_with_did.clsp`
    **curried with** ``PROTOCOL_DID_SINGLETON_STRUCT`` so the
    authorising-announcement check is constrained to the protocol
    DID singleton lineage at puzzle-hash time (not just at
    solution time).  This is what makes pre-spawning the deed
    launcher griefing-safe.

    See ``docs/PHASE_4_MINT_PUBLISH_AUDIT.md`` §2 for the security
    analysis vs. the standard ``SINGLETON_LAUNCHER`` puzzle.
    """
    if not isinstance(protocol_did_singleton_struct, Program):
        raise TypeError(
            "protocol_did_singleton_struct must be a Program"
        )
    curried = _singleton_launcher_with_did_mod().curry(
        protocol_did_singleton_struct
    )
    return bytes32(curried.get_tree_hash())


def deed_singleton_struct(
    *,
    deed_launcher_id: bytes32,
    protocol_did_singleton_struct: Program,
) -> Program:
    """Build the deed singleton's struct.

    Distinct from :func:`_standard_singleton_struct` because the
    deed's launcher uses ``singleton_launcher_with_did`` (curried
    with the protocol DID struct), not the standard chia
    launcher.  The struct's second slot is the launcher's puzzle
    hash, so it differs from a vanilla singleton.

    The struct is curried into :file:`smart_deed_inner_v2.clsp` as
    ``SINGLETON_STRUCT`` and into the eve mint-offer delegate via
    the singleton top layer.
    """
    if len(deed_launcher_id) != 32:
        raise ValueError(
            f"deed_launcher_id must be 32 bytes, got {len(deed_launcher_id)}"
        )
    did_launcher_ph = deed_launcher_puzzle_hash(
        protocol_did_singleton_struct=protocol_did_singleton_struct
    )
    return Program.to((SINGLETON_MOD_HASH, (deed_launcher_id, did_launcher_ph)))


# ─── Smart-deed inner + mint-offer eve helpers ─────────────────────────────


def make_smart_deed_inner(
    *,
    deed_singleton_struct_program: Program,
    protocol_did_puzhash: bytes32,
    par_value_mojos: int,
    asset_class: int,
    property_id_canon: bytes32,
    collection_id_canon: bytes32,
    share_ppm: int,
    jurisdiction: bytes,
    royalty_puzhash: bytes32,
    royalty_bps: int,
    pool_singleton_launcher_id: bytes32,
    pool_singleton_launcher_puzzle_hash: bytes32,
    p2_pool_mod_hash: bytes32,
    p2_vault_mod_hash: bytes32,
) -> Program:
    """Curry :file:`smart_deed_inner_v2.clsp` for the post-purchase deed inner.

    Currying order **must** match the puzzle's mod arguments (see
    the .clsp source):

        SINGLETON_STRUCT, PROTOCOL_DID_PUZHASH, PAR_VALUE,
        ASSET_CLASS, PROPERTY_ID, COLLECTION_ID_CANON, SHARE_PPM,
        JURISDICTION, ROYALTY_PUZHASH, ROYALTY_BPS,
        POOL_SINGLETON_MOD_HASH, POOL_SINGLETON_LAUNCHER_ID,
        POOL_SINGLETON_LAUNCHER_PUZZLE_HASH, P2_POOL_MOD_HASH,
        P2_VAULT_MOD_HASH

    The puzzle parameter named ``POOL_SINGLETON_MOD_HASH`` is the
    chia singleton top-layer mod hash (used in the deed's
    p2_pool-destination compute), **not** any solslot pool mod.
    The pool launcher fields bind deposit/redeem authorization to the
    sanctioned pool singleton lineage instead of solution-supplied identity.
    """
    if len(protocol_did_puzhash) != 32:
        raise ValueError(
            f"protocol_did_puzhash must be 32 bytes, got {len(protocol_did_puzhash)}"
        )
    if par_value_mojos <= 0:
        raise ValueError(
            f"par_value_mojos must be > 0, got {par_value_mojos}"
        )
    if len(property_id_canon) != 32:
        raise ValueError(
            f"property_id_canon must be 32 bytes, got {len(property_id_canon)}"
        )
    if len(collection_id_canon) != 32:
        raise ValueError(
            f"collection_id_canon must be 32 bytes, got {len(collection_id_canon)}"
        )
    if share_ppm <= 0 or share_ppm > 1_000_000:
        raise ValueError(
            f"share_ppm must be in [1, 1000000], got {share_ppm}"
        )
    if len(royalty_puzhash) != 32:
        raise ValueError(
            f"royalty_puzhash must be 32 bytes, got {len(royalty_puzhash)}"
        )
    if royalty_bps < 0 or royalty_bps > 10_000:
        raise ValueError(
            f"royalty_bps must be in [0, 10000], got {royalty_bps}"
        )
    if len(pool_singleton_launcher_id) != 32:
        raise ValueError(
            "pool_singleton_launcher_id must be 32 bytes, "
            f"got {len(pool_singleton_launcher_id)}"
        )
    if len(pool_singleton_launcher_puzzle_hash) != 32:
        raise ValueError(
            "pool_singleton_launcher_puzzle_hash must be 32 bytes, "
            f"got {len(pool_singleton_launcher_puzzle_hash)}"
        )
    if len(p2_pool_mod_hash) != 32:
        raise ValueError(
            f"p2_pool_mod_hash must be 32 bytes, got {len(p2_pool_mod_hash)}"
        )
    expected_p2_pool_mod_hash = canonical_p2_pool_mod_hash()
    if p2_pool_mod_hash != expected_p2_pool_mod_hash:
        raise ValueError(
            "p2_pool_mod_hash is retired or unsupported; expected Solslot v2 "
            f"{expected_p2_pool_mod_hash.hex()}"
        )
    if len(p2_vault_mod_hash) != 32:
        raise ValueError(
            f"p2_vault_mod_hash must be 32 bytes, got {len(p2_vault_mod_hash)}"
        )
    return _smart_deed_inner_mod().curry(
        deed_singleton_struct_program,
        protocol_did_puzhash,
        par_value_mojos,
        asset_class,
        property_id_canon,
        collection_id_canon,
        share_ppm,
        jurisdiction,
        royalty_puzhash,
        royalty_bps,
        SINGLETON_MOD_HASH,
        pool_singleton_launcher_id,
        pool_singleton_launcher_puzzle_hash,
        p2_pool_mod_hash,
        p2_vault_mod_hash,
    )


def make_mint_offer_eve_inner(
    *,
    smart_deed_inner_hash: bytes32,
    par_value_mojos: int,
    protocol_puzhash: bytes32,
) -> Program:
    """Curry :file:`mint_offer_delegate.clsp` for the deed's eve inner.

    This is the deed singleton's **initial** inner puzzle right
    after the launcher fires.  It is the on-chain standing offer
    that transitions the deed to the gated ``smart_deed_inner``
    once a buyer co-spends an ephemeral purchase_payment coin.
    """
    if len(smart_deed_inner_hash) != 32:
        raise ValueError(
            f"smart_deed_inner_hash must be 32 bytes, got {len(smart_deed_inner_hash)}"
        )
    if par_value_mojos <= 0:
        raise ValueError(
            f"par_value_mojos must be > 0, got {par_value_mojos}"
        )
    if len(protocol_puzhash) != 32:
        raise ValueError(
            f"protocol_puzhash must be 32 bytes, got {len(protocol_puzhash)}"
        )
    return _mint_offer_delegate_mod().curry(
        smart_deed_inner_hash,
        _purchase_payment_mod_hash(),
        par_value_mojos,
        protocol_puzhash,
    )


def compute_deed_full_puzzle_hash(
    *,
    deed_singleton_struct_program: Program,
    mint_offer_eve_inner_hash: bytes32,
) -> bytes32:
    """Tree hash of the deed singleton's full puzzle at launch.

    Equivalent to ``SINGLETON_MOD.curry(struct, inner).get_tree_hash()``
    but computed via ``curry_and_treehash`` so the caller never
    needs to materialise the eve inner puzzle when its tree hash
    is already known.

    The struct uses the DID-curried launcher hash in its second
    slot (see :func:`deed_singleton_struct`), which is what
    distinguishes the deed's lineage from a standard chia
    singleton.

    NOTE: ``curry_and_treehash`` takes the tree hashes of the BARE
    arguments — it wraps each one as ``(q . arg)`` internally via
    ``curried_values_tree_hash``.  Passing pre-quoted tree hashes
    double-wraps and produces the wrong result.  We pass raw
    ``bytes32`` here to match :func:`admin_authority_v2_driver.singleton_full_puzzle_hash`,
    which is verified against chia's ``puzzle_for_singleton`` in
    its own test suite.  (``protocol_deployment.singleton_full_puzzle_hash``
    has the double-wrap bug — do not copy its shape.)
    """
    quoted_mod = calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH)
    struct_hash = bytes32(deed_singleton_struct_program.get_tree_hash())
    return bytes32(
        curry_and_treehash(
            quoted_mod,
            struct_hash,
            mint_offer_eve_inner_hash,
        )
    )


def compute_proposal_hash_for_mint(
    *,
    deed_full_puzhash: bytes32,
    property_id_canon: bytes32,
    property_registry_puzzle_hash: bytes32,
    metadata_root: bytes32 | None = None,
    metadata_anchor_id: bytes32 | None = None,
) -> bytes32:
    """The 32-byte governance-tracker ``PROPOSAL_HASH`` for a MINT bill.

    Equals ``sha256tree((BILL_MINT, deed_full_puzhash, property_id_canon,
    property_registry_puzzle_hash))``.  The first payload slot remains the deed
    full puzzle hash consumed by ``governance_singleton_inner.clsp`` on EXECUTE;
    the two extra slots bind the MINT proposal hash to the property-registry
    registration context.  A later registry co-spend brick will have the tracker
    assert the corresponding registry announcement.

    The result is what SGT holders' tracker.VOTE spends bind to —
    Phase 3's vote runner already consumes this exact value as
    ``proposal_hash`` in its ``CurrentTrackerState``.
    """
    for value, name in (
        (deed_full_puzhash, "deed_full_puzhash"),
        (property_id_canon, "property_id_canon"),
        (property_registry_puzzle_hash, "property_registry_puzzle_hash"),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes, got {len(value)}")
    if (metadata_root is None) != (metadata_anchor_id is None):
        raise ValueError(
            "metadata_root and metadata_anchor_id must be supplied together"
        )
    bill_fields: list[object] = [
        BILL_MINT_TAG,
        deed_full_puzhash,
        property_id_canon,
        property_registry_puzzle_hash,
    ]
    if metadata_root is not None and metadata_anchor_id is not None:
        if len(metadata_root) != 32:
            raise ValueError(
                f"metadata_root must be 32 bytes, got {len(metadata_root)}"
            )
        if len(metadata_anchor_id) != 32:
            raise ValueError(
                "metadata_anchor_id must be 32 bytes, "
                f"got {len(metadata_anchor_id)}"
            )
        bill_fields.extend((metadata_root, metadata_anchor_id))
    bill_op = Program.to(bill_fields)
    return bytes32(bill_op.get_tree_hash())


# ─── Launcher coin computation ─────────────────────────────────────────────


def deed_launcher_coin_for_parent(
    *,
    parent_coin_name: bytes32,
    protocol_did_singleton_struct: Program,
) -> Coin:
    """Compute the deed launcher coin spawned from ``parent_coin_name``.

    The parent XCH coin spends with a ``CREATE_COIN`` at
    :func:`deed_launcher_puzzle_hash` amount 1.  The resulting
    launcher coin's name is deterministic from the parent coin
    name + puzzle hash + amount, allowing the publish bundle to
    pin ``deed_launcher_id`` (= launcher coin name) before the
    bundle is even signed.
    """
    if len(parent_coin_name) != 32:
        raise ValueError(
            f"parent_coin_name must be 32 bytes, got {len(parent_coin_name)}"
        )
    return Coin(
        parent_coin_info=parent_coin_name,
        puzzle_hash=deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=protocol_did_singleton_struct,
        ),
        amount=SINGLETON_AMOUNT,
    )


def proposal_singleton_launcher_coin_for_parent(
    *,
    parent_coin_name: bytes32,
) -> Coin:
    """Compute the Artifact A (V2 mint-proposal singleton) launcher coin.

    Uses the **standard** chia ``SINGLETON_LAUNCHER`` because the
    V2 mint-proposal singleton is admin-coordination only; it is
    not deed-launching and does not need DID gating.  The launcher
    is consumed atomically in the same publish bundle (parent →
    launcher → eve), so there is no idle-launcher griefing
    surface.
    """
    if len(parent_coin_name) != 32:
        raise ValueError(
            f"parent_coin_name must be 32 bytes, got {len(parent_coin_name)}"
        )
    return Coin(
        parent_coin_info=parent_coin_name,
        puzzle_hash=SINGLETON_LAUNCHER_HASH,
        amount=SINGLETON_AMOUNT,
    )


# ─── Artifacts dataclass + top-level builder ──────────────────────────────


@dataclass(frozen=True)
class MintPublishArtifacts:
    """All deterministic values pinned at publish time.

    Consumed by:
      * :mod:`scripts.dump_mint_publish_fixtures` (sub-brick 4b) →
        portal Karma fixture.
      * the Solslot portal mint-proposal service (sub-brick 4c)
        re-derives every field client-side, byte-equal.
      * the Solslot API publish endpoint (sub-brick
        4e) re-derives server-side and rejects bundles whose claimed
        hashes drift from the canonical computation.

    The fields divide into three groups:

    1. ``computed.*_puzhash`` row in the admin desk data model
       (``smart_deed_inner_puzhash``, ``eve_inner_puzhash``,
       ``deed_full_puzhash``, ``proposal_hash``).
    2. Launcher-coin identities (``deed_launcher_id``,
       ``proposal_singleton_launcher_id``) needed by callers to
       reference the just-spawned launchers in the rest of the
       publish bundle.
    3. Auxiliary programs (``bill_op_program``,
       ``deed_singleton_struct_program``) that downstream spend
       builders curry into solutions.
    """

    # ── computed.*_puzhash row (admin desk data model) ──
    smart_deed_inner_puzhash: bytes32
    """Tree hash of ``smart_deed_inner_v2.clsp`` curried with this deed's
    immutable metadata.  The deed's *post-purchase* inner — used by
    the mint-offer eve when it transitions the deed."""

    eve_inner_puzhash: bytes32
    """Tree hash of Artifact A's eve inner puzzle (V2 mint-proposal
    inner curried with state=DRAFT, version=0)."""

    deed_full_puzhash: bytes32
    """Singleton-wrapped mint-offer eve inner.  This is what
    governance ``EXECUTE_MINT`` commits to via the first payload slot of the
    expanded MINT bill and what the pre-spawned deed launcher will CREATE_COIN
    once that message fires."""

    proposal_hash: bytes32
    """Governance tracker ``PROPOSAL_HASH`` field for the MINT bill
    on Artifact B.  Equals ``sha256tree((BILL_MINT, deed_full_puzhash,
    property_id_canon, property_registry_puzzle_hash))``."""

    # ── Launcher-coin identities ──
    deed_launcher_id: bytes32
    """Name of the pre-spawned deed launcher coin (= future
    deed singleton's launcher id).  Determined by the
    ``deed_launcher_parent_coin_name`` argument."""

    proposal_singleton_launcher_id: bytes32
    """Name of Artifact A's launcher coin (= proposal_id on chain).
    Determined by the ``proposal_launcher_parent_coin_name``
    argument."""

    # ── Artifact A binding hash (audit log) ──
    proposal_data_hash: bytes32
    """sha256tree commitment over the proposal's immutable fields
    (property_id, par_value, royalty_bps, quorum_threshold).
    Curried into Artifact A so a future ``APPROVED → EXECUTED``
    cross-coin link can re-verify the bill_op's deed corresponds
    to this specific draft."""

    # ── Auxiliary programs ──
    bill_op_program: Program
    """``(BILL_MINT, deed_full_puzhash, property_id_canon,
    property_registry_puzzle_hash)`` Program.  Curried into tracker.PROPOSE's
    solution + Artifact B's recreated state."""

    deed_singleton_struct_program: Program
    """``(SINGLETON_MOD_HASH, (deed_launcher_id, did_curried_launcher_ph))``
    Program.  Curried into smart_deed_inner + used by the eve
    mint-offer's singleton top-layer wrap."""

    proposal_singleton_struct_program: Program
    """``(SINGLETON_MOD_HASH, (proposal_singleton_launcher_id,
    SINGLETON_LAUNCHER_HASH))`` Program.  Curried into Artifact
    A's singleton top-layer wrap."""


@dataclass(frozen=True)
class PrimaryPurchaseMintConfig:
    """Universal direct-purchase terms sealed into a collection deed at mint.

    The deed launcher and collection commitments are derived by
    :func:`build_mint_publish_artifacts`. ``usd_amount_minor`` is the governed
    base price; V5 computes and seals the technology fee and gross price.
    """

    network: str
    usd_amount_minor: int
    protocol_treasury_puzhash: bytes32
    validator_pubkeys: tuple[bytes, bytes, bytes]
    provider_id: bytes32
    technology_fee_bps: int = 100

    def __post_init__(self) -> None:
        if not self.network or len(self.network.encode("ascii")) > 32:
            raise ValueError("primary purchase network must be 1-32 ASCII bytes")
        if self.usd_amount_minor <= 0 or self.usd_amount_minor > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("primary purchase USD amount must be a positive uint64")
        expected_fee = technology_fee_minor(
            self.usd_amount_minor,
            self.technology_fee_bps,
        )
        if self.usd_amount_minor + expected_fee > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("primary purchase subtotal exceeds uint64")
        if len(self.protocol_treasury_puzhash) != 32:
            raise ValueError("protocol treasury puzzle hash must be bytes32")
        if len(self.validator_pubkeys) != 3:
            raise ValueError("primary purchase requires exactly three validator pubkeys")
        if len(set(self.validator_pubkeys)) != 3:
            raise ValueError("primary purchase validator pubkeys must be unique")
        if any(len(pubkey) != 48 for pubkey in self.validator_pubkeys):
            raise ValueError("primary purchase validator pubkeys must be 48-byte BLS keys")
        if len(self.provider_id) != 32:
            raise ValueError("primary purchase provider_id must be bytes32")


def build_mint_publish_artifacts(
    *,
    # Operator metadata (matches MintDraftStorageService fields).
    property_id_canon: bytes32,
    collection_id_canon: bytes32,
    share_ppm: int,
    par_value_mojos: int,
    asset_class: int,
    jurisdiction: bytes,
    royalty_puzhash: bytes32,
    royalty_bps: int,
    quorum_threshold: int,
    # Member auth (Eip712Member of admin EVM addr / env gov member).
    owner_member_hash: bytes32,
    gov_member_hash: bytes32,
    # Parent coin ids the wallet picked for the two launcher spends.
    deed_launcher_parent_coin_name: bytes32,
    proposal_launcher_parent_coin_name: bytes32,
    # Protocol deployment-derived context.
    protocol_did_singleton_struct: Program,
    protocol_did_puzhash: bytes32,
    protocol_did_inner_puzhash: bytes32,
    governance_singleton_struct: Program,
    pool_singleton_launcher_id: bytes32,
    pool_singleton_launcher_puzzle_hash: bytes32,
    p2_pool_mod_hash: bytes32,
    p2_vault_mod_hash: bytes32,
    property_registry_puzzle_hash: bytes32,
    metadata_root: bytes32 | None = None,
    metadata_anchor_id: bytes32 | None = None,
    primary_purchase: PrimaryPurchaseMintConfig | None = None,
) -> MintPublishArtifacts:
    """Deterministically pin all publish-time artifacts for a mint proposal.

    Pure function: same inputs always produce the same outputs.
    The portal and the API both run this in parallel; their
    results must match byte-for-byte or the API rejects the
    submission as a metadata tampering attempt.

    See module docstring for design rationale and the cross-repo
    contract surface.
    """
    if asset_class < 0:
        raise ValueError(
            f"asset_class must be >= 0, got {asset_class}"
        )
    if quorum_threshold < 0:
        raise ValueError(
            f"quorum_threshold must be >= 0, got {quorum_threshold}"
        )
    for ph, name in (
        (deed_launcher_parent_coin_name, "deed_launcher_parent_coin_name"),
        (proposal_launcher_parent_coin_name, "proposal_launcher_parent_coin_name"),
        (protocol_did_puzhash, "protocol_did_puzhash"),
        (protocol_did_inner_puzhash, "protocol_did_inner_puzhash"),
        (pool_singleton_launcher_id, "pool_singleton_launcher_id"),
        (
            pool_singleton_launcher_puzzle_hash,
            "pool_singleton_launcher_puzzle_hash",
        ),
        (property_registry_puzzle_hash, "property_registry_puzzle_hash"),
    ):
        if len(ph) != 32:
            raise ValueError(f"{name} must be 32 bytes, got {len(ph)}")

    # Step 1: pre-spawned launcher coins → ids.
    deed_launcher_coin = deed_launcher_coin_for_parent(
        parent_coin_name=deed_launcher_parent_coin_name,
        protocol_did_singleton_struct=protocol_did_singleton_struct,
    )
    deed_launcher_id = bytes32(deed_launcher_coin.name())

    proposal_singleton_launcher_coin = proposal_singleton_launcher_coin_for_parent(
        parent_coin_name=proposal_launcher_parent_coin_name,
    )
    proposal_singleton_launcher_id = bytes32(
        proposal_singleton_launcher_coin.name()
    )

    # Step 2: deed singleton struct + smart_deed_inner.
    deed_struct = deed_singleton_struct(
        deed_launcher_id=deed_launcher_id,
        protocol_did_singleton_struct=protocol_did_singleton_struct,
    )
    smart_deed_inner = make_smart_deed_inner(
        deed_singleton_struct_program=deed_struct,
        protocol_did_puzhash=protocol_did_puzhash,
        par_value_mojos=par_value_mojos,
        asset_class=asset_class,
        property_id_canon=property_id_canon,
        collection_id_canon=collection_id_canon,
        share_ppm=share_ppm,
        jurisdiction=jurisdiction,
        royalty_puzhash=royalty_puzhash,
        royalty_bps=royalty_bps,
        pool_singleton_launcher_id=pool_singleton_launcher_id,
        pool_singleton_launcher_puzzle_hash=pool_singleton_launcher_puzzle_hash,
        p2_pool_mod_hash=p2_pool_mod_hash,
        p2_vault_mod_hash=p2_vault_mod_hash,
    )
    smart_deed_inner_puzhash = bytes32(smart_deed_inner.get_tree_hash())

    # Step 3: mint-offer eve inner + deed_full_puzhash. New collection mints
    # use the native purchase delegate; the fixed-mojo delegate remains only
    # for historical fixtures and recall-only records.
    if primary_purchase is None:
        eve_mint_offer_inner = make_mint_offer_eve_inner(
            smart_deed_inner_hash=smart_deed_inner_puzhash,
            par_value_mojos=par_value_mojos,
            protocol_puzhash=protocol_did_puzhash,
        )
    else:
        if metadata_root is None:
            raise ValueError("primary purchase mints require metadata_root")
        resolved_anchor = metadata_anchor_id or deed_launcher_id
        fee_minor = technology_fee_minor(
            primary_purchase.usd_amount_minor,
            primary_purchase.technology_fee_bps,
        )
        eve_mint_offer_inner = make_inventory_available_inner(
            PrimaryMintTermsV3(
                network=primary_purchase.network,
                smart_deed_inner_hash=smart_deed_inner_puzhash,
                deed_launcher_id=deed_launcher_id,
                deed_launcher_puzzle_hash=deed_launcher_puzzle_hash(
                    protocol_did_singleton_struct=(
                        protocol_did_singleton_struct
                    )
                ),
                collection_id=collection_id_canon,
                metadata_root=metadata_root,
                metadata_anchor_id=resolved_anchor,
                share_ppm=share_ppm,
                base_amount_minor=primary_purchase.usd_amount_minor,
                technology_fee_bps=primary_purchase.technology_fee_bps,
                technology_fee_minor=fee_minor,
                subtotal_minor=primary_purchase.usd_amount_minor + fee_minor,
                protocol_treasury_puzzle_hash=(
                    primary_purchase.protocol_treasury_puzhash
                ),
                protocol_puzhash=primary_purchase.protocol_treasury_puzhash,
                validator_pubkeys=primary_purchase.validator_pubkeys,
                provider_id=primary_purchase.provider_id,
            )
        )
    eve_mint_offer_inner_hash = bytes32(eve_mint_offer_inner.get_tree_hash())
    deed_full_puzhash = compute_deed_full_puzzle_hash(
        deed_singleton_struct_program=deed_struct,
        mint_offer_eve_inner_hash=eve_mint_offer_inner_hash,
    )

    # Step 4: governance tracker proposal_hash + bill_op program.
    if metadata_root is None and metadata_anchor_id is not None:
        raise ValueError("metadata_anchor_id cannot be supplied without metadata_root")
    resolved_metadata_anchor_id = (
        metadata_anchor_id
        if metadata_anchor_id is not None
        else deed_launcher_id if metadata_root is not None else None
    )
    bill_fields: list[object] = [
        BILL_MINT_TAG,
        deed_full_puzhash,
        property_id_canon,
        property_registry_puzzle_hash,
    ]
    if metadata_root is not None and resolved_metadata_anchor_id is not None:
        if len(metadata_root) != 32:
            raise ValueError(
                f"metadata_root must be 32 bytes, got {len(metadata_root)}"
            )
        if len(resolved_metadata_anchor_id) != 32:
            raise ValueError(
                "metadata_anchor_id must be 32 bytes, "
                f"got {len(resolved_metadata_anchor_id)}"
            )
        bill_fields.extend((metadata_root, resolved_metadata_anchor_id))
    bill_op_program = Program.to(bill_fields)
    proposal_hash = bytes32(bill_op_program.get_tree_hash())

    # Step 5: Artifact A DRAFT eve inner puzzle hash + proposal data hash.
    proposal_data_hash = compute_proposal_data_hash(
        property_id_canon=property_id_canon,
        collection_id_canon=collection_id_canon,
        share_ppm=share_ppm,
        par_value_mojos=par_value_mojos,
        royalty_bps=royalty_bps,
        quorum_threshold=quorum_threshold,
        metadata_root=metadata_root,
        metadata_anchor_id=resolved_metadata_anchor_id,
    )
    eve_inner_puzhash = make_inner_puzzle_hash(
        owner_member_hash=owner_member_hash,
        gov_member_hash=gov_member_hash,
        proposal_data_hash=proposal_data_hash,
        governance_singleton_struct=governance_singleton_struct,
        governance_proposal_hash=proposal_hash,
        deed_launcher_id=deed_launcher_id,
        did_inner_puzzle_hash=protocol_did_inner_puzhash,
        deed_full_puzzle_hash=deed_full_puzhash,
        proposal_state=STATE_DRAFT,
        state_version=0,
    )

    proposal_struct = _standard_singleton_struct(proposal_singleton_launcher_id)

    return MintPublishArtifacts(
        smart_deed_inner_puzhash=smart_deed_inner_puzhash,
        eve_inner_puzhash=eve_inner_puzhash,
        deed_full_puzhash=deed_full_puzhash,
        proposal_hash=proposal_hash,
        deed_launcher_id=deed_launcher_id,
        proposal_singleton_launcher_id=proposal_singleton_launcher_id,
        proposal_data_hash=proposal_data_hash,
        bill_op_program=bill_op_program,
        deed_singleton_struct_program=deed_struct,
        proposal_singleton_struct_program=proposal_struct,
    )


# ─── Spend-bundle builders (Publish flow) ──────────────────────────────────
#
# The three builders below assemble the on-chain spends that constitute the
# publish bundle.  They are deliberately *bundle pieces*, not orchestrators:
# each returns a single ``CoinSpend`` (or, for the launcher hop, both the
# parent's announcement-pinning conditions and the launcher's own spend) so
# the wallet-side caller can compose them with arbitrary additional spends
# (e.g. fee coins) before signing.
#
# Why each piece is its own function:
#
#   * **Artifact A's launcher → eve hop** uses the *standard* chia launcher
#     because Artifact A is fully launched within the publish bundle — no
#     race surface, so no DID gating needed.  We delegate to chia's
#     ``launch_conditions_and_coinsol`` (the canonical helper) and surface
#     a thin wrapper that returns a typed result the TS port mirrors.
#
#   * **Artifact B's tracker.PROPOSE spend** opens the governance tracker
#     singleton with a MINT bill.  Mirrors
#     :func:`sgt_driver.build_tracker_vote_coin_spend` (Phase 3) for shape
#     consistency.  The PROPOSE handler in
#     :file:`governance_singleton_inner.clsp` asserts the SGT lock
#     announcement for ``(voter_inner_puzhash, proposal_hash, first_vote,
#     deadline)`` so the bundled SGT lock spend MUST emit that exact
#     announcement.
#
#   * **The proposer's SGT first-vote lock** is provided by a thin wrapper
#     around :func:`sgt_driver.build_sgt_lock_coin_spend` so the publish-
#     flow caller has a single import surface and clearer naming.  Phase 3
#     already verified the LOCK spend coin-sims green; we just rename for
#     the publish-flow caller.
#
# Note: the **deed launcher's spend** (consuming the pre-spawned DID-gated
# launcher coin) is **NOT** part of the publish bundle.  The publish bundle
# only *creates* that launcher coin via a CREATE_COIN condition in the
# wallet-built parent XCH spend; the launcher coin sits idle until the
# committee approves and the DID authorises the launch.  The spend builder
# for that later hop lands in the deed-launch brick (post-Phase 4), not
# 4d.1.


@dataclass(frozen=True)
class ProposalEveLaunchSpend:
    """Result of :func:`build_proposal_eve_launch_spend`.

    Mirrors the tuple returned by chia's
    :func:`launch_conditions_and_coinsol` but as a named dataclass so the
    TS port has a stable field surface to byte-compare against.

    Attributes:
        parent_conditions: List of CLVM ``Program`` conditions the parent
            XCH coin's spend must emit so that the launcher coin is
            created at the canonical Artifact A launcher puzzle hash with
            the canonical eve puzzle pre-announced.  Typically one
            ``CREATE_COIN`` and one ``ASSERT_COIN_ANNOUNCEMENT``.
        launcher_coin_spend: The launcher coin's own ``CoinSpend``.  When
            run, it emits the ``CREATE_COIN`` that brings the eve
            mint-proposal-v2 singleton into existence in DRAFT state.
        eve_coin: The eve mint-proposal-v2 singleton coin (computed,
            not yet on chain).  Exposed so callers can reference its
            coin id when building follow-up spends.
        eve_full_puzzle_hash: The singleton-wrapped eve puzzle hash.
            Equals ``puzzle_for_singleton(launcher_id,
            eve_inner_puzzle).get_tree_hash()`` — the value
            :func:`build_mint_publish_artifacts` exposes as
            ``eve_full_puzzle_hash`` (computed from the eve inner +
            launcher id, not the same as ``eve_inner_puzhash``).
    """

    parent_conditions: list[Program]
    launcher_coin_spend: CoinSpend
    eve_coin: Coin
    eve_full_puzzle_hash: bytes32


def build_proposal_eve_launch_spend(
    *,
    parent_coin: Coin,
    eve_inner_puzzle: Program,
    amount: int = SINGLETON_AMOUNT,
) -> ProposalEveLaunchSpend:
    """Build Artifact A's launcher → eve singleton launch hop.

    Wraps :func:`chia.wallet.puzzles.singleton_top_layer_v1_1.launch_conditions_and_coinsol`
    with publish-flow-friendly naming + dataclass return type.  The
    chia helper emits exactly the on-chain conventions required by the
    standard ``singleton_launcher.clsp``:

      1. Parent XCH coin spend must emit:
         ``(CREATE_COIN SINGLETON_LAUNCHER_HASH amount)`` and
         ``(ASSERT_COIN_ANNOUNCEMENT sha256(launcher_coin_id || launcher_solution_hash))``.

      2. Launcher coin spend's solution is
         ``(eve_full_puzzle_hash amount key_value_list=[])`` and the
         launcher's puzzle emits the ``CREATE_COIN`` that spawns the
         eve singleton.

    Args:
        parent_coin: The XCH coin (any standard puzzle) whose spend
            will include the launcher CREATE_COIN condition.  Its
            ``coin_id`` becomes the launcher coin's ``parent_coin_info``.
        eve_inner_puzzle: The V2 mint-proposal inner curried for the
            DRAFT eve state (output of
            :func:`mint_proposal_v2_driver.make_inner_puzzle`).  This is
            the *inner* puzzle; the chia helper wraps it with the
            singleton top-layer using the resulting launcher id.
        amount: Singleton coin amount (mojos).  Defaults to
            :data:`SINGLETON_AMOUNT` (= 1).  MUST be odd per the
            singleton convention; an even value raises ``ValueError``.

    Returns:
        :class:`ProposalEveLaunchSpend` with all four derived values.

    Raises:
        ValueError: if ``amount`` is even (rejected by the chia helper).
    """
    conditions, launcher_spend = launch_conditions_and_coinsol(
        parent_coin, eve_inner_puzzle, [], uint64(amount)
    )
    launcher_coin_id = bytes32(launcher_spend.coin.name())
    full_puzzle = puzzle_for_singleton(launcher_coin_id, eve_inner_puzzle)
    eve_full_puzzle_hash = bytes32(full_puzzle.get_tree_hash())
    eve_coin = Coin(launcher_coin_id, eve_full_puzzle_hash, uint64(amount))
    return ProposalEveLaunchSpend(
        parent_conditions=conditions,
        launcher_coin_spend=launcher_spend,
        eve_coin=eve_coin,
        eve_full_puzzle_hash=eve_full_puzzle_hash,
    )


def build_tracker_propose_coin_spend(
    *,
    tracker_coin: Coin,
    tracker_inner_puzzle: Program,
    tracker_launcher_id: bytes32,
    lineage_proof: LineageProof,
    proposal_hash: bytes32,
    bill_operation: Program,
    voter_inner_puzzle_hash: bytes32,
    first_vote_amount: int,
    voting_deadline: int,
) -> CoinSpend:
    """Singleton-wrapped PROPOSE spend for the governance proposal tracker.

    Opens a new proposal on an idle (no-active-proposal) tracker
    singleton.  After this spend, the tracker is recreated in OPEN
    state with the supplied ``proposal_hash``, ``bill_operation``,
    initial ``vote_tally = first_vote_amount`` (from the proposer's
    bundled SGT lock), and ``voting_deadline``.

    The PROPOSE handler in :file:`governance_singleton_inner.clsp`
    asserts the SGT lock announcement for
    ``(voter_inner_puzzle_hash, proposal_hash, first_vote_amount,
    voting_deadline)``, so the bundled SGT lock spend (see
    :func:`build_sgt_first_vote_coin_spend`) MUST emit that exact
    announcement.

    The inner solution layout matches
    :file:`governance_singleton_inner.clsp`'s dispatcher::

        (my_id my_inner_puzzlehash my_amount TRK_PROPOSE
            (proposal_hash bill_op voter_inner_puzhash first_vote voting_deadline))

    Args:
        tracker_coin: The current tracker singleton coin in IDLE state.
        tracker_inner_puzzle: The IDLE-state curried tracker inner
            puzzle (all ``PROPOSAL_HASH`` / ``BILL_OPERATION`` /
            ``VOTE_TALLY`` / ``VOTING_DEADLINE`` are zero).
        tracker_launcher_id: The tracker singleton's launcher id.
        lineage_proof: The lineage proof of ``tracker_coin``'s parent.
        proposal_hash: 32-byte ``sha256tree(bill_operation)`` of the
            proposal being opened.  Re-asserted on-chain via
            ``(= proposal_hash (sha256tree bill_op))``.
        bill_operation: The bill tuple — for a MINT proposal, this is
            ``Program.to([BILL_MINT_TAG, deed_full_puzhash,
            property_id_canon, property_registry_puzzle_hash])`` (the same
            value :func:`build_mint_publish_artifacts` exposes as
            ``bill_op_program``).
        voter_inner_puzzle_hash: The proposer's SGT free coin's inner
            puzzle hash — MUST match the curry of the bundled SGT lock
            spend so the LOCK announcement is produced by the
            proposer's coin (and not a different user's).
        first_vote_amount: The SGT mojos the proposer locks as their
            first vote.  MUST be ≥ ``MIN_PROPOSAL_STAKE`` (curried into
            the tracker) AND equal the co-spent SGT lock coin's
            amount (LOCK is a full-coin operation in Phase 3).
        voting_deadline: Absolute seconds (uint64) of the voting
            window's upper bound.  The tracker asserts both
            ``ASSERT_BEFORE_SECONDS_ABSOLUTE voting_deadline`` (now
            < deadline) and
            ``ASSERT_SECONDS_ABSOLUTE (voting_deadline - voting_window)``
            (now ≥ deadline - window) so the window is pinned within
            ``[deadline - window, deadline)``.

    Returns:
        A single ``CoinSpend`` ready to bundle with the matching SGT
        lock spend, Artifact A launch spend, and parent XCH spend(s),
        then signed and pushed.

    Raises:
        ValueError: if any 32-byte field has the wrong length or if
            ``first_vote_amount`` / ``voting_deadline`` is out of
            range.
    """
    if len(proposal_hash) != 32:
        raise ValueError("proposal_hash must be 32 bytes")
    if len(voter_inner_puzzle_hash) != 32:
        raise ValueError("voter_inner_puzzle_hash must be 32 bytes")
    if not isinstance(first_vote_amount, int) or first_vote_amount <= 0:
        raise ValueError("first_vote_amount must be a positive int")
    if (
        not isinstance(voting_deadline, int)
        or voting_deadline < 0
        or voting_deadline > 0xFFFFFFFFFFFFFFFF
    ):
        raise ValueError("voting_deadline must be a uint64")

    inner_solution = Program.to(
        [
            tracker_coin.name(),
            tracker_inner_puzzle.get_tree_hash(),
            tracker_coin.amount,
            TRK_PROPOSE,
            [
                proposal_hash,
                bill_operation,
                voter_inner_puzzle_hash,
                first_vote_amount,
                voting_deadline,
            ],
        ]
    )
    full_puzzle = puzzle_for_singleton(tracker_launcher_id, tracker_inner_puzzle)
    full_solution = solution_for_singleton(
        lineage_proof, uint64(tracker_coin.amount), inner_solution
    )
    return make_spend(tracker_coin, full_puzzle, full_solution)


def build_sgt_first_vote_coin_spend(
    *,
    sgt_coin: Coin,
    voter_inner_puzzle: Program,
    voter_inner_solution: Program,
    proposal_tracker_struct: Program,
    sgt_tail_hash: bytes32,
    lineage_proof: LineageProof,
    proposal_hash: bytes32,
    voting_deadline: int,
) -> CoinSpend:
    """The proposer's SGT free coin LOCK spend for the first vote.

    Phase 3's :func:`sgt_driver.build_sgt_lock_coin_spend` is generic
    across PROPOSE/VOTE/EXECUTE callers — this thin wrapper is the
    publish-flow-named entry point that delegates without changing
    semantics.  The publish bundle MUST include this spend co-spent
    with the tracker.PROPOSE spend from
    :func:`build_tracker_propose_coin_spend`; the tracker handler
    asserts the LOCK announcement this spend emits.

    Per Phase 3's LOCK semantics, the locked SGT amount equals
    ``sgt_coin.amount`` (LOCK is a full-coin op; ``extra_delta = 0``).
    The wallet must therefore have *already split* the proposer's
    SGT bag into a coin of exactly
    ``first_vote_amount = sgt_coin.amount``.  The tracker's
    ``first_vote_amount`` argument MUST equal this same value, or the
    on-chain ``lock_announcement_id`` won't match.

    Args:
        sgt_coin: The proposer's SGT free coin to lock.  Its puzzle
            hash MUST equal the canonical CAT2-wrapped sgt_free_inner
            puzhash for ``(proposal_tracker_struct, sgt_tail_hash,
            voter_inner_puzzle.tree_hash())``.
        voter_inner_puzzle: The reveal of the SGT owner's inner puzzle.
        voter_inner_solution: The signed inner solution; must yield
            exactly one CREATE_COIN to the canonical locked puzhash
            with ``amount == sgt_coin.amount``.
        proposal_tracker_struct: Singleton struct of the governance
            tracker.
        sgt_tail_hash: Tree hash of the curried SGT TAIL.
        lineage_proof: Lineage proof of the SGT coin's parent.
        proposal_hash: The proposal hash (same value the tracker
            PROPOSE solution asserts).
        voting_deadline: Absolute seconds of the voting deadline.

    Returns:
        The single ``CoinSpend`` for the CAT2-wrapped SGT lock.
    """
    return build_sgt_lock_coin_spend(
        sgt_coin=sgt_coin,
        voter_inner_puzzle=voter_inner_puzzle,
        voter_inner_solution=voter_inner_solution,
        proposal_tracker_struct=proposal_tracker_struct,
        sgt_tail_hash=sgt_tail_hash,
        lineage_proof=lineage_proof,
        proposal_hash=proposal_hash,
        deadline=voting_deadline,
    )


__all__ = [
    "BILL_MINT_TAG",
    "SINGLETON_AMOUNT",
    "MintPublishArtifacts",
    "PrimaryPurchaseMintConfig",
    "ProposalEveLaunchSpend",
    "build_mint_publish_artifacts",
    "build_sgt_first_vote_coin_spend",
    "build_proposal_eve_launch_spend",
    "build_tracker_propose_coin_spend",
    "compute_deed_full_puzzle_hash",
    "compute_proposal_hash_for_mint",
    "deed_launcher_coin_for_parent",
    "deed_launcher_puzzle_hash",
    "deed_singleton_struct",
    "make_mint_offer_eve_inner",
    "make_smart_deed_inner",
    "proposal_singleton_launcher_coin_for_parent",
]
