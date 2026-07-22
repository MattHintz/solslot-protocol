"""Tests for :mod:`solslot_puzzles.mint_publish_driver` (Phase 4a).

Coverage strategy:

  * ``TestMintPublishDriverConstants`` — pin the module's puzzle-source
    constants to detect drift if anyone edits the puzzle .clsp files
    without refreshing the driver.

  * ``TestDeedLauncherPuzzleHash`` — verify the deed launcher uses the
    *DID-curried* :file:`singleton_launcher_with_did.clsp` puzzle
    (the griefing-safe choice per the Phase 4 audit), not the standard
    chia singleton launcher.

  * ``TestSmartDeedInner`` + ``TestMintOfferEve`` — exercise the
    metadata-currying helpers and confirm input validation.

  * ``TestComputeDeedFullPuzzleHash`` — cross-check the
    ``curry_and_treehash`` fast path against the ground-truth
    ``SINGLETON_MOD.curry(struct, inner).get_tree_hash()`` so we know
    the driver matches chia's singleton top-layer math.

  * ``TestComputeProposalHashForMint`` — verify ``proposal_hash =
    sha256tree((BILL_MINT, deed_full_puzhash, property_id_canon,
    property_registry_puzzle_hash))`` matches the wire contract.

  * ``TestLauncherCoinComputation`` — verify both launcher coins
    have the right puzzle hashes + amounts and that their names are
    deterministic from the parent coin name.

  * ``TestBuildMintPublishArtifacts`` — top-level builder tests:
    determinism, input validation, dependency wiring (changing one
    input changes the right outputs), and a *golden vector* pinning
    the entire artifact set for one specific input tuple.

  * ``TestArtifactsCrossDriver`` — confirm the V2 mint-proposal
    driver and this driver produce the same ``eve_inner_puzhash``
    for matching inputs.
"""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.mint_proposal_v2_driver import (
    STATE_DRAFT,
    compute_proposal_data_hash,
    make_inner_puzzle_hash,
)
from solslot_puzzles.mint_publish_driver import (
    BILL_MINT_TAG,
    SINGLETON_AMOUNT,
    MintPublishArtifacts,
    ProposalEveLaunchSpend,
    build_mint_publish_artifacts,
    build_sgt_first_vote_coin_spend,
    build_proposal_eve_launch_spend,
    build_tracker_propose_coin_spend,
    compute_deed_full_puzzle_hash,
    compute_proposal_hash_for_mint,
    deed_launcher_coin_for_parent,
    deed_launcher_puzzle_hash,
    deed_singleton_struct,
    canonical_p2_pool_mod_hash,
    make_mint_offer_eve_inner,
    make_smart_deed_inner,
    proposal_singleton_launcher_coin_for_parent,
)


# ─── Test fixtures (synthetic but realistic shapes) ─────────────────────────

# 32-byte filler values are constructed by repeating a byte: visually
# distinct in fixture failures.
def _b(value: int) -> bytes32:
    return bytes32(bytes([value] * 32))


PROPERTY_ID = _b(0xA1)
COLLECTION_ID = _b(0xA8)
ROYALTY_PUZHASH = _b(0xA2)
PROTOCOL_DID_PUZHASH = _b(0xA3)
PROTOCOL_DID_INNER_PUZHASH = _b(0xA9)
P2_POOL_MOD_HASH = canonical_p2_pool_mod_hash()
P2_VAULT_MOD_HASH = _b(0xA5)
PROPERTY_REGISTRY_PUZZLE_HASH = _b(0xA7)
OWNER_MEMBER_HASH = _b(0xA6)
GOV_MEMBER_HASH = _b(0x00)  # placeholder zeros per Phase 4 alpha
DEED_LAUNCHER_PARENT = _b(0xB1)
PROPOSAL_LAUNCHER_PARENT = _b(0xB2)

PROTOCOL_DID_LAUNCHER_ID = _b(0xC1)
PROTOCOL_DID_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (PROTOCOL_DID_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
GOVERNANCE_LAUNCHER_ID = _b(0xC2)
GOVERNANCE_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (GOVERNANCE_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
POOL_SINGLETON_LAUNCHER_ID = _b(0xC3)
POOL_SINGLETON_LAUNCHER_PUZZLE_HASH = SINGLETON_LAUNCHER_HASH

PAR_VALUE = 250_000_000_000  # 250 XCH (mojos)
ASSET_CLASS = 1
SHARE_PPM = 750_000
JURISDICTION = b"US-CA"
ROYALTY_BPS = 250  # 2.5%
QUORUM_THRESHOLD = 5_000  # 50.00%


def _default_kwargs() -> dict:
    """Standard kwargs for ``build_mint_publish_artifacts``."""
    return {
        "property_id_canon": PROPERTY_ID,
        "collection_id_canon": COLLECTION_ID,
        "share_ppm": SHARE_PPM,
        "par_value_mojos": PAR_VALUE,
        "asset_class": ASSET_CLASS,
        "jurisdiction": JURISDICTION,
        "royalty_puzhash": ROYALTY_PUZHASH,
        "royalty_bps": ROYALTY_BPS,
        "quorum_threshold": QUORUM_THRESHOLD,
        "owner_member_hash": OWNER_MEMBER_HASH,
        "gov_member_hash": GOV_MEMBER_HASH,
        "deed_launcher_parent_coin_name": DEED_LAUNCHER_PARENT,
        "proposal_launcher_parent_coin_name": PROPOSAL_LAUNCHER_PARENT,
        "protocol_did_singleton_struct": PROTOCOL_DID_SINGLETON_STRUCT,
        "protocol_did_puzhash": PROTOCOL_DID_PUZHASH,
        "protocol_did_inner_puzhash": PROTOCOL_DID_INNER_PUZHASH,
        "governance_singleton_struct": GOVERNANCE_SINGLETON_STRUCT,
        "pool_singleton_launcher_id": POOL_SINGLETON_LAUNCHER_ID,
        "pool_singleton_launcher_puzzle_hash": POOL_SINGLETON_LAUNCHER_PUZZLE_HASH,
        "p2_pool_mod_hash": P2_POOL_MOD_HASH,
        "p2_vault_mod_hash": P2_VAULT_MOD_HASH,
        "property_registry_puzzle_hash": PROPERTY_REGISTRY_PUZZLE_HASH,
    }


# ─── 1. Module constants ────────────────────────────────────────────────────


class TestMintPublishDriverConstants:
    """Lock the puzzle-source constants.  Bump intentionally on .clsp edits."""

    def test_bill_mint_tag(self):
        # 'M' = 0x4d per governance_singleton_inner.clsp's BILL_MINT defconstant.
        assert BILL_MINT_TAG == 0x4D
        assert chr(BILL_MINT_TAG) == "M"

    def test_singleton_amount(self):
        # Odd-amount singletons per chia singleton_top_layer_v1_1.
        assert SINGLETON_AMOUNT == 1
        assert SINGLETON_AMOUNT % 2 == 1


# ─── 2. Deed launcher puzzle hash ───────────────────────────────────────────


class TestDeedLauncherPuzzleHash:
    """The deed launcher must be DID-curried (griefing-safe), not standard."""

    def test_is_not_standard_singleton_launcher(self):
        ph = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        assert ph != SINGLETON_LAUNCHER_HASH, (
            "deed launcher must NOT use the standard chia "
            "SINGLETON_LAUNCHER (griefing risk)"
        )

    def test_determinism_same_struct(self):
        ph1 = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        ph2 = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        assert ph1 == ph2

    def test_changes_with_did_struct(self):
        other_did_struct = Program.to(
            (SINGLETON_MOD_HASH, (_b(0xCC), SINGLETON_LAUNCHER_HASH))
        )
        ph_default = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        ph_other = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=other_did_struct,
        )
        assert ph_default != ph_other

    def test_rejects_non_program(self):
        with pytest.raises(TypeError, match="must be a Program"):
            deed_launcher_puzzle_hash(
                protocol_did_singleton_struct=b"\x00" * 32,  # type: ignore[arg-type]
            )


# ─── 3. Deed singleton struct ───────────────────────────────────────────────


class TestDeedSingletonStruct:
    def test_second_slot_is_did_curried_launcher_hash(self):
        struct = deed_singleton_struct(
            deed_launcher_id=_b(0xDD),
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        # Struct = (SINGLETON_MOD_HASH, (launcher_id, did_curried_launcher_ph))
        expected_did_ph = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        struct_first, struct_rest = struct.as_pair()
        assert struct_first.as_atom() == SINGLETON_MOD_HASH
        launcher_id_atom, launcher_ph_atom = struct_rest.as_pair()
        assert launcher_id_atom.as_atom() == _b(0xDD)
        assert launcher_ph_atom.as_atom() == expected_did_ph
        # Sanity: this is NOT the standard launcher hash.
        assert launcher_ph_atom.as_atom() != SINGLETON_LAUNCHER_HASH

    def test_rejects_short_launcher_id(self):
        with pytest.raises(ValueError, match="must be 32 bytes"):
            deed_singleton_struct(
                deed_launcher_id=b"\xaa" * 16,  # type: ignore[arg-type]
                protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
            )


# ─── 4. Smart-deed inner ────────────────────────────────────────────────────


class TestSmartDeedInner:
    def _kwargs(self) -> dict:
        struct = deed_singleton_struct(
            deed_launcher_id=_b(0xDD),
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        return {
            "deed_singleton_struct_program": struct,
            "protocol_did_puzhash": PROTOCOL_DID_PUZHASH,
            "par_value_mojos": PAR_VALUE,
            "asset_class": ASSET_CLASS,
            "property_id_canon": PROPERTY_ID,
            "collection_id_canon": COLLECTION_ID,
            "share_ppm": SHARE_PPM,
            "jurisdiction": JURISDICTION,
            "royalty_puzhash": ROYALTY_PUZHASH,
            "royalty_bps": ROYALTY_BPS,
            "pool_singleton_launcher_id": POOL_SINGLETON_LAUNCHER_ID,
            "pool_singleton_launcher_puzzle_hash": POOL_SINGLETON_LAUNCHER_PUZZLE_HASH,
            "p2_pool_mod_hash": P2_POOL_MOD_HASH,
            "p2_vault_mod_hash": P2_VAULT_MOD_HASH,
        }

    def test_returns_program(self):
        prog = make_smart_deed_inner(**self._kwargs())
        assert isinstance(prog, Program)

    def test_determinism(self):
        kwargs = self._kwargs()
        h1 = make_smart_deed_inner(**kwargs).get_tree_hash()
        h2 = make_smart_deed_inner(**kwargs).get_tree_hash()
        assert h1 == h2

    @pytest.mark.parametrize(
        "field,bad_value,msg",
        [
            ("protocol_did_puzhash", b"\x00" * 16, "must be 32 bytes"),
            ("par_value_mojos", 0, "must be > 0"),
            ("par_value_mojos", -1, "must be > 0"),
            ("property_id_canon", b"\x00" * 16, "must be 32 bytes"),
            ("collection_id_canon", b"\x00" * 16, "must be 32 bytes"),
            ("share_ppm", 0, r"must be in \[1, 1000000\]"),
            ("share_ppm", 1_000_001, r"must be in \[1, 1000000\]"),
            ("royalty_puzhash", b"\x00" * 16, "must be 32 bytes"),
            ("royalty_bps", -1, r"must be in \[0, 10000\]"),
            ("royalty_bps", 10_001, r"must be in \[0, 10000\]"),
            ("pool_singleton_launcher_id", b"\x00" * 16, "must be 32 bytes"),
            (
                "pool_singleton_launcher_puzzle_hash",
                b"\x00" * 16,
                "must be 32 bytes",
            ),
            ("p2_pool_mod_hash", b"\x00" * 16, "must be 32 bytes"),
            ("p2_vault_mod_hash", b"\x00" * 16, "must be 32 bytes"),
        ],
    )
    def test_input_validation(self, field, bad_value, msg):
        kwargs = self._kwargs()
        kwargs[field] = bad_value
        with pytest.raises(ValueError, match=msg):
            make_smart_deed_inner(**kwargs)

    def test_rejects_retired_p2_pool_module_hash(self):
        kwargs = self._kwargs()
        kwargs["p2_pool_mod_hash"] = _b(0xA5)
        with pytest.raises(ValueError, match="retired or unsupported"):
            make_smart_deed_inner(**kwargs)


# ─── 5. Mint-offer eve inner ────────────────────────────────────────────────


class TestMintOfferEve:
    def test_returns_program(self):
        prog = make_mint_offer_eve_inner(
            smart_deed_inner_hash=_b(0xEE),
            par_value_mojos=PAR_VALUE,
            protocol_puzhash=PROTOCOL_DID_PUZHASH,
        )
        assert isinstance(prog, Program)

    def test_determinism(self):
        h1 = make_mint_offer_eve_inner(
            smart_deed_inner_hash=_b(0xEE),
            par_value_mojos=PAR_VALUE,
            protocol_puzhash=PROTOCOL_DID_PUZHASH,
        ).get_tree_hash()
        h2 = make_mint_offer_eve_inner(
            smart_deed_inner_hash=_b(0xEE),
            par_value_mojos=PAR_VALUE,
            protocol_puzhash=PROTOCOL_DID_PUZHASH,
        ).get_tree_hash()
        assert h1 == h2

    @pytest.mark.parametrize(
        "field,bad_value,msg",
        [
            ("smart_deed_inner_hash", b"\x00" * 16, "must be 32 bytes"),
            ("par_value_mojos", 0, "must be > 0"),
            ("protocol_puzhash", b"\x00" * 16, "must be 32 bytes"),
        ],
    )
    def test_input_validation(self, field, bad_value, msg):
        kwargs = {
            "smart_deed_inner_hash": _b(0xEE),
            "par_value_mojos": PAR_VALUE,
            "protocol_puzhash": PROTOCOL_DID_PUZHASH,
        }
        kwargs[field] = bad_value
        with pytest.raises(ValueError, match=msg):
            make_mint_offer_eve_inner(**kwargs)


# ─── 6. Deed full puzzle hash (curry_and_treehash fast path) ───────────────


class TestComputeDeedFullPuzzleHash:
    """Cross-check our hash math against chia's ground-truth singleton wrap."""

    def test_matches_singleton_mod_curry_ground_truth(self):
        deed_struct = deed_singleton_struct(
            deed_launcher_id=_b(0xDD),
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        eve = make_mint_offer_eve_inner(
            smart_deed_inner_hash=_b(0xEE),
            par_value_mojos=PAR_VALUE,
            protocol_puzhash=PROTOCOL_DID_PUZHASH,
        )
        eve_hash = bytes32(eve.get_tree_hash())

        # Fast path under test:
        fast = compute_deed_full_puzzle_hash(
            deed_singleton_struct_program=deed_struct,
            mint_offer_eve_inner_hash=eve_hash,
        )

        # Ground truth: actually build the program and hash it.
        ground_truth = bytes32(
            SINGLETON_MOD.curry(deed_struct, eve).get_tree_hash()
        )

        assert fast == ground_truth, (
            f"compute_deed_full_puzzle_hash drift!\n"
            f"  fast path: {fast.hex()}\n"
            f"  chia gt:   {ground_truth.hex()}"
        )

    def test_determinism(self):
        deed_struct = deed_singleton_struct(
            deed_launcher_id=_b(0xDD),
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        h1 = compute_deed_full_puzzle_hash(
            deed_singleton_struct_program=deed_struct,
            mint_offer_eve_inner_hash=_b(0xEE),
        )
        h2 = compute_deed_full_puzzle_hash(
            deed_singleton_struct_program=deed_struct,
            mint_offer_eve_inner_hash=_b(0xEE),
        )
        assert h1 == h2

    def test_changes_with_eve_hash(self):
        deed_struct = deed_singleton_struct(
            deed_launcher_id=_b(0xDD),
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        a = compute_deed_full_puzzle_hash(
            deed_singleton_struct_program=deed_struct,
            mint_offer_eve_inner_hash=_b(0xEE),
        )
        b = compute_deed_full_puzzle_hash(
            deed_singleton_struct_program=deed_struct,
            mint_offer_eve_inner_hash=_b(0xEF),
        )
        assert a != b


# ─── 7. Proposal hash for MINT bill ────────────────────────────────────────


class TestComputeProposalHashForMint:
    def test_matches_sha256tree_of_bill_op_tuple(self):
        deed_full_ph = _b(0x77)
        expected = bytes32(
            Program.to(
                [
                    BILL_MINT_TAG,
                    deed_full_ph,
                    PROPERTY_ID,
                    PROPERTY_REGISTRY_PUZZLE_HASH,
                ]
            ).get_tree_hash()
        )
        actual = compute_proposal_hash_for_mint(
            deed_full_puzhash=deed_full_ph,
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
        )
        assert actual == expected

    def test_determinism(self):
        h1 = compute_proposal_hash_for_mint(
            deed_full_puzhash=_b(0x77),
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
        )
        h2 = compute_proposal_hash_for_mint(
            deed_full_puzhash=_b(0x77),
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
        )
        assert h1 == h2

    def test_changes_with_deed_full_ph(self):
        a = compute_proposal_hash_for_mint(
            deed_full_puzhash=_b(0x77),
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
        )
        b = compute_proposal_hash_for_mint(
            deed_full_puzhash=_b(0x78),
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
        )
        assert a != b

    def test_changes_with_property_registry_puzzle_hash(self):
        a = compute_proposal_hash_for_mint(
            deed_full_puzhash=_b(0x77),
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
        )
        b = compute_proposal_hash_for_mint(
            deed_full_puzhash=_b(0x77),
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=_b(0xA8),
        )
        assert a != b

    def test_rejects_short_deed_full_ph(self):
        with pytest.raises(ValueError, match="must be 32 bytes"):
            compute_proposal_hash_for_mint(
                deed_full_puzhash=b"\x77" * 16,  # type: ignore[arg-type]
                property_id_canon=PROPERTY_ID,
                property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
            )


# ─── 8. Launcher coin computation ──────────────────────────────────────────


class TestLauncherCoinComputation:
    def test_deed_launcher_coin_shape(self):
        coin = deed_launcher_coin_for_parent(
            parent_coin_name=DEED_LAUNCHER_PARENT,
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        assert coin.parent_coin_info == DEED_LAUNCHER_PARENT
        assert coin.amount == SINGLETON_AMOUNT
        # Deed launcher MUST use the DID-curried launcher puzzle hash.
        expected_ph = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        assert coin.puzzle_hash == expected_ph
        assert coin.puzzle_hash != SINGLETON_LAUNCHER_HASH

    def test_proposal_singleton_launcher_coin_shape(self):
        coin = proposal_singleton_launcher_coin_for_parent(
            parent_coin_name=PROPOSAL_LAUNCHER_PARENT,
        )
        assert coin.parent_coin_info == PROPOSAL_LAUNCHER_PARENT
        assert coin.amount == SINGLETON_AMOUNT
        # Artifact A uses the *standard* singleton launcher (atomic
        # parent → launcher → eve in same bundle, no griefing surface).
        assert coin.puzzle_hash == SINGLETON_LAUNCHER_HASH

    def test_deed_and_proposal_coins_have_different_puzzle_hashes(self):
        deed = deed_launcher_coin_for_parent(
            parent_coin_name=DEED_LAUNCHER_PARENT,
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        proposal = proposal_singleton_launcher_coin_for_parent(
            parent_coin_name=PROPOSAL_LAUNCHER_PARENT,
        )
        assert deed.puzzle_hash != proposal.puzzle_hash

    def test_deed_launcher_coin_name_deterministic(self):
        c1 = deed_launcher_coin_for_parent(
            parent_coin_name=DEED_LAUNCHER_PARENT,
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        c2 = deed_launcher_coin_for_parent(
            parent_coin_name=DEED_LAUNCHER_PARENT,
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        assert c1.name() == c2.name()

    def test_proposal_launcher_coin_name_deterministic(self):
        c1 = proposal_singleton_launcher_coin_for_parent(
            parent_coin_name=PROPOSAL_LAUNCHER_PARENT,
        )
        c2 = proposal_singleton_launcher_coin_for_parent(
            parent_coin_name=PROPOSAL_LAUNCHER_PARENT,
        )
        assert c1.name() == c2.name()

    def test_rejects_short_parent_coin_name(self):
        with pytest.raises(ValueError, match="must be 32 bytes"):
            deed_launcher_coin_for_parent(
                parent_coin_name=b"\xaa" * 16,  # type: ignore[arg-type]
                protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
            )
        with pytest.raises(ValueError, match="must be 32 bytes"):
            proposal_singleton_launcher_coin_for_parent(
                parent_coin_name=b"\xaa" * 16,  # type: ignore[arg-type]
            )


# ─── 9. Top-level build_mint_publish_artifacts ─────────────────────────────


class TestBuildMintPublishArtifacts:
    def test_returns_dataclass(self):
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        assert isinstance(artifacts, MintPublishArtifacts)

    def test_all_four_computed_hashes_present(self):
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        for field, value in (
            ("smart_deed_inner_puzhash", artifacts.smart_deed_inner_puzhash),
            ("eve_inner_puzhash", artifacts.eve_inner_puzhash),
            ("deed_full_puzhash", artifacts.deed_full_puzhash),
            ("proposal_hash", artifacts.proposal_hash),
        ):
            assert isinstance(value, bytes), f"{field} not bytes"
            assert len(value) == 32, f"{field} not 32 bytes"

    def test_determinism(self):
        a = build_mint_publish_artifacts(**_default_kwargs())
        b = build_mint_publish_artifacts(**_default_kwargs())
        # Compare every bytes32 field; Programs are compared by tree hash.
        assert a.smart_deed_inner_puzhash == b.smart_deed_inner_puzhash
        assert a.eve_inner_puzhash == b.eve_inner_puzhash
        assert a.deed_full_puzhash == b.deed_full_puzhash
        assert a.proposal_hash == b.proposal_hash
        assert a.deed_launcher_id == b.deed_launcher_id
        assert a.proposal_singleton_launcher_id == b.proposal_singleton_launcher_id
        assert a.proposal_data_hash == b.proposal_data_hash
        assert (
            a.bill_op_program.get_tree_hash()
            == b.bill_op_program.get_tree_hash()
        )
        assert (
            a.deed_singleton_struct_program.get_tree_hash()
            == b.deed_singleton_struct_program.get_tree_hash()
        )
        assert (
            a.proposal_singleton_struct_program.get_tree_hash()
            == b.proposal_singleton_struct_program.get_tree_hash()
        )

    def test_proposal_hash_equals_compute_proposal_hash_for_mint(self):
        """Top-level computation matches the standalone helper."""
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        expected = compute_proposal_hash_for_mint(
            deed_full_puzhash=artifacts.deed_full_puzhash,
            property_id_canon=PROPERTY_ID,
            property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
        )
        assert artifacts.proposal_hash == expected

    def test_proposal_data_hash_equals_v2_driver_compute(self):
        """Top-level computation matches V2 driver's standalone helper."""
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        expected = compute_proposal_data_hash(
            property_id_canon=PROPERTY_ID,
            collection_id_canon=COLLECTION_ID,
            share_ppm=SHARE_PPM,
            par_value_mojos=PAR_VALUE,
            royalty_bps=ROYALTY_BPS,
            quorum_threshold=QUORUM_THRESHOLD,
        )
        assert artifacts.proposal_data_hash == expected

    def test_eve_inner_puzhash_equals_v2_driver_make_inner_puzzle_hash(self):
        """Artifact A eve inner matches V2 driver's standalone make_inner_puzzle_hash."""
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        expected = make_inner_puzzle_hash(
            owner_member_hash=OWNER_MEMBER_HASH,
            gov_member_hash=GOV_MEMBER_HASH,
            proposal_data_hash=artifacts.proposal_data_hash,
            governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
            governance_proposal_hash=artifacts.proposal_hash,
            deed_launcher_id=artifacts.deed_launcher_id,
            did_inner_puzzle_hash=PROTOCOL_DID_INNER_PUZHASH,
            deed_full_puzzle_hash=artifacts.deed_full_puzhash,
            proposal_state=STATE_DRAFT,
            state_version=0,
        )
        assert artifacts.eve_inner_puzhash == expected

    def test_bill_op_program_is_mint_tag_plus_deed_full_and_registry_context(self):
        """The bill_op_program must bind MINT, deed ph, property id, and registry ph."""
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        items = list(artifacts.bill_op_program.as_iter())
        assert len(items) == 4
        assert int.from_bytes(items[0].as_atom(), "big") == BILL_MINT_TAG
        assert items[1].as_atom() == artifacts.deed_full_puzhash
        assert items[2].as_atom() == PROPERTY_ID
        assert items[3].as_atom() == PROPERTY_REGISTRY_PUZZLE_HASH

    def test_deed_launcher_id_matches_helper(self):
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        expected_coin = deed_launcher_coin_for_parent(
            parent_coin_name=DEED_LAUNCHER_PARENT,
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        assert artifacts.deed_launcher_id == bytes32(expected_coin.name())

    def test_proposal_singleton_launcher_id_matches_helper(self):
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        expected_coin = proposal_singleton_launcher_coin_for_parent(
            parent_coin_name=PROPOSAL_LAUNCHER_PARENT,
        )
        assert artifacts.proposal_singleton_launcher_id == bytes32(
            expected_coin.name()
        )

    # ── Dependency wiring: changing one input changes the right outputs ──

    def test_par_value_change_propagates_through_chain(self):
        a = build_mint_publish_artifacts(**_default_kwargs())
        kwargs = _default_kwargs()
        kwargs["par_value_mojos"] = PAR_VALUE + 1
        b = build_mint_publish_artifacts(**kwargs)

        # par_value flows into:
        #  - smart_deed_inner (curried) → smart_deed_inner_puzhash
        #  - mint_offer eve  (curried) → deed_full_puzhash
        #  - proposal_data_hash (sha256tree) → eve_inner_puzhash
        #  - proposal_hash (sha256tree of expanded MINT bill)
        assert a.smart_deed_inner_puzhash != b.smart_deed_inner_puzhash
        assert a.deed_full_puzhash != b.deed_full_puzhash
        assert a.proposal_hash != b.proposal_hash
        assert a.proposal_data_hash != b.proposal_data_hash
        assert a.eve_inner_puzhash != b.eve_inner_puzhash

        # But par_value does NOT touch the launcher coin parents,
        # so launcher ids should be unchanged.
        assert a.deed_launcher_id == b.deed_launcher_id
        assert a.proposal_singleton_launcher_id == b.proposal_singleton_launcher_id

    def test_owner_member_hash_change_only_affects_eve_inner(self):
        a = build_mint_publish_artifacts(**_default_kwargs())
        kwargs = _default_kwargs()
        kwargs["owner_member_hash"] = _b(0xCD)
        b = build_mint_publish_artifacts(**kwargs)

        # owner_member_hash only flows through Artifact A's inner puzzle.
        assert a.eve_inner_puzhash != b.eve_inner_puzhash
        # Smart-deed and downstream deed hashes do NOT depend on member auth.
        assert a.smart_deed_inner_puzhash == b.smart_deed_inner_puzhash
        assert a.deed_full_puzhash == b.deed_full_puzhash
        assert a.proposal_hash == b.proposal_hash
        # Launchers + proposal_data_hash unchanged.
        assert a.deed_launcher_id == b.deed_launcher_id
        assert a.proposal_singleton_launcher_id == b.proposal_singleton_launcher_id
        assert a.proposal_data_hash == b.proposal_data_hash

    def test_deed_launcher_parent_change_cascades_through_deed_chain(self):
        a = build_mint_publish_artifacts(**_default_kwargs())
        kwargs = _default_kwargs()
        kwargs["deed_launcher_parent_coin_name"] = _b(0xCE)
        b = build_mint_publish_artifacts(**kwargs)

        # Changing the deed launcher parent changes:
        #  - deed_launcher_id
        #  - deed_singleton_struct (depends on deed_launcher_id)
        #  - smart_deed_inner (depends on struct) → smart_deed_inner_puzhash
        #  - mint_offer eve  (depends on smart_deed_inner_puzhash) → deed_full_puzhash
        #  - proposal_hash (depends on deed_full_puzhash)
        assert a.deed_launcher_id != b.deed_launcher_id
        assert a.smart_deed_inner_puzhash != b.smart_deed_inner_puzhash
        assert a.deed_full_puzhash != b.deed_full_puzhash
        assert a.proposal_hash != b.proposal_hash

        # The Artifact A launcher id is independent, but its eve changes because
        # the proposal now commits the exact deed launcher and deed output.
        assert a.proposal_singleton_launcher_id == b.proposal_singleton_launcher_id
        assert a.eve_inner_puzhash != b.eve_inner_puzhash

    def test_proposal_launcher_parent_change_only_affects_proposal_singleton(self):
        a = build_mint_publish_artifacts(**_default_kwargs())
        kwargs = _default_kwargs()
        kwargs["proposal_launcher_parent_coin_name"] = _b(0xCF)
        b = build_mint_publish_artifacts(**kwargs)

        assert a.proposal_singleton_launcher_id != b.proposal_singleton_launcher_id
        # Everything else (deed chain, eve inner) unchanged.
        assert a.deed_launcher_id == b.deed_launcher_id
        assert a.smart_deed_inner_puzhash == b.smart_deed_inner_puzhash
        assert a.deed_full_puzhash == b.deed_full_puzhash
        assert a.proposal_hash == b.proposal_hash
        assert a.eve_inner_puzhash == b.eve_inner_puzhash

    # ── Input validation ──

    @pytest.mark.parametrize(
        "field,bad_value,msg",
        [
            ("asset_class", -1, "must be >= 0"),
            ("quorum_threshold", -1, "must be >= 0"),
            ("deed_launcher_parent_coin_name", b"\xaa" * 16, "must be 32 bytes"),
            ("proposal_launcher_parent_coin_name", b"\xaa" * 16, "must be 32 bytes"),
            ("protocol_did_puzhash", b"\xaa" * 16, "must be 32 bytes"),
            ("pool_singleton_launcher_id", b"\xaa" * 16, "must be 32 bytes"),
            (
                "pool_singleton_launcher_puzzle_hash",
                b"\xaa" * 16,
                "must be 32 bytes",
            ),
            ("property_registry_puzzle_hash", b"\xaa" * 16, "must be 32 bytes"),
        ],
    )
    def test_top_level_input_validation(self, field, bad_value, msg):
        kwargs = _default_kwargs()
        kwargs[field] = bad_value
        with pytest.raises(ValueError, match=msg):
            build_mint_publish_artifacts(**kwargs)

    # ── Golden vector ──

    def test_golden_vector(self):
        """Pin the entire artifact set for ONE specific input tuple.

        If any computation drifts (puzzle source edits, Python lib
        upgrades, etc.) this test surfaces the change immediately and
        forces a deliberate refreeze.  Refreezing means:

          1. Read the failure output.
          2. Confirm the change is intentional.
          3. Update the constants below + the cross-repo fixture (4b).

        DO NOT refreeze blindly.  A drift here without a matching
        puzzle source change indicates a regression.
        """
        artifacts = build_mint_publish_artifacts(**_default_kwargs())

        # Each constant below was generated by running this test with
        # placeholders; populated on first run after the driver is
        # stable.  We dump artifact hashes via printable hex so a
        # failing assertion shows the new value to refreeze with.
        observed = {
            "smart_deed_inner_puzhash": artifacts.smart_deed_inner_puzhash.hex(),
            "eve_inner_puzhash": artifacts.eve_inner_puzhash.hex(),
            "deed_full_puzhash": artifacts.deed_full_puzhash.hex(),
            "proposal_hash": artifacts.proposal_hash.hex(),
            "deed_launcher_id": artifacts.deed_launcher_id.hex(),
            "proposal_singleton_launcher_id": (
                artifacts.proposal_singleton_launcher_id.hex()
            ),
            "proposal_data_hash": artifacts.proposal_data_hash.hex(),
        }

        # PINNED golden vector.  Refrozen when intentional puzzle
        # source / driver / V2 inner mod changes land.  Any drift
        # here without a corresponding source change is a regression.
        #
        # To refreeze: set any slot to ``None`` to surface the
        # current observed value in the assertion diff, copy the new
        # hex into the slot, and bump the freeze comment below.
        #
        # Refrozen 2026-07-18 for PA13 pool identity binding in SmartDeed curry.
        pinned = {
            "smart_deed_inner_puzhash": (
                "dbadecca7eb32bc914c532a001058b3f82c205b6740883926c0ae3e471e74bf7"
            ),
            "eve_inner_puzhash": (
                "ed1a797a1c7c0e709538aaf7245ed8fe7fa1f4919e07bcd8d5b9e004a53da6da"
            ),
            "deed_full_puzhash": (
                "e20e153e294df3e2f4d81d7f924aa162ea52e97e992b90c8531a9dca5aed32d3"
            ),
            "proposal_hash": (
                "b50ab4c0d8c51edca7523d3090aa55ba993a598eff810e1e94cb4d05a81c3896"
            ),
            "deed_launcher_id": (
                "1310b78bf387ea58bb9365e261ff099a6971fd2ca5cc98e750b1d07e92e29b1d"
            ),
            "proposal_singleton_launcher_id": (
                "1e92dd4960d1ddfbd84b857b4836285eb4f3abe13efd639f16fb3f25ee8af534"
            ),
            "proposal_data_hash": (
                "f55fe9821001f5012b34cf0b3f87d97386fb9ab8b9f89813500479b58eb0fa95"
            ),
        }

        # Only assert on pinned values that have been set.  Slots
        # left as ``None`` are surfaced via the dump below so the
        # developer can refreeze them after confirming the change
        # is intentional.
        for k, expected in pinned.items():
            if expected is not None:
                assert observed[k] == expected, (
                    f"{k} drift: expected {expected!r} got {observed[k]!r}"
                )

        # If any slot is None, surface the dump for refreeze:
        if not all(v is not None for v in pinned.values()):
            print("\n== Golden vector dump (pin these in pinned{}) ==")
            for k, v in observed.items():
                print(f'  "{k}": "{v}",')


# ─── 10. Cross-driver consistency ─────────────────────────────────────────


class TestArtifactsCrossDriver:
    """Sanity-check that this driver and the V2 driver agree on shared math."""

    def test_eve_inner_puzhash_matches_standalone(self):
        """Top-level builder's eve_inner_puzhash matches V2 driver computed standalone."""
        artifacts = build_mint_publish_artifacts(**_default_kwargs())

        # Recompute from V2 driver primitives:
        pdh = compute_proposal_data_hash(
            property_id_canon=PROPERTY_ID,
            collection_id_canon=COLLECTION_ID,
            share_ppm=SHARE_PPM,
            par_value_mojos=PAR_VALUE,
            royalty_bps=ROYALTY_BPS,
            quorum_threshold=QUORUM_THRESHOLD,
        )
        expected = make_inner_puzzle_hash(
            owner_member_hash=OWNER_MEMBER_HASH,
            gov_member_hash=GOV_MEMBER_HASH,
            proposal_data_hash=pdh,
            governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
            governance_proposal_hash=artifacts.proposal_hash,
            deed_launcher_id=artifacts.deed_launcher_id,
            did_inner_puzzle_hash=PROTOCOL_DID_INNER_PUZHASH,
            deed_full_puzzle_hash=artifacts.deed_full_puzhash,
            proposal_state=STATE_DRAFT,
            state_version=0,
        )
        assert artifacts.eve_inner_puzhash == expected

    def test_deed_full_puzhash_matches_ground_truth(self):
        """Cross-check the deed full ph against an end-to-end Program build."""
        artifacts = build_mint_publish_artifacts(**_default_kwargs())

        # Reconstruct the deed structure end-to-end.
        deed_coin = deed_launcher_coin_for_parent(
            parent_coin_name=DEED_LAUNCHER_PARENT,
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        struct = deed_singleton_struct(
            deed_launcher_id=bytes32(deed_coin.name()),
            protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        )
        smart = make_smart_deed_inner(
            deed_singleton_struct_program=struct,
            protocol_did_puzhash=PROTOCOL_DID_PUZHASH,
            par_value_mojos=PAR_VALUE,
            asset_class=ASSET_CLASS,
            property_id_canon=PROPERTY_ID,
            collection_id_canon=COLLECTION_ID,
            share_ppm=SHARE_PPM,
            jurisdiction=JURISDICTION,
            royalty_puzhash=ROYALTY_PUZHASH,
            royalty_bps=ROYALTY_BPS,
            pool_singleton_launcher_id=POOL_SINGLETON_LAUNCHER_ID,
            pool_singleton_launcher_puzzle_hash=POOL_SINGLETON_LAUNCHER_PUZZLE_HASH,
            p2_pool_mod_hash=P2_POOL_MOD_HASH,
            p2_vault_mod_hash=P2_VAULT_MOD_HASH,
        )
        eve = make_mint_offer_eve_inner(
            smart_deed_inner_hash=bytes32(smart.get_tree_hash()),
            par_value_mojos=PAR_VALUE,
            protocol_puzhash=PROTOCOL_DID_PUZHASH,
        )
        full = SINGLETON_MOD.curry(struct, eve)
        expected = bytes32(full.get_tree_hash())

        assert artifacts.deed_full_puzhash == expected


# ─── Sub-brick 4d.1 — Spend-bundle builders ────────────────────────────────


# ── Shared fixtures for the spend-builder tests ──
# Reuse the publish-artifacts test surface so the spend-builder fixtures
# stay consistent with the rest of the file.  These coins/parents are
# *synthetic*; the builders accept any 32-byte parent ids and produce
# deterministic outputs from them.

_FAKE_XCH_PARENT = Coin(
    parent_coin_info=_b(0xE1),
    puzzle_hash=_b(0xE2),  # arbitrary p2_delegated puzhash
    amount=10**12,  # 1 XCH worth of mojos
)


class TestBuildProposalEveLaunchSpend:
    """Verify the Artifact A launcher→eve hop matches chia's helper output.

    These tests are deliberately thin: we delegate to
    :func:`launch_conditions_and_coinsol`, so the only things to verify
    are that our dataclass surface (a) wraps the chia helper's tuple
    correctly and (b) computes the eve_full_puzzle_hash + eve_coin
    consistently with the launcher coin's id.
    """

    def _eve_inner(self) -> Program:
        """Build the V2 mint-proposal inner curried for DRAFT eve state."""
        from solslot_puzzles.mint_proposal_v2_driver import make_inner_puzzle
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        return make_inner_puzzle(
            owner_member_hash=OWNER_MEMBER_HASH,
            gov_member_hash=GOV_MEMBER_HASH,
            proposal_data_hash=artifacts.proposal_data_hash,
            governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
            governance_proposal_hash=artifacts.proposal_hash,
            deed_launcher_id=artifacts.deed_launcher_id,
            did_inner_puzzle_hash=PROTOCOL_DID_INNER_PUZHASH,
            deed_full_puzzle_hash=artifacts.deed_full_puzhash,
            proposal_state=STATE_DRAFT,
            state_version=0,
        )

    def test_returns_dataclass(self):
        result = build_proposal_eve_launch_spend(
            parent_coin=_FAKE_XCH_PARENT,
            eve_inner_puzzle=self._eve_inner(),
        )
        assert isinstance(result, ProposalEveLaunchSpend)
        assert isinstance(result.parent_conditions, list)
        assert len(result.parent_conditions) >= 2  # CREATE_COIN + ASSERT_COIN_ANN
        assert result.launcher_coin_spend.coin.puzzle_hash == SINGLETON_LAUNCHER_HASH
        assert result.launcher_coin_spend.coin.amount == SINGLETON_AMOUNT

    def test_eve_coin_consistency(self):
        """``eve_coin`` is parent=launcher_id, ph=eve_full_ph, amount=1."""
        result = build_proposal_eve_launch_spend(
            parent_coin=_FAKE_XCH_PARENT,
            eve_inner_puzzle=self._eve_inner(),
        )
        launcher_id = bytes32(result.launcher_coin_spend.coin.name())
        assert result.eve_coin.parent_coin_info == launcher_id
        assert result.eve_coin.puzzle_hash == result.eve_full_puzzle_hash
        assert result.eve_coin.amount == SINGLETON_AMOUNT

    def test_eve_full_puzzle_hash_matches_singleton_wrap(self):
        """``eve_full_puzzle_hash`` = puzzle_for_singleton(launcher_id, inner).hash."""
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton

        eve_inner = self._eve_inner()
        result = build_proposal_eve_launch_spend(
            parent_coin=_FAKE_XCH_PARENT,
            eve_inner_puzzle=eve_inner,
        )
        launcher_id = bytes32(result.launcher_coin_spend.coin.name())
        expected = bytes32(
            puzzle_for_singleton(launcher_id, eve_inner).get_tree_hash()
        )
        assert result.eve_full_puzzle_hash == expected

    def test_determinism(self):
        """Same inputs → same outputs (every field)."""
        eve_inner = self._eve_inner()
        a = build_proposal_eve_launch_spend(
            parent_coin=_FAKE_XCH_PARENT, eve_inner_puzzle=eve_inner
        )
        b = build_proposal_eve_launch_spend(
            parent_coin=_FAKE_XCH_PARENT, eve_inner_puzzle=eve_inner
        )
        assert a.launcher_coin_spend == b.launcher_coin_spend
        assert a.eve_coin == b.eve_coin
        assert a.eve_full_puzzle_hash == b.eve_full_puzzle_hash

    def test_even_amount_rejected(self):
        with pytest.raises(ValueError, match="even"):
            build_proposal_eve_launch_spend(
                parent_coin=_FAKE_XCH_PARENT,
                eve_inner_puzzle=self._eve_inner(),
                amount=2,
            )


class TestBuildTrackerProposeCoinSpend:
    """Verify the tracker.PROPOSE spend builder's solution shape + on-chain effect.

    Strategy:
      1. Curry an *idle* tracker (no active proposal).
      2. Call the builder.
      3. Decode the resulting CoinSpend's inner solution and confirm the
         dispatcher layout matches the .clsp signature.
      4. Run the curried tracker inner puzzle on the builder's inner
         solution and confirm the emitted conditions match the
         PROPOSE handler's expected output (CREATE_COIN to next state,
         ASSERT_PUZZLE_ANNOUNCEMENT for SGT lock, time bounds, REMARK).
    """

    # Tracker curry parameters — mirror test_governance.py's defaults.
    _TRACKER_LAUNCHER_ID = bytes32(b"\xb0" * 32)
    _TRACKER_AMOUNT = SINGLETON_AMOUNT

    def _tracker_struct(self) -> Program:
        return Program.to(
            (
                SINGLETON_MOD_HASH,
                (self._TRACKER_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH),
            )
        )

    def _idle_tracker_inner(self) -> Program:
        """Build an idle (no-active-proposal) tracker inner puzzle."""
        from solslot_puzzles.sgt_driver import (
            TEST_KOS_MINT_EXECUTE_PUBKEY,
            sgt_free_inner_mod,
            sgt_locked_inner_mod,
            proposal_tracker_inner_puzzle,
        )

        return proposal_tracker_inner_puzzle(
            self._tracker_struct(),
            bytes32(sgt_free_inner_mod().get_tree_hash()),
            bytes32(sgt_locked_inner_mod().get_tree_hash()),
            bytes32(b"\xca" * 32),  # cat_mod_hash
            bytes32(b"\xea" * 32),  # sgt_tail_hash
            bytes32(b"\xd0" * 32),  # did_puzhash
            Program.to(
                (
                    SINGLETON_MOD_HASH,
                    (bytes32(b"\xc0" * 32), SINGLETON_LAUNCHER_HASH),
                )
            ),  # pool_struct
            5000,  # quorum_bps (50%)
            300,  # voting_window (5 min)
            1_000_000,  # sgt_total_supply
            10_000,  # min_proposal_stake
            TEST_KOS_MINT_EXECUTE_PUBKEY,
            proposal_hash=0,
            bill_operation=0,
            vote_tally=0,
            voting_deadline=0,
        )

    def _fake_tracker_coin(self, inner: Program) -> Coin:
        """Synthesize a tracker coin whose name we can re-derive from inner."""
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton

        full = puzzle_for_singleton(self._TRACKER_LAUNCHER_ID, inner)
        return Coin(
            parent_coin_info=bytes32(b"\xb1" * 32),
            puzzle_hash=bytes32(full.get_tree_hash()),
            amount=self._TRACKER_AMOUNT,
        )

    def test_returns_coin_spend_with_correct_coin_and_puzzle(self):
        from chia.types.coin_spend import CoinSpend
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton

        inner = self._idle_tracker_inner()
        coin = self._fake_tracker_coin(inner)
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        spend = build_tracker_propose_coin_spend(
            tracker_coin=coin,
            tracker_inner_puzzle=inner,
            tracker_launcher_id=self._TRACKER_LAUNCHER_ID,
            lineage_proof=LineageProof(
                parent_name=bytes32(b"\x00" * 32),
                inner_puzzle_hash=bytes32(b"\x00" * 32),
                amount=self._TRACKER_AMOUNT,
            ),
            proposal_hash=artifacts.proposal_hash,
            bill_operation=artifacts.bill_op_program,
            voter_inner_puzzle_hash=bytes32(b"\x77" * 32),
            first_vote_amount=10_000,
            voting_deadline=2_000_000_000,
        )
        assert isinstance(spend, CoinSpend)
        assert spend.coin == coin
        # The puzzle reveal is the singleton-wrapped tracker inner.
        expected_full_puzzle = puzzle_for_singleton(
            self._TRACKER_LAUNCHER_ID, inner
        )
        assert (
            Program.from_serialized(spend.puzzle_reveal).get_tree_hash()
            == expected_full_puzzle.get_tree_hash()
        )

    def test_inner_solution_layout(self):
        """Decode the inner solution and pin its dispatcher layout."""
        inner = self._idle_tracker_inner()
        coin = self._fake_tracker_coin(inner)
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        spend = build_tracker_propose_coin_spend(
            tracker_coin=coin,
            tracker_inner_puzzle=inner,
            tracker_launcher_id=self._TRACKER_LAUNCHER_ID,
            lineage_proof=LineageProof(
                parent_name=bytes32(b"\x00" * 32),
                inner_puzzle_hash=bytes32(b"\x00" * 32),
                amount=self._TRACKER_AMOUNT,
            ),
            proposal_hash=artifacts.proposal_hash,
            bill_operation=artifacts.bill_op_program,
            voter_inner_puzzle_hash=bytes32(b"\x77" * 32),
            first_vote_amount=10_000,
            voting_deadline=2_000_000_000,
        )
        # solution_for_singleton wraps inner_solution as
        # ``(lineage_proof, my_amount, inner_solution)``.  Decode it back
        # to confirm the inner_solution shape matches.
        full_sol = Program.from_serialized(spend.solution)
        # full_sol is (lineage_proof, my_amount, inner_solution); index 2.
        inner_sol = list(full_sol.as_iter())[2]
        items = list(inner_sol.as_iter())
        # (my_id my_inner_puzzlehash my_amount TRK_PROPOSE params)
        assert len(items) == 5
        from solslot_puzzles.sgt_driver import TRK_PROPOSE

        assert int.from_bytes(items[3].atom or b"\x00", "big") == TRK_PROPOSE
        # params = (proposal_hash bill_op voter_inner_puzhash first_vote deadline)
        params = list(items[4].as_iter())
        assert len(params) == 5
        assert bytes(params[0].atom) == artifacts.proposal_hash
        # params[1] is the bill_op program itself, not its hash.
        assert (
            params[1].get_tree_hash()
            == artifacts.bill_op_program.get_tree_hash()
        )
        assert bytes(params[2].atom) == b"\x77" * 32
        assert int.from_bytes(params[3].atom or b"\x00", "big") == 10_000
        assert int.from_bytes(params[4].atom or b"\x00", "big") == 2_000_000_000

    def test_running_inner_emits_expected_conditions(self):
        """End-to-end sanity: running the inner puzzle on the inner solution
        emits the conditions the .clsp PROPOSE handler is supposed to produce.

        Catches the "we built the wrong solution shape" class of bugs
        without requiring a full coin sim — the puzzle does the heavy
        lifting and reports a structurally-correct condition list.
        """
        inner = self._idle_tracker_inner()
        coin = self._fake_tracker_coin(inner)
        artifacts = build_mint_publish_artifacts(**_default_kwargs())
        spend = build_tracker_propose_coin_spend(
            tracker_coin=coin,
            tracker_inner_puzzle=inner,
            tracker_launcher_id=self._TRACKER_LAUNCHER_ID,
            lineage_proof=LineageProof(
                parent_name=bytes32(b"\x00" * 32),
                inner_puzzle_hash=bytes32(b"\x00" * 32),
                amount=self._TRACKER_AMOUNT,
            ),
            proposal_hash=artifacts.proposal_hash,
            bill_operation=artifacts.bill_op_program,
            voter_inner_puzzle_hash=bytes32(b"\x77" * 32),
            first_vote_amount=10_000,
            voting_deadline=2_000_000_000,
        )
        # Run the *inner* puzzle on the inner solution and confirm the
        # PROPOSE handler's structural conditions are present.
        full_sol = Program.from_serialized(spend.solution)
        inner_sol = list(full_sol.as_iter())[2]
        conds = inner.run(inner_sol)
        opcodes = {
            int.from_bytes(list(c.as_iter())[0].atom or b"\x00", "big")
            for c in conds.as_iter()
        }
        # PROPOSE emits: CREATE_COIN (51), ASSERT_PUZZLE_ANNOUNCEMENT (63),
        # ASSERT_BEFORE_SECONDS_ABSOLUTE (85), ASSERT_SECONDS_ABSOLUTE (81),
        # REMARK (1), plus identity_conditions (70 ASSERT_MY_COIN_ID,
        # 72 ASSERT_MY_PUZZLEHASH, 73 ASSERT_MY_AMOUNT).
        assert {51, 63, 85, 81, 1}.issubset(opcodes)

    def test_rejects_wrong_size_proposal_hash(self):
        inner = self._idle_tracker_inner()
        coin = self._fake_tracker_coin(inner)
        with pytest.raises(ValueError, match="proposal_hash"):
            build_tracker_propose_coin_spend(
                tracker_coin=coin,
                tracker_inner_puzzle=inner,
                tracker_launcher_id=self._TRACKER_LAUNCHER_ID,
                lineage_proof=LineageProof(
                    parent_name=bytes32(b"\x00" * 32),
                    inner_puzzle_hash=bytes32(b"\x00" * 32),
                    amount=self._TRACKER_AMOUNT,
                ),
                proposal_hash=b"\xaa" * 16,  # wrong size
                bill_operation=Program.to(0),
                voter_inner_puzzle_hash=bytes32(b"\x77" * 32),
                first_vote_amount=10_000,
                voting_deadline=2_000_000_000,
            )

    def test_rejects_non_positive_first_vote(self):
        inner = self._idle_tracker_inner()
        coin = self._fake_tracker_coin(inner)
        with pytest.raises(ValueError, match="first_vote_amount"):
            build_tracker_propose_coin_spend(
                tracker_coin=coin,
                tracker_inner_puzzle=inner,
                tracker_launcher_id=self._TRACKER_LAUNCHER_ID,
                lineage_proof=LineageProof(
                    parent_name=bytes32(b"\x00" * 32),
                    inner_puzzle_hash=bytes32(b"\x00" * 32),
                    amount=self._TRACKER_AMOUNT,
                ),
                proposal_hash=bytes32(b"\xab" * 32),
                bill_operation=Program.to(0),
                voter_inner_puzzle_hash=bytes32(b"\x77" * 32),
                first_vote_amount=0,
                voting_deadline=2_000_000_000,
            )

    def test_rejects_voting_deadline_out_of_range(self):
        inner = self._idle_tracker_inner()
        coin = self._fake_tracker_coin(inner)
        with pytest.raises(ValueError, match="voting_deadline"):
            build_tracker_propose_coin_spend(
                tracker_coin=coin,
                tracker_inner_puzzle=inner,
                tracker_launcher_id=self._TRACKER_LAUNCHER_ID,
                lineage_proof=LineageProof(
                    parent_name=bytes32(b"\x00" * 32),
                    inner_puzzle_hash=bytes32(b"\x00" * 32),
                    amount=self._TRACKER_AMOUNT,
                ),
                proposal_hash=bytes32(b"\xab" * 32),
                bill_operation=Program.to(0),
                voter_inner_puzzle_hash=bytes32(b"\x77" * 32),
                first_vote_amount=10_000,
                voting_deadline=-1,
            )


class TestBuildSgtFirstVoteCoinSpend:
    """Confirm the first-vote wrapper delegates to ``build_sgt_lock_coin_spend``.

    The Phase 3 LOCK spend already has coin-sim coverage via
    ``test_sgt_e2e.py``; this brick adds only the publish-flow-named
    entry point.  We assert the wrapper produces a byte-equal
    ``CoinSpend`` to the underlying helper for identical args, which
    is the strongest test we can give a delegating function.
    """

    # The SGT_TAIL_HASH used in the test must match what cat_sgt_free_puzzle_hash
    # internally bakes into the CAT mod hash math.  We use the same fixed value
    # the Phase 3 LOCK builder tests use, so the underlying helper's puzzle
    # reveal hashes to the expected coin puzzle hash.
    _SGT_TAIL_HASH = bytes32(b"\xea" * 32)
    _PROPOSAL_HASH = bytes32(b"\xcd" * 32)
    _DEADLINE = 2_000_000_000
    _AMOUNT = 10_000

    def _common_args(self) -> dict:
        from solslot_puzzles.sgt_driver import (
            cat_sgt_free_puzzle_hash,
            sgt_free_inner_mod,
            sgt_locked_inner_hash,
            sgt_locked_inner_mod,
        )

        tracker_struct = Program.to(
            (
                SINGLETON_MOD_HASH,
                (bytes32(b"\xb0" * 32), SINGLETON_LAUNCHER_HASH),
            )
        )
        sgt_free_mod_h = bytes32(sgt_free_inner_mod().get_tree_hash())
        sgt_locked_mod_h = bytes32(sgt_locked_inner_mod().get_tree_hash())
        # CAT_MOD_HASH used by ``cat_sgt_free_puzzle_hash`` is the chia
        # bundled CAT mod hash, not an arbitrary one.  Import it directly.
        from chia.wallet.cat_wallet.cat_utils import CAT_MOD

        cat_mod_hash = bytes32(CAT_MOD.get_tree_hash())

        # Identity-style voter inner: solution IS the conditions list.
        voter_inner_puzzle = Program.to(1)
        voter_inner_ph = bytes32(voter_inner_puzzle.get_tree_hash())

        cat_ph = cat_sgt_free_puzzle_hash(
            tracker_struct,
            sgt_free_mod_h,
            sgt_locked_mod_h,
            cat_mod_hash,
            self._SGT_TAIL_HASH,
            voter_inner_ph,
        )
        sgt_coin = Coin(
            parent_coin_info=bytes32(b"\xa1" * 32),
            puzzle_hash=cat_ph,
            amount=self._AMOUNT,
        )

        # Compute the canonical locked-inner puzhash the LOCK spend MUST
        # create.  ``sgt_locked_inner_hash`` takes the v2 signature
        # ``(sgt_free_mod_h, tracker_struct, voter_ph, proposal_hash,
        # deadline)``.
        locked_ph = sgt_locked_inner_hash(
            sgt_free_mod_h,
            tracker_struct,
            voter_inner_ph,
            self._PROPOSAL_HASH,
            self._DEADLINE,
        )
        # voter_inner_solution: emit one CREATE_COIN to the canonical
        # locked puzhash with amount == sgt_coin.amount.
        voter_inner_solution = Program.to([[51, locked_ph, self._AMOUNT]])

        return {
            "sgt_coin": sgt_coin,
            "voter_inner_puzzle": voter_inner_puzzle,
            "voter_inner_solution": voter_inner_solution,
            "proposal_tracker_struct": tracker_struct,
            "sgt_tail_hash": self._SGT_TAIL_HASH,
            "lineage_proof": LineageProof(),
            "proposal_hash": self._PROPOSAL_HASH,
        }

    def test_equals_underlying_sgt_lock_spend(self):
        from solslot_puzzles.sgt_driver import build_sgt_lock_coin_spend

        common = self._common_args()
        deadline = 2_000_000_000
        from_wrapper = build_sgt_first_vote_coin_spend(
            **common, voting_deadline=deadline
        )
        from_underlying = build_sgt_lock_coin_spend(**common, deadline=deadline)
        assert from_wrapper == from_underlying

    def test_returns_a_single_coin_spend(self):
        from chia.types.coin_spend import CoinSpend

        spend = build_sgt_first_vote_coin_spend(
            **self._common_args(),
            voting_deadline=2_000_000_000,
        )
        assert isinstance(spend, CoinSpend)
        assert spend.coin == self._common_args()["sgt_coin"]
