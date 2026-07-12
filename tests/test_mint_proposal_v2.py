"""Tests for ``mint_proposal_inner_v2.clsp`` and ``mint_proposal_v2_driver``.

Phase 9-Hermes-D: validates the MIPS-pluggable mint-proposal puzzle
against both BLS and Eip712Member auth members, plus the cross-repo
mod-hash pin and the binding-hash replay-protection invariant.

The test suite intentionally mirrors the structure of
``test_mint_proposal.py`` (V1) so the V2 refactor's regression
coverage is at least as strong as V1's.  Where V1 hard-coded
BLS-only AGG_SIG_ME emission, V2 must continue to produce equivalent
auth conditions while also accepting Eip712Member ASSERT_MY_COIN_ID
emissions \u2014 the explicit value-add of this refactor.
"""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.mint_proposal_v2_driver import (
    MintProposalV2State,
    STATE_APPROVED,
    STATE_CANCELLED,
    STATE_DRAFT,
    TRANSITION_APPROVE,
    TRANSITION_CANCEL,
    build_approve_spend,
    build_cancel_spend,
    compute_binding_hash,
    compute_proposal_data_hash,
    compute_transition_message,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    mint_proposal_inner_v2_mod_hash,
    parse_inner_puzzle,
)


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Pinned constants \u2014 cross-checked against the .clsp source.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

# Pinned mod hash for the V2 puzzle.  Update both here AND in the
# portal's TS port if the .clsp source changes intentionally.
PINNED_V2_MOD_HASH = bytes32.fromhex(
    "a21505befe18b82a51a5644a184aad514b86a1c7e86fce04594e83bf376329d6"
)

# Sample proposal data.
PROPERTY_ID_CANON = bytes32(b"\x11" * 32)
COLLECTION_ID_CANON = bytes32(b"\x12" * 32)
SHARE_PPM = 750_000
PAR_VALUE = 100_000
ROYALTY_BPS = 250
QUORUM_THRESHOLD = 1_000_000

# Test fixtures \u2014 32-byte sentinels for non-curve-specific tests.
SENTINEL_OWNER_HASH = bytes32(b"\xAA" * 32)
SENTINEL_GOV_HASH = bytes32(b"\xBB" * 32)
SENTINEL_OTHER_HASH = bytes32(b"\xCC" * 32)
SINGLETON_AMOUNT = 1


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Member fixtures (cached \u2014 lazy load).
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

_BLS_MEMBER_FIXTURE: Program | None = None
_EIP712_MEMBER_FIXTURE: Program | None = None


def _bls_member_fixture() -> Program:
    """Minimal BLS-style member; emits ``((AGG_SIG_ME PUBKEY message))``.

    Solution shape: ``(message)`` \u2014 single-element list containing the
    message to sign.  When V2's puzzle prepends the binding hash, the
    member's first solution slot IS the binding hash; the
    ``member_solution_remainder`` is therefore an empty list.
    """
    global _BLS_MEMBER_FIXTURE
    if _BLS_MEMBER_FIXTURE is None:
        _BLS_MEMBER_FIXTURE = load_clvm(
            "test_fixture_bls_member.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _BLS_MEMBER_FIXTURE


def _eip712_member_fixture() -> Program:
    """Eip712Member (verbatim copy of chia-wallet-sdk's PR #395 puzzle).

    Solution shape: ``(Delegated_Puzzle_Hash my_id signed_hash signature)``.
    V2's puzzle prepends the binding hash to fill the first slot, so
    ``member_solution_remainder`` for this curve is
    ``(my_id signed_hash signature)``.
    """
    global _EIP712_MEMBER_FIXTURE
    if _EIP712_MEMBER_FIXTURE is None:
        _EIP712_MEMBER_FIXTURE = load_clvm(
            "test_fixture_eip712_member.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _EIP712_MEMBER_FIXTURE


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# EIP-712 helpers (mirrors test_admin_authority_v2.py).
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


def _keccak256(data: bytes) -> bytes:
    """Keccak-256 (NOT sha3-256) per Ethereum / CHIP-0036."""
    from Crypto.Hash import keccak

    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def _eip712_domain_separator(genesis_challenge: bytes) -> bytes:
    """The 32-byte EIP-712 domain separator per CHIP-0037."""
    eip712_domain_typehash = _keccak256(
        b"EIP712Domain(string name,string version,bytes32 salt)"
    )
    name_hash = _keccak256(b"Chia Coin Spend")
    version_hash = _keccak256(b"1")
    return _keccak256(
        eip712_domain_typehash + name_hash + version_hash + genesis_challenge
    )


def _eip712_prefix_and_domain_separator(genesis_challenge: bytes) -> bytes:
    """34-byte concatenation of EIP-712 prefix (0x1901) + domain separator."""
    return b"\x19\x01" + _eip712_domain_separator(genesis_challenge)


def _eip712_type_hash() -> bytes:
    """Keccak-256 of the canonical CHIP-0037 type signature."""
    return _keccak256(
        b"ChiaCoinSpend(bytes32 coin_id,bytes32 delegated_puzzle_hash)"
    )


def _eip712_hash_to_sign(
    prefix_and_domain: bytes, coin_id: bytes, dph: bytes
) -> bytes:
    """The 32-byte digest the off-chain wallet must sign."""
    inner = _keccak256(_eip712_type_hash() + coin_id + dph)
    return _keccak256(prefix_and_domain + inner)


def _compress_pubkey(uncompressed_pk: bytes) -> bytes:
    """Compress a 64-byte (x || y) secp256k1 pubkey to 33 bytes (02/03 || x)."""
    if len(uncompressed_pk) == 64:
        x = uncompressed_pk[:32]
        y = uncompressed_pk[32:]
    elif len(uncompressed_pk) == 65 and uncompressed_pk[0] == 0x04:
        x = uncompressed_pk[1:33]
        y = uncompressed_pk[33:]
    else:
        raise ValueError(f"Unexpected pubkey length: {len(uncompressed_pk)}")
    prefix = b"\x02" if (y[-1] % 2 == 0) else b"\x03"
    return prefix + x


MAINNET_GENESIS = bytes.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)

EIP712_TEST_SK_SEED = bytes.fromhex(
    "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"
)
EIP712_TEST_COIN_ID = bytes32(b"\x77" * 32)


def _eip712_run_flags() -> int:
    """CLVM flags for secp256k1_verify + softfork-guarded keccak256."""
    import chia_rs

    return (
        chia_rs.MEMPOOL_MODE
        | chia_rs.ENABLE_SECP_OPS
        | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD
    )


# Real BLS pubkey + message sentinels for AGG_SIG_ME emission tests.
REAL_BLS_PUBKEY = bytes(b"\x42" * 48)


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Helpers for assembling V2 inner solutions.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


def _build_v2_solution(
    *,
    my_amount: int,
    transition_case: int,
    new_state_version: int,
    member_puzzle_reveal: Program,
    member_solution_remainder: Program,
) -> Program:
    """Assemble the full V2 inner solution from its 5 slots."""
    return Program.to(
        [
            my_amount,
            transition_case,
            new_state_version,
            member_puzzle_reveal,
            member_solution_remainder,
        ]
    )


def _draft_state(
    *,
    owner_member_hash: bytes = SENTINEL_OWNER_HASH,
    gov_member_hash: bytes = SENTINEL_GOV_HASH,
    state_version: int = 0,
) -> MintProposalV2State:
    """Build a DRAFT-state V2 proposal record for transition tests."""
    return MintProposalV2State(
        self_mod_hash=mint_proposal_inner_v2_mod_hash(),
        owner_member_hash=bytes32(owner_member_hash),
        gov_member_hash=bytes32(gov_member_hash),
        proposal_data_hash=compute_proposal_data_hash(
            property_id_canon=PROPERTY_ID_CANON,
            collection_id_canon=COLLECTION_ID_CANON,
            share_ppm=SHARE_PPM,
            par_value_mojos=PAR_VALUE,
            royalty_bps=ROYALTY_BPS,
            quorum_threshold=QUORUM_THRESHOLD,
        ),
        proposal_state=STATE_DRAFT,
        state_version=state_version,
    )


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Mod hash + checksum integration.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


class TestModHash:
    def test_mod_hash_pinned(self):
        """The compiled mod hash matches the value pinned in the driver
        + cross-repo fixture.  Drift here means a puzzle source change
        wasn't propagated to the TS port.
        """
        assert mint_proposal_inner_v2_mod_hash() == PINNED_V2_MOD_HASH


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Construction validation.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


class TestConstruction:
    def test_make_inner_puzzle_rejects_short_owner_member_hash(self):
        with pytest.raises(ValueError, match="owner_member_hash must be 32 bytes"):
            make_inner_puzzle(
                owner_member_hash=b"\x00" * 16,
                gov_member_hash=SENTINEL_GOV_HASH,
                proposal_data_hash=bytes32(b"\x33" * 32),
                proposal_state=STATE_DRAFT,
                state_version=0,
            )

    def test_make_inner_puzzle_rejects_short_gov_member_hash(self):
        with pytest.raises(ValueError, match="gov_member_hash must be 32 bytes"):
            make_inner_puzzle(
                owner_member_hash=SENTINEL_OWNER_HASH,
                gov_member_hash=b"\x00" * 31,
                proposal_data_hash=bytes32(b"\x33" * 32),
                proposal_state=STATE_DRAFT,
                state_version=0,
            )

    def test_make_inner_puzzle_rejects_short_data_hash(self):
        with pytest.raises(ValueError, match="proposal_data_hash must be 32 bytes"):
            make_inner_puzzle(
                owner_member_hash=SENTINEL_OWNER_HASH,
                gov_member_hash=SENTINEL_GOV_HASH,
                proposal_data_hash=b"\x00" * 31,
                proposal_state=STATE_DRAFT,
                state_version=0,
            )

    def test_make_inner_puzzle_rejects_unknown_state(self):
        with pytest.raises(ValueError, match="proposal_state must be one of"):
            make_inner_puzzle(
                owner_member_hash=SENTINEL_OWNER_HASH,
                gov_member_hash=SENTINEL_GOV_HASH,
                proposal_data_hash=bytes32(b"\x33" * 32),
                proposal_state=99,
                state_version=0,
            )

    def test_compute_binding_hash_rejects_unknown_case(self):
        with pytest.raises(ValueError, match="transition_case must be"):
            compute_binding_hash(
                transition_case=0xFF,
                new_state_version=1,
                proposal_data_hash=bytes32(b"\x33" * 32),
            )

    def test_compute_binding_hash_rejects_short_data_hash(self):
        with pytest.raises(ValueError, match="proposal_data_hash must be 32 bytes"):
            compute_binding_hash(
                transition_case=TRANSITION_APPROVE,
                new_state_version=1,
                proposal_data_hash=b"\x33" * 31,
            )

    def test_parse_inner_puzzle_round_trip(self):
        """Curry then parse \u2014 every field round-trips byte-for-byte."""
        original = _draft_state()
        puzzle = make_inner_puzzle(
            owner_member_hash=original.owner_member_hash,
            gov_member_hash=original.gov_member_hash,
            proposal_data_hash=original.proposal_data_hash,
            proposal_state=original.proposal_state,
            state_version=original.state_version,
        )
        parsed = parse_inner_puzzle(puzzle)
        assert parsed == original


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# APPROVE / CANCEL with BLS member.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


class TestApproveSpendBls:
    """Gov-authorised APPROVE using a BLS-style member."""

    def _setup(self):
        gov_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        gov_hash = bytes32(gov_member.get_tree_hash())
        state = _draft_state(gov_member_hash=gov_hash)
        artifacts = build_approve_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        # BLS test fixture takes (message); V2 prepends binding_hash so
        # the remainder is empty.
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_APPROVE,
            new_state_version=1,
            member_puzzle_reveal=gov_member,
            member_solution_remainder=Program.to([]),
        )
        return puzzle, solution, artifacts

    def test_emits_agg_sig_me_with_binding_hash(self):
        """The gov BLS member's AGG_SIG_ME flows through with the
        binding hash as the message \u2014 binding the signature to this
        specific (case, version, proposal) triple.
        """
        puzzle, solution, artifacts = self._setup()
        result = puzzle.run(solution)
        conditions = list(result.as_iter())
        agg_sig_me = next(
            (c for c in conditions if int(c.first().as_int()) == 50), None,
        )
        assert agg_sig_me is not None, "BLS member's AGG_SIG_ME not emitted"
        sig_pubkey = bytes(agg_sig_me.rest().first().as_atom())
        sig_message = bytes(agg_sig_me.rest().rest().first().as_atom())
        assert sig_pubkey == REAL_BLS_PUBKEY
        assert sig_message == bytes(artifacts.binding_hash)

    def test_emits_create_coin_with_approved_state(self):
        """CREATE_COIN puzzle hash equals the post-transition inner
        hash with PROPOSAL_STATE = STATE_APPROVED, and amount equals
        my_amount.
        """
        puzzle, solution, artifacts = self._setup()
        conditions = list(puzzle.run(solution).as_iter())
        create_coin = next(
            (c for c in conditions if int(c.first().as_int()) == 51), None,
        )
        assert create_coin is not None
        emitted_puzhash = bytes(create_coin.rest().first().as_atom())
        emitted_amount = int(create_coin.rest().rest().first().as_int())
        assert emitted_puzhash == bytes(artifacts.new_inner_puzzle_hash)
        assert emitted_amount == SINGLETON_AMOUNT
        assert artifacts.new_state == STATE_APPROVED

    def test_emits_announcement_with_protocol_prefix(self):
        """CREATE_PUZZLE_ANNOUNCEMENT body equals
        ``PROTOCOL_PREFIX || sha256tree([case, new_state, new_version])``,
        stable for Solslot V2 monitors.
        """
        puzzle, solution, artifacts = self._setup()
        conditions = list(puzzle.run(solution).as_iter())
        ann = next(
            (c for c in conditions if int(c.first().as_int()) == 62), None,
        )
        assert ann is not None
        body = bytes(ann.rest().first().as_atom())
        expected_body = b"\x53" + bytes(
            compute_transition_message(
                transition_case=TRANSITION_APPROVE,
                new_state=STATE_APPROVED,
                new_state_version=1,
            )
        )
        assert body == expected_body
        assert body == artifacts.transition_announcement_message


class TestCancelSpendBls:
    """Owner-authorised CANCEL using a BLS-style member."""

    def _setup(self):
        owner_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        owner_hash = bytes32(owner_member.get_tree_hash())
        state = _draft_state(owner_member_hash=owner_hash)
        artifacts = build_cancel_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_CANCEL,
            new_state_version=1,
            member_puzzle_reveal=owner_member,
            member_solution_remainder=Program.to([]),
        )
        return puzzle, solution, artifacts

    def test_agg_sig_me_uses_owner_pubkey_and_binding(self):
        puzzle, solution, artifacts = self._setup()
        conditions = list(puzzle.run(solution).as_iter())
        agg_sig_me = next(
            (c for c in conditions if int(c.first().as_int()) == 50), None,
        )
        assert agg_sig_me is not None
        sig_message = bytes(agg_sig_me.rest().rest().first().as_atom())
        assert sig_message == bytes(artifacts.binding_hash)

    def test_emits_create_coin_with_cancelled_state(self):
        puzzle, solution, artifacts = self._setup()
        conditions = list(puzzle.run(solution).as_iter())
        create_coin = next(
            (c for c in conditions if int(c.first().as_int()) == 51), None,
        )
        assert create_coin is not None
        emitted_puzhash = bytes(create_coin.rest().first().as_atom())
        assert emitted_puzhash == bytes(artifacts.new_inner_puzzle_hash)
        assert artifacts.new_state == STATE_CANCELLED

    def test_signature_message_distinct_from_approve(self):
        """CANCEL binding hash must differ from APPROVE binding hash
        on the same proposal+version, blocking sig replay across cases.
        """
        owner = _bls_member_fixture().curry(REAL_BLS_PUBKEY).get_tree_hash()
        gov = _bls_member_fixture().curry(b"\x99" * 48).get_tree_hash()
        state = _draft_state(
            owner_member_hash=bytes32(owner), gov_member_hash=bytes32(gov),
        )
        approve = build_approve_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        cancel = build_cancel_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        assert approve.binding_hash != cancel.binding_hash


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# APPROVE / CANCEL with Eip712Member.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


class TestEip712MemberTransitions:
    """The flagship V2 capability: EVM admins authorise transitions via
    an Eip712Member curried with their secp256k1 pubkey.  V1 forced
    BLS, so this test class is the explicit value-add of the refactor.
    """

    def _build_eip712_member(self):
        from eth_keys import keys

        prefix_and_domain = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        type_h = _eip712_type_hash()
        sk = keys.PrivateKey(EIP712_TEST_SK_SEED)
        pk_compressed = _compress_pubkey(sk.public_key.to_bytes())
        member = _eip712_member_fixture().curry(
            prefix_and_domain, type_h, pk_compressed
        )
        return member, prefix_and_domain, sk

    def _sign_binding_hash(self, sk, prefix_and_domain, binding_hash, coin_id):
        """Reproduce the off-chain signing flow: sign the EIP-712 digest
        constructed from (binding_hash, coin_id) and return (signed_hash,
        sig_64) so the caller can build the member's solution.
        """
        signed_hash = _eip712_hash_to_sign(prefix_and_domain, coin_id, binding_hash)
        sig_64 = sk.sign_msg_hash(signed_hash).to_bytes()[:64]
        return signed_hash, sig_64

    def test_approve_with_eip712_gov_emits_assert_my_coin_id(self):
        """Gov authorises APPROVE via an Eip712Member.  The member's
        emitted ASSERT_MY_COIN_ID flows through, alongside the V2
        proposal puzzle's CREATE_COIN / announcement / ASSERT_MY_AMOUNT.
        """
        member, prefix_and_domain, sk = self._build_eip712_member()
        gov_hash = bytes32(member.get_tree_hash())
        state = _draft_state(gov_member_hash=gov_hash)
        artifacts = build_approve_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        signed_hash, sig_64 = self._sign_binding_hash(
            sk, prefix_and_domain, artifacts.binding_hash, EIP712_TEST_COIN_ID,
        )
        # Eip712Member solution shape: (DPH my_id signed_hash sig).
        # V2 prepends DPH (the binding hash); remainder is (my_id signed_hash sig).
        member_remainder = Program.to(
            [EIP712_TEST_COIN_ID, signed_hash, sig_64]
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_APPROVE,
            new_state_version=1,
            member_puzzle_reveal=member,
            member_solution_remainder=member_remainder,
        )
        result = puzzle.run(solution, flags=_eip712_run_flags())
        conditions = list(result.as_iter())

        # ASSERT_MY_COIN_ID (opcode 73, 32-byte payload) from the member.
        # V2 also emits ASSERT_MY_AMOUNT (also opcode 73 but with a uint
        # payload) \u2014 differentiate on payload length.
        coin_id_assertions = [
            c for c in conditions
            if int(c.first().as_int()) == 73
            and len(bytes(c.rest().first().as_atom())) == 32
        ]
        assert len(coin_id_assertions) == 1
        assert (
            bytes(coin_id_assertions[0].rest().first().as_atom())
            == EIP712_TEST_COIN_ID
        )

        # V2 lifecycle conditions present.
        opcodes = [int(c.first().as_int()) for c in conditions]
        assert 51 in opcodes  # CREATE_COIN
        assert 62 in opcodes  # CREATE_PUZZLE_ANNOUNCEMENT
        assert 73 in opcodes  # ASSERT_MY_AMOUNT (also opcode 73)

    def test_cancel_with_eip712_owner_emits_assert_my_coin_id(self):
        """Symmetric case: owner authorises CANCEL via an Eip712Member."""
        member, prefix_and_domain, sk = self._build_eip712_member()
        owner_hash = bytes32(member.get_tree_hash())
        state = _draft_state(owner_member_hash=owner_hash)
        artifacts = build_cancel_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        signed_hash, sig_64 = self._sign_binding_hash(
            sk, prefix_and_domain, artifacts.binding_hash, EIP712_TEST_COIN_ID,
        )
        member_remainder = Program.to(
            [EIP712_TEST_COIN_ID, signed_hash, sig_64]
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_CANCEL,
            new_state_version=1,
            member_puzzle_reveal=member,
            member_solution_remainder=member_remainder,
        )
        result = puzzle.run(solution, flags=_eip712_run_flags())
        conditions = list(result.as_iter())
        # CREATE_COIN should reference STATE_CANCELLED.
        create_coin = next(
            (c for c in conditions if int(c.first().as_int()) == 51), None,
        )
        assert create_coin is not None
        emitted_puzhash = bytes(create_coin.rest().first().as_atom())
        assert emitted_puzhash == bytes(artifacts.new_inner_puzzle_hash)
        assert artifacts.new_state == STATE_CANCELLED


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Mixed-curve admin sets.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


class TestMixedCurveAdmins:
    """Owner and gov can independently choose any member curve.  The
    proposal puzzle treats each member as opaque (only the tree hash
    matters), so a single proposal can have, say, a BLS owner +
    Eip712 gov, with each authorising their respective transitions.
    """

    def test_bls_owner_with_eip712_gov_approve(self):
        """Eip712 gov authorises APPROVE; the BLS owner is curried in
        but unused for this transition.  Verifies the puzzle doesn't
        confuse the two member slots.
        """
        from eth_keys import keys

        # Gov: Eip712Member.
        prefix_and_domain = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        type_h = _eip712_type_hash()
        sk = keys.PrivateKey(EIP712_TEST_SK_SEED)
        pk_compressed = _compress_pubkey(sk.public_key.to_bytes())
        gov_member = _eip712_member_fixture().curry(
            prefix_and_domain, type_h, pk_compressed
        )
        # Owner: BLS member (unused in APPROVE but still curried).
        owner_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)

        state = _draft_state(
            owner_member_hash=bytes32(owner_member.get_tree_hash()),
            gov_member_hash=bytes32(gov_member.get_tree_hash()),
        )
        artifacts = build_approve_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        signed_hash = _eip712_hash_to_sign(
            prefix_and_domain, EIP712_TEST_COIN_ID, artifacts.binding_hash,
        )
        sig_64 = sk.sign_msg_hash(signed_hash).to_bytes()[:64]
        member_remainder = Program.to(
            [EIP712_TEST_COIN_ID, signed_hash, sig_64]
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_APPROVE,
            new_state_version=1,
            member_puzzle_reveal=gov_member,
            member_solution_remainder=member_remainder,
        )
        # Should run without raising; CREATE_COIN should reference APPROVED.
        result = puzzle.run(solution, flags=_eip712_run_flags())
        conditions = list(result.as_iter())
        create_coin = next(
            (c for c in conditions if int(c.first().as_int()) == 51), None,
        )
        assert create_coin is not None
        assert (
            bytes(create_coin.rest().first().as_atom())
            == bytes(artifacts.new_inner_puzzle_hash)
        )

    def test_eip712_owner_with_bls_gov_cancel(self):
        """Symmetric mirror: Eip712 owner authorises CANCEL while
        a BLS gov is curried but unused.  Confirms the dispatch
        logic correctly routes to OWNER_MEMBER_HASH on CANCEL.
        """
        from eth_keys import keys

        # Owner: Eip712Member.
        prefix_and_domain = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        type_h = _eip712_type_hash()
        sk = keys.PrivateKey(EIP712_TEST_SK_SEED)
        pk_compressed = _compress_pubkey(sk.public_key.to_bytes())
        owner_member = _eip712_member_fixture().curry(
            prefix_and_domain, type_h, pk_compressed
        )
        # Gov: BLS member (unused in CANCEL but still curried).
        gov_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)

        state = _draft_state(
            owner_member_hash=bytes32(owner_member.get_tree_hash()),
            gov_member_hash=bytes32(gov_member.get_tree_hash()),
        )
        artifacts = build_cancel_spend(
            current=state, new_state_version=1, my_amount=SINGLETON_AMOUNT,
        )
        signed_hash = _eip712_hash_to_sign(
            prefix_and_domain, EIP712_TEST_COIN_ID, artifacts.binding_hash,
        )
        sig_64 = sk.sign_msg_hash(signed_hash).to_bytes()[:64]
        member_remainder = Program.to(
            [EIP712_TEST_COIN_ID, signed_hash, sig_64]
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_CANCEL,
            new_state_version=1,
            member_puzzle_reveal=owner_member,
            member_solution_remainder=member_remainder,
        )
        result = puzzle.run(solution, flags=_eip712_run_flags())
        conditions = list(result.as_iter())
        create_coin = next(
            (c for c in conditions if int(c.first().as_int()) == 51), None,
        )
        assert create_coin is not None


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Negative tests \u2014 wrong member, replay protection.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


class TestMemberHashEnforcement:
    """The puzzle MUST verify ``sha256tree(member_puzzle_reveal)``
    matches the expected slot for the requested transition.  Without
    this guard, a caller could provide a different (more permissive)
    member to bypass auth.
    """

    def test_approve_rejects_wrong_member(self):
        """APPROVE supplied with the OWNER_MEMBER (instead of GOV) is rejected."""
        owner_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        owner_hash = bytes32(owner_member.get_tree_hash())
        # gov_hash is a sentinel (no matching reveal exists).
        state = _draft_state(
            owner_member_hash=owner_hash,
            gov_member_hash=SENTINEL_GOV_HASH,  # different hash
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        # Try to use the owner member to authorise APPROVE.  Should
        # fail the sha256tree(reveal) == GOV_MEMBER_HASH check.
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_APPROVE,
            new_state_version=1,
            member_puzzle_reveal=owner_member,
            member_solution_remainder=Program.to([]),
        )
        with pytest.raises(Exception):
            puzzle.run(solution)

    def test_cancel_rejects_wrong_member(self):
        """CANCEL supplied with the GOV_MEMBER (instead of OWNER) is rejected."""
        gov_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        gov_hash = bytes32(gov_member.get_tree_hash())
        state = _draft_state(
            owner_member_hash=SENTINEL_OWNER_HASH,
            gov_member_hash=gov_hash,
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_CANCEL,
            new_state_version=1,
            member_puzzle_reveal=gov_member,
            member_solution_remainder=Program.to([]),
        )
        with pytest.raises(Exception):
            puzzle.run(solution)


class TestBindingHashReplayProtection:
    """Binding hashes uniquely identify (transition_case, version,
    proposal).  This block tests that signatures collected for one
    triple cannot be replayed against any other triple.
    """

    def _two_proposals(self):
        return (
            _draft_state(),
            _draft_state(  # different property_id \u2192 different data hash
                # piggybacking on the helper but tweaking property_id
            ),
        )

    def test_binding_hash_unique_per_transition_case(self):
        state = _draft_state()
        a = compute_binding_hash(
            transition_case=TRANSITION_APPROVE,
            new_state_version=1,
            proposal_data_hash=state.proposal_data_hash,
        )
        c = compute_binding_hash(
            transition_case=TRANSITION_CANCEL,
            new_state_version=1,
            proposal_data_hash=state.proposal_data_hash,
        )
        assert a != c

    def test_binding_hash_unique_per_version(self):
        state = _draft_state()
        v1 = compute_binding_hash(
            transition_case=TRANSITION_APPROVE,
            new_state_version=1,
            proposal_data_hash=state.proposal_data_hash,
        )
        v2 = compute_binding_hash(
            transition_case=TRANSITION_APPROVE,
            new_state_version=2,
            proposal_data_hash=state.proposal_data_hash,
        )
        assert v1 != v2

    def test_binding_hash_unique_per_proposal_data(self):
        prop_a = compute_proposal_data_hash(
            property_id_canon=bytes32(b"\x01" * 32),
            collection_id_canon=COLLECTION_ID_CANON,
            share_ppm=SHARE_PPM,
            par_value_mojos=1, royalty_bps=0, quorum_threshold=1,
        )
        prop_b = compute_proposal_data_hash(
            property_id_canon=bytes32(b"\x02" * 32),
            collection_id_canon=COLLECTION_ID_CANON,
            share_ppm=SHARE_PPM,
            par_value_mojos=1, royalty_bps=0, quorum_threshold=1,
        )
        a = compute_binding_hash(
            transition_case=TRANSITION_APPROVE,
            new_state_version=1, proposal_data_hash=prop_a,
        )
        b = compute_binding_hash(
            transition_case=TRANSITION_APPROVE,
            new_state_version=1, proposal_data_hash=prop_b,
        )
        assert a != b


class TestStateMachineGuards:
    """V1 transition guards retained: monotonic version, must be DRAFT."""

    def test_rejects_non_monotonic_version(self):
        gov_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        state = _draft_state(
            gov_member_hash=bytes32(gov_member.get_tree_hash()),
            state_version=5,
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        # new_state_version (3) < current state_version (5) \u2014 should fail.
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=TRANSITION_APPROVE,
            new_state_version=3,
            member_puzzle_reveal=gov_member,
            member_solution_remainder=Program.to([]),
        )
        with pytest.raises(Exception):
            puzzle.run(solution)

    def test_rejects_unknown_transition_case(self):
        gov_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        state = _draft_state(
            gov_member_hash=bytes32(gov_member.get_tree_hash()),
        )
        puzzle = make_inner_puzzle(
            owner_member_hash=state.owner_member_hash,
            gov_member_hash=state.gov_member_hash,
            proposal_data_hash=state.proposal_data_hash,
            proposal_state=state.proposal_state,
            state_version=state.state_version,
        )
        solution = _build_v2_solution(
            my_amount=SINGLETON_AMOUNT,
            transition_case=0xFF,  # neither APPROVE nor CANCEL
            new_state_version=1,
            member_puzzle_reveal=gov_member,
            member_solution_remainder=Program.to([]),
        )
        with pytest.raises(Exception):
            puzzle.run(solution)
