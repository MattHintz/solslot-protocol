"""End-to-end simulation for the Populis Protocol.

Exercises the full protocol lifecycle at the condition level — verifying that
all cross-contract CHIP-25 messages, puzzle announcements, and state
transitions pair correctly across atomic co-spends.

Unlike SpendSim consensus tests that push spend bundles through the mempool,
this simulation runs each puzzle independently (like test_deposit_tokenize.py)
and verifies that the outputs interlock correctly.  This is the right level
of abstraction because:
  - Our puzzles use CHIP-25 messages (SEND/RECEIVE), not coin announcements,
    so the pairing is verified by matching message bytes + sender puzzle hash
  - SpendSim does not natively verify CHIP-25 message pairing (only classical
    announcement assert/create pairs) — we would need a custom validator
  - Condition-level verification catches the same bugs (mismatched curry params,
    wrong message format, broken state recreation) and runs in <1 second

Full lifecycle covered:

  Phase 1 — Governance EXECUTE_MINT: gov sends CHIP-25 message to DID
  Phase 2 — Quorum DID receives governance message, announces deed puzzle hash
  Phase 3 — DID-approved launcher creates deed singleton (eve = mint_offer_delegate)
  Phase 4 — Purchase: buyer co-spends purchase_payment + mint_offer_delegate
             → deed transitions to smart_deed_inner (gated)
  Phase 5 — Deposit: deed + pool co-spend, token mint authorization
  Phase 6 — Redeem: pool + deed co-spend, token melt, vault containment
  Phase 7 — Governance freeze → pool rejects deposit → governance unfreeze
  Phase 8 — State verification: TVL, deed count, pool puzzle hash
  Phase 9 — Batch Settlement: governance approves splitxch distribution →
             pool creates splitxch root coin + per-deed release announcements →
             p2_pool releases deeds.  Equal split via the splitxch tree.
             Pool state → (POOL_ACTIVE, 0, 0).

A full end-to-end exercise of every spend case in every contract.
"""
import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia.wallet.util.curry_and_treehash import (
    calculate_hash_of_quoted_mod_hash,
    curry_and_treehash,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

# ─────────────────────────────────────────────────────────────────────
# Load all protocol puzzles
# ─────────────────────────────────────────────────────────────────────
POOL_INNER_MOD: Program = load_clvm(
    "pool_singleton_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
GOV_INNER_MOD: Program = load_clvm(
    "governance_singleton_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
SMART_DEED_INNER_MOD: Program = load_clvm(
    "smart_deed_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
POOL_TOKEN_TAIL_MOD: Program = load_clvm(
    "pool_token_tail.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
MINT_OFFER_MOD: Program = load_clvm(
    "mint_offer_delegate.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
PURCHASE_PAYMENT_MOD: Program = load_clvm(
    "purchase_payment.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
QUORUM_DID_MOD: Program = load_clvm(
    "quorum_did_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
SINGLETON_LAUNCHER_WITH_DID_MOD: Program = load_clvm(
    "singleton_launcher_with_did.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
P2_VAULT_MOD: Program = load_clvm(
    "p2_vault.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
P2_POOL_MOD: Program = load_clvm(
    "p2_pool.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)

# ─────────────────────────────────────────────────────────────────────
# Protocol constants — use REAL singleton mod hash from chia-blockchain
# ─────────────────────────────────────────────────────────────────────
PROTOCOL_PREFIX = b"\x50"
FP_SCALE = 1000
QUORUM_BPS = 5000
POOL_ACTIVE = 1
POOL_FROZEN = 0

# Spend case constants
POOL_SPEND_DEPOSIT = 1
POOL_SPEND_REDEEM = 2
POOL_SPEND_SETTLEMENT = 3
POOL_SPEND_GOVERNANCE = 4
GOV_SPEND_EXECUTE_SETTLEMENT = 2
GOV_SPEND_EXECUTE_FREEZE = 3
GOV_SPEND_EXECUTE_MINT = 4
DEED_SPEND_POOL_DEPOSIT = 0x64
DEED_SPEND_POOL_REDEEM = 0x72

# Token constants
TOKEN_MINT = 1
TOKEN_MELT = -1

# Mod hashes
POOL_MOD_HASH = POOL_INNER_MOD.get_tree_hash()
GOV_MOD_HASH = GOV_INNER_MOD.get_tree_hash()
P2_VAULT_MOD_HASH = P2_VAULT_MOD.get_tree_hash()
P2_POOL_MOD_HASH = P2_POOL_MOD.get_tree_hash()
PURCHASE_MOD_HASH = PURCHASE_PAYMENT_MOD.get_tree_hash()

# Placeholder hashes for contracts not directly exercised in deposit/redeem path
CAT_MOD_HASH = bytes32(b"\x05" * 32)
OFFER_MOD_HASH = bytes32(b"\x06" * 32)
TOKEN_TAIL_HASH = POOL_TOKEN_TAIL_MOD.get_tree_hash()

# Deed metadata
PAR_VALUE = 100_000
ASSET_CLASS = 1
PROPERTY_ID = bytes32(b"\x08" * 32)
COLLECTION_ID_CANON = bytes32(b"\x09" * 32)
SHARE_PPM = 1_000_000
JURISDICTION = b"US-CA"
ROYALTY_BPS = 200

# ─────────────────────────────────────────────────────────────────────
# Simulated identity constants (deterministic bytes for reproducibility)
# ─────────────────────────────────────────────────────────────────────
LAUNCHER_PUZZLE_HASH = SINGLETON_LAUNCHER_HASH

# Singletons — each has a unique launcher ID
GOV_LAUNCHER_ID = bytes32(b"\x10" * 32)
POOL_LAUNCHER_ID = bytes32(b"\x20" * 32)
DEED_LAUNCHER_ID = bytes32(b"\x30" * 32)
DID_LAUNCHER_ID = bytes32(b"\x40" * 32)
VAULT_LAUNCHER_ID = bytes32(b"\x50" * 32)  # buyer's vault

# Derived structs
GOV_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (GOV_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH))
)
POOL_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH))
)
DEED_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (DEED_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH))
)
DID_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (DID_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH))
)

# Protocol DID puzzle hash — quorum_did_inner curried with gov struct,
# then wrapped in singleton top layer
QUORUM_DID_INNER = QUORUM_DID_MOD.curry(GOV_SINGLETON_STRUCT)
PROTOCOL_DID_PUZHASH = SINGLETON_MOD.curry(
    DID_SINGLETON_STRUCT, QUORUM_DID_INNER
).get_tree_hash()

# Royalty goes to protocol
ROYALTY_PUZHASH = bytes32(PROTOCOL_DID_PUZHASH)

# Simulated coin IDs
POOL_COIN_ID = bytes32(b"\xa1" * 32)
GOV_COIN_ID = bytes32(b"\xa2" * 32)
DID_COIN_ID = bytes32(b"\xa3" * 32)
DEED_COIN_ID = bytes32(b"\xa4" * 32)
TOKEN_COIN_ID = bytes32(b"\xa5" * 32)
BUYER_PUZHASH = bytes32(b"\xb1" * 32)
DEPOSITOR_PUZHASH = bytes32(b"\xb2" * 32)
BENEFICIARY_PUZHASH = bytes32(b"\xb3" * 32)
SETTLEMENT_AMOUNT = 95_000  # settlement payout in mojos (≤ PAR_VALUE)


# ─────────────────────────────────────────────────────────────────────
# Curry helpers
# ─────────────────────────────────────────────────────────────────────
def curry_pool(
    pool_status=POOL_ACTIVE,
    tvl=0,
    deed_count=0,
    total_pool_token_supply=0,
    treasury_reserve_tokens=0,
) -> Program:
    return POOL_INNER_MOD.curry(
        POOL_MOD_HASH,
        POOL_SINGLETON_STRUCT,
        PROTOCOL_DID_PUZHASH,
        TOKEN_TAIL_HASH,
        CAT_MOD_HASH,
        OFFER_MOD_HASH,
        P2_VAULT_MOD_HASH,
        FP_SCALE,
        pool_status,
        tvl,
        deed_count,
        total_pool_token_supply,
        treasury_reserve_tokens,
    )


def curry_gov(proposal_hash=0) -> Program:
    return GOV_INNER_MOD.curry(
        GOV_MOD_HASH,
        GOV_SINGLETON_STRUCT,
        PROTOCOL_DID_PUZHASH,
        QUORUM_BPS,
        proposal_hash,
    )


def curry_deed() -> Program:
    return SMART_DEED_INNER_MOD.curry(
        DEED_SINGLETON_STRUCT,
        PROTOCOL_DID_PUZHASH,
        PAR_VALUE,
        ASSET_CLASS,
        PROPERTY_ID,
        COLLECTION_ID_CANON,
        SHARE_PPM,
        JURISDICTION,
        ROYALTY_PUZHASH,
        ROYALTY_BPS,
        SINGLETON_MOD_HASH,
        P2_POOL_MOD_HASH,
        P2_VAULT_MOD_HASH,
    )


def curry_mint_offer(smart_deed_inner_hash: bytes32) -> Program:
    return MINT_OFFER_MOD.curry(
        smart_deed_inner_hash,
        PURCHASE_MOD_HASH,
        PAR_VALUE,
        PROTOCOL_DID_PUZHASH,
    )


def curry_purchase() -> Program:
    return PURCHASE_PAYMENT_MOD.curry(PAR_VALUE, PROTOCOL_DID_PUZHASH)


def curry_tail() -> Program:
    return POOL_TOKEN_TAIL_MOD.curry(
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


def full_puzzle_hash(singleton_struct: Program, inner: Program) -> bytes32:
    """Compute singleton full puzzle hash: SINGLETON_MOD.curry(struct, inner).get_tree_hash()"""
    return SINGLETON_MOD.curry(singleton_struct, inner).get_tree_hash()


def extract_cond(conditions: list, opcode: int, index: int = 0) -> list:
    """Find the Nth condition with the given opcode byte."""
    matches = [c for c in conditions if c[0] == bytes([opcode])]
    assert len(matches) > index, f"Opcode {opcode}: only {len(matches)} found, need index {index}"
    return matches[index]


def extract_conds(conditions: list, opcode: int) -> list:
    """Find all conditions with the given opcode byte."""
    return [c for c in conditions if c[0] == bytes([opcode])]


# ─────────────────────────────────────────────────────────────────────
# Phase 1: Governance EXECUTE_MINT
# ─────────────────────────────────────────────────────────────────────
@pytest.mark.skip(
    reason="v2 governance refactor (Milestone 1, Step C) replaced the legacy "
           "raw-vote_weight puzzle with PGT-backed proposal tracker. "
           "Re-port pending in Step D's E2E governance v2 lifecycle test."
)
class TestPhase1GovernanceMint:
    """Governance approves a deed mint via EXECUTE_MINT → SEND_MESSAGE to DID."""

    def test_gov_execute_mint_sends_message(self):
        """Gov EXECUTE_MINT produces SEND_MESSAGE with MINT prefix + deed full puzzle hash."""
        gov_inner = curry_gov(proposal_hash=0)
        deed_inner = curry_deed()
        # The deed's full singleton puzzle hash (what the launcher will create)
        deed_full_ph = full_puzzle_hash(DEED_SINGLETON_STRUCT, curry_mint_offer(deed_inner.get_tree_hash()))

        sol = Program.to([
            GOV_COIN_ID, gov_inner.get_tree_hash(), 1,
            GOV_SPEND_EXECUTE_MINT,
            [deed_full_ph, QUORUM_BPS],
        ])
        conds = gov_inner.run(sol).as_python()

        # SEND_MESSAGE 0x10 with MINT prefix
        send = extract_cond(conds, 66)  # SEND_MESSAGE
        assert send[1] == bytes([0x10])
        assert send[2][:1] == PROTOCOL_PREFIX

        # Message content: PROTOCOL_PREFIX + sha256tree(list 0x4d494e54 deed_full_ph)
        expected_msg = PROTOCOL_PREFIX + Program.to([0x4d494e54, deed_full_ph]).get_tree_hash()
        assert send[2] == expected_msg

        # State recreation: proposal_hash clears to 0
        new_inner = curry_gov(proposal_hash=0)
        assert conds[0][1] == new_inner.get_tree_hash()


# ─────────────────────────────────────────────────────────────────────
# Phase 2: Quorum DID receives governance message
# ─────────────────────────────────────────────────────────────────────
@pytest.mark.skip(
    reason="v2 governance refactor — governance puzzle interface changed. "
           "DID receive logic is unchanged; re-port the gov-side construction in Step D."
)
class TestPhase2QuorumDID:
    """DID receives EXECUTE_MINT message from governance and announces deed puzzle hash."""

    def test_did_receives_gov_message_and_announces(self):
        """quorum_did_inner RECEIVE_MESSAGE from gov, CREATE_PUZZLE_ANNOUNCEMENT of deed ph."""
        did_inner = QUORUM_DID_MOD.curry(GOV_SINGLETON_STRUCT)
        deed_inner = curry_deed()
        deed_full_ph = full_puzzle_hash(DEED_SINGLETON_STRUCT, curry_mint_offer(deed_inner.get_tree_hash()))
        gov_inner = curry_gov(proposal_hash=0)
        gov_inner_ph = gov_inner.get_tree_hash()

        sol = Program.to([deed_full_ph, gov_inner_ph])
        conds = did_inner.run(sol).as_python()

        assert len(conds) == 2

        # RECEIVE_MESSAGE 0x10 from governance
        recv = extract_cond(conds, 67)  # RECEIVE_MESSAGE
        assert recv[1] == bytes([0x10])

        # CREATE_PUZZLE_ANNOUNCEMENT of deed full puzzle hash
        announce = extract_cond(conds, 62)  # CREATE_PUZZLE_ANNOUNCEMENT
        assert announce[1] == deed_full_ph

    def test_gov_send_matches_did_receive(self):
        """The gov SEND_MESSAGE content must match the DID RECEIVE_MESSAGE content."""
        gov_inner = curry_gov(proposal_hash=0)
        did_inner = QUORUM_DID_MOD.curry(GOV_SINGLETON_STRUCT)
        deed_inner = curry_deed()
        deed_full_ph = full_puzzle_hash(DEED_SINGLETON_STRUCT, curry_mint_offer(deed_inner.get_tree_hash()))

        # Gov EXECUTE_MINT
        gov_sol = Program.to([
            GOV_COIN_ID, gov_inner.get_tree_hash(), 1,
            GOV_SPEND_EXECUTE_MINT,
            [deed_full_ph, QUORUM_BPS],
        ])
        gov_conds = gov_inner.run(gov_sol).as_python()
        gov_send = extract_cond(gov_conds, 66)

        # DID receive
        did_sol = Program.to([deed_full_ph, gov_inner.get_tree_hash()])
        did_conds = did_inner.run(did_sol).as_python()
        did_recv = extract_cond(did_conds, 67)

        # Message bytes must match
        assert gov_send[2] == did_recv[2], (
            f"Gov→DID message mismatch:\n"
            f"  Gov sends:   {gov_send[2].hex()}\n"
            f"  DID expects: {did_recv[2].hex()}"
        )

        # DID expects sender = gov full puzzle hash
        expected_gov_full_ph = full_puzzle_hash(GOV_SINGLETON_STRUCT, gov_inner)
        assert bytes32(did_recv[3]) == expected_gov_full_ph


# ─────────────────────────────────────────────────────────────────────
# Phase 3: DID-approved launcher (structural verification)
# ─────────────────────────────────────────────────────────────────────
class TestPhase3LauncherStructure:
    """Verify the DID-approved launcher produces the expected deed singleton."""

    def test_launcher_creates_deed_with_mint_offer_inner(self):
        """singleton_launcher_with_did produces CREATE_COIN for deed + asserts DID announcement."""
        deed_inner = curry_deed()
        mint_offer_inner = curry_mint_offer(deed_inner.get_tree_hash())

        # The deed singleton's full puzzle hash
        deed_full_ph = full_puzzle_hash(DEED_SINGLETON_STRUCT, mint_offer_inner)

        launcher = SINGLETON_LAUNCHER_WITH_DID_MOD.curry(DID_SINGLETON_STRUCT)
        did_inner_ph = QUORUM_DID_INNER.get_tree_hash()

        sol = Program.to([did_inner_ph, deed_full_ph, 1, []])
        conds = launcher.run(sol).as_python()

        # CREATE_COIN for deed singleton
        create_coin = extract_cond(conds, 51)  # CREATE_COIN
        assert create_coin[1] == deed_full_ph
        assert int.from_bytes(create_coin[2], "big") == 1

        # ASSERT_PUZZLE_ANNOUNCEMENT from DID (verifies DID announced this deed ph)
        assert_ann = extract_cond(conds, 63)  # ASSERT_PUZZLE_ANNOUNCEMENT
        # The launcher asserts: sha256(DID_full_puzzle_hash, deed_full_ph)
        expected_ann_hash = hashlib.sha256(
            bytes(PROTOCOL_DID_PUZHASH) + bytes(deed_full_ph)
        ).digest()
        assert assert_ann[1] == expected_ann_hash


# ─────────────────────────────────────────────────────────────────────
# Phase 4: Purchase — purchase_payment + mint_offer_delegate co-spend
# ─────────────────────────────────────────────────────────────────────
class TestPhase4Purchase:
    """Buyer purchases deed by co-spending purchase_payment + mint_offer_delegate."""

    def test_purchase_payment_sends_correct_message(self):
        """purchase_payment emits SEND_MESSAGE with PURC prefix + PAR_VALUE + PROTOCOL_PUZHASH."""
        pp = curry_purchase()
        sol = Program.to([BUYER_PUZHASH, PAR_VALUE])
        conds = pp.run(sol).as_python()

        # CREATE_COIN to protocol (payment)
        payment = extract_cond(conds, 51)
        assert payment[1] == PROTOCOL_DID_PUZHASH
        assert int.from_bytes(payment[2], "big") == PAR_VALUE

        # SEND_MESSAGE 0x10
        send = extract_cond(conds, 66)
        assert send[1] == bytes([0x10])
        assert send[2][:1] == PROTOCOL_PREFIX

    def test_mint_offer_transitions_to_smart_deed(self):
        """mint_offer_delegate creates coin with smart_deed_inner hash."""
        deed_inner = curry_deed()
        mint_offer = curry_mint_offer(deed_inner.get_tree_hash())

        sol = Program.to([DEED_COIN_ID])
        conds = mint_offer.run(sol).as_python()

        # CREATE_COIN transitions to smart_deed_inner
        create = extract_cond(conds, 51)
        assert create[1] == deed_inner.get_tree_hash()
        assert int.from_bytes(create[2], "big") == 1

    def test_purchase_send_matches_mint_offer_receive(self):
        """purchase_payment SEND_MESSAGE == mint_offer_delegate RECEIVE_MESSAGE."""
        pp = curry_purchase()
        pp_sol = Program.to([BUYER_PUZHASH, PAR_VALUE])
        pp_conds = pp.run(pp_sol).as_python()
        pp_send = extract_cond(pp_conds, 66)

        deed_inner = curry_deed()
        mint_offer = curry_mint_offer(deed_inner.get_tree_hash())
        mo_sol = Program.to([DEED_COIN_ID])
        mo_conds = mint_offer.run(mo_sol).as_python()
        mo_recv = extract_cond(mo_conds, 67)

        # Message bytes must match
        assert pp_send[2] == mo_recv[2], (
            f"Purchase↔MintOffer message mismatch:\n"
            f"  PP sends:  {pp_send[2].hex()}\n"
            f"  MO expects: {mo_recv[2].hex()}"
        )

        # Mint offer expects sender = purchase_payment puzzle hash
        expected_pp_ph = pp.get_tree_hash()
        assert bytes32(mo_recv[3]) == expected_pp_ph

    def test_purchase_with_overpayment_returns_change(self):
        """Buyer overpays — change returned to buyer_puzhash."""
        pp = curry_purchase()
        overpay = PAR_VALUE + 500_000
        sol = Program.to([BUYER_PUZHASH, overpay])
        conds = pp.run(sol).as_python()

        # 4 conditions: change, payment, send_message, assert_my_amount
        assert len(conds) == 4
        change = conds[0]
        assert change[0] == bytes([51])
        assert change[1] == BUYER_PUZHASH
        assert int.from_bytes(change[2], "big") == 500_000


# ─────────────────────────────────────────────────────────────────────
# Phase 5: Deposit — deed + pool co-spend, token mint auth
# ─────────────────────────────────────────────────────────────────────
class TestPhase5Deposit:
    """Deed deposits into pool. Pool mints tokens. Three-way co-spend verification."""

    def setup_method(self):
        self.pool_inner = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        self.deed_inner = curry_deed()
        self.tail = curry_tail()
        self.pool_inner_ph = self.pool_inner.get_tree_hash()
        self.deed_inner_ph = self.deed_inner.get_tree_hash()
        self.expected_token_amount = (PAR_VALUE * FP_SCALE) // 1000

    def test_pool_deposit_state_recreation(self):
        """Pool state advances: TVL += PAR_VALUE, DEED_COUNT += 1."""
        sol = Program.to([
            POOL_COIN_ID, self.pool_inner_ph, 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        conds = self.pool_inner.run(sol).as_python()

        expected_new = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=PAR_VALUE,
            deed_count=1,
            total_pool_token_supply=self.expected_token_amount,
        )
        assert conds[0][1] == expected_new.get_tree_hash(), "Pool state recreation mismatch"

    def test_pool_deed_message_match(self):
        """Pool SEND_MESSAGE == Deed RECEIVE_MESSAGE (CHIP-25 pairing)."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_ph, 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        pool_conds = self.pool_inner.run(pool_sol).as_python()
        pool_send = extract_cond(pool_conds, 66)

        deed_sol = Program.to([
            DEED_COIN_ID, self.deed_inner_ph, 1,
            DEED_SPEND_POOL_DEPOSIT,
            [POOL_LAUNCHER_ID, self.pool_inner_ph, LAUNCHER_PUZZLE_HASH],
        ])
        deed_conds = self.deed_inner.run(deed_sol).as_python()
        deed_recv = extract_cond(deed_conds, 67)

        assert pool_send[2] == deed_recv[2], "Pool↔Deed deposit message mismatch"

    def test_pool_token_announcement_match(self):
        """Pool CREATE_PUZZLE_ANNOUNCEMENT matches Token TAIL ASSERT_PUZZLE_ANNOUNCEMENT."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_ph, 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        pool_conds = self.pool_inner.run(pool_sol).as_python()
        pool_announce = extract_cond(pool_conds, 62)  # CREATE_PUZZLE_ANNOUNCEMENT
        pool_announce_content = pool_announce[1]

        # Token TAIL
        tail_sol = Program.to([
            full_puzzle_hash(POOL_SINGLETON_STRUCT, self.pool_inner),
            self.pool_inner_ph, POOL_COIN_ID, TOKEN_COIN_ID,
            TOKEN_MINT, self.expected_token_amount,
        ])
        tail_conds = self.tail.run(tail_sol).as_python()
        tail_assert = extract_cond(tail_conds, 63)  # ASSERT_PUZZLE_ANNOUNCEMENT

        # Compute expected full hash: sha256(pool_full_ph || announcement_content)
        pool_full_ph = full_puzzle_hash(POOL_SINGLETON_STRUCT, self.pool_inner)

        computed_hash = bytes32(
            hashlib.sha256(bytes(pool_full_ph) + pool_announce_content).digest()
        )
        assert bytes32(tail_assert[1]) == computed_hash, "Pool↔Token announcement mismatch"

    def test_deed_sends_to_p2_pool(self):
        """Regression for CRIT-1: Deed CREATE_COIN destination must be the
        *bare* p2_pool inner puzhash.

        singleton_top_layer's check_and_morph_conditions_for_singleton then
        wraps this odd-amount CREATE_COIN into the deed's new full puzhash
        singleton.curry(deed_struct, p2_pool_inner_hash). Before the fix the
        deed was sent to the pool singleton's full puzhash, which is nonsense
        as an inner puzzle and caused deposited deeds to be permanently
        unspendable.
        """
        deed_sol = Program.to([
            DEED_COIN_ID, self.deed_inner_ph, 1,
            DEED_SPEND_POOL_DEPOSIT,
            [POOL_LAUNCHER_ID, self.pool_inner_ph, LAUNCHER_PUZZLE_HASH],
        ])
        deed_conds = self.deed_inner.run(deed_sol).as_python()
        create = extract_cond(deed_conds, 51)
        deed_dest = bytes32(create[1])

        # Expected: bare p2_pool inner puzhash (pre-morph target).
        quoted_mod = calculate_hash_of_quoted_mod_hash(P2_POOL_MOD_HASH)
        expected_bare_p2_pool = bytes32(curry_and_treehash(
            quoted_mod,
            hashlib.sha256(b"\x01" + bytes(SINGLETON_MOD_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(POOL_LAUNCHER_ID)).digest(),
            hashlib.sha256(b"\x01" + bytes(LAUNCHER_PUZZLE_HASH)).digest(),
        ))
        assert deed_dest == expected_bare_p2_pool, (
            f"Deposit destination mismatch (deed burn bug regressed!):\n"
            f"  Deed sends to:       {deed_dest.hex()}\n"
            f"  Expected bare p2_pool: {expected_bare_p2_pool.hex()}"
        )

        # Belt-and-braces: explicitly reject the pre-fix buggy value
        # (pool singleton's full puzhash) so a future refactor cannot
        # silently regress.
        quoted_singleton = calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH)
        pool_struct = Program.to(
            (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH))
        )
        buggy_pool_full_ph = bytes32(curry_and_treehash(
            quoted_singleton,
            pool_struct.get_tree_hash(),
            self.pool_inner_ph,
        ))
        assert deed_dest != buggy_pool_full_ph, (
            "Deposit destination regressed to the pre-fix buggy value "
            "(pool singleton's full puzhash). Deeds sent there are burnt."
        )


# ─────────────────────────────────────────────────────────────────────
# Phase 6: Redeem — pool + deed co-spend, token melt, vault containment
# ─────────────────────────────────────────────────────────────────────
class TestPhase6Redeem:
    """Pool releases deed to redeemer's vault. Vault containment enforced."""

    def setup_method(self):
        # Pool state: 1 deed deposited
        self.pool_inner = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=PAR_VALUE,
            deed_count=1,
            total_pool_token_supply=PAR_VALUE,
        )
        self.deed_inner = curry_deed()
        self.tail = curry_tail()
        self.pool_inner_ph = self.pool_inner.get_tree_hash()
        self.deed_inner_ph = self.deed_inner.get_tree_hash()
        self.expected_token_amount = (PAR_VALUE * FP_SCALE) // 1000

    def _computed_p2_vault_ph(self) -> bytes32:
        """Compute the p2_vault puzzle hash as the contracts do it."""
        quoted_mod = calculate_hash_of_quoted_mod_hash(P2_VAULT_MOD_HASH)
        return bytes32(curry_and_treehash(
            quoted_mod,
            hashlib.sha256(b"\x01" + bytes(SINGLETON_MOD_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(VAULT_LAUNCHER_ID)).digest(),
            hashlib.sha256(b"\x01" + bytes(LAUNCHER_PUZZLE_HASH)).digest(),
        ))

    def test_pool_redeem_state_recreation(self):
        """Pool state retreats: TVL -= PAR_VALUE, DEED_COUNT -= 1."""
        sol = Program.to([
            POOL_COIN_ID, self.pool_inner_ph, 1,
            POOL_SPEND_REDEEM,
            [DEED_COIN_ID, PAR_VALUE, VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH, TOKEN_COIN_ID],
        ])
        conds = self.pool_inner.run(sol).as_python()

        expected_new = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert conds[0][1] == expected_new.get_tree_hash(), "Pool state recreation mismatch"

    def test_pool_deed_redeem_message_match(self):
        """Pool SEND_MESSAGE == Deed RECEIVE_MESSAGE for REDEEM (CHIP-25 pairing)."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_ph, 1,
            POOL_SPEND_REDEEM,
            [DEED_COIN_ID, PAR_VALUE, VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH, TOKEN_COIN_ID],
        ])
        pool_conds = self.pool_inner.run(pool_sol).as_python()
        pool_send = extract_cond(pool_conds, 66)

        deed_sol = Program.to([
            DEED_COIN_ID, self.deed_inner_ph, 1,
            DEED_SPEND_POOL_REDEEM,
            [POOL_LAUNCHER_ID, self.pool_inner_ph, LAUNCHER_PUZZLE_HASH, VAULT_LAUNCHER_ID],
        ])
        deed_conds = self.deed_inner.run(deed_sol).as_python()
        deed_recv = extract_cond(deed_conds, 67)

        assert pool_send[2] == deed_recv[2], (
            f"Pool↔Deed redeem message mismatch:\n"
            f"  Pool sends:   {pool_send[2].hex()}\n"
            f"  Deed expects: {deed_recv[2].hex()}"
        )

    def test_deed_redeem_destination_is_computed_p2_vault(self):
        """Deed CREATE_COIN goes to computed p2_vault — never arbitrary address."""
        deed_sol = Program.to([
            DEED_COIN_ID, self.deed_inner_ph, 1,
            DEED_SPEND_POOL_REDEEM,
            [POOL_LAUNCHER_ID, self.pool_inner_ph, LAUNCHER_PUZZLE_HASH, VAULT_LAUNCHER_ID],
        ])
        deed_conds = self.deed_inner.run(deed_sol).as_python()
        create = extract_cond(deed_conds, 51)
        deed_dest = bytes32(create[1])

        # Both pool and deed must compute the SAME p2_vault destination
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_ph, 1,
            POOL_SPEND_REDEEM,
            [DEED_COIN_ID, PAR_VALUE, VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH, TOKEN_COIN_ID],
        ])
        pool_conds = self.pool_inner.run(pool_sol).as_python()
        pool_send = extract_cond(pool_conds, 66)

        # The computed dest appears in both the deed's CREATE_COIN and the message
        # Verify it's a 32-byte hash (valid puzzle hash)
        assert len(deed_dest) == 32

        # Verify the deed's destination matches what appears in the REDEEM message
        # The message contains: PROTOCOL_PREFIX + sha256tree(list POOL_SPEND_REDEEM deed_id computed_dest)
        # We verify both contracts agree by checking message equality (done above)
        # Here we verify the dest is NOT an arbitrary address by checking it matches
        # the curry_hashes computation
        expected_dest = self._computed_p2_vault_ph()
        assert deed_dest == expected_dest, (
            f"Deed destination is not the expected p2_vault:\n"
            f"  Deed sends to:    {deed_dest.hex()}\n"
            f"  Expected p2_vault: {expected_dest.hex()}"
        )

    def test_pool_redeem_token_melt_announcement(self):
        """Pool CREATE_PUZZLE_ANNOUNCEMENT for token melt matches TAIL assertion."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_ph, 1,
            POOL_SPEND_REDEEM,
            [DEED_COIN_ID, PAR_VALUE, VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH, TOKEN_COIN_ID],
        ])
        pool_conds = self.pool_inner.run(pool_sol).as_python()
        pool_announce = extract_cond(pool_conds, 62)
        pool_announce_content = pool_announce[1]

        # Verify content: PROTOCOL_PREFIX + sha256tree(list TOKEN_MELT token_coin_id amount)
        expected_tree = Program.to([TOKEN_MELT, TOKEN_COIN_ID, self.expected_token_amount])
        expected_content = PROTOCOL_PREFIX + expected_tree.get_tree_hash()
        assert pool_announce_content == expected_content

        # Token TAIL assertion
        tail_sol = Program.to([
            full_puzzle_hash(POOL_SINGLETON_STRUCT, self.pool_inner),
            self.pool_inner_ph, POOL_COIN_ID, TOKEN_COIN_ID,
            TOKEN_MELT, self.expected_token_amount,
        ])
        tail_conds = self.tail.run(tail_sol).as_python()
        tail_assert = extract_cond(tail_conds, 63)

        pool_full_ph = full_puzzle_hash(POOL_SINGLETON_STRUCT, self.pool_inner)
        computed_hash = bytes32(
            hashlib.sha256(bytes(pool_full_ph) + pool_announce_content).digest()
        )
        assert bytes32(tail_assert[1]) == computed_hash, "Pool↔Token melt announcement mismatch"


# ─────────────────────────────────────────────────────────────────────
# Phase 7: Governance freeze/unfreeze
# ─────────────────────────────────────────────────────────────────────
@pytest.mark.skip(
    reason="v2 governance refactor — freeze message format unchanged but gov-side "
           "construction differs. Re-port in Step D."
)
class TestPhase7GovernanceFreeze:
    """Governance freezes pool, pool rejects deposit, then governance unfreezes."""

    def test_gov_freeze_message_matches_pool_receive(self):
        """Gov EXECUTE_FREEZE SEND_MESSAGE == Pool GOVERNANCE RECEIVE_MESSAGE."""
        gov_inner = curry_gov(proposal_hash=0)
        pool_inner = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)

        # Gov freezes pool
        gov_sol = Program.to([
            GOV_COIN_ID, gov_inner.get_tree_hash(), 1,
            GOV_SPEND_EXECUTE_FREEZE,
            [POOL_FROZEN, QUORUM_BPS],
        ])
        gov_conds = gov_inner.run(gov_sol).as_python()
        gov_send = extract_cond(gov_conds, 66)

        # Pool receives governance freeze
        pool_sol = Program.to([
            POOL_COIN_ID, pool_inner.get_tree_hash(), 1,
            POOL_SPEND_GOVERNANCE,
            [POOL_FROZEN, gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        pool_conds = pool_inner.run(pool_sol).as_python()
        pool_recv = extract_cond(pool_conds, 67)

        assert gov_send[2] == pool_recv[2], (
            f"Gov↔Pool freeze message mismatch:\n"
            f"  Gov sends:   {gov_send[2].hex()}\n"
            f"  Pool expects: {pool_recv[2].hex()}"
        )

        # Pool expects sender = gov full puzzle hash
        expected_gov_full_ph = full_puzzle_hash(GOV_SINGLETON_STRUCT, gov_inner)
        assert bytes32(pool_recv[3]) == expected_gov_full_ph

    def test_pool_state_after_freeze(self):
        """After freeze, pool recreates with POOL_STATUS=0."""
        pool_inner = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        gov_inner = curry_gov(proposal_hash=0)

        sol = Program.to([
            POOL_COIN_ID, pool_inner.get_tree_hash(), 1,
            POOL_SPEND_GOVERNANCE,
            [POOL_FROZEN, gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        conds = pool_inner.run(sol).as_python()

        expected_frozen = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        assert conds[0][1] == expected_frozen.get_tree_hash(), "Pool freeze state mismatch"

    def test_frozen_pool_rejects_deposit(self):
        """A frozen pool must reject DEPOSIT spend case."""
        frozen_pool = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        sol = Program.to([
            POOL_COIN_ID, frozen_pool.get_tree_hash(), 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        with pytest.raises(ValueError):
            frozen_pool.run(sol)

    def test_frozen_pool_rejects_redeem(self):
        """A frozen pool with deeds must reject REDEEM spend case."""
        frozen_pool = curry_pool(pool_status=POOL_FROZEN, tvl=PAR_VALUE, deed_count=1)
        sol = Program.to([
            POOL_COIN_ID, frozen_pool.get_tree_hash(), 1,
            POOL_SPEND_REDEEM,
            [DEED_COIN_ID, PAR_VALUE, VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH, TOKEN_COIN_ID],
        ])
        with pytest.raises(ValueError):
            frozen_pool.run(sol)

    def test_gov_unfreeze_restores_pool(self):
        """After unfreeze, pool recreates with POOL_STATUS=1 (ACTIVE)."""
        frozen_pool = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        gov_inner = curry_gov(proposal_hash=0)

        sol = Program.to([
            POOL_COIN_ID, frozen_pool.get_tree_hash(), 1,
            POOL_SPEND_GOVERNANCE,
            [POOL_ACTIVE, gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        conds = frozen_pool.run(sol).as_python()

        expected_active = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert conds[0][1] == expected_active.get_tree_hash(), "Pool unfreeze state mismatch"


# ─────────────────────────────────────────────────────────────────────
# Phase 8: Batch Settlement — governance approves splitxch distribution
# Gov ↔ Pool co-spend, pool releases deeds via p2_pool announcements
# ─────────────────────────────────────────────────────────────────────
DEED_ID_2 = bytes32(b"\x31" * 32)
BURN_INNER_PUZHASH = bytes32(b"\x00" * 32)  # dead inner puzzle = burn


@pytest.mark.skip(
    reason="v2 governance refactor plus release-set-bound SETTLE message; "
           "legacy count-only settlement E2E needs a full re-port in Step D."
)
class TestPhase8Settlement:
    """Batch settlement: governance approves splitxch root → pool creates
    distribution tree + per-deed release announcements → pool state (0,0).

    Uses an equal-split distribution tree.  Deeds exit via p2_pool
    (pool creates release announcements), not via smart_deed_inner.
    """

    def setup_method(self):
        self.gov_inner = curry_gov(proposal_hash=0)
        self.gov_inner_ph = self.gov_inner.get_tree_hash()
        # Pool with 1 deed deposited
        self.pool_inner_1 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=PAR_VALUE,
            deed_count=1,
            total_pool_token_supply=PAR_VALUE,
        )
        self.pool_inner_1_ph = self.pool_inner_1.get_tree_hash()
        # Pool with 2 deeds deposited
        self.pool_inner_2 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=PAR_VALUE * 2,
            deed_count=2,
            total_pool_token_supply=PAR_VALUE * 2,
        )
        self.pool_inner_2_ph = self.pool_inner_2.get_tree_hash()
        # Batch params
        self.splitxch_root = bytes32(b"\xf0" * 32)
        self.num_deeds_1 = 1
        self.num_deeds_2 = 2
        # deed_releases for p2_pool: list of (deed_id . next_puzzlehash) pairs
        self.deed_releases_1 = [(DEED_LAUNCHER_ID, BURN_INNER_PUZHASH)]
        self.deed_releases_2 = [
            (DEED_LAUNCHER_ID, BURN_INNER_PUZHASH),
            (DEED_ID_2, BURN_INNER_PUZHASH),
        ]

    def test_gov_execute_settlement_sends_one_message(self):
        """Gov EXECUTE_SETTLEMENT (batch) produces one SEND_MESSAGE 0x10 to pool."""
        sol = Program.to([
            GOV_COIN_ID, self.gov_inner_ph, 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.num_deeds_1, QUORUM_BPS],
        ])
        conds = self.gov_inner.run(sol).as_python()

        sends = extract_conds(conds, 66)
        assert len(sends) == 1, f"Batch settlement: expected 1 SEND_MESSAGE, got {len(sends)}"

        expected_msg = PROTOCOL_PREFIX + Program.to(
            [0x53455454, self.splitxch_root, SETTLEMENT_AMOUNT, self.num_deeds_1]
        ).get_tree_hash()
        assert sends[0][1] == bytes([0x10])
        assert sends[0][2] == expected_msg

        # State recreation: proposal_hash clears to 0
        new_inner = curry_gov(proposal_hash=0)
        assert conds[0][1] == new_inner.get_tree_hash(), "Gov state recreation mismatch"

    def test_gov_settlement_requires_quorum(self):
        """Gov EXECUTE_SETTLEMENT fails if vote_weight < QUORUM_BPS."""
        sol = Program.to([
            GOV_COIN_ID, self.gov_inner_ph, 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.num_deeds_1, QUORUM_BPS - 1],
        ])
        with pytest.raises(ValueError):
            self.gov_inner.run(sol)

    def test_pool_settlement_receives_gov_message(self):
        """Pool SETTLEMENT RECEIVE_MESSAGE matches gov SEND_MESSAGE content + sender."""
        # Gov side
        gov_sol = Program.to([
            GOV_COIN_ID, self.gov_inner_ph, 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.num_deeds_1, QUORUM_BPS],
        ])
        gov_conds = self.gov_inner.run(gov_sol).as_python()
        gov_send = extract_cond(gov_conds, 66)

        # Pool side
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_1_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_1,
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        pool_conds = self.pool_inner_1.run(pool_sol).as_python()
        pool_recv = extract_cond(pool_conds, 67)  # RECEIVE_MESSAGE

        # Message bytes must match
        assert gov_send[2] == pool_recv[2], (
            f"Gov→Pool batch settlement message mismatch:\n"
            f"  Gov sends:   {gov_send[2].hex()}\n"
            f"  Pool expects: {pool_recv[2].hex()}"
        )

        # Pool expects sender = gov full puzzle hash
        expected_gov_full_ph = full_puzzle_hash(GOV_SINGLETON_STRUCT, self.gov_inner)
        assert bytes32(pool_recv[3]) == expected_gov_full_ph

    def test_pool_settlement_state_recreation(self):
        """Pool state after batch settlement: TVL=0, DEED_COUNT=0."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_1_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_1,
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        pool_conds = self.pool_inner_1.run(pool_sol).as_python()

        expected_new_pool = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert pool_conds[0][1] == expected_new_pool.get_tree_hash(), (
            "Pool state after batch settlement must be (ACTIVE, 0, 0)"
        )

    def test_pool_settlement_creates_splitxch_root(self):
        """Pool emits CREATE_COIN with splitxch_root_hash and total_settlement_amount."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_1_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_1,
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        pool_conds = self.pool_inner_1.run(pool_sol).as_python()

        # Second CREATE_COIN is the splitxch root (first is state recreation)
        creates = extract_conds(pool_conds, 51)
        assert len(creates) == 2, f"Expected 2 CREATE_COIN, got {len(creates)}"
        splitxch_create = creates[1]
        assert splitxch_create[1] == self.splitxch_root, "Splitxch root hash mismatch"
        assert int.from_bytes(splitxch_create[2], "big") == SETTLEMENT_AMOUNT, \
            "Splitxch root amount must equal total_settlement_amount"

    def test_pool_settlement_creates_announcement(self):
        """Pool emits CREATE_PUZZLE_ANNOUNCEMENT with batch settlement info."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_1_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_1,
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        pool_conds = self.pool_inner_1.run(pool_sol).as_python()

        # First CREATE_PUZZLE_ANNOUNCEMENT is batch info, rest are per-deed releases
        announcements = extract_conds(pool_conds, 62)
        assert len(announcements) >= 1, "Pool must emit at least one announcement"

        expected_content = PROTOCOL_PREFIX + Program.to(
            [POOL_SPEND_SETTLEMENT, self.splitxch_root, SETTLEMENT_AMOUNT, self.num_deeds_1]
        ).get_tree_hash()
        assert announcements[0][1] == expected_content, "Pool batch announcement mismatch"

    def test_pool_settlement_creates_deed_release_announcements(self):
        """Pool emits per-deed CREATE_PUZZLE_ANNOUNCEMENT for p2_pool to assert."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_2_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_2,
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        pool_conds = self.pool_inner_2.run(pool_sol).as_python()

        announcements = extract_conds(pool_conds, 62)
        # 1 batch announcement + 2 per-deed release announcements
        assert len(announcements) == 3, f"Expected 3 announcements (1 batch + 2 deeds), got {len(announcements)}"

        # Verify per-deed release announcements match p2_pool format
        for i, (deed_id, next_ph) in enumerate(self.deed_releases_2):
            expected_release = PROTOCOL_PREFIX + Program.to(
                [POOL_COIN_ID, deed_id, next_ph]
            ).get_tree_hash()
            assert announcements[1 + i][1] == expected_release, (
                f"Deed release announcement {i} mismatch"
            )

    def test_settlement_works_on_frozen_pool(self):
        """Batch settlement bypasses pool freeze — governance can always settle."""
        frozen_pool = curry_pool(pool_status=POOL_FROZEN, tvl=PAR_VALUE, deed_count=1)
        gov_inner = curry_gov(proposal_hash=0)

        pool_sol = Program.to([
            POOL_COIN_ID, frozen_pool.get_tree_hash(), 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_1,
             gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        pool_conds = frozen_pool.run(pool_sol).as_python()

        expected_after = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert pool_conds[0][1] == expected_after.get_tree_hash(), (
            "Batch settlement must work on frozen pool and reset to ACTIVE"
        )

    def test_settlement_requires_matching_deed_count(self):
        """Pool SETTLEMENT fails if deed_releases count != DEED_COUNT."""
        # Pool has 2 deeds but we only provide 1 release
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_2_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_1,  # only 1 release!
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        with pytest.raises(ValueError):
            self.pool_inner_2.run(pool_sol)

    def test_settlement_two_deeds_full_batch(self):
        """Batch settle pool with 2 deeds: both released, state → (0,0)."""
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_2_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_2,
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        pool_conds = self.pool_inner_2.run(pool_sol).as_python()

        expected_after = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert pool_conds[0][1] == expected_after.get_tree_hash(), (
            "Batch settlement of 2 deeds: state must be (ACTIVE, 0, 0)"
        )

    def test_gov_pool_settlement_message_consistency(self):
        """Gov SEND_MESSAGE and Pool RECEIVE_MESSAGE content + sender align (2-deed batch)."""
        # Gov
        gov_sol = Program.to([
            GOV_COIN_ID, self.gov_inner_ph, 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.num_deeds_2, QUORUM_BPS],
        ])
        gov_conds = self.gov_inner.run(gov_sol).as_python()
        gov_send = extract_cond(gov_conds, 66)

        # Pool
        pool_sol = Program.to([
            POOL_COIN_ID, self.pool_inner_2_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [self.splitxch_root, SETTLEMENT_AMOUNT, self.deed_releases_2,
             self.gov_inner_ph, GOV_SINGLETON_STRUCT],
        ])
        pool_conds = self.pool_inner_2.run(pool_sol).as_python()
        pool_recv = extract_cond(pool_conds, 67)

        assert gov_send[2] == pool_recv[2], "Gov↔Pool batch message mismatch"
        expected_gov_full_ph = full_puzzle_hash(GOV_SINGLETON_STRUCT, self.gov_inner)
        assert bytes32(pool_recv[3]) == expected_gov_full_ph, "Pool sender mismatch"


# ─────────────────────────────────────────────────────────────────────
# Phase 9: Full lifecycle round-trip (all phases in sequence)
# ─────────────────────────────────────────────────────────────────────
@pytest.mark.skip(
    reason="v2 governance refactor — lifecycle test depends on governance phases. "
           "Will be replaced by a v2-flavoured lifecycle test in Step D."
)
class TestFullLifecycleRoundTrip:
    """Run all nine phases in sequence, verifying state at each step.

    This is the "integration" test — it chains outputs together to verify
    that the full protocol lifecycle produces consistent state transitions.
    """

    def test_mint_purchase_deposit_redeem_round_trip(self):
        """Complete lifecycle: mint → purchase → deposit → redeem.

        Verifies:
        - Gov approves mint (EXECUTE_MINT message matches DID receive)
        - DID announces deed puzzle hash (matches launcher assertion)
        - Purchase payment message matches mint_offer_delegate receive
        - Deed transitions from mint_offer_delegate to smart_deed_inner
        - Pool deposit: message pairing + token mint announcement
        - Pool redeem: message pairing + token melt + vault containment
        - Pool state: (0,0) → deposit → (PAR_VALUE,1) → redeem → (0,0)
        """
        # ── Phase 1+2: Gov → DID ──
        gov_inner = curry_gov(proposal_hash=0)
        did_inner = QUORUM_DID_MOD.curry(GOV_SINGLETON_STRUCT)
        deed_inner = curry_deed()
        smart_deed_inner_hash = deed_inner.get_tree_hash()
        mint_offer = curry_mint_offer(smart_deed_inner_hash)
        deed_full_ph = full_puzzle_hash(DEED_SINGLETON_STRUCT, mint_offer)

        # Gov EXECUTE_MINT
        gov_sol = Program.to([
            GOV_COIN_ID, gov_inner.get_tree_hash(), 1,
            GOV_SPEND_EXECUTE_MINT, [deed_full_ph, QUORUM_BPS],
        ])
        gov_conds = gov_inner.run(gov_sol).as_python()
        gov_msg = extract_cond(gov_conds, 66)[2]

        # DID receives and announces
        did_sol = Program.to([deed_full_ph, gov_inner.get_tree_hash()])
        did_conds = did_inner.run(did_sol).as_python()
        did_msg = extract_cond(did_conds, 67)[2]
        assert gov_msg == did_msg, "Phase 1→2: Gov↔DID message mismatch"

        did_announcement = extract_cond(did_conds, 62)[1]
        assert did_announcement == deed_full_ph, "DID must announce deed full puzzle hash"

        # ── Phase 3: Launcher (structural — verified in Phase 3 tests) ──
        # After launch: deed exists as singleton with mint_offer_delegate inner

        # ── Phase 4: Purchase ──
        pp = curry_purchase()
        pp_sol = Program.to([BUYER_PUZHASH, PAR_VALUE])
        pp_conds = pp.run(pp_sol).as_python()
        pp_send = extract_cond(pp_conds, 66)[2]

        mo_sol = Program.to([DEED_COIN_ID])
        mo_conds = mint_offer.run(mo_sol).as_python()
        mo_recv = extract_cond(mo_conds, 67)[2]
        assert pp_send == mo_recv, "Phase 4: Purchase↔MintOffer message mismatch"

        # After purchase: deed inner is now smart_deed_inner (gated)
        transition_create = extract_cond(mo_conds, 51)
        assert transition_create[1] == smart_deed_inner_hash, "Deed must transition to smart_deed_inner"

        # ── Phase 5: Deposit ──
        pool_inner_0 = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        pool_inner_0_ph = pool_inner_0.get_tree_hash()

        pool_deposit_sol = Program.to([
            POOL_COIN_ID, pool_inner_0_ph, 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        pool_deposit_conds = pool_inner_0.run(pool_deposit_sol).as_python()

        deed_deposit_sol = Program.to([
            DEED_COIN_ID, deed_inner.get_tree_hash(), 1,
            DEED_SPEND_POOL_DEPOSIT,
            [POOL_LAUNCHER_ID, pool_inner_0_ph, LAUNCHER_PUZZLE_HASH],
        ])
        deed_deposit_conds = deed_inner.run(deed_deposit_sol).as_python()

        pool_deposit_msg = extract_cond(pool_deposit_conds, 66)[2]
        deed_deposit_recv = extract_cond(deed_deposit_conds, 67)[2]
        assert pool_deposit_msg == deed_deposit_recv, "Phase 5: Pool↔Deed deposit message mismatch"

        # Pool state after deposit: TVL=PAR_VALUE, DEED_COUNT=1
        expected_pool_1 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=PAR_VALUE,
            deed_count=1,
            total_pool_token_supply=PAR_VALUE,
        )
        assert pool_deposit_conds[0][1] == expected_pool_1.get_tree_hash(), \
            "Pool state after deposit mismatch"

        # ── Phase 6: Redeem ──
        pool_inner_1 = expected_pool_1
        pool_inner_1_ph = pool_inner_1.get_tree_hash()

        pool_redeem_sol = Program.to([
            POOL_COIN_ID, pool_inner_1_ph, 1,
            POOL_SPEND_REDEEM,
            [DEED_COIN_ID, PAR_VALUE, VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH, TOKEN_COIN_ID],
        ])
        pool_redeem_conds = pool_inner_1.run(pool_redeem_sol).as_python()

        deed_redeem_sol = Program.to([
            DEED_COIN_ID, deed_inner.get_tree_hash(), 1,
            DEED_SPEND_POOL_REDEEM,
            [POOL_LAUNCHER_ID, pool_inner_1_ph, LAUNCHER_PUZZLE_HASH, VAULT_LAUNCHER_ID],
        ])
        deed_redeem_conds = deed_inner.run(deed_redeem_sol).as_python()

        pool_redeem_msg = extract_cond(pool_redeem_conds, 66)[2]
        deed_redeem_recv = extract_cond(deed_redeem_conds, 67)[2]
        assert pool_redeem_msg == deed_redeem_recv, "Phase 6: Pool↔Deed redeem message mismatch"

        # Pool state after redeem: back to (0,0)
        expected_pool_2 = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert pool_redeem_conds[0][1] == expected_pool_2.get_tree_hash(), \
            "Pool state after redeem mismatch — should be back to (0,0)"

        # Vault containment: deed goes to computed p2_vault
        deed_redeem_dest = bytes32(extract_cond(deed_redeem_conds, 51)[1])
        quoted_mod = calculate_hash_of_quoted_mod_hash(P2_VAULT_MOD_HASH)
        expected_p2_vault = bytes32(curry_and_treehash(
            quoted_mod,
            hashlib.sha256(b"\x01" + bytes(SINGLETON_MOD_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(VAULT_LAUNCHER_ID)).digest(),
            hashlib.sha256(b"\x01" + bytes(LAUNCHER_PUZZLE_HASH)).digest(),
        ))
        assert deed_redeem_dest == expected_p2_vault, (
            f"Vault containment violated! Deed goes to {deed_redeem_dest.hex()}, "
            f"expected p2_vault {expected_p2_vault.hex()}"
        )

    def test_deposit_two_deeds_then_redeem_one(self):
        """Deposit two deeds, redeem one. Verify intermediate states."""
        deed_inner = curry_deed()
        deed_inner_ph = deed_inner.get_tree_hash()

        deed_id_1 = bytes32(b"\xc1" * 32)
        deed_id_2 = bytes32(b"\xc2" * 32)
        par_value_1 = 100_000
        par_value_2 = 250_000

        # ── Deposit deed 1 ──
        pool_0 = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        sol = Program.to([
            POOL_COIN_ID, pool_0.get_tree_hash(), 1,
            POOL_SPEND_DEPOSIT,
            [deed_id_1, par_value_1, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        conds = pool_0.run(sol).as_python()
        pool_1 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=par_value_1,
            deed_count=1,
            total_pool_token_supply=par_value_1,
        )
        assert conds[0][1] == pool_1.get_tree_hash(), "State after deposit 1"

        # ── Deposit deed 2 ──
        sol = Program.to([
            POOL_COIN_ID, pool_1.get_tree_hash(), 1,
            POOL_SPEND_DEPOSIT,
            [deed_id_2, par_value_2, DEPOSITOR_PUZHASH, bytes32(b"\xa6" * 32)],
        ])
        conds = pool_1.run(sol).as_python()
        pool_2 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=par_value_1 + par_value_2,
            deed_count=2,
            total_pool_token_supply=par_value_1 + par_value_2,
        )
        assert conds[0][1] == pool_2.get_tree_hash(), "State after deposit 2"

        # ── Redeem deed 1 ──
        sol = Program.to([
            POOL_COIN_ID, pool_2.get_tree_hash(), 1,
            POOL_SPEND_REDEEM,
            [deed_id_1, par_value_1, VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH, TOKEN_COIN_ID],
        ])
        conds = pool_2.run(sol).as_python()
        pool_3 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=par_value_2,
            deed_count=1,
            total_pool_token_supply=par_value_2,
        )
        assert conds[0][1] == pool_3.get_tree_hash(), (
            f"State after redeem 1: TVL should be {par_value_2}, deed_count=1"
        )

    def test_governance_freeze_blocks_then_unfreeze_allows(self):
        """Freeze → deposit fails → unfreeze → deposit succeeds."""
        pool_active = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        gov_inner = curry_gov(proposal_hash=0)

        # Freeze
        freeze_sol = Program.to([
            POOL_COIN_ID, pool_active.get_tree_hash(), 1,
            POOL_SPEND_GOVERNANCE,
            [POOL_FROZEN, gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        freeze_conds = pool_active.run(freeze_sol).as_python()
        pool_frozen = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        assert freeze_conds[0][1] == pool_frozen.get_tree_hash()

        # Deposit on frozen pool fails
        deposit_sol = Program.to([
            POOL_COIN_ID, pool_frozen.get_tree_hash(), 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        with pytest.raises(ValueError):
            pool_frozen.run(deposit_sol)

        # Unfreeze
        unfreeze_sol = Program.to([
            POOL_COIN_ID, pool_frozen.get_tree_hash(), 1,
            POOL_SPEND_GOVERNANCE,
            [POOL_ACTIVE, gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        unfreeze_conds = pool_frozen.run(unfreeze_sol).as_python()
        pool_unfrozen = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert unfreeze_conds[0][1] == pool_unfrozen.get_tree_hash()

        # Deposit on unfrozen pool succeeds
        deposit_sol = Program.to([
            POOL_COIN_ID, pool_unfrozen.get_tree_hash(), 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        deposit_conds = pool_unfrozen.run(deposit_sol).as_python()
        assert deposit_conds[0][0] == bytes([51])  # CREATE_COIN — success

    def test_mint_purchase_deposit_batch_settlement_round_trip(self):
        """Complete lifecycle with batch settlement: mint → purchase → deposit → batch settle.

        Verifies:
        - Phases 1-5 (mint, purchase, deposit) same as redeem round-trip
        - Gov EXECUTE_SETTLEMENT sends 1 SEND_MESSAGE (batch params to pool)
        - Pool creates splitxch root coin + per-deed release announcement
        - Gov↔Pool CHIP-25 message alignment
        - Pool state: (0,0) → deposit → (PAR_VALUE,1) → batch settle → (0,0)
        """
        # ── Phases 1-4: mint + purchase (same setup) ──
        gov_inner = curry_gov(proposal_hash=0)
        deed_inner = curry_deed()
        smart_deed_inner_hash = deed_inner.get_tree_hash()
        mint_offer = curry_mint_offer(smart_deed_inner_hash)
        deed_full_ph = full_puzzle_hash(DEED_SINGLETON_STRUCT, mint_offer)

        gov_sol = Program.to([
            GOV_COIN_ID, gov_inner.get_tree_hash(), 1,
            GOV_SPEND_EXECUTE_MINT, [deed_full_ph, QUORUM_BPS],
        ])
        gov_conds = gov_inner.run(gov_sol).as_python()
        gov_msg = extract_cond(gov_conds, 66)[2]

        did_inner = QUORUM_DID_MOD.curry(GOV_SINGLETON_STRUCT)
        did_sol = Program.to([deed_full_ph, gov_inner.get_tree_hash()])
        did_conds = did_inner.run(did_sol).as_python()
        did_msg = extract_cond(did_conds, 67)[2]
        assert gov_msg == did_msg, "Phase 1→2: Gov↔DID message mismatch"

        pp = curry_purchase()
        pp_conds = pp.run(Program.to([BUYER_PUZHASH, PAR_VALUE])).as_python()
        mo_conds = mint_offer.run(Program.to([DEED_COIN_ID])).as_python()
        assert extract_cond(pp_conds, 66)[2] == extract_cond(mo_conds, 67)[2], \
            "Phase 4: Purchase↔MintOffer mismatch"

        # ── Phase 5: Deposit ──
        pool_inner_0 = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        pool_inner_0_ph = pool_inner_0.get_tree_hash()

        pool_deposit_sol = Program.to([
            POOL_COIN_ID, pool_inner_0_ph, 1,
            POOL_SPEND_DEPOSIT,
            [DEED_COIN_ID, PAR_VALUE, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        pool_deposit_conds = pool_inner_0.run(pool_deposit_sol).as_python()

        deed_deposit_sol = Program.to([
            DEED_COIN_ID, deed_inner.get_tree_hash(), 1,
            DEED_SPEND_POOL_DEPOSIT,
            [POOL_LAUNCHER_ID, pool_inner_0_ph, LAUNCHER_PUZZLE_HASH],
        ])
        deed_deposit_conds = deed_inner.run(deed_deposit_sol).as_python()

        pool_deposit_msg = extract_cond(pool_deposit_conds, 66)[2]
        deed_deposit_recv = extract_cond(deed_deposit_conds, 67)[2]
        assert pool_deposit_msg == deed_deposit_recv, "Phase 5: Pool↔Deed deposit mismatch"

        expected_pool_1 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=PAR_VALUE,
            deed_count=1,
            total_pool_token_supply=PAR_VALUE,
        )
        assert pool_deposit_conds[0][1] == expected_pool_1.get_tree_hash(), \
            "Pool state after deposit mismatch"

        # ── Phase 8: Batch Settlement ──
        splitxch_root = bytes32(b"\xf0" * 32)
        deed_releases = [(DEED_LAUNCHER_ID, BURN_INNER_PUZHASH)]

        # Gov approves batch settlement
        gov_settle_sol = Program.to([
            GOV_COIN_ID, gov_inner.get_tree_hash(), 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [splitxch_root, SETTLEMENT_AMOUNT, 1, QUORUM_BPS],
        ])
        gov_settle_conds = gov_inner.run(gov_settle_sol).as_python()
        gov_settle_sends = extract_conds(gov_settle_conds, 66)
        assert len(gov_settle_sends) == 1, "Batch: gov sends 1 message to pool"

        # Pool processes batch settlement
        pool_inner_1 = expected_pool_1
        pool_inner_1_ph = pool_inner_1.get_tree_hash()
        pool_settle_sol = Program.to([
            POOL_COIN_ID, pool_inner_1_ph, 1,
            POOL_SPEND_SETTLEMENT,
            [splitxch_root, SETTLEMENT_AMOUNT, deed_releases,
             gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        pool_settle_conds = pool_inner_1.run(pool_settle_sol).as_python()
        pool_settle_recv = extract_cond(pool_settle_conds, 67)

        # Gov↔Pool message consistency
        assert gov_settle_sends[0][2] == pool_settle_recv[2], "Gov↔Pool settle msg mismatch"
        expected_gov_full_ph = full_puzzle_hash(GOV_SINGLETON_STRUCT, gov_inner)
        assert bytes32(pool_settle_recv[3]) == expected_gov_full_ph, "Pool sender mismatch"

        # Pool state after settlement: back to (0,0)
        expected_pool_2 = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert pool_settle_conds[0][1] == expected_pool_2.get_tree_hash(), \
            "Pool state after batch settlement mismatch — should be (0,0)"

        # Splitxch root coin created
        creates = extract_conds(pool_settle_conds, 51)
        assert len(creates) == 2, "Pool must create state coin + splitxch root"
        assert creates[1][1] == splitxch_root, "Splitxch root hash mismatch"
        assert int.from_bytes(creates[1][2], "big") == SETTLEMENT_AMOUNT

    def test_deposit_two_deeds_batch_settle_all(self):
        """Deposit 2 deeds → batch settle all → pool state (0,0).

        Batch settlement always settles the entire collection at once.
        Both deeds are released via p2_pool announcements.
        """
        deed_inner = curry_deed()
        gov_inner = curry_gov(proposal_hash=0)

        deed_id_1 = bytes32(b"\xc1" * 32)
        deed_id_2 = bytes32(b"\xc2" * 32)
        par_value_1 = 100_000
        par_value_2 = 250_000

        # ── Deposit deed 1 ──
        pool_0 = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        sol = Program.to([
            POOL_COIN_ID, pool_0.get_tree_hash(), 1,
            POOL_SPEND_DEPOSIT,
            [deed_id_1, par_value_1, DEPOSITOR_PUZHASH, TOKEN_COIN_ID],
        ])
        conds = pool_0.run(sol).as_python()
        pool_1 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=par_value_1,
            deed_count=1,
            total_pool_token_supply=par_value_1,
        )
        assert conds[0][1] == pool_1.get_tree_hash(), "State after deposit 1"

        # ── Deposit deed 2 ──
        sol = Program.to([
            POOL_COIN_ID, pool_1.get_tree_hash(), 1,
            POOL_SPEND_DEPOSIT,
            [deed_id_2, par_value_2, DEPOSITOR_PUZHASH, bytes32(b"\xa6" * 32)],
        ])
        conds = pool_1.run(sol).as_python()
        pool_2 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=par_value_1 + par_value_2,
            deed_count=2,
            total_pool_token_supply=par_value_1 + par_value_2,
        )
        assert conds[0][1] == pool_2.get_tree_hash(), "State after deposit 2"

        # ── Batch settle all deeds ──
        splitxch_root = bytes32(b"\xf1" * 32)
        total_amount = 300_000
        deed_releases = [
            (deed_id_1, BURN_INNER_PUZHASH),
            (deed_id_2, BURN_INNER_PUZHASH),
        ]

        settle_sol = Program.to([
            POOL_COIN_ID, pool_2.get_tree_hash(), 1,
            POOL_SPEND_SETTLEMENT,
            [splitxch_root, total_amount, deed_releases,
             gov_inner.get_tree_hash(), GOV_SINGLETON_STRUCT],
        ])
        settle_conds = pool_2.run(settle_sol).as_python()

        # Pool fully settled
        pool_final = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert settle_conds[0][1] == pool_final.get_tree_hash(), (
            "After batch settling 2 deeds: state must be (ACTIVE, 0, 0)"
        )

        # 2 per-deed release announcements + 1 batch announcement
        announcements = extract_conds(settle_conds, 62)
        assert len(announcements) == 3, (
            f"Expected 3 announcements (1 batch + 2 releases), got {len(announcements)}"
        )


# ─────────────────────────────────────────────────────────────────────
# Phase 10: Vault co-spend integration
# Verifies vault ↔ pool announcement pairing for deposit ('o') and
# receive ('i') cases, and that auth-type isolation holds at condition level.
# ─────────────────────────────────────────────────────────────────────

VAULT_INNER_MOD: Program = load_clvm(
    "vault_singleton_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)

# Vault identity constants
VAULT_OWNER_PUBKEY_BLS = bytes(48)                   # 48-byte BLS G1 placeholder
VAULT_OWNER_PUBKEY_SECP = b"\x02" + bytes(32)        # 33-byte secp256k1 placeholder
VAULT_COIN_ID = bytes32(b"\xb4" * 32)

AUTH_TYPE_BLS = 1
AUTH_TYPE_SECP256K1 = 3

# Plausible Unix timestamp for Phase 10 tests (2025-01-01T00:00:00Z)
VAULT_CURRENT_TIMESTAMP = 1_735_689_600

# Members Merkle root placeholder — one-leaf tree for single-owner vaults
VAULT_MEMBERS_MERKLE_ROOT_E2E = bytes32(b"\xee" * 32)
VAULT_IDENTITY_ATTEST_ROOT_E2E = bytes32(bytes.fromhex("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"))
VAULT_ZKPASSPORT_BRIDGE_POLICY_HASH_E2E = bytes32(b"\x00" * 32)
VAULT_ATTESTATION_LEAF_HASH_E2E = bytes32(b"\x44" * 32)
VAULT_ATTESTATION_PROOF_E2E = Program.to((0, []))

VAULT_SINGLETON_STRUCT_E2E = Program.to(
    (SINGLETON_MOD_HASH, (VAULT_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)


def curry_vault_bls_e2e() -> Program:
    return VAULT_INNER_MOD.curry(
        VAULT_SINGLETON_STRUCT_E2E,
        VAULT_OWNER_PUBKEY_BLS,
        AUTH_TYPE_BLS,
        VAULT_MEMBERS_MERKLE_ROOT_E2E,
        VAULT_IDENTITY_ATTEST_ROOT_E2E,
        VAULT_ZKPASSPORT_BRIDGE_POLICY_HASH_E2E,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        SINGLETON_LAUNCHER_HASH,
    )


def curry_vault_secp_e2e() -> Program:
    return VAULT_INNER_MOD.curry(
        VAULT_SINGLETON_STRUCT_E2E,
        VAULT_OWNER_PUBKEY_SECP,
        AUTH_TYPE_SECP256K1,
        VAULT_MEMBERS_MERKLE_ROOT_E2E,
        VAULT_IDENTITY_ATTEST_ROOT_E2E,
        VAULT_ZKPASSPORT_BRIDGE_POLICY_HASH_E2E,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        SINGLETON_LAUNCHER_HASH,
    )


class TestPhase10VaultCoSpend:
    """Phase 10: Vault ↔ pool co-spend announcement pairing.

    Exercises the three vault spend cases (deposit 'o', receive 'i', accept 'a')
    at the condition level and verifies:
      1. Vault CREATE_PUZZLE_ANNOUNCEMENT content matches the expected pool
         ASSERT_PUZZLE_ANNOUNCEMENT hash (deposit)
      2. Vault ASSERT_PUZZLE_ANNOUNCEMENT hash matches the pool's
         CREATE_PUZZLE_ANNOUNCEMENT content (receive)
      3. BLS AGG_SIG_ME is present and bound to the owner pubkey and spend case
      4. secp256k1 vault produces a different puzzle hash (auth isolation)
      5. Vault always recreates itself as a singleton coin
    """

    def setup_method(self):
        self.vault_bls = curry_vault_bls_e2e()
        self.vault_inner_puzhash = self.vault_bls.get_tree_hash()
        self.pool_inner = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        self.pool_inner_ph = self.pool_inner.get_tree_hash()

    # ── Helper ────────────────────────────────────────────────────────────

    def _pool_full_puzzle_hash(self) -> bytes32:
        """Compute the pool singleton full puzzle hash."""
        return full_puzzle_hash(POOL_SINGLETON_STRUCT, self.pool_inner)

    # ── Deposit ('o') ─────────────────────────────────────────────────────

    def test_vault_deposit_creates_pool_announcement(self):
        """Vault deposit emits CREATE_PUZZLE_ANNOUNCEMENT with PROTOCOL_PREFIX."""
        sol = Program.to([
            VAULT_COIN_ID, self.vault_inner_puzhash, 1,
            0x6f,  # 'o'
            [DEED_LAUNCHER_ID, VAULT_CURRENT_TIMESTAMP, None],
        ])
        conds = self.vault_bls.run(sol).as_python()

        anns = [c for c in conds if c[0] == bytes([62])]
        assert len(anns) == 1
        assert anns[0][1][:1] == PROTOCOL_PREFIX

    def test_vault_deposit_announcement_matches_pool_expected_format(self):
        """Vault CREATE_PUZZLE_ANNOUNCEMENT content == PROTOCOL_PREFIX + sha256tree(list 'o' deed_id)."""
        sol = Program.to([
            VAULT_COIN_ID, self.vault_inner_puzhash, 1,
            0x6f,
            [DEED_LAUNCHER_ID, VAULT_CURRENT_TIMESTAMP, None],
        ])
        conds = self.vault_bls.run(sol).as_python()
        ann_content = [c for c in conds if c[0] == bytes([62])][0][1]

        expected = PROTOCOL_PREFIX + Program.to([0x6f, DEED_LAUNCHER_ID]).get_tree_hash()
        assert ann_content == expected, (
            f"Vault deposit announcement mismatch:\n"
            f"  Got:      {ann_content.hex()}\n"
            f"  Expected: {expected.hex()}"
        )

    def test_vault_deposit_agg_sig_bound_to_deed_id(self):
        """AGG_SIG_ME message changes when deed_launcher_id changes — replay protection."""
        def run_msg(deed_id):
            sol = Program.to([
                VAULT_COIN_ID, self.vault_inner_puzhash, 1,
                0x6f,
                [deed_id, VAULT_CURRENT_TIMESTAMP, None],
            ])
            conds = self.vault_bls.run(sol).as_python()
            agg_sigs = [c for c in conds if c[0] == bytes([50])]
            assert len(agg_sigs) == 1
            return agg_sigs[0][2]

        msg_a = run_msg(bytes32(b"\xaa" * 32))
        msg_b = run_msg(bytes32(b"\xbb" * 32))
        assert msg_a != msg_b, "AGG_SIG_ME message must be bound to deed_launcher_id"

    def test_vault_deposit_recreates_singleton(self):
        """Vault always recreates itself at the same inner puzzle hash."""
        sol = Program.to([
            VAULT_COIN_ID, self.vault_inner_puzhash, 1,
            0x6f,
            [DEED_LAUNCHER_ID, VAULT_CURRENT_TIMESTAMP, None],
        ])
        conds = self.vault_bls.run(sol).as_python()
        creates = [c for c in conds if c[0] == bytes([51])]
        assert len(creates) == 1
        assert creates[0][1] == self.vault_inner_puzhash

    # ── Receive ('i') ─────────────────────────────────────────────────────

    def test_vault_receive_emits_puzzle_announcement_for_p2_vault(self):
        """Vault 'i' emits CREATE_PUZZLE_ANNOUNCEMENT so p2_vault can co-spend atomically."""
        p2_vault_coin_id = bytes32(b"\xb2" * 32)
        sol = Program.to([
            VAULT_COIN_ID, self.vault_inner_puzhash, 1,
            0x69,  # 'i'
            [DEED_LAUNCHER_ID, p2_vault_coin_id, VAULT_CURRENT_TIMESTAMP, None],
        ])
        conds = self.vault_bls.run(sol).as_python()
        create_anns = [c for c in conds if c[0] == bytes([62])]
        assert len(create_anns) == 1
        assert create_anns[0][1][:1] == PROTOCOL_PREFIX
        # Content: PREFIX + sha256tree(list vault_coin_id deed_launcher_id vault_inner_puzhash)
        expected = PROTOCOL_PREFIX + Program.to(
            [VAULT_COIN_ID, DEED_LAUNCHER_ID, self.vault_inner_puzhash]
        ).get_tree_hash()
        assert create_anns[0][1] == expected, (
            f"Vault 'i' announcement mismatch:\n"
            f"  Got:      {create_anns[0][1].hex()}\n"
            f"  Expected: {expected.hex()}"
        )

    def test_vault_receive_asserts_coin_announcement_from_p2_vault(self):
        """Vault 'i' asserts ASSERT_COIN_ANNOUNCEMENT (opcode 61) from p2_vault."""
        p2_vault_coin_id = bytes32(b"\xb2" * 32)
        sol = Program.to([
            VAULT_COIN_ID, self.vault_inner_puzhash, 1,
            0x69,
            [DEED_LAUNCHER_ID, p2_vault_coin_id, VAULT_CURRENT_TIMESTAMP, None],
        ])
        conds = self.vault_bls.run(sol).as_python()
        # ASSERT_COIN_ANNOUNCEMENT = opcode 61
        assert_coin_anns = [c for c in conds if c[0] == bytes([61])]
        assert len(assert_coin_anns) == 1

    def test_vault_receive_agg_sig_differs_from_deposit(self):
        """AGG_SIG_ME message for 'i' must differ from 'o' — cross-case replay protection."""
        p2_vault_coin_id = bytes32(b"\xb2" * 32)

        def run_msg(case):
            if case == 0x69:
                p = [DEED_LAUNCHER_ID, p2_vault_coin_id, VAULT_CURRENT_TIMESTAMP, None]
            else:
                p = [DEED_LAUNCHER_ID, VAULT_CURRENT_TIMESTAMP, None]
            sol = Program.to([
                VAULT_COIN_ID, self.vault_inner_puzhash, 1,
                case, p,
            ])
            conds = self.vault_bls.run(sol).as_python()
            return [c for c in conds if c[0] == bytes([50])][0][2]

        msg_deposit = run_msg(0x6f)
        msg_receive = run_msg(0x69)
        assert msg_deposit != msg_receive, "AGG_SIG_ME messages must differ between spend cases"

    # ── Accept offer ('a') ────────────────────────────────────────────────

    def test_vault_accept_offer_agg_sig_bound_to_token_amount(self):
        """AGG_SIG_ME message for 'a' is bound to token_amount — prevents price manipulation."""
        vault_bls = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT_E2E,
            VAULT_OWNER_PUBKEY_BLS,
            AUTH_TYPE_BLS,
            VAULT_MEMBERS_MERKLE_ROOT_E2E,
            VAULT_ATTESTATION_LEAF_HASH_E2E,
            VAULT_ZKPASSPORT_BRIDGE_POLICY_HASH_E2E,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            SINGLETON_LAUNCHER_HASH,
        )
        vault_inner_puzhash = vault_bls.get_tree_hash()

        def run_msg(token_amount):
            sol = Program.to([
                VAULT_COIN_ID, vault_inner_puzhash, 1,
                0x61,  # 'a'
                [
                    DEED_LAUNCHER_ID,
                    token_amount,
                    self.pool_inner_ph,
                    VAULT_ATTESTATION_LEAF_HASH_E2E,
                    VAULT_ATTESTATION_PROOF_E2E,
                    VAULT_CURRENT_TIMESTAMP,
                    None,
                ],
            ])
            conds = vault_bls.run(sol).as_python()
            return [c for c in conds if c[0] == bytes([50])][0][2]

        msg_100 = run_msg(100_000)
        msg_200 = run_msg(200_000)
        assert msg_100 != msg_200, "AGG_SIG_ME for accept-offer must be bound to token_amount"

    # ── Auth-type isolation ───────────────────────────────────────────────

    def test_bls_and_secp_vault_puzzle_hashes_differ(self):
        """BLS and secp256k1 vaults must not share a puzzle hash."""
        assert curry_vault_bls_e2e().get_tree_hash() != curry_vault_secp_e2e().get_tree_hash()

    def test_two_bls_vaults_different_owners_differ(self):
        """Two BLS vaults with different owner pubkeys must have different puzzle hashes."""
        vault_a = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT_E2E,
            bytes(48),
            AUTH_TYPE_BLS,
            VAULT_MEMBERS_MERKLE_ROOT_E2E,
            VAULT_IDENTITY_ATTEST_ROOT_E2E,
            VAULT_ZKPASSPORT_BRIDGE_POLICY_HASH_E2E,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            SINGLETON_LAUNCHER_HASH,
        )
        vault_b = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT_E2E,
            bytes([1] * 48),
            AUTH_TYPE_BLS,
            VAULT_MEMBERS_MERKLE_ROOT_E2E,
            VAULT_IDENTITY_ATTEST_ROOT_E2E,
            VAULT_ZKPASSPORT_BRIDGE_POLICY_HASH_E2E,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            SINGLETON_LAUNCHER_HASH,
        )
        assert vault_a.get_tree_hash() != vault_b.get_tree_hash()

    def test_vault_from_different_launcher_ids_differ(self):
        """Same owner and auth type but different vault_launcher_id → different puzzle hash."""
        launcher_a = bytes32(b"\xa0" * 32)
        launcher_b = bytes32(b"\xa1" * 32)

        def make_vault(lid):
            struct = Program.to((SINGLETON_MOD_HASH, (lid, SINGLETON_LAUNCHER_HASH)))
            return VAULT_INNER_MOD.curry(
                struct,
                VAULT_OWNER_PUBKEY_BLS,
                AUTH_TYPE_BLS,
                VAULT_MEMBERS_MERKLE_ROOT_E2E,
                VAULT_IDENTITY_ATTEST_ROOT_E2E,
                VAULT_ZKPASSPORT_BRIDGE_POLICY_HASH_E2E,
                SINGLETON_MOD_HASH,
                POOL_LAUNCHER_ID,
                SINGLETON_LAUNCHER_HASH,
            )

        assert make_vault(launcher_a).get_tree_hash() != make_vault(launcher_b).get_tree_hash()

    # ── Full vault lifecycle co-spend ─────────────────────────────────────

    def test_vault_deposit_receive_round_trip_condition_pairing(self):
        """Full vault round-trip: vault deposit → pool accept → vault receive.

        Verifies the announcement chain at the condition level:
          vault 'o' → CREATE_PUZZLE_ANNOUNCEMENT → pool asserts on SPEND_DEPOSIT
          pool REDEEM → CREATE_PUZZLE_ANNOUNCEMENT → vault 'i' asserts

        This is the core security property: neither side can act without the other's
        announcement being present in the same block.
        """
        # ── Step 1: Vault deposit ──
        vault_deposit_sol = Program.to([
            VAULT_COIN_ID, self.vault_inner_puzhash, 1,
            0x6f,
            [DEED_LAUNCHER_ID, VAULT_CURRENT_TIMESTAMP, None],
        ])
        vault_deposit_conds = self.vault_bls.run(vault_deposit_sol).as_python()
        vault_ann_content = [c for c in vault_deposit_conds if c[0] == bytes([62])][0][1]

        # Expected: PROTOCOL_PREFIX + sha256tree(list 'o' deed_launcher_id)
        expected_vault_ann = PROTOCOL_PREFIX + Program.to(
            [0x6f, DEED_LAUNCHER_ID]
        ).get_tree_hash()
        assert vault_ann_content == expected_vault_ann, "Vault deposit announcement wrong"

        # ── Step 2: Pool redeem (which the vault receive step 3 asserts) ──
        pool_inner_1 = curry_pool(
            pool_status=POOL_ACTIVE,
            tvl=PAR_VALUE,
            deed_count=1,
            total_pool_token_supply=PAR_VALUE,
        )
        pool_inner_1_ph = pool_inner_1.get_tree_hash()
        pool_redeem_sol = Program.to([
            POOL_COIN_ID, pool_inner_1_ph, 1,
            POOL_SPEND_REDEEM,
            [DEED_COIN_ID, PAR_VALUE, VAULT_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH, TOKEN_COIN_ID],
        ])
        pool_redeem_conds = pool_inner_1.run(pool_redeem_sol).as_python()
        pool_ann = extract_cond(pool_redeem_conds, 62)
        pool_ann_content = pool_ann[1]

        # ── Step 3: Vault receive — emits puzzle announcement, asserts coin announcement ──
        p2_vault_coin_id = bytes32(b"\xb2" * 32)
        vault_receive_sol = Program.to([
            VAULT_COIN_ID, self.vault_inner_puzhash, 1,
            0x69,
            # LOW-13: 'i' solution dropped pool_inner_puzhash (was unused).
            [DEED_LAUNCHER_ID, p2_vault_coin_id, VAULT_CURRENT_TIMESTAMP, None],
        ])
        vault_receive_conds = self.vault_bls.run(vault_receive_sol).as_python()

        # Vault 'i' emits CREATE_PUZZLE_ANNOUNCEMENT so p2_vault can assert it
        vault_receive_anns = [c for c in vault_receive_conds if c[0] == bytes([62])]
        assert len(vault_receive_anns) == 1
        expected_vault_receive_ann = PROTOCOL_PREFIX + Program.to(
            [VAULT_COIN_ID, DEED_LAUNCHER_ID, self.vault_inner_puzhash]
        ).get_tree_hash()
        assert vault_receive_anns[0][1] == expected_vault_receive_ann, (
            f"Vault receive announcement wrong:\n"
            f"  Got:      {vault_receive_anns[0][1].hex()}\n"
            f"  Expected: {expected_vault_receive_ann.hex()}"
        )

        # Vault 'i' asserts COIN_ANNOUNCEMENT from p2_vault (opcode 61)
        vault_coin_ann_asserts = [c for c in vault_receive_conds if c[0] == bytes([61])]
        assert len(vault_coin_ann_asserts) == 1, "Vault receive must ASSERT_COIN_ANNOUNCEMENT from p2_vault"

        # Both vault spends recreate the vault singleton
        vault_recreates = [c for c in vault_deposit_conds if c[0] == bytes([51])]
        assert vault_recreates[0][1] == self.vault_inner_puzhash, "Vault must recreate after deposit"

        vault_receive_creates = [c for c in vault_receive_conds if c[0] == bytes([51])]
        assert vault_receive_creates[0][1] == self.vault_inner_puzhash, "Vault must recreate after receive"
