"""Recovery-aware pre-genesis administrator authority.

Authority V3 has no mutable administrator list.  It commits to three identity
vault singleton launchers and composes the constitutional quorum from those
stable identities:

    slot 0 AND (slot 1 OR slot 2)

Daily and recovery keys live behind each identity singleton.  The identity
custody policies use the Apache-2.0 Chia Wallet SDK MIPS primitives.  A daily
key is paired with the authority singleton, so it cannot silently rekey its
identity.  Lost-key recovery additionally requires the recovery BLS key and
both other identity singletons.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.custody.custody_architecture import (
    DelegatedPuzzleAndSolution,
    MofN,
    PuzzleWithRestrictions,
    ProvenSpend,
)
from chia.wallet.puzzles.custody.member_puzzles import BLSWithTaprootMember
from chia.wallet.puzzles.custody.restriction_utilities import (
    ValidatorStackRestriction,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_puzzles_py import programs as puzzle_mods
from chia_rs import G1Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.admin_authority_v2_driver import (
    _ProgramMember,
    singleton_full_puzzle_hash,
)
from solslot_puzzles.eip712_helpers import (
    compute_eip712_member_v2_leaf_hash,
    eip712_prefix_and_domain_separator,
    genesis_challenge_for_network,
    make_eip712_member_v2_puzzle,
)

SPEND_OPERATIONAL = 0x01
SPEND_PREPARE_ROUTINE = 0x02
SPEND_PREPARE_LOST = 0x03
SPEND_CANCEL = 0x04
SPEND_COMPLETE = 0x05

PENDING_NONE = 0
PENDING_ROUTINE = 1
PENDING_LOST = 2

ROUTINE_DELAY_SECONDS = 86_400
LOST_KEY_DELAY_SECONDS = 604_800
SINGLETON_MEMBER_MODE = 0b010_010
IDENTITY_LAUNCHER_AMOUNTS = (3, 5, 7)
AUTHORITY_LAUNCHER_AMOUNT = 1
ADMIN_AUTHORITY_FUNDING_AMOUNT = sum(
    (AUTHORITY_LAUNCHER_AMOUNT, *IDENTITY_LAUNCHER_AMOUNTS)
)
ZERO_32 = bytes32.zeros

_ADMIN_AUTHORITY_V3_INNER_MOD: Program | None = None


def admin_authority_v3_inner_mod() -> Program:
    global _ADMIN_AUTHORITY_V3_INNER_MOD
    if _ADMIN_AUTHORITY_V3_INNER_MOD is None:
        _ADMIN_AUTHORITY_V3_INNER_MOD = load_puzzle(
            "admin_authority_v3_inner.clsp"
        )
    return _ADMIN_AUTHORITY_V3_INNER_MOD


def admin_authority_v3_inner_mod_hash() -> bytes32:
    return bytes32(admin_authority_v3_inner_mod().get_tree_hash())


@dataclass(frozen=True)
class _ProgramWrapper:
    """Adapter for an upstream delegated-puzzle wrapper program."""

    program: Program

    def memo(self, nonce: int) -> Program:
        return Program.to(None)

    def puzzle(self, nonce: int) -> Program:
        return self.program

    def puzzle_hash(self, nonce: int) -> bytes32:
        return bytes32(self.program.get_tree_hash())


@dataclass(frozen=True)
class _ProgramRestriction:
    """Adapter for an upstream member or delegated-puzzle validator."""

    program: Program
    member_not_dpuz: bool

    def memo(self, nonce: int) -> Program:
        return Program.to(None)

    def puzzle(self, nonce: int) -> Program:
        return self.program

    def puzzle_hash(self, nonce: int) -> bytes32:
        return bytes32(self.program.get_tree_hash())


@dataclass(frozen=True)
class _SingletonMemberWithMode:
    launcher_id: bytes32
    mode: int = SINGLETON_MEMBER_MODE

    def memo(self, nonce: int) -> Program:
        return Program.to([self.launcher_id, self.mode])

    def puzzle(self, nonce: int) -> Program:
        singleton_struct = Program.to(
            (
                bytes32(SINGLETON_MOD_HASH),
                (self.launcher_id, bytes32(SINGLETON_LAUNCHER_HASH)),
            )
        )
        return Program.from_bytes(puzzle_mods.SINGLETON_MEMBER_WITH_MODE).curry(
            singleton_struct,
            self.mode,
        )

    def puzzle_hash(self, nonce: int) -> bytes32:
        return bytes32(self.puzzle(nonce).get_tree_hash())


@dataclass(frozen=True)
class IdentityVaultGenesis:
    slot: int
    launcher_amount: int
    launcher_id: bytes32
    daily_compressed_pubkey: bytes
    daily_member_reveal: Program
    daily_member_hash: bytes32
    recovery_member_hash: bytes32
    daily_path: MofN
    daily_path_branch: PuzzleWithRestrictions
    recovery_key_branch: PuzzleWithRestrictions
    custody_policy: MofN
    custody_root: PuzzleWithRestrictions
    custody_reveal: Program
    custody_hash: bytes32
    full_puzzle_hash: bytes32
    recovery_bls_pubkey: bytes


@dataclass(frozen=True)
class IdentityVaultTransition:
    """Deterministic two-stage custody transition for one identity vault."""

    kind: int
    slot: int
    delay_seconds: int
    current_identity_coin_id: bytes32
    intermediate_identity_coin_id: bytes32
    intent_hash: bytes32
    original_custody_hash: bytes32
    replacement_daily_compressed_pubkey: bytes
    replacement_daily_member_reveal: Program
    replacement_daily_member_hash: bytes32
    replacement_recovery_bls_pubkey: bytes
    final_custody_policy: MofN
    final_custody_root: PuzzleWithRestrictions
    final_custody_reveal: Program
    final_custody_hash: bytes32
    final_full_puzzle_hash: bytes32
    completion_message: bytes32
    finish_delegated_puzzle: Program
    finish_member_branch: PuzzleWithRestrictions
    finish_member_hash: bytes32
    intermediate_custody_policy: MofN
    intermediate_custody_root: PuzzleWithRestrictions
    intermediate_custody_reveal: Program
    intermediate_custody_hash: bytes32
    intermediate_full_puzzle_hash: bytes32
    prepare_binding_hash: bytes32
    prepare_delegated_puzzle: Program


@dataclass(frozen=True)
class GenesisAdminAuthorityV3:
    authority_launcher_id: bytes32
    identity_vaults: tuple[
        IdentityVaultGenesis,
        IdentityVaultGenesis,
        IdentityVaultGenesis,
    ]
    operational_policy: MofN
    operational_root: PuzzleWithRestrictions
    operational_reveal: Program
    operational_root_hash: bytes32
    lost_recovery_policies: tuple[MofN, MofN, MofN]
    lost_recovery_roots: tuple[
        PuzzleWithRestrictions,
        PuzzleWithRestrictions,
        PuzzleWithRestrictions,
    ]
    lost_recovery_reveals: tuple[Program, Program, Program]
    lost_recovery_root_hashes: tuple[bytes32, bytes32, bytes32]
    source_manifest_hash: bytes32
    inner_puzzle_hash: bytes32
    full_puzzle_hash: bytes32


@dataclass(frozen=True)
class AdminAuthorityV3State:
    authority_version: int = 1
    pending_kind: int = PENDING_NONE
    pending_slot: int = 0
    pending_intent_hash: bytes32 = ZERO_32
    pending_identity_coin_id: bytes32 = ZERO_32
    pending_replacement_custody_hash: bytes32 = ZERO_32
    pending_replacement_member_hash: bytes32 = ZERO_32
    pending_delay_seconds: int = 0

    def validate(self) -> None:
        if self.authority_version < 1:
            raise ValueError("authority_version must be at least one")
        if self.pending_kind == PENDING_NONE:
            if any(
                (
                    self.pending_slot,
                    self.pending_intent_hash != ZERO_32,
                    self.pending_identity_coin_id != ZERO_32,
                    self.pending_replacement_custody_hash != ZERO_32,
                    self.pending_replacement_member_hash != ZERO_32,
                    self.pending_delay_seconds,
                )
            ):
                raise ValueError("empty Authority V3 state must be canonical")
            return
        if self.pending_kind not in (PENDING_ROUTINE, PENDING_LOST):
            raise ValueError("pending_kind is not supported")
        if self.pending_slot not in range(3):
            raise ValueError("pending_slot must be 0, 1, or 2")
        for label, value in (
            ("pending_intent_hash", self.pending_intent_hash),
            ("pending_identity_coin_id", self.pending_identity_coin_id),
            (
                "pending_replacement_custody_hash",
                self.pending_replacement_custody_hash,
            ),
            (
                "pending_replacement_member_hash",
                self.pending_replacement_member_hash,
            ),
        ):
            if value == ZERO_32:
                raise ValueError(f"{label} must be nonzero while recovery is pending")
        expected_delay = (
            ROUTINE_DELAY_SECONDS
            if self.pending_kind == PENDING_ROUTINE
            else LOST_KEY_DELAY_SECONDS
        )
        if self.pending_delay_seconds != expected_delay:
            raise ValueError("pending delay does not match recovery kind")


@dataclass(frozen=True)
class ParsedAdminAuthorityV3:
    """Strictly decoded immutable configuration and mutable V3 state."""

    operational_root_hash: bytes32
    lost_recovery_root_hashes: tuple[bytes32, bytes32, bytes32]
    identity_launcher_ids: tuple[bytes32, bytes32, bytes32]
    routine_delay_seconds: int
    lost_key_delay_seconds: int
    source_manifest_hash: bytes32
    state: AdminAuthorityV3State


def _launcher_id(
    parent_coin_id: bytes32,
    amount: int,
) -> bytes32:
    if amount <= 0 or amount % 2 == 0:
        raise ValueError("singleton launcher amount must be positive and odd")
    return bytes32(
        Coin(
            parent_coin_id,
            bytes32(SINGLETON_LAUNCHER_HASH),
            uint64(amount),
        ).name()
    )


def authority_v3_launcher_ids(
    parent_coin_id: bytes32,
) -> tuple[bytes32, bytes32, bytes32, bytes32]:
    return (
        _launcher_id(parent_coin_id, AUTHORITY_LAUNCHER_AMOUNT),
        *(
            _launcher_id(parent_coin_id, amount)
            for amount in IDENTITY_LAUNCHER_AMOUNTS
        ),
    )


def _branch(
    *,
    nonce: int,
    puzzle: object,
    restrictions: Sequence[object] = (),
) -> PuzzleWithRestrictions:
    return PuzzleWithRestrictions(
        nonce=nonce,
        restrictions=list(restrictions),  # type: ignore[arg-type]
        puzzle=puzzle,  # type: ignore[arg-type]
    )


def _nil_hash() -> bytes32:
    return bytes32(Program.to(None).get_tree_hash())


def _tree_hash_list(values: Sequence[bytes32]) -> bytes32:
    tree_hash = _nil_hash()
    for value in reversed(values):
        tree_hash = bytes32(
            hashlib.sha256(b"\x02" + bytes(value) + bytes(tree_hash)).digest()
        )
    return tree_hash


def _recovery_restrictions(
    *,
    left_side_subtree_hash: bytes32,
    delay_seconds: int,
    replacement_member_nonce: int,
) -> tuple[ValidatorStackRestriction, ...]:
    timelock = Program.from_bytes(puzzle_mods.TIMELOCK).curry(delay_seconds)
    force = Program.from_bytes(
        puzzle_mods.FORCE_1_OF_2_W_RESTRICTED_VARIABLE
    ).curry(
        bytes32(puzzle_mods.DELEGATED_PUZZLE_FEEDER_HASH),
        bytes32(puzzle_mods.ONE_OF_N_HASH),
        bytes32(Program.to(left_side_subtree_hash).get_tree_hash()),
        bytes32(Program.to([2, 5, 7]).get_tree_hash()),
        replacement_member_nonce,
        bytes32(puzzle_mods.RESTRICTIONS_HASH),
        _tree_hash_list((bytes32(timelock.get_tree_hash()),)),
        _nil_hash(),
    )
    wrappers: list[_ProgramWrapper] = [_ProgramWrapper(force)]
    for opcode in (60, 62, 66, 67):
        wrappers.append(
            _ProgramWrapper(
                Program.from_bytes(
                    puzzle_mods.PREVENT_CONDITION_OPCODE
                ).curry(opcode),
            )
        )
    wrappers.append(
        _ProgramWrapper(
            Program.from_bytes(puzzle_mods.PREVENT_MULTIPLE_CREATE_COINS),
        )
    )
    return (ValidatorStackRestriction(required_wrappers=wrappers),)


def _identity_policy(
    *,
    slot: int,
    daily_member: Program,
    recovery_bls_pubkey: bytes,
    authority_launcher_id: bytes32,
) -> tuple[
    MofN,
    bytes32,
    bytes32,
    MofN,
    PuzzleWithRestrictions,
    PuzzleWithRestrictions,
]:
    policy_nonce = slot
    daily_member_branch = _branch(
        nonce=policy_nonce,
        puzzle=_ProgramMember(daily_member),
    )
    authority_member = _branch(
        nonce=policy_nonce,
        puzzle=_SingletonMemberWithMode(authority_launcher_id),
    )
    daily_path = MofN(
        m=2,
        members=[daily_member_branch, authority_member],
    )
    daily_path_branch = _branch(
        nonce=policy_nonce,
        puzzle=daily_path,
    )
    daily_path_hash = daily_path_branch.puzzle_hash(_top_level=False)

    recovery_key = G1Element.from_bytes(recovery_bls_pubkey)
    recovery_member = BLSWithTaprootMember(synthetic_key=recovery_key)
    recovery_key_branch = _branch(
        nonce=policy_nonce,
        puzzle=recovery_member,
        restrictions=_recovery_restrictions(
            left_side_subtree_hash=daily_path_hash,
            delay_seconds=LOST_KEY_DELAY_SECONDS,
            replacement_member_nonce=policy_nonce,
        ),
    )
    policy = MofN(
        m=1,
        members=[daily_path_branch, recovery_key_branch],
    )
    return (
        policy,
        bytes32(daily_member.get_tree_hash()),
        recovery_key_branch.puzzle_hash(_top_level=False),
        daily_path,
        daily_path_branch,
        recovery_key_branch,
    )


def _root_policies(
    identity_launcher_ids: Sequence[bytes32],
) -> tuple[MofN, tuple[MofN, MofN, MofN]]:
    if len(identity_launcher_ids) != 3:
        raise ValueError("Authority V3 requires exactly three identity launchers")
    members = [
        _branch(
            nonce=100 + slot,
            puzzle=_SingletonMemberWithMode(launcher_id),
        )
        for slot, launcher_id in enumerate(identity_launcher_ids)
    ]
    coadmin = MofN(m=1, members=members[1:])
    operational = MofN(
        m=2,
        members=[
            members[0],
            _branch(nonce=104, puzzle=coadmin),
        ],
    )
    lost_recovery = tuple(
        MofN(
            m=2,
            members=[
                _branch(
                    nonce=120 + member_slot,
                    puzzle=_SingletonMemberWithMode(
                        identity_launcher_ids[member_slot]
                    ),
                )
                for member_slot in range(3)
                if member_slot != recovered_slot
            ],
        )
        for recovered_slot in range(3)
    )
    return operational, lost_recovery  # type: ignore[return-value]


def make_inner_puzzle(
    *,
    operational_root_hash: bytes32,
    lost_recovery_root_hashes: Sequence[bytes32],
    identity_launcher_ids: Sequence[bytes32],
    source_manifest_hash: bytes32,
    state: AdminAuthorityV3State | None = None,
    routine_delay_seconds: int = ROUTINE_DELAY_SECONDS,
    lost_key_delay_seconds: int = LOST_KEY_DELAY_SECONDS,
) -> Program:
    if len(lost_recovery_root_hashes) != 3:
        raise ValueError(
            "Authority V3 requires one lost-key recovery root per slot"
        )
    if len(identity_launcher_ids) != 3:
        raise ValueError("Authority V3 requires exactly three identity launchers")
    if len(set(identity_launcher_ids)) != 3:
        raise ValueError("identity launcher ids must be distinct")
    if source_manifest_hash == ZERO_32:
        raise ValueError("source_manifest_hash must be nonzero")
    resolved = state or AdminAuthorityV3State()
    resolved.validate()
    return admin_authority_v3_inner_mod().curry(
        admin_authority_v3_inner_mod_hash(),
        operational_root_hash,
        list(lost_recovery_root_hashes),
        *identity_launcher_ids,
        routine_delay_seconds,
        lost_key_delay_seconds,
        source_manifest_hash,
        resolved.authority_version,
        resolved.pending_kind,
        resolved.pending_slot,
        resolved.pending_intent_hash,
        resolved.pending_identity_coin_id,
        resolved.pending_replacement_custody_hash,
        resolved.pending_replacement_member_hash,
        resolved.pending_delay_seconds,
    )


def build_genesis_admin_authority_v3(
    *,
    parent_coin_id: bytes32,
    network: str,
    daily_compressed_pubkeys: Sequence[bytes],
    recovery_bls_pubkeys: Sequence[bytes],
    source_manifest_hash: bytes32,
) -> GenesisAdminAuthorityV3:
    daily_keys = tuple(bytes(value) for value in daily_compressed_pubkeys)
    recovery_keys = tuple(bytes(value) for value in recovery_bls_pubkeys)
    if len(daily_keys) != 3 or any(len(value) != 33 for value in daily_keys):
        raise ValueError("Authority V3 requires three compressed daily keys")
    if len(set(daily_keys)) != 3:
        raise ValueError("daily keys must be distinct")
    if len(recovery_keys) != 3 or any(len(value) != 48 for value in recovery_keys):
        raise ValueError("Authority V3 requires three recovery BLS public keys")
    if len(set(recovery_keys)) != 3:
        raise ValueError("recovery BLS public keys must be distinct")

    (
        authority_launcher_id,
        identity_0,
        identity_1,
        identity_2,
    ) = authority_v3_launcher_ids(parent_coin_id)
    identity_launcher_ids = (identity_0, identity_1, identity_2)
    prefix = eip712_prefix_and_domain_separator(
        genesis_challenge_for_network(network)
    )
    daily_members = tuple(
        make_eip712_member_v2_puzzle(
            secp256k1_pubkey=pubkey,
            prefix_and_domain_separator=prefix,
        )
        for pubkey in daily_keys
    )
    identities: list[IdentityVaultGenesis] = []
    for slot, (amount, daily_member, recovery_key, launcher_id) in enumerate(
        zip(
            IDENTITY_LAUNCHER_AMOUNTS,
            daily_members,
            recovery_keys,
            identity_launcher_ids,
            strict=True,
        )
    ):
        (
            policy,
            daily_hash,
            recovery_hash,
            daily_path,
            daily_path_branch,
            recovery_key_branch,
        ) = _identity_policy(
            slot=slot,
            daily_member=daily_member,
            recovery_bls_pubkey=recovery_key,
            authority_launcher_id=authority_launcher_id,
        )
        expected_daily_hash = compute_eip712_member_v2_leaf_hash(
            secp256k1_pubkey=daily_keys[slot],
            prefix_and_domain_separator=prefix,
        )
        if daily_hash != expected_daily_hash:
            raise ValueError("daily EIP-712 member hash does not match")
        custody_root = _branch(
            nonce=slot,
            puzzle=policy,
        )
        custody_reveal = custody_root.puzzle_reveal()
        custody_hash = bytes32(custody_reveal.get_tree_hash())
        identities.append(
            IdentityVaultGenesis(
                slot=slot,
                launcher_amount=amount,
                launcher_id=launcher_id,
                daily_compressed_pubkey=daily_keys[slot],
                daily_member_reveal=daily_member,
                daily_member_hash=daily_hash,
                recovery_member_hash=recovery_hash,
                daily_path=daily_path,
                daily_path_branch=daily_path_branch,
                recovery_key_branch=recovery_key_branch,
                custody_policy=policy,
                custody_root=custody_root,
                custody_reveal=custody_reveal,
                custody_hash=custody_hash,
                full_puzzle_hash=singleton_full_puzzle_hash(
                    launcher_id,
                    custody_hash,
                ),
                recovery_bls_pubkey=recovery_key,
            )
        )

    operational, lost_recovery_policies = _root_policies(
        identity_launcher_ids
    )
    operational_root = _branch(nonce=200, puzzle=operational)
    lost_recovery_roots = tuple(
        _branch(nonce=201 + slot, puzzle=policy)
        for slot, policy in enumerate(lost_recovery_policies)
    )
    operational_reveal = operational_root.puzzle_reveal()
    lost_recovery_reveals = tuple(
        root.puzzle_reveal() for root in lost_recovery_roots
    )
    lost_recovery_root_hashes = tuple(
        bytes32(reveal.get_tree_hash())
        for reveal in lost_recovery_reveals
    )
    inner = make_inner_puzzle(
        operational_root_hash=bytes32(operational_reveal.get_tree_hash()),
        lost_recovery_root_hashes=lost_recovery_root_hashes,
        identity_launcher_ids=identity_launcher_ids,
        source_manifest_hash=source_manifest_hash,
    )
    return GenesisAdminAuthorityV3(
        authority_launcher_id=authority_launcher_id,
        identity_vaults=tuple(identities),  # type: ignore[arg-type]
        operational_policy=operational,
        operational_root=operational_root,
        operational_reveal=operational_reveal,
        operational_root_hash=bytes32(operational_reveal.get_tree_hash()),
        lost_recovery_policies=lost_recovery_policies,
        lost_recovery_roots=lost_recovery_roots,
        lost_recovery_reveals=lost_recovery_reveals,
        lost_recovery_root_hashes=lost_recovery_root_hashes,
        source_manifest_hash=source_manifest_hash,
        inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        full_puzzle_hash=singleton_full_puzzle_hash(
            authority_launcher_id,
            bytes32(inner.get_tree_hash()),
        ),
    )


def parse_inner_puzzle(curried_inner_puzzle: Program) -> ParsedAdminAuthorityV3:
    """Decode one Authority V3 inner puzzle and reject lookalike modules."""

    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("Authority V3 inner puzzle is not curried")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != admin_authority_v3_inner_mod_hash():
        raise ValueError("inner puzzle module hash is not Authority V3")
    values = list(args.as_iter())
    if len(values) != 17:
        raise ValueError(
            f"Authority V3 inner puzzle must have 17 arguments, got {len(values)}"
        )
    if bytes32(values[0].atom) != admin_authority_v3_inner_mod_hash():
        raise ValueError("Authority V3 self module hash is inconsistent")
    recovery_roots = tuple(
        bytes32(value.atom) for value in values[2].as_iter()
    )
    if len(recovery_roots) != 3 or len(set(recovery_roots)) != 3:
        raise ValueError(
            "Authority V3 must commit three distinct lost-key roots"
        )
    routine_delay = int(values[6].as_int())
    lost_delay = int(values[7].as_int())
    if routine_delay != ROUTINE_DELAY_SECONDS:
        raise ValueError("Authority V3 routine delay is not canonical")
    if lost_delay != LOST_KEY_DELAY_SECONDS:
        raise ValueError("Authority V3 lost-key delay is not canonical")
    identity_launcher_ids = tuple(
        bytes32(values[index].atom) for index in (3, 4, 5)
    )
    if len(set(identity_launcher_ids)) != 3:
        raise ValueError("Authority V3 identity launcher IDs are not distinct")
    state = AdminAuthorityV3State(
        authority_version=int(values[9].as_int()),
        pending_kind=int(values[10].as_int()),
        pending_slot=int(values[11].as_int()),
        pending_intent_hash=bytes32(values[12].atom),
        pending_identity_coin_id=bytes32(values[13].atom),
        pending_replacement_custody_hash=bytes32(values[14].atom),
        pending_replacement_member_hash=bytes32(values[15].atom),
        pending_delay_seconds=int(values[16].as_int()),
    )
    state.validate()
    return ParsedAdminAuthorityV3(
        operational_root_hash=bytes32(values[1].atom),
        lost_recovery_root_hashes=recovery_roots,  # type: ignore[arg-type]
        identity_launcher_ids=identity_launcher_ids,  # type: ignore[arg-type]
        routine_delay_seconds=routine_delay,
        lost_key_delay_seconds=lost_delay,
        source_manifest_hash=bytes32(values[8].atom),
        state=state,
    )


def compute_prepare_binding_hash(
    *,
    pending_kind: int,
    slot: int,
    intent_hash: bytes32,
    current_identity_coin_id: bytes32,
    intermediate_identity_coin_id: bytes32,
    replacement_custody_hash: bytes32,
    replacement_member_hash: bytes32,
    source_manifest_hash: bytes32,
    current_authority_version: int,
    new_authority_version: int,
    identity_launcher_id: bytes32,
) -> bytes32:
    if pending_kind not in (PENDING_ROUTINE, PENDING_LOST):
        raise ValueError("pending_kind must be routine or lost-key")
    if slot not in range(3):
        raise ValueError("slot must be 0, 1, or 2")
    delay = (
        ROUTINE_DELAY_SECONDS
        if pending_kind == PENDING_ROUTINE
        else LOST_KEY_DELAY_SECONDS
    )
    return bytes32(
        Program.to(
            [
                pending_kind,
                slot,
                intent_hash,
                current_identity_coin_id,
                intermediate_identity_coin_id,
                replacement_custody_hash,
                replacement_member_hash,
                delay,
                source_manifest_hash,
                current_authority_version,
                new_authority_version,
                identity_launcher_id,
            ]
        ).get_tree_hash()
    )


def _compute_completion_message_fields(
    *,
    pending_kind: int,
    pending_slot: int,
    pending_intent_hash: bytes32,
    pending_replacement_custody_hash: bytes32,
    pending_replacement_member_hash: bytes32,
    source_manifest_hash: bytes32,
) -> bytes32:
    return bytes32(
        Program.to(
            [
                SPEND_COMPLETE,
                pending_kind,
                pending_slot,
                pending_intent_hash,
                pending_replacement_custody_hash,
                pending_replacement_member_hash,
                source_manifest_hash,
            ]
        ).get_tree_hash()
    )


def compute_completion_message(
    *,
    state: AdminAuthorityV3State,
    source_manifest_hash: bytes32,
) -> bytes32:
    state.validate()
    if state.pending_kind == PENDING_NONE:
        raise ValueError("completion requires a pending key change")
    return _compute_completion_message_fields(
        pending_kind=state.pending_kind,
        pending_slot=state.pending_slot,
        pending_intent_hash=state.pending_intent_hash,
        pending_replacement_custody_hash=(
            state.pending_replacement_custody_hash
        ),
        pending_replacement_member_hash=(
            state.pending_replacement_member_hash
        ),
        source_manifest_hash=source_manifest_hash,
    )


def _quoted_conditions(conditions: Sequence[Sequence[object]]) -> Program:
    return Program.to((1, [list(condition) for condition in conditions]))


def _puzzle_announcement_id(
    puzzle_hash: bytes32,
    message: bytes32,
) -> bytes32:
    return bytes32(hashlib.sha256(puzzle_hash + message).digest())


def build_identity_vault_transition(
    *,
    identity: IdentityVaultGenesis,
    authority_launcher_id: bytes32,
    authority_current_full_puzzle_hash: bytes32,
    network: str,
    kind: int,
    intent_hash: bytes32,
    current_identity_coin_id: bytes32,
    replacement_daily_compressed_pubkey: bytes,
    source_manifest_hash: bytes32,
    current_authority_version: int,
    replacement_recovery_bls_pubkey: bytes | None = None,
) -> IdentityVaultTransition:
    """Build the exact initiate, wait, and finish custody commitments.

    The intermediate root preserves the old daily path as its veto branch.
    Its other branch is a fixed finish puzzle protected by the canonical
    upstream timelock restriction. Lost-key initiation is additionally
    constrained by the recovery branch's upstream force-1-of-2 and
    side-effect wrappers.
    """

    if kind not in (PENDING_ROUTINE, PENDING_LOST):
        raise ValueError("identity transition kind must be routine or lost-key")
    if identity.slot not in range(3):
        raise ValueError("identity slot must be 0, 1, or 2")
    if len(replacement_daily_compressed_pubkey) != 33:
        raise ValueError("replacement daily key must be compressed secp256k1")
    if intent_hash == ZERO_32 or current_identity_coin_id == ZERO_32:
        raise ValueError("identity transition ids must be nonzero")
    if current_authority_version < 1:
        raise ValueError("current authority version must be positive")

    recovery_pubkey = (
        bytes(replacement_recovery_bls_pubkey)
        if replacement_recovery_bls_pubkey is not None
        else identity.recovery_bls_pubkey
    )
    if len(recovery_pubkey) != 48:
        raise ValueError("replacement recovery key must be a BLS public key")

    prefix = eip712_prefix_and_domain_separator(
        genesis_challenge_for_network(network)
    )
    replacement_daily_member = make_eip712_member_v2_puzzle(
        secp256k1_pubkey=replacement_daily_compressed_pubkey,
        prefix_and_domain_separator=prefix,
    )
    (
        final_policy,
        replacement_member_hash,
        _,
        _,
        _,
        _,
    ) = _identity_policy(
        slot=identity.slot,
        daily_member=replacement_daily_member,
        recovery_bls_pubkey=recovery_pubkey,
        authority_launcher_id=authority_launcher_id,
    )
    final_root = _branch(nonce=identity.slot, puzzle=final_policy)
    final_reveal = final_root.puzzle_reveal()
    final_custody_hash = bytes32(final_reveal.get_tree_hash())
    final_full_puzzle_hash = singleton_full_puzzle_hash(
        identity.launcher_id,
        final_custody_hash,
    )

    delay = (
        ROUTINE_DELAY_SECONDS
        if kind == PENDING_ROUTINE
        else LOST_KEY_DELAY_SECONDS
    )
    completion_message = _compute_completion_message_fields(
        pending_kind=kind,
        pending_slot=identity.slot,
        pending_intent_hash=intent_hash,
        pending_replacement_custody_hash=final_custody_hash,
        pending_replacement_member_hash=replacement_member_hash,
        source_manifest_hash=source_manifest_hash,
    )
    finish_delegated_puzzle = _quoted_conditions(
        (
            (51, final_custody_hash, identity.launcher_amount),
            (60, completion_message),
            (73, identity.launcher_amount),
            (80, delay),
        )
    )
    timelock = Program.from_bytes(puzzle_mods.TIMELOCK).curry(delay)
    finish_member = _ProgramMember(finish_delegated_puzzle)
    finish_member_branch = _branch(
        nonce=identity.slot,
        puzzle=finish_member,
        restrictions=(
            _ProgramRestriction(
                program=timelock,
                member_not_dpuz=True,
            ),
        ),
    )
    finish_member_hash = finish_member_branch.puzzle_hash(
        _top_level=False
    )
    intermediate_policy = MofN(
        m=1,
        members=[identity.daily_path_branch, finish_member_branch],
    )
    intermediate_root = _branch(
        nonce=identity.slot,
        puzzle=intermediate_policy,
    )
    intermediate_reveal = intermediate_root.puzzle_reveal()
    intermediate_custody_hash = bytes32(
        intermediate_reveal.get_tree_hash()
    )
    intermediate_full_puzzle_hash = singleton_full_puzzle_hash(
        identity.launcher_id,
        intermediate_custody_hash,
    )
    intermediate_coin_id = bytes32(
        Coin(
            current_identity_coin_id,
            intermediate_full_puzzle_hash,
            uint64(identity.launcher_amount),
        ).name()
    )
    binding = compute_prepare_binding_hash(
        pending_kind=kind,
        slot=identity.slot,
        intent_hash=intent_hash,
        current_identity_coin_id=current_identity_coin_id,
        intermediate_identity_coin_id=intermediate_coin_id,
        replacement_custody_hash=final_custody_hash,
        replacement_member_hash=replacement_member_hash,
        source_manifest_hash=source_manifest_hash,
        current_authority_version=current_authority_version,
        new_authority_version=current_authority_version + 1,
        identity_launcher_id=identity.launcher_id,
    )
    prepare_delegated_puzzle = _quoted_conditions(
        (
            (51, intermediate_custody_hash, identity.launcher_amount),
            (
                63,
                _puzzle_announcement_id(
                    authority_current_full_puzzle_hash,
                    binding,
                ),
            ),
            (70, current_identity_coin_id),
            (73, identity.launcher_amount),
        )
    )

    return IdentityVaultTransition(
        kind=kind,
        slot=identity.slot,
        delay_seconds=delay,
        current_identity_coin_id=current_identity_coin_id,
        intermediate_identity_coin_id=intermediate_coin_id,
        intent_hash=intent_hash,
        original_custody_hash=identity.custody_hash,
        replacement_daily_compressed_pubkey=bytes(
            replacement_daily_compressed_pubkey
        ),
        replacement_daily_member_reveal=replacement_daily_member,
        replacement_daily_member_hash=replacement_member_hash,
        replacement_recovery_bls_pubkey=recovery_pubkey,
        final_custody_policy=final_policy,
        final_custody_root=final_root,
        final_custody_reveal=final_reveal,
        final_custody_hash=final_custody_hash,
        final_full_puzzle_hash=final_full_puzzle_hash,
        completion_message=completion_message,
        finish_delegated_puzzle=finish_delegated_puzzle,
        finish_member_branch=finish_member_branch,
        finish_member_hash=finish_member_hash,
        intermediate_custody_policy=intermediate_policy,
        intermediate_custody_root=intermediate_root,
        intermediate_custody_reveal=intermediate_reveal,
        intermediate_custody_hash=intermediate_custody_hash,
        intermediate_full_puzzle_hash=intermediate_full_puzzle_hash,
        prepare_binding_hash=binding,
        prepare_delegated_puzzle=prepare_delegated_puzzle,
    )


def build_lost_recovery_identity_solution(
    *,
    identity: IdentityVaultGenesis,
    transition: IdentityVaultTransition,
) -> Program:
    """Build the target identity MIPS solution for lost-key initiation."""

    if transition.kind != PENDING_LOST or transition.slot != identity.slot:
        raise ValueError("lost recovery transition does not match identity")
    stack = identity.recovery_key_branch.restrictions[0]
    if not isinstance(stack, ValidatorStackRestriction):
        raise ValueError("identity recovery branch lacks wrapper enforcement")
    delegated = DelegatedPuzzleAndSolution(
        puzzle=transition.prepare_delegated_puzzle,
        solution=Program.to(None),
    )
    wrapped = stack.modify_delegated_puzzle_and_solution(
        delegated,
        [
            Program.to(
                [bytes32(transition.finish_delegated_puzzle.get_tree_hash())]
            ),
            Program.to(None),
            Program.to(None),
            Program.to(None),
            Program.to(None),
            Program.to(None),
        ],
    )
    recovery_member = identity.recovery_key_branch.puzzle
    if not isinstance(recovery_member, BLSWithTaprootMember):
        raise ValueError("identity recovery member is not BLS")
    recovery_solution = identity.recovery_key_branch.solve(
        [],
        [stack.solve(transition.prepare_delegated_puzzle)],
        recovery_member.solve(),
    )
    policy_solution = identity.custody_policy.solve(
        {
            identity.recovery_key_branch.puzzle_hash(
                _top_level=False
            ): ProvenSpend(
                puzzle_reveal=identity.recovery_key_branch.puzzle_reveal(
                    _top_level=False
                ),
                solution=recovery_solution,
            )
        }
    )
    return identity.custody_root.solve(
        [],
        [],
        policy_solution,
        wrapped,
    )


def build_identity_finish_solution(
    transition: IdentityVaultTransition,
) -> Program:
    """Build the permissionless timelocked finish MIPS solution."""

    finish_member = transition.finish_member_branch.puzzle
    finish_solution = transition.finish_member_branch.solve(
        [Program.to(None)],
        [],
        Program.to(None),
    )
    policy_solution = transition.intermediate_custody_policy.solve(
        {
            transition.finish_member_hash: ProvenSpend(
                puzzle_reveal=(
                    transition.finish_member_branch.puzzle_reveal(
                        _top_level=False
                    )
                ),
                solution=finish_solution,
            )
        }
    )
    return transition.intermediate_custody_root.solve(
        [],
        [],
        policy_solution,
        DelegatedPuzzleAndSolution(
            puzzle=Program.to(None),
            solution=Program.to(None),
        ),
    )


def build_operational_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    mips_reveal: Program,
    mips_solution: Program,
) -> Program:
    return Program.to(
        [
            SPEND_OPERATIONAL,
            my_amount,
            new_authority_version,
            [mips_reveal, mips_solution],
        ]
    )


def build_prepare_solution(
    *,
    lost_key: bool,
    my_amount: int,
    new_authority_version: int,
    mips_reveal: Program,
    mips_solution: Program,
    replacement_member_reveal: Program,
    replacement_member_solution: Program,
    slot: int,
    intent_hash: bytes32,
    current_identity_coin_id: bytes32,
    intermediate_identity_coin_id: bytes32,
    replacement_custody_hash: bytes32,
    replacement_member_hash: bytes32,
) -> Program:
    if bytes32(replacement_member_reveal.get_tree_hash()) != replacement_member_hash:
        raise ValueError("replacement member hash does not match its reveal")
    return Program.to(
        [
            SPEND_PREPARE_LOST if lost_key else SPEND_PREPARE_ROUTINE,
            my_amount,
            new_authority_version,
            [
                mips_reveal,
                mips_solution,
                replacement_member_reveal,
                replacement_member_solution,
                slot,
                intent_hash,
                current_identity_coin_id,
                intermediate_identity_coin_id,
                replacement_custody_hash,
            ],
        ]
    )


def build_cancel_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    mips_reveal: Program,
    mips_solution: Program,
) -> Program:
    return Program.to(
        [
            SPEND_CANCEL,
            my_amount,
            new_authority_version,
            [mips_reveal, mips_solution],
        ]
    )


def build_complete_solution(
    *,
    my_amount: int,
    new_authority_version: int,
) -> Program:
    return Program.to(
        [SPEND_COMPLETE, my_amount, new_authority_version, []]
    )


__all__ = [
    "ADMIN_AUTHORITY_FUNDING_AMOUNT",
    "AUTHORITY_LAUNCHER_AMOUNT",
    "AdminAuthorityV3State",
    "GenesisAdminAuthorityV3",
    "IdentityVaultGenesis",
    "IdentityVaultTransition",
    "IDENTITY_LAUNCHER_AMOUNTS",
    "LOST_KEY_DELAY_SECONDS",
    "PENDING_LOST",
    "PENDING_NONE",
    "PENDING_ROUTINE",
    "ParsedAdminAuthorityV3",
    "ROUTINE_DELAY_SECONDS",
    "SPEND_CANCEL",
    "SPEND_COMPLETE",
    "SPEND_OPERATIONAL",
    "SPEND_PREPARE_LOST",
    "SPEND_PREPARE_ROUTINE",
    "admin_authority_v3_inner_mod",
    "admin_authority_v3_inner_mod_hash",
    "authority_v3_launcher_ids",
    "build_cancel_solution",
    "build_complete_solution",
    "build_genesis_admin_authority_v3",
    "build_identity_finish_solution",
    "build_identity_vault_transition",
    "build_lost_recovery_identity_solution",
    "build_operational_solution",
    "build_prepare_solution",
    "compute_completion_message",
    "compute_prepare_binding_hash",
    "make_inner_puzzle",
    "parse_inner_puzzle",
]
