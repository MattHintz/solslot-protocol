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
from chia.wallet.puzzles.custody.member_puzzles import (
    BLSWithTaprootMember,
)
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
from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)

SPEND_OPERATIONAL = 0x01
SPEND_PREPARE_ROUTINE = 0x02
SPEND_PREPARE_LOST = 0x03
SPEND_CANCEL = 0x04
SPEND_COMPLETE = 0x05
SPEND_PREPARE_KIT = 0x06

PENDING_NONE = 0
PENDING_ROUTINE = 1
PENDING_LOST = 2
PENDING_RECOVERY_KIT = 3

ID_ACTION_OPERATIONAL = 1
ID_ACTION_APPROVE = 2
ID_ACTION_PREPARE = 3
ID_ACTION_CANCEL = 4
ID_ACTION_COMPLETE = 5

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
_ADMIN_AUTHORITY_ACTION_V1_MOD: Program | None = None
_ADMIN_IDENTITY_ACTION_V1_MOD: Program | None = None
_ADMIN_IDENTITY_TERMINAL_ACTION_V1_MOD: Program | None = None
_ADMIN_IDENTITY_PREPARE_ANNOUNCEMENT_V1_MOD: Program | None = None


def admin_authority_v3_inner_mod() -> Program:
    global _ADMIN_AUTHORITY_V3_INNER_MOD
    if _ADMIN_AUTHORITY_V3_INNER_MOD is None:
        _ADMIN_AUTHORITY_V3_INNER_MOD = load_puzzle(
            "admin_authority_v3_inner.clsp"
        )
    return _ADMIN_AUTHORITY_V3_INNER_MOD


def admin_authority_v3_inner_mod_hash() -> bytes32:
    return bytes32(admin_authority_v3_inner_mod().get_tree_hash())


def admin_authority_action_v1_mod() -> Program:
    global _ADMIN_AUTHORITY_ACTION_V1_MOD
    if _ADMIN_AUTHORITY_ACTION_V1_MOD is None:
        _ADMIN_AUTHORITY_ACTION_V1_MOD = load_puzzle(
            "admin_authority_action_v1.clsp"
        )
    return _ADMIN_AUTHORITY_ACTION_V1_MOD


def admin_identity_action_v1_mod() -> Program:
    global _ADMIN_IDENTITY_ACTION_V1_MOD
    if _ADMIN_IDENTITY_ACTION_V1_MOD is None:
        _ADMIN_IDENTITY_ACTION_V1_MOD = load_puzzle(
            "admin_identity_action_v1.clsp"
        )
    return _ADMIN_IDENTITY_ACTION_V1_MOD


def admin_identity_terminal_action_v1_mod() -> Program:
    global _ADMIN_IDENTITY_TERMINAL_ACTION_V1_MOD
    if _ADMIN_IDENTITY_TERMINAL_ACTION_V1_MOD is None:
        _ADMIN_IDENTITY_TERMINAL_ACTION_V1_MOD = load_puzzle(
            "admin_identity_terminal_action_v1.clsp"
        )
    return _ADMIN_IDENTITY_TERMINAL_ACTION_V1_MOD


def admin_identity_prepare_announcement_v1_mod() -> Program:
    global _ADMIN_IDENTITY_PREPARE_ANNOUNCEMENT_V1_MOD
    if _ADMIN_IDENTITY_PREPARE_ANNOUNCEMENT_V1_MOD is None:
        _ADMIN_IDENTITY_PREPARE_ANNOUNCEMENT_V1_MOD = load_puzzle(
            "admin_identity_prepare_announcement_v1.clsp"
        )
    return _ADMIN_IDENTITY_PREPARE_ANNOUNCEMENT_V1_MOD


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
    cancel_message: bytes32
    authority_current_inner_puzzle: Program
    authority_current_full_puzzle_hash: bytes32
    authority_prepare_action: Program
    authority_prepare_action_hash: bytes32
    authority_pending_state: AdminAuthorityV3State
    authority_pending_inner_puzzle: Program
    authority_pending_full_puzzle_hash: bytes32
    authority_cancel_action: Program
    authority_cancel_action_hash: bytes32
    target_prepare_message: bytes32
    finish_member_reveal: Program
    finish_member_branch: PuzzleWithRestrictions
    finish_member_hash: bytes32
    finish_member_branch_hash: bytes32
    cancel_identity_action: Program
    cancel_identity_action_hash: bytes32
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
    inner_puzzle: Program
    inner_puzzle_hash: bytes32
    full_puzzle_hash: bytes32


@dataclass(frozen=True)
class AuthorityMipsSpend:
    """Canonical MIPS reveal, solution, and identity coin records."""

    reveal: Program
    solution: Program
    identity_records: tuple[tuple[int, bytes32], tuple[int, bytes32]]
    selected_slots: tuple[int, int]


@dataclass(frozen=True)
class AdminAuthorityV3State:
    current_identity_custody_hashes: tuple[
        bytes32,
        bytes32,
        bytes32,
    ] = (ZERO_32, ZERO_32, ZERO_32)
    authority_version: int = 1
    pending_kind: int = PENDING_NONE
    pending_slot: int = 0
    pending_intent_hash: bytes32 = ZERO_32
    pending_identity_coin_id: bytes32 = ZERO_32
    pending_original_custody_hash: bytes32 = ZERO_32
    pending_replacement_custody_hash: bytes32 = ZERO_32
    pending_replacement_member_hash: bytes32 = ZERO_32
    pending_delay_seconds: int = 0

    def validate(self) -> None:
        if self.authority_version < 1:
            raise ValueError("authority_version must be at least one")
        if (
            len(self.current_identity_custody_hashes) != 3
            or any(
                value == ZERO_32
                for value in self.current_identity_custody_hashes
            )
        ):
            raise ValueError(
                "Authority V3 requires three nonzero identity custody hashes"
            )
        if self.pending_kind == PENDING_NONE:
            if any(
                (
                    self.pending_slot,
                    self.pending_intent_hash != ZERO_32,
                    self.pending_identity_coin_id != ZERO_32,
                    self.pending_original_custody_hash != ZERO_32,
                    self.pending_replacement_custody_hash != ZERO_32,
                    self.pending_replacement_member_hash != ZERO_32,
                    self.pending_delay_seconds,
                )
            ):
                raise ValueError("empty Authority V3 state must be canonical")
            return
        if self.pending_kind not in (
            PENDING_ROUTINE,
            PENDING_LOST,
            PENDING_RECOVERY_KIT,
        ):
            raise ValueError("pending_kind is not supported")
        if self.pending_slot not in range(3):
            raise ValueError("pending_slot must be 0, 1, or 2")
        for label, value in (
            ("pending_intent_hash", self.pending_intent_hash),
            ("pending_identity_coin_id", self.pending_identity_coin_id),
            (
                "pending_original_custody_hash",
                self.pending_original_custody_hash,
            ),
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
            LOST_KEY_DELAY_SECONDS
            if self.pending_kind == PENDING_LOST
            else ROUTINE_DELAY_SECONDS
        )
        if self.pending_delay_seconds != expected_delay:
            raise ValueError("pending delay does not match recovery kind")


@dataclass(frozen=True)
class ParsedAdminAuthorityV3:
    """Strictly decoded immutable configuration and mutable V3 state."""

    operational_root_hash: bytes32
    authority_launcher_id: bytes32
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
    wrappers.append(
        _ProgramWrapper(admin_identity_prepare_announcement_v1_mod())
    )
    for opcode in (62, 66, 67):
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
    authority_launcher_id: bytes32,
    operational_root_hash: bytes32,
    lost_recovery_root_hashes: Sequence[bytes32],
    identity_launcher_ids: Sequence[bytes32],
    current_identity_custody_hashes: Sequence[bytes32] | None = None,
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
    if authority_launcher_id == ZERO_32:
        raise ValueError("authority_launcher_id must be nonzero")
    supplied_custodies = (
        tuple(bytes32(value) for value in current_identity_custody_hashes)
        if current_identity_custody_hashes is not None
        else None
    )
    if state is None:
        if supplied_custodies is None:
            raise ValueError(
                "current_identity_custody_hashes are required for genesis state"
            )
        if len(supplied_custodies) != 3:
            raise ValueError(
                "Authority V3 requires exactly three identity custody hashes"
            )
        resolved = AdminAuthorityV3State(
            current_identity_custody_hashes=supplied_custodies,  # type: ignore[arg-type]
        )
    else:
        resolved = state
        if (
            supplied_custodies is not None
            and supplied_custodies
            != resolved.current_identity_custody_hashes
        ):
            raise ValueError(
                "state custody hashes do not match supplied custody hashes"
            )
    resolved.validate()
    return admin_authority_v3_inner_mod().curry(
        admin_authority_v3_inner_mod_hash(),
        bytes32(SINGLETON_MOD_HASH),
        bytes32(SINGLETON_LAUNCHER_HASH),
        authority_launcher_id,
        bytes32(admin_authority_action_v1_mod().get_tree_hash()),
        bytes32(admin_identity_action_v1_mod().get_tree_hash()),
        operational_root_hash,
        list(lost_recovery_root_hashes),
        *identity_launcher_ids,
        list(resolved.current_identity_custody_hashes),
        routine_delay_seconds,
        lost_key_delay_seconds,
        source_manifest_hash,
        resolved.authority_version,
        resolved.pending_kind,
        resolved.pending_slot,
        resolved.pending_intent_hash,
        resolved.pending_identity_coin_id,
        resolved.pending_original_custody_hash,
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
    identities: list[IdentityVaultGenesis] = []
    for slot, (recovery_key, launcher_id) in enumerate(
        zip(
            recovery_keys,
            identity_launcher_ids,
            strict=True,
        )
    ):
        identities.append(
            build_admin_identity_vault(
                slot=slot,
                launcher_id=launcher_id,
                authority_launcher_id=authority_launcher_id,
                network=network,
                daily_compressed_pubkey=daily_keys[slot],
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
        authority_launcher_id=authority_launcher_id,
        operational_root_hash=bytes32(operational_reveal.get_tree_hash()),
        lost_recovery_root_hashes=lost_recovery_root_hashes,
        identity_launcher_ids=identity_launcher_ids,
        current_identity_custody_hashes=tuple(
            identity.custody_hash for identity in identities
        ),
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
        inner_puzzle=inner,
        inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        full_puzzle_hash=singleton_full_puzzle_hash(
            authority_launcher_id,
            bytes32(inner.get_tree_hash()),
        ),
    )


def build_admin_identity_vault(
    *,
    slot: int,
    launcher_id: bytes32,
    authority_launcher_id: bytes32,
    network: str,
    daily_compressed_pubkey: bytes,
    recovery_bls_pubkey: bytes,
) -> IdentityVaultGenesis:
    """Rebuild one current identity from immutable coordinates and keys.

    Genesis creation and post-rotation spend construction use this same
    constructor.  Services therefore never need to reproduce the MIPS policy
    or infer a custody reveal from a tree hash.
    """

    if slot not in range(3):
        raise ValueError("identity slot must be 0, 1, or 2")
    if launcher_id == ZERO_32 or authority_launcher_id == ZERO_32:
        raise ValueError("identity and authority launcher IDs must be nonzero")
    daily_key = bytes(daily_compressed_pubkey)
    recovery_key = bytes(recovery_bls_pubkey)
    if len(daily_key) != 33:
        raise ValueError("daily key must be compressed secp256k1")
    if len(recovery_key) != 48:
        raise ValueError("recovery key must be a BLS public key")

    prefix = eip712_prefix_and_domain_separator(
        genesis_challenge_for_network(network)
    )
    daily_member = make_eip712_member_v2_puzzle(
        secp256k1_pubkey=daily_key,
        prefix_and_domain_separator=prefix,
    )
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
        secp256k1_pubkey=daily_key,
        prefix_and_domain_separator=prefix,
    )
    if daily_hash != expected_daily_hash:
        raise ValueError("daily EIP-712 member hash does not match")
    custody_root = _branch(nonce=slot, puzzle=policy)
    custody_reveal = custody_root.puzzle_reveal()
    custody_hash = bytes32(custody_reveal.get_tree_hash())
    return IdentityVaultGenesis(
        slot=slot,
        launcher_amount=IDENTITY_LAUNCHER_AMOUNTS[slot],
        launcher_id=launcher_id,
        daily_compressed_pubkey=daily_key,
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


def parse_inner_puzzle(curried_inner_puzzle: Program) -> ParsedAdminAuthorityV3:
    """Decode one Authority V3 inner puzzle and reject lookalike modules."""

    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("Authority V3 inner puzzle is not curried")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != admin_authority_v3_inner_mod_hash():
        raise ValueError("inner puzzle module hash is not Authority V3")
    values = list(args.as_iter())
    if len(values) != 24:
        raise ValueError(
            f"Authority V3 inner puzzle must have 24 arguments, got {len(values)}"
        )
    if bytes32(values[0].atom) != admin_authority_v3_inner_mod_hash():
        raise ValueError("Authority V3 self module hash is inconsistent")
    if bytes32(values[1].atom) != bytes32(SINGLETON_MOD_HASH):
        raise ValueError("Authority V3 singleton module hash is inconsistent")
    if bytes32(values[2].atom) != bytes32(SINGLETON_LAUNCHER_HASH):
        raise ValueError("Authority V3 singleton launcher hash is inconsistent")
    if bytes32(values[4].atom) != bytes32(
        admin_authority_action_v1_mod().get_tree_hash()
    ):
        raise ValueError("Authority V3 action module hash is inconsistent")
    if bytes32(values[5].atom) != bytes32(
        admin_identity_action_v1_mod().get_tree_hash()
    ):
        raise ValueError("Authority V3 identity action hash is inconsistent")
    recovery_roots = tuple(
        bytes32(value.atom) for value in values[7].as_iter()
    )
    if len(recovery_roots) != 3 or len(set(recovery_roots)) != 3:
        raise ValueError(
            "Authority V3 must commit three distinct lost-key roots"
        )
    routine_delay = int(values[12].as_int())
    lost_delay = int(values[13].as_int())
    if routine_delay != ROUTINE_DELAY_SECONDS:
        raise ValueError("Authority V3 routine delay is not canonical")
    if lost_delay != LOST_KEY_DELAY_SECONDS:
        raise ValueError("Authority V3 lost-key delay is not canonical")
    identity_launcher_ids = tuple(
        bytes32(values[index].atom) for index in (8, 9, 10)
    )
    if len(set(identity_launcher_ids)) != 3:
        raise ValueError("Authority V3 identity launcher IDs are not distinct")
    identity_custody_hashes = tuple(
        bytes32(value.atom) for value in values[11].as_iter()
    )
    if (
        len(identity_custody_hashes) != 3
        or any(value == ZERO_32 for value in identity_custody_hashes)
    ):
        raise ValueError(
            "Authority V3 must commit three nonzero identity custody hashes"
        )
    state = AdminAuthorityV3State(
        current_identity_custody_hashes=identity_custody_hashes,  # type: ignore[arg-type]
        authority_version=int(values[15].as_int()),
        pending_kind=int(values[16].as_int()),
        pending_slot=int(values[17].as_int()),
        pending_intent_hash=bytes32(values[18].atom),
        pending_identity_coin_id=bytes32(values[19].atom),
        pending_original_custody_hash=bytes32(values[20].atom),
        pending_replacement_custody_hash=bytes32(values[21].atom),
        pending_replacement_member_hash=bytes32(values[22].atom),
        pending_delay_seconds=int(values[23].as_int()),
    )
    state.validate()
    return ParsedAdminAuthorityV3(
        operational_root_hash=bytes32(values[6].atom),
        authority_launcher_id=bytes32(values[3].atom),
        lost_recovery_root_hashes=recovery_roots,  # type: ignore[arg-type]
        identity_launcher_ids=identity_launcher_ids,  # type: ignore[arg-type]
        routine_delay_seconds=routine_delay,
        lost_key_delay_seconds=lost_delay,
        source_manifest_hash=bytes32(values[14].atom),
        state=state,
    )


def compute_prepare_binding_hash(
    *,
    pending_kind: int,
    slot: int,
    intent_hash: bytes32,
    current_identity_coin_id: bytes32,
    intermediate_identity_coin_id: bytes32,
    original_custody_hash: bytes32,
    intermediate_custody_hash: bytes32,
    replacement_custody_hash: bytes32,
    replacement_member_hash: bytes32,
    source_manifest_hash: bytes32,
    current_authority_version: int,
    new_authority_version: int,
    identity_launcher_id: bytes32,
) -> bytes32:
    if pending_kind not in (
        PENDING_ROUTINE,
        PENDING_LOST,
        PENDING_RECOVERY_KIT,
    ):
        raise ValueError(
            "pending_kind must be routine, lost-key, or recovery-kit"
        )
    if slot not in range(3):
        raise ValueError("slot must be 0, 1, or 2")
    delay = (
        LOST_KEY_DELAY_SECONDS
        if pending_kind == PENDING_LOST
        else ROUTINE_DELAY_SECONDS
    )
    return bytes32(
        Program.to(
            [
                pending_kind,
                slot,
                intent_hash,
                current_identity_coin_id,
                intermediate_identity_coin_id,
                original_custody_hash,
                intermediate_custody_hash,
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
    pending_original_custody_hash: bytes32,
    pending_replacement_custody_hash: bytes32,
    pending_replacement_member_hash: bytes32,
    source_manifest_hash: bytes32,
) -> bytes32:
    return bytes32(
        Program.to(
            [
                ID_ACTION_COMPLETE,
                pending_kind,
                pending_slot,
                pending_intent_hash,
                pending_original_custody_hash,
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
        pending_original_custody_hash=state.pending_original_custody_hash,
        pending_replacement_custody_hash=(
            state.pending_replacement_custody_hash
        ),
        pending_replacement_member_hash=(
            state.pending_replacement_member_hash
        ),
        source_manifest_hash=source_manifest_hash,
    )


def _compute_cancel_message_fields(
    *,
    pending_kind: int,
    pending_slot: int,
    pending_intent_hash: bytes32,
    pending_original_custody_hash: bytes32,
    pending_replacement_custody_hash: bytes32,
    pending_replacement_member_hash: bytes32,
    source_manifest_hash: bytes32,
) -> bytes32:
    return bytes32(
        Program.to(
            [
                ID_ACTION_CANCEL,
                pending_kind,
                pending_slot,
                pending_intent_hash,
                pending_original_custody_hash,
                pending_replacement_custody_hash,
                pending_replacement_member_hash,
                source_manifest_hash,
            ]
        ).get_tree_hash()
    )


def compute_cancel_message(
    *,
    state: AdminAuthorityV3State,
    source_manifest_hash: bytes32,
) -> bytes32:
    state.validate()
    if state.pending_kind == PENDING_NONE:
        raise ValueError("cancellation requires a pending key change")
    return _compute_cancel_message_fields(
        pending_kind=state.pending_kind,
        pending_slot=state.pending_slot,
        pending_intent_hash=state.pending_intent_hash,
        pending_original_custody_hash=state.pending_original_custody_hash,
        pending_replacement_custody_hash=(
            state.pending_replacement_custody_hash
        ),
        pending_replacement_member_hash=(
            state.pending_replacement_member_hash
        ),
        source_manifest_hash=source_manifest_hash,
    )


def build_authority_action_puzzle(
    *,
    action_tag: int,
    binding_hash: bytes32,
) -> Program:
    if action_tag <= 0:
        raise ValueError("action_tag must be positive")
    if binding_hash == ZERO_32:
        raise ValueError("binding_hash must be nonzero")
    return admin_authority_action_v1_mod().curry(
        action_tag,
        binding_hash,
    )


def build_identity_action_puzzle(
    *,
    action_tag: int,
    output_custody_hash: bytes32,
    authority_full_puzzle_hash: bytes32,
    authority_delegated_puzzle_hash: bytes32,
    authority_announcement_message: bytes32 | None,
    coin_announcement_message: bytes32 | None,
    identity_full_puzzle_hash: bytes32,
    amount: int,
) -> Program:
    if action_tag <= 0:
        raise ValueError("action_tag must be positive")
    if amount <= 0 or amount % 2 == 0:
        raise ValueError("identity amount must be positive and odd")
    for label, value in (
        ("output_custody_hash", output_custody_hash),
        ("authority_full_puzzle_hash", authority_full_puzzle_hash),
        (
            "authority_delegated_puzzle_hash",
            authority_delegated_puzzle_hash,
        ),
        ("identity_full_puzzle_hash", identity_full_puzzle_hash),
    ):
        if value == ZERO_32:
            raise ValueError(f"{label} must be nonzero")
    return admin_identity_action_v1_mod().curry(
        action_tag,
        output_custody_hash,
        authority_full_puzzle_hash,
        authority_delegated_puzzle_hash,
        authority_announcement_message,
        coin_announcement_message,
        identity_full_puzzle_hash,
        amount,
    )


def build_identity_terminal_action_puzzle(
    *,
    action_tag: int,
    output_custody_hash: bytes32,
    coin_announcement_message: bytes32,
    amount: int,
    delay_seconds: int,
) -> Program:
    if action_tag not in (ID_ACTION_CANCEL, ID_ACTION_COMPLETE):
        raise ValueError("terminal action must be cancel or complete")
    if amount <= 0 or amount % 2 == 0:
        raise ValueError("identity amount must be positive and odd")
    if delay_seconds < 0:
        raise ValueError("delay_seconds cannot be negative")
    return admin_identity_terminal_action_v1_mod().curry(
        action_tag,
        output_custody_hash,
        coin_announcement_message,
        amount,
        delay_seconds,
        _nil_hash(),
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
    authority_current_inner_puzzle: Program,
    network: str,
    kind: int,
    intent_hash: bytes32,
    current_identity_coin_id: bytes32,
    replacement_daily_compressed_pubkey: bytes,
    replacement_recovery_bls_pubkey: bytes | None = None,
) -> IdentityVaultTransition:
    """Build the exact initiate, wait, and finish custody commitments.

    The intermediate root preserves the old daily-plus-authority path as its
    veto branch. The authority half of that path is permissionless while a
    change is pending, but pairs only the exact restoration action. Its other
    branch is a fixed completion member protected by the canonical upstream
    timelock restriction. Lost-key initiation is additionally constrained by
    the recovery branch's upstream force-1-of-2 and side-effect wrappers.
    """

    if kind not in (
        PENDING_ROUTINE,
        PENDING_LOST,
        PENDING_RECOVERY_KIT,
    ):
        raise ValueError(
            "identity transition kind must be routine, lost-key, or recovery-kit"
        )
    if identity.slot not in range(3):
        raise ValueError("identity slot must be 0, 1, or 2")
    if len(replacement_daily_compressed_pubkey) != 33:
        raise ValueError("replacement daily key must be compressed secp256k1")
    if intent_hash == ZERO_32 or current_identity_coin_id == ZERO_32:
        raise ValueError("identity transition ids must be nonzero")

    parsed_authority = parse_inner_puzzle(authority_current_inner_puzzle)
    current_state = parsed_authority.state
    if current_state.pending_kind != PENDING_NONE:
        raise ValueError("another Authority V3 key change is already pending")
    if (
        current_state.current_identity_custody_hashes[identity.slot]
        != identity.custody_hash
    ):
        raise ValueError(
            "identity custody does not match the authority's current state"
        )
    authority_launcher_id = parsed_authority.authority_launcher_id
    source_manifest_hash = parsed_authority.source_manifest_hash
    current_authority_full_puzzle_hash = singleton_full_puzzle_hash(
        authority_launcher_id,
        bytes32(authority_current_inner_puzzle.get_tree_hash()),
    )

    recovery_pubkey = (
        bytes(replacement_recovery_bls_pubkey)
        if replacement_recovery_bls_pubkey is not None
        else identity.recovery_bls_pubkey
    )
    if len(recovery_pubkey) != 48:
        raise ValueError("replacement recovery key must be a BLS public key")
    replacement_daily_key = bytes(replacement_daily_compressed_pubkey)
    if kind == PENDING_RECOVERY_KIT:
        if replacement_recovery_bls_pubkey is None:
            raise ValueError(
                "recovery-kit rotation requires a replacement recovery key"
            )
        if recovery_pubkey == identity.recovery_bls_pubkey:
            raise ValueError("replacement recovery key must change")
        if replacement_daily_key != identity.daily_compressed_pubkey:
            raise ValueError(
                "recovery-kit rotation cannot also change the daily key"
            )
    else:
        if replacement_daily_key == identity.daily_compressed_pubkey:
            raise ValueError("replacement daily key must change")
        if (
            kind == PENDING_ROUTINE
            and replacement_recovery_bls_pubkey is not None
        ):
            raise ValueError(
                "routine rotation cannot also change the recovery key"
            )

    prefix = eip712_prefix_and_domain_separator(
        genesis_challenge_for_network(network)
    )
    replacement_daily_member = make_eip712_member_v2_puzzle(
        secp256k1_pubkey=replacement_daily_key,
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
        LOST_KEY_DELAY_SECONDS
        if kind == PENDING_LOST
        else ROUTINE_DELAY_SECONDS
    )
    completion_message = _compute_completion_message_fields(
        pending_kind=kind,
        pending_slot=identity.slot,
        pending_intent_hash=intent_hash,
        pending_original_custody_hash=identity.custody_hash,
        pending_replacement_custody_hash=final_custody_hash,
        pending_replacement_member_hash=replacement_member_hash,
        source_manifest_hash=source_manifest_hash,
    )
    cancel_message = _compute_cancel_message_fields(
        pending_kind=kind,
        pending_slot=identity.slot,
        pending_intent_hash=intent_hash,
        pending_original_custody_hash=identity.custody_hash,
        pending_replacement_custody_hash=final_custody_hash,
        pending_replacement_member_hash=replacement_member_hash,
        source_manifest_hash=source_manifest_hash,
    )
    finish_member_reveal = build_identity_terminal_action_puzzle(
        action_tag=ID_ACTION_COMPLETE,
        output_custody_hash=final_custody_hash,
        coin_announcement_message=completion_message,
        amount=identity.launcher_amount,
        delay_seconds=delay,
    )
    timelock = Program.from_bytes(puzzle_mods.TIMELOCK).curry(delay)
    finish_member = _ProgramMember(finish_member_reveal)
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
    finish_member_hash = bytes32(finish_member_reveal.get_tree_hash())
    finish_member_branch_hash = finish_member_branch.puzzle_hash(
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
        original_custody_hash=identity.custody_hash,
        intermediate_custody_hash=intermediate_custody_hash,
        replacement_custody_hash=final_custody_hash,
        replacement_member_hash=replacement_member_hash,
        source_manifest_hash=source_manifest_hash,
        current_authority_version=current_state.authority_version,
        new_authority_version=current_state.authority_version + 1,
        identity_launcher_id=identity.launcher_id,
    )
    authority_prepare_action = build_authority_action_puzzle(
        action_tag=(
            SPEND_PREPARE_LOST
            if kind == PENDING_LOST
            else (
                SPEND_PREPARE_KIT
                if kind == PENDING_RECOVERY_KIT
                else SPEND_PREPARE_ROUTINE
            )
        ),
        binding_hash=binding,
    )
    authority_prepare_action_hash = bytes32(
        authority_prepare_action.get_tree_hash()
    )
    target_prepare_message = bytes32(
        Program.to(
            (
                [
                    ID_ACTION_PREPARE,
                    intermediate_custody_hash,
                    identity.launcher_amount,
                ]
                if kind == PENDING_LOST
                else [
                    ID_ACTION_PREPARE,
                    kind,
                    identity.slot,
                    intent_hash,
                    current_identity_coin_id,
                    intermediate_coin_id,
                    intermediate_custody_hash,
                    final_custody_hash,
                    source_manifest_hash,
                ]
            )
        ).get_tree_hash()
    )
    if kind == PENDING_LOST:
        prepare_delegated_puzzle = _quoted_conditions(
            (
                (51, intermediate_custody_hash, identity.launcher_amount),
                (
                    63,
                    _puzzle_announcement_id(
                        current_authority_full_puzzle_hash,
                        binding,
                    ),
                ),
                (60, target_prepare_message),
                (70, current_identity_coin_id),
                (72, identity.full_puzzle_hash),
                (73, identity.launcher_amount),
            )
        )
    else:
        prepare_delegated_puzzle = build_identity_action_puzzle(
            action_tag=ID_ACTION_PREPARE,
            output_custody_hash=intermediate_custody_hash,
            authority_full_puzzle_hash=(
                current_authority_full_puzzle_hash
            ),
            authority_delegated_puzzle_hash=(
                authority_prepare_action_hash
            ),
            authority_announcement_message=binding,
            coin_announcement_message=target_prepare_message,
            identity_full_puzzle_hash=identity.full_puzzle_hash,
            amount=identity.launcher_amount,
        )

    pending_custodies = list(current_state.current_identity_custody_hashes)
    pending_custodies[identity.slot] = intermediate_custody_hash
    pending_state = AdminAuthorityV3State(
        current_identity_custody_hashes=tuple(pending_custodies),  # type: ignore[arg-type]
        authority_version=current_state.authority_version + 1,
        pending_kind=kind,
        pending_slot=identity.slot,
        pending_intent_hash=intent_hash,
        pending_identity_coin_id=intermediate_coin_id,
        pending_original_custody_hash=identity.custody_hash,
        pending_replacement_custody_hash=final_custody_hash,
        pending_replacement_member_hash=replacement_member_hash,
        pending_delay_seconds=delay,
    )
    pending_authority_inner = make_inner_puzzle(
        authority_launcher_id=authority_launcher_id,
        operational_root_hash=parsed_authority.operational_root_hash,
        lost_recovery_root_hashes=(
            parsed_authority.lost_recovery_root_hashes
        ),
        identity_launcher_ids=parsed_authority.identity_launcher_ids,
        source_manifest_hash=source_manifest_hash,
        state=pending_state,
    )
    pending_authority_full_puzzle_hash = singleton_full_puzzle_hash(
        authority_launcher_id,
        bytes32(pending_authority_inner.get_tree_hash()),
    )
    authority_cancel_action = build_authority_action_puzzle(
        action_tag=SPEND_CANCEL,
        binding_hash=cancel_message,
    )
    authority_cancel_action_hash = bytes32(
        authority_cancel_action.get_tree_hash()
    )
    cancel_identity_action = build_identity_action_puzzle(
        action_tag=ID_ACTION_CANCEL,
        output_custody_hash=identity.custody_hash,
        authority_full_puzzle_hash=pending_authority_full_puzzle_hash,
        authority_delegated_puzzle_hash=authority_cancel_action_hash,
        authority_announcement_message=None,
        coin_announcement_message=cancel_message,
        identity_full_puzzle_hash=intermediate_full_puzzle_hash,
        amount=identity.launcher_amount,
    )

    return IdentityVaultTransition(
        kind=kind,
        slot=identity.slot,
        delay_seconds=delay,
        current_identity_coin_id=current_identity_coin_id,
        intermediate_identity_coin_id=intermediate_coin_id,
        intent_hash=intent_hash,
        original_custody_hash=identity.custody_hash,
        replacement_daily_compressed_pubkey=replacement_daily_key,
        replacement_daily_member_reveal=replacement_daily_member,
        replacement_daily_member_hash=replacement_member_hash,
        replacement_recovery_bls_pubkey=recovery_pubkey,
        final_custody_policy=final_policy,
        final_custody_root=final_root,
        final_custody_reveal=final_reveal,
        final_custody_hash=final_custody_hash,
        final_full_puzzle_hash=final_full_puzzle_hash,
        completion_message=completion_message,
        cancel_message=cancel_message,
        authority_current_inner_puzzle=authority_current_inner_puzzle,
        authority_current_full_puzzle_hash=(
            current_authority_full_puzzle_hash
        ),
        authority_prepare_action=authority_prepare_action,
        authority_prepare_action_hash=authority_prepare_action_hash,
        authority_pending_state=pending_state,
        authority_pending_inner_puzzle=pending_authority_inner,
        authority_pending_full_puzzle_hash=(
            pending_authority_full_puzzle_hash
        ),
        authority_cancel_action=authority_cancel_action,
        authority_cancel_action_hash=authority_cancel_action_hash,
        target_prepare_message=target_prepare_message,
        finish_member_reveal=finish_member_reveal,
        finish_member_branch=finish_member_branch,
        finish_member_hash=finish_member_hash,
        finish_member_branch_hash=finish_member_branch_hash,
        cancel_identity_action=cancel_identity_action,
        cancel_identity_action_hash=bytes32(
            cancel_identity_action.get_tree_hash()
        ),
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
                [transition.finish_member_hash]
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

    finish_solution = transition.finish_member_branch.solve(
        [Program.to(None)],
        [],
        Program.to([transition.intermediate_identity_coin_id]),
    )
    policy_solution = transition.intermediate_custody_policy.solve(
        {
            transition.finish_member_branch_hash: ProvenSpend(
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


def _build_daily_path_identity_solution(
    *,
    daily_path: MofN,
    daily_path_branch: PuzzleWithRestrictions,
    custody_policy: MofN,
    custody_root: PuzzleWithRestrictions,
    daily_member_solution: Program,
    authority_inner_puzzle_hash: bytes32,
    authority_amount: int,
    delegated_puzzle: Program,
    delegated_solution: Program,
) -> Program:
    """Solve a daily-key plus authority-singleton identity path."""

    if authority_amount <= 0 or authority_amount % 2 == 0:
        raise ValueError("authority singleton amount must be positive and odd")
    if len(daily_path.members) != 2:
        raise ValueError("daily identity path must have exactly two members")
    daily_member_branch = daily_path.members[0]
    authority_member_branch = daily_path.members[1]
    daily_branch_solution = daily_member_branch.solve(
        [],
        [],
        daily_member_solution,
    )
    authority_branch_solution = authority_member_branch.solve(
        [],
        [],
        Program.to([authority_inner_puzzle_hash, authority_amount]),
    )
    daily_path_solution = daily_path.solve(
        {
            daily_member_branch.puzzle_hash(
                _top_level=False
            ): ProvenSpend(
                puzzle_reveal=daily_member_branch.puzzle_reveal(
                    _top_level=False
                ),
                solution=daily_branch_solution,
            ),
            authority_member_branch.puzzle_hash(
                _top_level=False
            ): ProvenSpend(
                puzzle_reveal=authority_member_branch.puzzle_reveal(
                    _top_level=False
                ),
                solution=authority_branch_solution,
            ),
        }
    )
    daily_path_branch_solution = daily_path_branch.solve(
        [],
        [],
        daily_path_solution,
    )
    policy_solution = custody_policy.solve(
        {
            daily_path_branch.puzzle_hash(
                _top_level=False
            ): ProvenSpend(
                puzzle_reveal=daily_path_branch.puzzle_reveal(
                    _top_level=False
                ),
                solution=daily_path_branch_solution,
            )
        }
    )
    return custody_root.solve(
        [],
        [],
        policy_solution,
        DelegatedPuzzleAndSolution(
            puzzle=delegated_puzzle,
            solution=delegated_solution,
        ),
    )


def build_routine_identity_prepare_solution(
    *,
    identity: IdentityVaultGenesis,
    transition: IdentityVaultTransition,
    daily_member_solution: Program,
    authority_amount: int = AUTHORITY_LAUNCHER_AMOUNT,
) -> Program:
    """Build the target identity spend for routine or kit rotation."""

    if transition.kind not in (
        PENDING_ROUTINE,
        PENDING_RECOVERY_KIT,
    ):
        raise ValueError("target prepare requires routine or recovery-kit kind")
    if transition.slot != identity.slot:
        raise ValueError("identity transition does not match target slot")
    return _build_daily_path_identity_solution(
        daily_path=identity.daily_path,
        daily_path_branch=identity.daily_path_branch,
        custody_policy=identity.custody_policy,
        custody_root=identity.custody_root,
        daily_member_solution=daily_member_solution,
        authority_inner_puzzle_hash=bytes32(
            transition.authority_current_inner_puzzle.get_tree_hash()
        ),
        authority_amount=authority_amount,
        delegated_puzzle=transition.prepare_delegated_puzzle,
        delegated_solution=Program.to(
            [transition.current_identity_coin_id]
        ),
    )


def build_identity_approval_action(
    *,
    identity: IdentityVaultGenesis,
    transition: IdentityVaultTransition,
) -> Program:
    """Build one unchanged identity continuation approving a key change."""

    parsed = parse_inner_puzzle(transition.authority_current_inner_puzzle)
    if (
        parsed.state.current_identity_custody_hashes[identity.slot]
        != identity.custody_hash
    ):
        raise ValueError("approving identity is not current in authority state")
    return build_identity_action_puzzle(
        action_tag=ID_ACTION_APPROVE,
        output_custody_hash=identity.custody_hash,
        authority_full_puzzle_hash=(
            transition.authority_current_full_puzzle_hash
        ),
        authority_delegated_puzzle_hash=(
            transition.authority_prepare_action_hash
        ),
        authority_announcement_message=transition.prepare_binding_hash,
        coin_announcement_message=None,
        identity_full_puzzle_hash=identity.full_puzzle_hash,
        amount=identity.launcher_amount,
    )


def build_identity_approval_solution(
    *,
    identity: IdentityVaultGenesis,
    transition: IdentityVaultTransition,
    current_identity_coin_id: bytes32,
    daily_member_solution: Program,
    authority_amount: int = AUTHORITY_LAUNCHER_AMOUNT,
) -> Program:
    """Build a daily-key identity continuation approving a peer's change."""

    if current_identity_coin_id == ZERO_32:
        raise ValueError("approving identity coin id must be nonzero")
    action = build_identity_approval_action(
        identity=identity,
        transition=transition,
    )
    return _build_daily_path_identity_solution(
        daily_path=identity.daily_path,
        daily_path_branch=identity.daily_path_branch,
        custody_policy=identity.custody_policy,
        custody_root=identity.custody_root,
        daily_member_solution=daily_member_solution,
        authority_inner_puzzle_hash=bytes32(
            transition.authority_current_inner_puzzle.get_tree_hash()
        ),
        authority_amount=authority_amount,
        delegated_puzzle=action,
        delegated_solution=Program.to([current_identity_coin_id]),
    )


def _solve_singleton_identity_branch(
    *,
    branch: PuzzleWithRestrictions,
    identity: IdentityVaultGenesis,
) -> Program:
    return branch.solve(
        [],
        [],
        Program.to([identity.custody_hash, identity.launcher_amount]),
    )


def build_authority_prepare_mips_spend(
    *,
    authority: GenesisAdminAuthorityV3,
    transition: IdentityVaultTransition,
    current_identities: Sequence[IdentityVaultGenesis],
    current_identity_coin_ids: Sequence[bytes32],
    coadmin_slot: int | None = None,
) -> AuthorityMipsSpend:
    """Build the fixed constitutional MIPS proof for one key-change prepare."""

    if len(current_identities) != 3 or len(current_identity_coin_ids) != 3:
        raise ValueError("Authority V3 requires exactly three current identities")
    identities = tuple(current_identities)
    coin_ids = tuple(bytes32(value) for value in current_identity_coin_ids)
    if tuple(identity.slot for identity in identities) != (0, 1, 2):
        raise ValueError("current identities must be ordered by slot")
    if any(value == ZERO_32 for value in coin_ids):
        raise ValueError("current identity coin ids must be nonzero")
    parsed = parse_inner_puzzle(transition.authority_current_inner_puzzle)
    if parsed.authority_launcher_id != authority.authority_launcher_id:
        raise ValueError("transition authority launcher does not match policy")
    if parsed.operational_root_hash != authority.operational_root_hash:
        raise ValueError("transition operational root does not match policy")
    if (
        parsed.lost_recovery_root_hashes
        != authority.lost_recovery_root_hashes
    ):
        raise ValueError("transition recovery roots do not match policy")
    if tuple(identity.launcher_id for identity in identities) != (
        parsed.identity_launcher_ids
    ):
        raise ValueError("current identity launchers do not match authority")
    if tuple(identity.custody_hash for identity in identities) != (
        parsed.state.current_identity_custody_hashes
    ):
        raise ValueError("current identity custody hashes do not match authority")

    delegated = DelegatedPuzzleAndSolution(
        puzzle=transition.authority_prepare_action,
        solution=Program.to(None),
    )
    if transition.kind == PENDING_LOST:
        selected_slots = tuple(
            slot for slot in range(3) if slot != transition.slot
        )
        policy = authority.lost_recovery_policies[transition.slot]
        root = authority.lost_recovery_roots[transition.slot]
        proven: dict[bytes32, ProvenSpend] = {}
        for branch, slot in zip(
            policy.members,
            selected_slots,
            strict=True,
        ):
            branch_solution = _solve_singleton_identity_branch(
                branch=branch,
                identity=identities[slot],
            )
            proven[
                branch.puzzle_hash(_top_level=False)
            ] = ProvenSpend(
                puzzle_reveal=branch.puzzle_reveal(_top_level=False),
                solution=branch_solution,
            )
        policy_solution = policy.solve(proven)
    else:
        if transition.slot == 0:
            selected_coadmin = 1 if coadmin_slot is None else coadmin_slot
            if selected_coadmin not in (1, 2):
                raise ValueError("owner rotation requires coadmin slot 1 or 2")
        else:
            selected_coadmin = transition.slot
            if coadmin_slot is not None and coadmin_slot != selected_coadmin:
                raise ValueError(
                    "coadmin rotation must be approved by that coadmin and owner"
                )
        selected_slots = (0, selected_coadmin)
        policy = authority.operational_policy
        root = authority.operational_root
        owner_branch = policy.members[0]
        coadmin_container = policy.members[1]
        owner_solution = _solve_singleton_identity_branch(
            branch=owner_branch,
            identity=identities[0],
        )
        coadmin_policy = coadmin_container.puzzle
        if not isinstance(coadmin_policy, MofN):
            raise ValueError("operational coadmin branch is not a MIPS policy")
        coadmin_branch = coadmin_policy.members[selected_coadmin - 1]
        coadmin_solution = _solve_singleton_identity_branch(
            branch=coadmin_branch,
            identity=identities[selected_coadmin],
        )
        coadmin_policy_solution = coadmin_policy.solve(
            {
                coadmin_branch.puzzle_hash(
                    _top_level=False
                ): ProvenSpend(
                    puzzle_reveal=coadmin_branch.puzzle_reveal(
                        _top_level=False
                    ),
                    solution=coadmin_solution,
                )
            }
        )
        coadmin_container_solution = coadmin_container.solve(
            [],
            [],
            coadmin_policy_solution,
        )
        policy_solution = policy.solve(
            {
                owner_branch.puzzle_hash(
                    _top_level=False
                ): ProvenSpend(
                    puzzle_reveal=owner_branch.puzzle_reveal(
                        _top_level=False
                    ),
                    solution=owner_solution,
                ),
                coadmin_container.puzzle_hash(
                    _top_level=False
                ): ProvenSpend(
                    puzzle_reveal=coadmin_container.puzzle_reveal(
                        _top_level=False
                    ),
                    solution=coadmin_container_solution,
                ),
            }
        )

    root_solution = root.solve(
        [],
        [],
        policy_solution,
        delegated,
    )
    return AuthorityMipsSpend(
        reveal=root.puzzle_reveal(),
        solution=root_solution,
        identity_records=tuple(  # type: ignore[arg-type]
            (slot, coin_ids[slot]) for slot in selected_slots
        ),
        selected_slots=selected_slots,  # type: ignore[arg-type]
    )


def build_identity_cancel_solution(
    *,
    identity: IdentityVaultGenesis,
    transition: IdentityVaultTransition,
    daily_member_solution: Program,
    authority_amount: int = AUTHORITY_LAUNCHER_AMOUNT,
) -> Program:
    """Build the exact old-daily-key veto spend for an intermediate vault."""

    if transition.slot != identity.slot:
        raise ValueError("identity transition does not match target slot")
    return _build_daily_path_identity_solution(
        daily_path=identity.daily_path,
        daily_path_branch=identity.daily_path_branch,
        custody_policy=transition.intermediate_custody_policy,
        custody_root=transition.intermediate_custody_root,
        daily_member_solution=daily_member_solution,
        authority_inner_puzzle_hash=bytes32(
            transition.authority_pending_inner_puzzle.get_tree_hash()
        ),
        authority_amount=authority_amount,
        delegated_puzzle=transition.cancel_identity_action,
        delegated_solution=Program.to(
            [transition.intermediate_identity_coin_id]
        ),
    )


def build_operational_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    mips_reveal: Program,
    mips_solution: Program,
    authority_delegated_puzzle: Program,
    identity_records: Sequence[tuple[int, bytes32]],
) -> Program:
    return Program.to(
        [
            SPEND_OPERATIONAL,
            my_amount,
            new_authority_version,
            [
                mips_reveal,
                mips_solution,
                bytes32(authority_delegated_puzzle.get_tree_hash()),
                [[slot, coin_id] for slot, coin_id in identity_records],
            ],
        ]
    )


def build_prepare_solution(
    *,
    transition: IdentityVaultTransition,
    my_amount: int,
    new_authority_version: int,
    mips_reveal: Program,
    mips_solution: Program,
    replacement_member_solution: Program,
    identity_records: Sequence[tuple[int, bytes32]],
) -> Program:
    expected_version = (
        parse_inner_puzzle(
            transition.authority_current_inner_puzzle
        ).state.authority_version
        + 1
    )
    if new_authority_version != expected_version:
        raise ValueError("prepare must advance authority version exactly once")
    if bytes32(
        transition.replacement_daily_member_reveal.get_tree_hash()
    ) != transition.replacement_daily_member_hash:
        raise ValueError("replacement member hash does not match its reveal")
    spend_tag = (
        SPEND_PREPARE_LOST
        if transition.kind == PENDING_LOST
        else (
            SPEND_PREPARE_KIT
            if transition.kind == PENDING_RECOVERY_KIT
            else SPEND_PREPARE_ROUTINE
        )
    )
    return Program.to(
        [
            spend_tag,
            my_amount,
            new_authority_version,
            [
                mips_reveal,
                mips_solution,
                transition.replacement_daily_member_reveal,
                replacement_member_solution,
                transition.authority_prepare_action_hash,
                [
                    [slot, coin_id]
                    for slot, coin_id in identity_records
                ],
                [
                    transition.slot,
                    transition.intent_hash,
                    transition.current_identity_coin_id,
                    transition.intermediate_identity_coin_id,
                    transition.intermediate_custody_hash,
                    transition.final_custody_hash,
                ],
            ],
        ]
    )


def build_cancel_solution(
    *,
    my_amount: int,
    new_authority_version: int,
) -> Program:
    return Program.to(
        [
            SPEND_CANCEL,
            my_amount,
            new_authority_version,
            [],
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
    "AuthorityMipsSpend",
    "GenesisAdminAuthorityV3",
    "IdentityVaultGenesis",
    "IdentityVaultTransition",
    "IDENTITY_LAUNCHER_AMOUNTS",
    "LOST_KEY_DELAY_SECONDS",
    "PENDING_LOST",
    "PENDING_NONE",
    "PENDING_RECOVERY_KIT",
    "PENDING_ROUTINE",
    "PINNED_CNI_WALLET_SDK_COMMIT",
    "PINNED_CNI_WALLET_SDK_REPOSITORY",
    "RECOVERY_DEPENDENCY_MANIFEST_HASH",
    "ParsedAdminAuthorityV3",
    "ROUTINE_DELAY_SECONDS",
    "SPEND_CANCEL",
    "SPEND_COMPLETE",
    "SPEND_OPERATIONAL",
    "SPEND_PREPARE_LOST",
    "SPEND_PREPARE_KIT",
    "SPEND_PREPARE_ROUTINE",
    "admin_authority_action_v1_mod",
    "admin_authority_v3_inner_mod",
    "admin_authority_v3_inner_mod_hash",
    "admin_identity_action_v1_mod",
    "admin_identity_prepare_announcement_v1_mod",
    "admin_identity_terminal_action_v1_mod",
    "authority_v3_launcher_ids",
    "build_authority_action_puzzle",
    "build_authority_prepare_mips_spend",
    "build_cancel_solution",
    "build_complete_solution",
    "build_admin_identity_vault",
    "build_genesis_admin_authority_v3",
    "build_identity_action_puzzle",
    "build_identity_approval_action",
    "build_identity_approval_solution",
    "build_identity_cancel_solution",
    "build_identity_finish_solution",
    "build_identity_vault_transition",
    "build_lost_recovery_identity_solution",
    "build_operational_solution",
    "build_prepare_solution",
    "build_routine_identity_prepare_solution",
    "compute_cancel_message",
    "compute_completion_message",
    "compute_prepare_binding_hash",
    "make_inner_puzzle",
    "parse_inner_puzzle",
]
