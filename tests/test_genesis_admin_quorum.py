from __future__ import annotations

import pytest
import chia_rs
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.custody.custody_architecture import (
    MofN,
    NofN_MOD,
    OneOfN_MOD,
    ProvenSpend,
)
from eth_keys import keys
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v2_driver import (
    build_genesis_eip712_admin_quorum,
    compute_admins_hash,
)
from solslot_puzzles.eip712_helpers import (
    eip712_hash_to_sign,
    eip712_prefix_and_domain_separator,
    genesis_challenge_for_network,
)


PUBKEYS = (
    bytes.fromhex("02" + "11" * 32),
    bytes.fromhex("03" + "22" * 32),
    bytes.fromhex("02" + "33" * 32),
)

EIP712_RUN_FLAGS = (
    chia_rs.MEMPOOL_MODE
    | chia_rs.ENABLE_SECP_OPS
    | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD
)
DELEGATED_PUZZLE_HASH = bytes32(b"\x55" * 32)


def _runtime_quorum():
    private_keys = tuple(keys.PrivateKey(bytes([index]) * 32) for index in (1, 2, 3))
    public_keys = tuple(key.public_key.to_compressed_bytes() for key in private_keys)
    return private_keys, build_genesis_eip712_admin_quorum(
        network="testnet11",
        compressed_pubkeys=public_keys,
    )


def _member_solution(private_key: keys.PrivateKey, *, coin_id: bytes32) -> Program:
    signed_hash = eip712_hash_to_sign(
        eip712_prefix_and_domain_separator(genesis_challenge_for_network("testnet11")),
        coin_id,
        DELEGATED_PUZZLE_HASH,
    )
    signature = private_key.sign_msg_hash(bytes(signed_hash)).to_bytes()[:64]
    # Bare MofN prepends the shared delegated-puzzle hash before executing
    # each selected member, so an Eip712Member contributes only its remainder.
    return Program.to([coin_id, signed_hash, signature])


def _coadmin_branch_solution(quorum, private_keys, *, coadmin_offset: int) -> Program:
    coadmin_branch = quorum.mips_policy.members[1]
    coadmin_policy = coadmin_branch.puzzle
    assert isinstance(coadmin_policy, MofN)
    selected = coadmin_policy.members[coadmin_offset]
    selected_solution = _member_solution(
        private_keys[coadmin_offset + 1],
        coin_id=bytes32(bytes([0x72 + coadmin_offset]) * 32),
    )
    one_of_two_solution = coadmin_policy.solve(
        {
            selected.puzzle_hash(_top_level=False): ProvenSpend(
                puzzle_reveal=selected.puzzle_reveal(_top_level=False),
                solution=selected_solution,
            )
        }
    )
    return coadmin_branch.solve([], [], one_of_two_solution)


def test_genesis_admin_quorum_requires_owner_and_one_coadmin() -> None:
    quorum = build_genesis_eip712_admin_quorum(
        network="testnet11",
        compressed_pubkeys=PUBKEYS,
    )

    assert quorum.threshold == 2
    assert quorum.owner_index == 0
    assert quorum.coadmin_indices == (1, 2)
    assert quorum.coadmin_threshold == 1
    assert [admin.admin_idx for admin in quorum.admins] == [0, 1, 2]
    assert all(admin.m_within == 1 for admin in quorum.admins)
    assert quorum.admins_hash == compute_admins_hash(quorum.admins)
    assert quorum.mips_root_hash == bytes32(quorum.mips_reveal.get_tree_hash())

    uncurried = quorum.mips_reveal.uncurry()
    assert uncurried is not None
    mod, args = uncurried
    assert bytes32(mod.get_tree_hash()) == bytes32(NofN_MOD.get_tree_hash())
    branches = list(list(args.as_iter())[0].as_iter())
    assert len(branches) == 2
    coadmin_wrapper = branches[1].uncurry()
    assert coadmin_wrapper is not None
    _wrapper_mod, wrapper_args = coadmin_wrapper
    coadmin_policy = list(wrapper_args.as_iter())[1]
    coadmin_uncurried = coadmin_policy.uncurry()
    assert coadmin_uncurried is not None
    coadmin_mod, _coadmin_args = coadmin_uncurried
    assert bytes32(coadmin_mod.get_tree_hash()) == bytes32(OneOfN_MOD.get_tree_hash())


@pytest.mark.parametrize("coadmin_offset", [0, 1])
def test_genesis_admin_quorum_executes_only_owner_plus_one_coadmin(
    coadmin_offset: int,
) -> None:
    private_keys, quorum = _runtime_quorum()
    owner_branch = quorum.mips_policy.members[0]
    coadmin_branch = quorum.mips_policy.members[1]
    owner_solution = _member_solution(
        private_keys[0], coin_id=bytes32(b"\x71" * 32)
    )
    coadmin_solution = _coadmin_branch_solution(
        quorum, private_keys, coadmin_offset=coadmin_offset
    )
    solution = quorum.mips_policy.solve(
        {
            owner_branch.puzzle_hash(_top_level=False): ProvenSpend(
                puzzle_reveal=owner_branch.puzzle_reveal(_top_level=False),
                solution=owner_solution,
            ),
            coadmin_branch.puzzle_hash(_top_level=False): ProvenSpend(
                puzzle_reveal=coadmin_branch.puzzle_reveal(_top_level=False),
                solution=coadmin_solution,
            ),
        }
    )

    mips_solution = Program.to([DELEGATED_PUZZLE_HASH, *solution.as_iter()])
    conditions = list(
        quorum.mips_reveal.run(mips_solution, flags=EIP712_RUN_FLAGS).as_iter()
    )
    asserted_coin_ids = {
        condition.rest().first().atom
        for condition in conditions
        if condition.first().as_int() == 73
        and condition.rest().first().atom is not None
        and len(condition.rest().first().atom) == 32
    }
    assert bytes(b"\x71" * 32) in asserted_coin_ids
    assert bytes([0x72 + coadmin_offset]) * 32 in asserted_coin_ids


def test_genesis_admin_quorum_rejects_both_coadmins_without_owner() -> None:
    private_keys, quorum = _runtime_quorum()
    coadmin_one_solution = _member_solution(
        private_keys[1], coin_id=bytes32(b"\x72" * 32)
    )
    coadmin_two_branch_solution = _coadmin_branch_solution(
        quorum, private_keys, coadmin_offset=1
    )

    # N-of-N always runs the first solution against the slot-0 member puzzle.
    # Supplying a valid slot-1 signature there must fail secp256k1 verification.
    coadmins_only = Program.to(
        [
            DELEGATED_PUZZLE_HASH,
            [coadmin_one_solution, coadmin_two_branch_solution],
        ]
    )
    with pytest.raises(Exception):
        quorum.mips_reveal.run(coadmins_only, flags=EIP712_RUN_FLAGS)


@pytest.mark.parametrize(
    "pubkeys,match",
    [
        (PUBKEYS[:2], "exactly three"),
        (PUBKEYS + (bytes.fromhex("03" + "44" * 32),), "exactly three"),
        ((PUBKEYS[0], PUBKEYS[0], PUBKEYS[2]), "distinct"),
        ((b"short", PUBKEYS[1], PUBKEYS[2]), "33-byte"),
    ],
)
def test_genesis_admin_quorum_rejects_noncanonical_rosters(
    pubkeys: tuple[bytes, ...], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        build_genesis_eip712_admin_quorum(
            network="testnet11",
            compressed_pubkeys=pubkeys,
        )


def test_genesis_admin_quorum_is_network_bound() -> None:
    testnet = build_genesis_eip712_admin_quorum(
        network="testnet11", compressed_pubkeys=PUBKEYS
    )
    mainnet = build_genesis_eip712_admin_quorum(
        network="mainnet", compressed_pubkeys=PUBKEYS
    )
    assert testnet.member_puzzle_hashes != mainnet.member_puzzle_hashes
    assert testnet.mips_root_hash != mainnet.mips_root_hash
