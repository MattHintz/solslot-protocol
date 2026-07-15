from __future__ import annotations

import pytest
from chia.wallet.puzzles.custody.custody_architecture import MofN_MOD
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v2_driver import (
    build_genesis_eip712_admin_quorum,
    compute_admins_hash,
)


PUBKEYS = (
    bytes.fromhex("02" + "11" * 32),
    bytes.fromhex("03" + "22" * 32),
    bytes.fromhex("02" + "33" * 32),
)


def test_genesis_admin_quorum_is_canonical_two_of_three() -> None:
    quorum = build_genesis_eip712_admin_quorum(
        network="testnet11",
        compressed_pubkeys=PUBKEYS,
    )

    assert quorum.threshold == 2
    assert [admin.admin_idx for admin in quorum.admins] == [0, 1, 2]
    assert all(admin.m_within == 1 for admin in quorum.admins)
    assert quorum.admins_hash == compute_admins_hash(quorum.admins)
    assert quorum.mips_root_hash == bytes32(quorum.mips_reveal.get_tree_hash())

    uncurried = quorum.mips_reveal.uncurry()
    assert uncurried is not None
    mod, args = uncurried
    assert bytes32(mod.get_tree_hash()) == bytes32(MofN_MOD.get_tree_hash())
    assert list(args.as_iter())[0].as_int() == 2


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
