"""Replay confirmed governance transitions into exact current output state.

Opening supply, tally, deadlines and closure receipts come from consensus
spends. Local wall time and API settings never choose voting rules. This is
an evidence reader, not a validator for an unconfirmed transaction bundle.
"""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_governance import Governance, OpenProposal
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_registry_reader import exact_list, uint
from solslot_puzzles.holdings import SumNode, quorum

MAX_GOVERNANCE_READ_COST = 11_000_000_000


def ballot_weight(program: Program) -> int:
    rows = list(program.as_iter())
    if not 0 < len(rows) <= 256 or Program.to(rows) != program:
        raise ValueError('governance ballots exceed the canonical evidence bound')
    weight = 0
    for row in rows:
        coin, description, _, _ = exact_list(row, 4)
        bytes32(coin.as_atom())
        _, amount, _, _, _ = exact_list(description, 5)
        weight += uint(amount)
    return weight


@dataclass(frozen=True)
class GovernanceTransition:
    action: str
    before: Governance
    after: Governance
    successor: Coin
    auxiliary_outputs: tuple[Coin, ...]
    publication_issued_at: int | None = None
    publication_expires_at: int | None = None


def reconstruct_governance_successor(spend: CoinSpend, expected: Governance) -> GovernanceTransition:
    full = Program.from_bytes(bytes(spend.puzzle_reveal))
    module, raw = full.uncurry()
    if (module.get_tree_hash() != SINGLETON_MOD_HASH or full.get_tree_hash() != spend.coin.puzzle_hash
            or spend.coin.amount != 1):
        raise ValueError('governance evidence differs from the confirmed singleton input')
    structure, inner = exact_list(raw, 2)
    if structure != singleton_struct(expected.sgt.governance_launcher_id) or inner != expected.inner():
        raise ValueError('governance evidence does not continue the last verified state')
    _, amount, solution = exact_list(Program.from_bytes(bytes(spend.solution)), 3)
    action, my_id, args = exact_list(solution, 3)
    if uint(amount) != 1 or my_id.as_atom() != spend.coin.name():
        raise ValueError('governance solution identifies a different input')
    tag = action.as_atom()
    after = expected
    issued = expires = None
    if tag == b'OPEN':
        _, raw_issued, raw_expires, _, _, raw_root, sequence, bill, sponsors = exact_list(args, 9)
        root_hash, eligible, total = exact_list(raw_root, 3)
        root = SumNode(bytes32(root_hash.as_atom()), uint(eligible), uint(total))
        quorum(root.eligible)
        proposal = Program.to([b'HOLDER_PROPOSAL_V1', expected.sgt.generation, expected.nonce,
                               bill, root.program()]).get_tree_hash()
        clock = Coin(spend.coin.name(), expected.clock_puzzle(proposal).get_tree_hash(), uint64(0))
        after = replace(expected, nonce=expected.nonce + 1,
            active=OpenProposal(proposal, bill, root, uint(sequence), ballot_weight(sponsors), clock.name()),
            upgrade_reserved=expected.upgrade_reserved or bill.first().as_atom() == b'UPGRADE')
        issued, expires = uint(raw_issued), uint(raw_expires)
    elif tag == b'ANCHOR':
        born, = exact_list(args, 1)
        after = expected.anchored(uint(born))
    elif tag == b'VOTE':
        after = expected.voted(ballot_weight(args))
    elif tag == b'FINALIZE':
        exact_list(args, 2)
        after = expected.finalized()
    elif tag == b'EXECUTE':
        proposal, bill, _, _, _ = exact_list(args, 5)
        after = expected.executed(bytes32(proposal.as_atom()), bill)
    elif tag == b'UPGRADE':
        _, _, logic, version, compatibility = exact_list(args, 5)
        after = replace(expected, module_hash=bytes32(logic.as_atom()), version=uint(version),
                        compatibility=uint(compatibility))
    elif tag in (b'READ', b'ACTIVATION_CLEARANCE'):
        exact_list(args, 2)
    elif tag == b'UNLOCK':
        rows = list(args.as_iter())
        if not 0 < len(rows) <= 256 or Program.to(rows) != args:
            raise ValueError('governance unlock evidence exceeds the canonical bound')
    else:
        raise ValueError('unsupported governance transition')
    # Executes all Merkle proofs and immutable transition rules. Confirmed chain
    # evidence is additionally required by the caller for signatures, paired
    # spends and consensus timestamps; puzzle execution alone is not admission.
    additions, _ = compute_additions_with_cost(spend, max_cost=MAX_GOVERNANCE_READ_COST)
    successor = Coin(spend.coin.name(), puzzle_for_singleton(expected.sgt.governance_launcher_id,
                     after.inner()).get_tree_hash(), uint64(1))
    if [coin for coin in additions if coin.amount % 2] != [successor]:
        raise ValueError('governance reconstruction differs from the consensus successor')
    return GovernanceTransition(tag.decode('ascii'), expected, after, successor,
        tuple(coin for coin in additions if coin != successor), issued, expires)
