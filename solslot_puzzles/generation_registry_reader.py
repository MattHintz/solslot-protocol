"""Reconstruct registry successors from confirmed spends, not their old curry.

The RPC may return a spent parent's puzzle. Decoding that puzzle alone reports
stale versions. This reader executes the spend, projects its typed transition,
and requires the reconstructed state to match the actual singleton output.
It constructs no spend bundle and cannot reserve, sign or submit anything.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_MOD_HASH, puzzle_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import (
    CodeChange, Component, Registry, UpgradePlan, singleton_struct,
)

MAX_REGISTRY_SPEND_COST = 2_000_000_000
MAX_COMPONENTS = 32


def exact_list(program: Program, length: int) -> list[Program]:
    values = list(program.as_iter())
    if len(values) != length or Program.to(values) != program:
        raise ValueError('registry evidence has a noncanonical list shape')
    return values


def uint(program: Program) -> int:
    value = program.as_int()
    if not 0 <= value < 2**64 or Program.to(value) != program:
        raise ValueError('registry evidence requires canonical uint64 values')
    return value


def parse_upgrade_plan(program: Program) -> UpgradePlan:
    source, raw_changes = exact_list(program, 2)
    changes = list(raw_changes.as_iter())
    if not 0 < len(changes) <= MAX_COMPONENTS:
        raise ValueError('registry upgrade exceeds the affected-component bound')
    result = []
    for raw in changes:
        identity, old, new, version, compatibility, policy = exact_list(raw, 6)
        if policy.as_atom() != b'PRESERVE_STATE':
            raise ValueError('registry upgrade changes the state policy')
        result.append(CodeChange(bytes32(identity.as_atom()), bytes32(old.as_atom()),
            bytes32(new.as_atom()), uint(version), uint(compatibility)))
    plan = UpgradePlan(bytes32(source.as_atom()), tuple(result))
    if Program.to(plan.program()) != program:
        raise ValueError('registry upgrade is not canonical')
    return plan


def decode_registry_inner(inner: Program, *, generation: bytes32, launcher_id: bytes32,
                          governance_id: bytes32, administrator_id: bytes32) -> Registry:
    mod, raw_args = inner.uncurry()
    expected = load_puzzle('generation_registry_v1.clsp').get_tree_hash()
    if mod.get_tree_hash() != expected:
        raise ValueError('registry module differs from the frozen kernel')
    (self_hash, gen, mine, governance, administrator, ticket, components, nonce,
     pending, mask, epoch, reopening) = exact_list(raw_args, 12)
    if (self_hash.as_atom() != expected or gen.as_atom() != generation
            or mine != singleton_struct(launcher_id) or governance != singleton_struct(governance_id)
            or administrator != singleton_struct(administrator_id)
            or ticket.as_atom() != load_puzzle('generation_delay_ticket_v1.clsp').get_tree_hash()):
        raise ValueError('registry authority or deployment binding changed')
    entries = list(components.as_iter())
    if not 0 < len(entries) <= MAX_COMPONENTS:
        raise ValueError('registry component inventory exceeds the bound')
    parsed = []
    for item in entries:
        identity, launcher, kernel, module, version, compatibility = exact_list(item, 6)
        parsed.append(Component(bytes32(identity.as_atom()), bytes32(launcher.as_atom()),
            bytes32(kernel.as_atom()), bytes32(module.as_atom()), uint(version), uint(compatibility)))
    waiting = () if pending == Program.to([]) else tuple(bytes32(p.as_atom()) for p in exact_list(pending, 2))
    reopen = ()
    if reopening != Program.to([]):
        plan_hash, ticket_id, scope, pause_epoch = exact_list(reopening, 4)
        reopen = (bytes32(plan_hash.as_atom()), bytes32(ticket_id.as_atom()), uint(scope), uint(pause_epoch))
        if not 0 < reopen[2] < 32 or reopen[3] != uint(epoch) or uint(mask) & reopen[2] != reopen[2]:
            raise ValueError('registry reopening is inconsistent with the paused scope')
    state = Registry(generation, launcher_id, governance_id, administrator_id, tuple(parsed),
        uint(nonce), waiting, uint(mask), uint(epoch), reopen)
    if state.inner() != inner:
        raise ValueError('registry state cannot be reproduced exactly')
    return state


@dataclass(frozen=True)
class RegistryTransition:
    action: str
    before: Registry
    after: Registry
    successor: Coin
    auxiliary_outputs: tuple[Coin, ...]
    cost: int


def reconstruct_registry_successor(spend: CoinSpend, expected: Registry) -> RegistryTransition:
    full = Program.from_bytes(bytes(spend.puzzle_reveal))
    if full.get_tree_hash() != spend.coin.puzzle_hash or spend.coin.amount != 1:
        raise ValueError('registry reveal differs from the confirmed input')
    mod, args = full.uncurry()
    if mod.get_tree_hash() != SINGLETON_MOD_HASH:
        raise ValueError('registry evidence does not use the canonical singleton')
    structure, inner = exact_list(args, 2)
    if structure != singleton_struct(expected.launcher_id):
        raise ValueError('registry evidence substituted the singleton identity')
    before = decode_registry_inner(inner, generation=expected.generation, launcher_id=expected.launcher_id,
        governance_id=expected.governance_id, administrator_id=expected.administrator_id)
    if before != expected:
        raise ValueError('registry spend does not continue the last verified state')
    _, amount, raw_solution = exact_list(Program.from_bytes(bytes(spend.solution)), 3)
    action, my_id, action_args = exact_list(raw_solution, 3)
    if uint(amount) != 1 or my_id.as_atom() != spend.coin.name():
        raise ValueError('registry spend identifies a different input')
    tag = action.as_atom()
    if tag == b'RATIFY_UPGRADE':
        _, plan = exact_list(action_args, 2)
        after, _ = before.ratified(spend.coin, parse_upgrade_plan(plan))
    elif tag == b'ACTIVATE':
        plan, _, _ = exact_list(action_args, 3)
        after = before.activated(parse_upgrade_plan(plan))
    elif tag == b'PAUSE':
        _, scope = exact_list(action_args, 2)
        after = before.paused(uint(scope))
    elif tag == b'RATIFY_REOPEN':
        _, scope = exact_list(action_args, 2)
        after, _ = before.reopen_ratified(spend.coin, uint(scope))
    elif tag == b'REOPEN':
        exact_list(action_args, 0)
        after = before.reopened()
    elif tag == b'AUTHORIZE_NEW':
        exact_list(action_args, 4)
        after = before
    else:
        raise ValueError('unsupported registry transition')
    # This is native puzzle execution, not a coordinator-selected child hash.
    additions, cost = compute_additions_with_cost(spend, max_cost=MAX_REGISTRY_SPEND_COST)
    odd = [coin for coin in additions if coin.amount % 2]
    if (len(odd) != 1 or odd[0].amount != 1
            or odd[0].puzzle_hash != puzzle_for_singleton(after.launcher_id, after.inner()).get_tree_hash()):
        raise ValueError('reconstructed registry state differs from its actual output')
    return RegistryTransition(tag.decode('ascii'), before, after, odd[0],
        tuple(coin for coin in additions if coin != odd[0]), cost)
