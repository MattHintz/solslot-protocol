"""Deterministic native governance transactions, with no keys or network I/O.

These builders consume exact reconstructed current states. Callers must verify
the inputs against the primary node and review any fee attachment before saving
or signing a bundle. A builder's next-state projection is not confirmation.
"""
from dataclasses import dataclass, field, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH, SINGLETON_MOD_HASH, lineage_proof_for_coinsol,
    puzzle_for_singleton, solution_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_mint import GenerationMint,TestMintEdition
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_registry import Component, Registry, UpgradePlan, inner_solution, singleton_struct

MAX_NATIVE_COST = 11_000_000_000


@dataclass(frozen=True)
class SingletonTip:
    launcher_id: bytes32
    inner: Program
    coin: Coin
    parent: CoinSpend

    def validate(self):
        full = puzzle_for_singleton(self.launcher_id, self.inner)
        if (self.coin.amount != 1 or self.coin.puzzle_hash != full.get_tree_hash()
                or self.coin.parent_coin_info != self.parent.coin.name()):
            raise ValueError('current singleton does not match its exact state and parent')
        reveal = Program.from_bytes(bytes(self.parent.puzzle_reveal))
        if reveal.get_tree_hash() != self.parent.coin.puzzle_hash:
            raise ValueError('singleton parent reveal does not match its coin')
        if self.parent.coin.name() == self.launcher_id:
            if self.parent.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH or self.parent.coin.amount != 1:
                raise ValueError('unrecognized generation singleton launcher')
        else:
            mod, args = reveal.uncurry()
            values = list(args.as_iter())
            if (mod.get_tree_hash() != SINGLETON_MOD_HASH or len(values) != 2
                    or Program.to(values) != args or values[0] != singleton_struct(self.launcher_id)):
                raise ValueError('singleton parent belongs to another lineage')
        additions, _ = compute_additions_with_cost(self.parent, max_cost=MAX_NATIVE_COST)
        if [c for c in additions if c.amount % 2] != [self.coin]:
            raise ValueError('singleton parent does not create the exact current output')
        return self

    def spend(self, solution: Program) -> CoinSpend:
        self.validate()
        return make_spend(self.coin, puzzle_for_singleton(self.launcher_id, self.inner),
            solution_for_singleton(lineage_proof_for_coinsol(self.parent), uint64(1), solution))

    def advanced(self, spend: CoinSpend, inner: Program):
        if spend.coin != self.coin:
            raise ValueError('continuation consumes another singleton')
        coin = Coin(self.coin.name(), puzzle_for_singleton(self.launcher_id, inner).get_tree_hash(), uint64(1))
        return SingletonTip(self.launcher_id, inner, coin, spend).validate()


@dataclass(frozen=True)
class NativeOperation:
    generation: bytes32
    kind: str
    spends: tuple[CoinSpend, ...]
    successors: tuple[SingletonTip, ...]
    auxiliary_outputs: tuple[Coin, ...] = ()
    aggregated_signature: G2Element = field(default_factory=G2Element)

    def bundle(self):
        if not self.spends or len({s.coin.name() for s in self.spends}) != len(self.spends):
            raise ValueError('operation requires distinct native inputs')
        return SpendBundle(list(self.spends), self.aggregated_signature)

    def with_aggregated_signature(self, signature: G2Element):
        # Attach only after collecting the exact reviewed wallet signatures.
        # This is assembly, not verification; native admission verifies the
        # entire aggregate before any fee input can be selected or broadcast.
        if not isinstance(signature,G2Element):
            raise ValueError('a canonical BLS aggregate is required')
        return replace(self,aggregated_signature=signature)

    @property
    def commitment(self):
        # Fee attachment changes the final transaction and needs a separate
        # reviewed commitment. This identifies the immutable protocol intent.
        return Program.to([b'GENERATION_NATIVE_OPERATION_V1', self.generation,
            self.kind.encode(), bytes(self.bundle())]).get_tree_hash()


def _tip(tip, launcher, inner):
    if tip.launcher_id != launcher or tip.inner != inner:
        raise ValueError('supplied singleton is not the reconstructed authority')
    return tip.validate()


def _authorities(governance, gov_tip, registry, reg_tip):
    if (governance.sgt.generation != registry.generation or governance.registry_id != registry.launcher_id
            or governance.sgt.governance_launcher_id != registry.governance_id
            or governance.admin_id != registry.administrator_id):
        raise ValueError('governance and registry bindings disagree')
    _tip(gov_tip, registry.governance_id, governance.inner())
    _tip(reg_tip, registry.launcher_id, registry.inner())


def anchor_vote(governance: Governance, tip: SingletonTip, clock: Coin, confirmed_birth: int):
    _tip(tip, governance.sgt.governance_launcher_id, governance.inner())
    active = governance.active
    if (not active or active.opened_at or type(confirmed_birth) is not int or confirmed_birth <= 0
            or clock.name() != active.clock_id or clock.amount != 0
            or clock.puzzle_hash != governance.clock_puzzle(active.proposal_id).get_tree_hash()):
        raise ValueError('opening clock requires exact confirmed evidence')
    updated = governance.anchored(confirmed_birth)
    spend = tip.spend(inner_solution('ANCHOR', tip.coin, [confirmed_birth]))
    clock_spend = make_spend(clock, governance.clock_puzzle(active.proposal_id),
                            Program.to([tip.inner.get_tree_hash(), confirmed_birth]))
    return NativeOperation(governance.sgt.generation, 'ANCHOR_VOTE', (spend, clock_spend),
                           (tip.advanced(spend, updated.inner()),)), updated


def finalize_vote(governance: Governance, tip: SingletonTip):
    _tip(tip, governance.sgt.governance_launcher_id, governance.inner())
    active = governance.active
    if not active or not active.opened_at:
        raise ValueError('no confirmed vote is ready for finalization')
    updated = governance.finalized()
    spend = tip.spend(inner_solution('FINALIZE', tip.coin, [governance.closed.proof(active.proposal_id),
        governance.approved.proof(governance.action_key(active.proposal_id, active.bill))]))
    return NativeOperation(governance.sgt.generation, 'FINALIZE_VOTE', (spend,),
                           (tip.advanced(spend, updated.inner()),)), updated


def prove_state(governance: Governance, tip: SingletonTip):
    """Exercise the reviewed rehearsal successor without changing its state.

    No caller-supplied extension can stand in for the approved instruction.
    Native execution must accept PROVE_STATE and create the exact continuation.
    """
    from solslot_puzzles import load_puzzle
    _tip(tip, governance.sgt.governance_launcher_id, governance.inner())
    successor = load_puzzle('generation_extension_v2.clsp')
    if governance.module_hash != successor.get_tree_hash() or governance.version < 2:
        raise ValueError('PROVE_STATE requires the activated reviewed rehearsal successor')
    spend = tip.spend(inner_solution('READ', tip.coin, [successor, b'PROVE_STATE']))
    return NativeOperation(governance.sgt.generation, 'PROVE_STATE', (spend,),
        (tip.advanced(spend, governance.inner()),))


def apply_parameters(governance: Governance, gov_tip: SingletonTip, registry: Registry,
                     reg_tip: SingletonTip, parameters: GenerationParameters, parameter_tip: SingletonTip,
                     proposal: bytes32, values: tuple[int, ...], *, policy: Program | None = None):
    """Apply exactly the closed holder vote; no administrator fast-track."""
    from solslot_puzzles import load_puzzle
    _authorities(governance, gov_tip, registry, reg_tip)
    _tip(parameter_tip, parameters.launcher_id, parameters.inner())
    if (parameters.generation != registry.generation or parameters.registry_id != registry.launcher_id
            or parameters.governance_id != registry.governance_id
            or parameters.component() not in registry.components):
        raise ValueError('parameter authority differs from the active generation registry')
    from solslot_puzzles.generation_statutes import GenerationStatutes
    policy = policy if policy is not None else load_puzzle(
        'generation_statutes_logic_v1.clsp' if isinstance(parameters,GenerationStatutes)
        else 'generation_parameter_logic_v1.clsp')
    if not isinstance(policy, Program) or policy.get_tree_hash() != parameters.logic_hash():
        raise ValueError('parameter change requires the active reviewed policy')
    bill = parameters.bill(values)
    updated = governance.executed(proposal, bill)
    next_parameters = parameters.updated(values)
    execute = gov_tip.spend(inner_solution('EXECUTE', gov_tip.coin, [proposal, bill,
        governance.approved.proof(governance.action_key(proposal, bill)), parameter_tip.inner.get_tree_hash(), bytes32.zeros]))
    change = parameter_tip.spend(Program.to([b'UPDATE', [gov_tip.inner.get_tree_hash(), parameters.revision,
        Program.to(list(parameters.values)).get_tree_hash(), list(values), policy]]))
    operation = NativeOperation(registry.generation, 'APPLY_PARAMETERS', (execute, change),
        (gov_tip.advanced(execute, updated.inner()), parameter_tip.advanced(change, next_parameters.inner())))
    return operation, updated, next_parameters


def apply_statutes(governance, gov_tip, registry, reg_tip, statutes, statutes_tip,
                  proposal, kind, records, replacement, *, policy=None):
    """Consume one exact ratified economic fact; no raw-root setter exists."""
    from solslot_puzzles import load_puzzle
    from solslot_puzzles.generation_statutes import GenerationStatutes
    _authorities(governance,gov_tip,registry,reg_tip)
    if (not isinstance(statutes,GenerationStatutes) or statutes.generation!=registry.generation
            or statutes.registry_id!=registry.launcher_id or statutes.governance_id!=registry.governance_id
            or statutes.component() not in registry.components):
        raise ValueError('statutes differ from the active generation registry')
    _tip(statutes_tip,statutes.launcher_id,statutes.inner())
    policy=policy if policy is not None else load_puzzle('generation_statutes_logic_v1.clsp')
    if not isinstance(policy,Program) or policy.get_tree_hash()!=statutes.logic_hash():
        raise ValueError('statutes require the active reviewed policy')
    bill,next_statutes,entries=statutes.record_change(kind,records,replacement)
    updated=governance.executed(proposal,bill)
    execute=gov_tip.spend(inner_solution('EXECUTE',gov_tip.coin,[proposal,bill,
        governance.approved.proof(governance.action_key(proposal,bill)),statutes_tip.inner.get_tree_hash(),bytes32.zeros]))
    change=statutes_tip.spend(Program.to([b'MUTATE',[gov_tip.inner.get_tree_hash(),statutes.revision,
        kind.encode(),replacement.as_program_value()[0],replacement.as_program_value(),
        [r.as_program_value() for r in records],policy]]))
    operation=NativeOperation(registry.generation,'APPLY_STATUTES',(execute,change),
        (gov_tip.advanced(execute,updated.inner()),statutes_tip.advanced(change,next_statutes.inner())))
    return operation,updated,next_statutes,entries


def ratify_upgrade(governance: Governance, gov_tip: SingletonTip, registry: Registry,
                   reg_tip: SingletonTip, proposal: bytes32, plan: UpgradePlan):
    _authorities(governance, gov_tip, registry, reg_tip)
    bill = Program.to([b'UPGRADE', registry.nonce, plan.program()])
    updated = governance.executed(proposal, bill)  # Exact approved action, consumed once.
    pending, ticket = registry.ratified(reg_tip.coin, plan)
    execute = gov_tip.spend(inner_solution('EXECUTE', gov_tip.coin, [proposal, bill,
        governance.approved.proof(governance.action_key(proposal, bill)), reg_tip.inner.get_tree_hash(), bytes32.zeros]))
    ratify = reg_tip.spend(inner_solution('RATIFY_UPGRADE', reg_tip.coin, [gov_tip.inner.get_tree_hash(), plan.program()]))
    return NativeOperation(registry.generation, 'RATIFY_UPGRADE', (execute, ratify),
        (gov_tip.advanced(execute, updated.inner()), reg_tip.advanced(ratify, pending.inner())), (ticket,)), updated, pending


def _component(state):
    if isinstance(state, Governance):
        from solslot_puzzles import load_puzzle
        return Component(state.component_id, state.sgt.governance_launcher_id,
            load_puzzle('generation_governance_v1.clsp').get_tree_hash(), state.module_hash, state.version, state.compatibility)
    if isinstance(state, (GenerationMint, GenerationParameters, GenerationPool)):
        return state.component()
    raise ValueError('component requires its supported economic boundary builder')


def activate_upgrade(governance: Governance, gov_tip: SingletonTip, registry: Registry,
                     reg_tip: SingletonTip, plan: UpgradePlan, ticket: Coin, components: tuple):
    """components contains (state, exact tip) for EVERY changed component.

    Native consensus enforces ticket age. An API wall clock can display a
    countdown but cannot cause this builder or a node to bypass that delay.
    """
    _authorities(governance, gov_tip, registry, reg_tip)
    if governance.active:
        raise ValueError('finish the affected open proposal before activation')
    activated = registry.activated(plan)
    if (ticket.name() != registry.pending[1] or ticket.amount != 0
            or ticket.puzzle_hash != registry.ticket_puzzle(registry.pending[0]).get_tree_hash()):
        raise ValueError('activation requires the exact single-use ratification ticket')
    if tuple(_component(s).component_id for s, _ in components) != tuple(c.component_id for c in plan.changes):
        raise ValueError('all affected components must be supplied in the approved order')
    records = {c.component_id: c for c in registry.components}
    states, component_spends, successors, updated_states = [], [], [], []
    changed_governance = False
    for (state, tip), change in zip(components, plan.changes):
        component = _component(state)
        generation = state.sgt.generation if isinstance(state, Governance) else state.generation
        if component != records.get(component.component_id) or generation != registry.generation or state.registry_id != registry.launcher_id:
            raise ValueError('component state differs from the confirmed registry')
        _tip(tip, component.launcher_id, state.inner())
        if isinstance(state, Governance):
            # Independently reconstructed sparse sets are different Python
            # objects. Compare the canonical chain commitment, never identity.
            if state.inner() != governance.inner() or tip != gov_tip:
                raise ValueError('activation clearance must use the current governance state')
            changed_governance = True
        args = [reg_tip.inner.get_tree_hash(), registry.pending[0], change.new_module_hash,
                change.next_version, change.compatibility]
        solution = (inner_solution('UPGRADE', tip.coin, args) if isinstance(state, Governance)
            else state.solution(tip.coin, 'UPGRADE', args) if isinstance(state, GenerationPool)
            else Program.to([b'UPGRADE', args]))
        spend = tip.spend(solution)
        successor_state = replace(state, module_hash=change.new_module_hash, version=change.next_version)
        if successor_state.state() != state.state():
            raise ValueError('upgrade changes component state')
        states.append([component.component_id, state.state()])
        component_spends.append(spend)
        successors.append(tip.advanced(spend, successor_state.inner()))
        updated_states.append(successor_state)
    activate = reg_tip.spend(inner_solution('ACTIVATE', reg_tip.coin,
        [plan.program(), states, gov_tip.inner.get_tree_hash()]))
    spends = [activate, make_spend(ticket, registry.ticket_puzzle(registry.pending[0]),
                                  Program.to([reg_tip.inner.get_tree_hash()])), *component_spends]
    if not changed_governance:
        clearance = gov_tip.spend(inner_solution('ACTIVATION_CLEARANCE', gov_tip.coin,
            [reg_tip.inner.get_tree_hash(), registry.pending[0]]))
        spends.append(clearance)
        successors.append(gov_tip.advanced(clearance, governance.inner()))
    successors.insert(0, reg_tip.advanced(activate, activated.inner()))
    operation = NativeOperation(registry.generation, 'ACTIVATE_UPGRADE', tuple(spends), tuple(successors))
    operation.bundle()  # Reject any duplicate input before review.
    return operation, activated, tuple(updated_states)


def ratify_reopening(governance: Governance, gov_tip: SingletonTip, registry: Registry,
                     reg_tip: SingletonTip, proposal: bytes32, scope: int):
    _authorities(governance, gov_tip, registry, reg_tip)
    bill = Program.to([b'REOPEN', registry.pause_epoch, scope])
    updated = governance.executed(proposal, bill)
    pending, ticket = registry.reopen_ratified(reg_tip.coin, scope)
    execute = gov_tip.spend(inner_solution('EXECUTE', gov_tip.coin, [proposal, bill,
        governance.approved.proof(governance.action_key(proposal, bill)), reg_tip.inner.get_tree_hash(), bytes32.zeros]))
    ratify = reg_tip.spend(inner_solution('RATIFY_REOPEN', reg_tip.coin, [gov_tip.inner.get_tree_hash(), scope]))
    return NativeOperation(registry.generation, 'RATIFY_REOPENING', (execute, ratify),
        (gov_tip.advanced(execute, updated.inner()), reg_tip.advanced(ratify, pending.inner())), (ticket,)), updated, pending


def reopen_operations(registry: Registry, tip: SingletonTip, ticket: Coin):
    _tip(tip, registry.launcher_id, registry.inner())
    opened = registry.reopened()
    if (ticket.name() != registry.reopening[1] or ticket.amount != 0
            or ticket.puzzle_hash != registry.ticket_puzzle(registry.reopening[0]).get_tree_hash()):
        raise ValueError('reopening requires the exact single-use ratification ticket')
    spend = tip.spend(inner_solution('REOPEN', tip.coin, []))
    delay = make_spend(ticket, registry.ticket_puzzle(registry.reopening[0]), Program.to([tip.inner.get_tree_hash()]))
    return NativeOperation(registry.generation, 'REOPEN_OPERATIONS', (spend, delay),
                           (tip.advanced(spend, opened.inner()),)), opened


def mint_collection(governance:Governance,gov_tip:SingletonTip,registry:Registry,reg_tip:SingletonTip,
                    mint:GenerationMint,mint_tip:SingletonTip,proposal:bytes32,edition:TestMintEdition,
                    funding_spends:tuple[CoinSpend,...],*,policy:Program|None=None):
    """Assemble the exact approved edition and retained one-mojo funding inputs.

    Funding parents are already sealed into the edition. This function cannot
    select replacements. Each funding input creates only its committed launcher
    and unchanged-puzzle change; additional network fees use the separate exact
    fee-admission/dispatch path. Wallet signatures are attached after review.
    """
    _authorities(governance,gov_tip,registry,reg_tip)
    _tip(mint_tip,mint.launcher_id,mint.inner())
    if (mint.generation!=registry.generation or mint.registry_id!=registry.launcher_id
            or mint.governance_id!=registry.governance_id or mint.launcher_id!=governance.mint_id
            or mint.component() not in registry.components):
        raise ValueError('mint authority differs from the confirmed governance registry')
    bill=edition.bill();key=governance.action_key(proposal,bill)
    approved=governance.executed(proposal,bill)
    after=mint.minted(edition);inventories=mint.inventories(edition)
    if len(funding_spends)!=len(inventories):raise ValueError('every committed launcher funding input is required')
    funding=[]
    for row,item,spend in zip(edition.rows,inventories,funding_spends):
        if spend.coin.name()!=row.launcher_parent or spend.coin.amount<1:
            raise ValueError('mint funding differs from the approved fixed parent')
        if Program.from_bytes(bytes(spend.puzzle_reveal)).get_tree_hash()!=spend.coin.puzzle_hash:
            raise ValueError('mint funding reveal differs from the reviewed coin')
        additions,_=compute_additions_with_cost(spend,max_cost=MAX_NATIVE_COST)
        expected=[item.launcher_spend.coin]
        if spend.coin.amount>1:expected.append(Coin(spend.coin.name(),spend.coin.puzzle_hash,uint64(spend.coin.amount-1)))
        if sorted(additions,key=lambda c:c.name())!=sorted(expected,key=lambda c:c.name()):
            raise ValueError('mint funding changes a destination, amount or unauthorized fee')
        funding.extend((spend,item.launcher_spend))
    execute=gov_tip.spend(inner_solution('EXECUTE',gov_tip.coin,[proposal,bill,
        governance.approved.proof(key),mint_tip.inner.get_tree_hash(),reg_tip.inner.get_tree_hash()]))
    permission=reg_tip.spend(inner_solution('AUTHORIZE_NEW',reg_tip.coin,[2,gov_tip.coin.puzzle_hash,key,bill]))
    issuance=mint_tip.spend(mint.mint_solution(edition,gov_tip.inner.get_tree_hash(),policy=policy))
    operation=NativeOperation(registry.generation,'MINT_COLLECTION',(execute,permission,issuance,*funding),
        (gov_tip.advanced(execute,approved.inner()),reg_tip.advanced(permission,registry.inner()),
         mint_tip.advanced(issuance,after.inner())),tuple(item.coin for item in inventories))
    operation.bundle()
    return operation,approved,after,inventories
