"""Governed reserve allocation and permissionless delivery to unchanged owners.

These deterministic builders do not choose recipients, poll, sign, select fees
or broadcast. A grant consumes its exact approved bill once. Escrow delivery
adds eligible supply only through the authenticated holdings transition.
"""
from dataclasses import dataclass,replace

from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,unsigned_spend_bundle_for_spendable_cats
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.generation_ballots import CurrentHoldings,SGTInput
from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles.generation_sgt import SGTBindings,SGTOutput,ledger_inner,transition_witness
from solslot_puzzles.generation_transactions import NativeOperation,SingletonTip,_tip
from solslot_puzzles.holdings import HoldingKind


@dataclass(frozen=True)
class AllocationOperation:
    operation:NativeOperation
    governance:Governance
    holdings:CurrentHoldings
    outputs:tuple[SGTInput,...]


def grant_bill(bindings:SGTBindings,reserve:SGTInput,outputs:tuple[SGTOutput,...])->Program:
    reserve.validate(bindings)
    old=reserve.descriptor
    if old.kind!=HoldingKind.RESERVE or old.owner!=bindings.reserve_owner or old.lock_id:
        raise ValueError('grant requires the exact nonvoting reserve input')
    if not 1<=len(outputs)<=32:
        raise ValueError('grant requires between one and 32 exact outputs')
    descriptors=[]
    for output in outputs:
        output.inner(bindings)
        if (output.kind not in (HoldingKind.RESERVE,HoldingKind.UNDELIVERED_ESCROW)
                or output.lock_id or output.owner==bytes32.zeros):
            raise ValueError('grant may create only reserve or undelivered recipient escrow')
        descriptors.append(output.descriptor())
    if (sum(o.amount for o in outputs)!=reserve.coin.amount
            or len({bytes(Program.to(v)) for v in descriptors})!=len(outputs)):
        raise ValueError('grant must conserve its entire reserve input with distinct outputs')
    return Program.to([b'GRANT',reserve.coin.name(),descriptors])


def _transition(governance,holdings,item,action,outputs):
    holdings.validate(governance)
    lineage=item.validate(holdings.bindings)
    if holdings.tree.holdings.get(item.coin.name())!=item.descriptor.holding(holdings.bindings):
        raise ValueError('allocation input is absent or spent in the current holdings ledger')
    witness,tree=transition_witness(holdings.bindings,holdings.tree,item.coin,item.descriptor,action,outputs)
    cat=SpendableCAT(coin=item.coin,limitations_program_hash=holdings.bindings.tail_hash,
        inner_puzzle=item.descriptor.inner(holdings.bindings),lineage_proof=lineage,
        inner_solution=Program.to([action.encode(),item.coin.name(),item.coin.amount,holdings.tip.inner.get_tree_hash(),
            [],[],governance.inner().get_tree_hash(),[o.descriptor() for o in outputs]]))
    bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat])
    update=holdings.tip.spend(Program.to([b'UPDATE',[witness]]))
    tip=holdings.tip.advanced(update,ledger_inner(holdings.bindings,tree,holdings.sequence+1))
    updated=CurrentHoldings(holdings.bindings,tree,holdings.sequence+1,tip)
    created=tuple(SGTInput(o.coin(holdings.bindings,item.coin.name()),o,bundle.coin_spends[0]) for o in outputs)
    for output in created:output.validate(holdings.bindings)
    return tuple(bundle.coin_spends)+(update,),updated,created


def allocate_grant(governance:Governance,gov_tip:SingletonTip,holdings:CurrentHoldings,
                   reserve:SGTInput,outputs:tuple[SGTOutput,...],proposal:bytes32)->AllocationOperation:
    _tip(gov_tip,governance.sgt.governance_launcher_id,governance.inner())
    bill=grant_bill(governance.sgt,reserve,outputs)
    updated=governance.executed(proposal,bill)
    execute=gov_tip.spend(inner_solution('EXECUTE',gov_tip.coin,[proposal,bill,
        governance.approved.proof(governance.action_key(proposal,bill)),bytes32.zeros,bytes32.zeros]))
    transitions,current,created=_transition(governance,holdings,reserve,'ALLOCATE',outputs)
    operation=NativeOperation(governance.sgt.generation,'ALLOCATE_SGT_GRANT',(execute,)+transitions,
        (gov_tip.advanced(execute,updated.inner()),current.tip))
    operation.bundle()
    return AllocationOperation(operation,updated,current,created)


def deliver_escrow(governance:Governance,holdings:CurrentHoldings,escrow:SGTInput)->AllocationOperation:
    """No recipient ID gate or owner signature; custody cannot be reassigned."""
    if escrow.descriptor.kind!=HoldingKind.UNDELIVERED_ESCROW or escrow.descriptor.lock_id:
        raise ValueError('delivery requires the exact undelivered escrow input')
    output=replace(escrow.descriptor,kind=HoldingKind.HOLDER)
    spends,current,created=_transition(governance,holdings,escrow,'DELIVER',(output,))
    operation=NativeOperation(governance.sgt.generation,'DELIVER_SGT_GRANT',spends,(current.tip,))
    operation.bundle()
    return AllocationOperation(operation,governance,current,created)
