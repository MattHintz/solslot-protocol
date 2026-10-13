"""Native holder-ballot assembly from exact, independently reconstructed inputs.

No wallet requests, keys, funding selection, clock shortcuts or network I/O.
The returned operation is unsigned; native admission and the generation-bound
wallet review remain mandatory. GET/status handlers must never call builders.
"""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import Governance, ADMIN_APPROVAL_SECONDS, ballot_witnesses
from solslot_puzzles.generation_registry import Registry, inner_solution
from solslot_puzzles.generation_sgt import SGTBindings, SGTOutput, ledger_inner, transition_digest, transition_witness
from solslot_puzzles.generation_transactions import MAX_NATIVE_COST, NativeOperation, SingletonTip, _authorities, _tip
from solslot_puzzles.generation_vault import authorization_solution, owner_solution, sgt_owner
from solslot_puzzles.holdings import HoldingsTree, HoldingKind
from solslot_puzzles.admin_authority_v3_driver import (
    admin_authority_v3_inner_mod_hash,
)
from solslot_puzzles.generation_admin import publication_action
from solslot_puzzles.generation_admin_transactions import advance_operational_authority

MAX_BALLOT_INPUTS = 32


@dataclass(frozen=True)
class SGTInput:
    coin: Coin
    descriptor: SGTOutput
    parent: CoinSpend

    def validate(self, bindings: SGTBindings) -> LineageProof:
        if (self.coin.puzzle_hash != self.descriptor.full(bindings).get_tree_hash()
                or self.coin.amount != self.descriptor.amount
                or self.coin.parent_coin_info != self.parent.coin.name()):
            raise ValueError('SGT input differs from its exact holding and parent')
        reveal = Program.from_bytes(bytes(self.parent.puzzle_reveal))
        mod, args = reveal.uncurry()
        values = list(args.as_iter())
        if (reveal.get_tree_hash() != self.parent.coin.puzzle_hash
                or mod.get_tree_hash() != CAT_MOD.get_tree_hash() or len(values) != 3
                or Program.to(values) != args or values[0].as_atom() != CAT_MOD.get_tree_hash()
                or values[1].as_atom() != bindings.tail_hash):
            raise ValueError('SGT parent must use the same CAT identity')
        additions, _ = compute_additions_with_cost(self.parent, max_cost=MAX_NATIVE_COST)
        if sum(c == self.coin for c in additions) != 1:
            raise ValueError('SGT parent does not create this exact holding')
        return LineageProof(self.parent.coin.parent_coin_info, values[2].get_tree_hash(), self.parent.coin.amount)


@dataclass(frozen=True)
class CurrentHoldings:
    bindings: SGTBindings
    tree: HoldingsTree
    sequence: int
    tip: SingletonTip

    def validate(self, governance: Governance):
        if (self.bindings != governance.sgt or type(self.sequence) is not int
                or not 0 <= self.sequence < 2**64-1):
            raise ValueError('holdings belong to another generation or ledger sequence')
        _tip(self.tip, self.bindings.ledger_launcher_id, ledger_inner(self.bindings, self.tree, self.sequence))
        return self


@dataclass(frozen=True)
class CustodyAuthorization:
    holding: SGTInput
    vault: SingletonTip
    expires_at: int
    evm_signature: bytes = b''

    def validate(self, bindings):
        lineage = self.holding.validate(bindings)
        self.vault.validate()
        mod, _ = self.vault.inner.uncurry()
        if (mod.get_tree_hash() != load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash()
                or sgt_owner(bindings.generation, self.vault.launcher_id).get_tree_hash() != self.holding.descriptor.owner):
            raise ValueError('SGT holding requires its exact generation custody vault')
        if type(self.expires_at) is not int or not 0 < self.expires_at < 2**64:
            raise ValueError('custody authorization requires an explicit expiry')
        if not isinstance(self.evm_signature, bytes) or len(self.evm_signature) not in (0,64):
            raise ValueError('custody signature must be empty BLS authorization or compact EVM signature')
        return lineage


@dataclass(frozen=True)
class BallotOperation:
    operation: NativeOperation
    governance: Governance
    holdings: CurrentHoldings
    outputs: tuple[SGTInput, ...]


def _selected(inputs):
    if not 0 < len(inputs) <= MAX_BALLOT_INPUTS:
        raise ValueError('select between one and 32 complete eligible holdings')
    if len({i.coin.name() for i in inputs}) != len(inputs):
        raise ValueError('duplicate SGT input')


def _publication_continuation(administrator,spend,*,generation,target,proposal,issued_at):
    mod,_=administrator.inner.uncurry()
    known={admin_authority_v3_inner_mod_hash(v) for v in (3,4)}
    if mod.get_tree_hash() not in known:
        # Generic stable-authority adapters may retain their original state.
        # They still require an exact native continuation. Final genesis
        # admission independently pins the real recovery-aware V4 authority.
        return administrator.advanced(spend,administrator.inner)
    delegated=publication_action(generation,target,proposal,issued_at)
    return advance_operational_authority(administrator,spend,delegated)


def _lock(governance, holdings, snapshot, proposal, authorizations):
    inputs = tuple(a.holding for a in authorizations)
    _selected(inputs)
    # Current UI requests authorize a single holding per custody continuation.
    # Never silently reuse a signature against a later ephemeral vault coin.
    if len({a.vault.coin.name() for a in authorizations}) != len(authorizations):
        raise ValueError('combine at most one holding per custody vault in this review')
    ballots = ballot_witnesses(snapshot, [i.coin.name() for i in inputs], governance.closed)
    cats, witnesses, custody_spends, custody_tips, outputs = [], [], [], [], []
    tree, bindings = holdings.tree, holdings.bindings
    for auth in authorizations:
        item, vault = auth.holding, auth.vault
        lineage = auth.validate(bindings)
        if tree.holdings.get(item.coin.name()) != item.descriptor.holding(bindings):
            raise ValueError('selected holding is spent or absent from the current ledger')
        if snapshot.holdings.get(item.coin.name()) != item.descriptor.holding(bindings):
            raise ValueError('selected holding is not eligible in this opening snapshot')
        output = replace(item.descriptor, kind=HoldingKind.LOCKED_HOLDER, lock_id=proposal)
        witness, tree = transition_witness(bindings, tree, item.coin, item.descriptor, 'LOCK', (output,))
        digest = transition_digest(bindings, item.coin, 'LOCK', (output,))
        custody = vault.spend(authorization_solution(bindings.generation, vault.coin, vault.inner,
            item.coin.name(), digest, auth.expires_at, auth.evm_signature))
        custody_spends.append(custody)
        custody_tips.append(vault.advanced(custody, vault.inner))
        cats.append(SpendableCAT(coin=item.coin,limitations_program_hash=bindings.tail_hash,
            inner_puzzle=item.descriptor.inner(bindings),lineage_proof=lineage,
            inner_solution=Program.to([b'LOCK',item.coin.name(),item.coin.amount,holdings.tip.inner.get_tree_hash(),
                sgt_owner(bindings.generation,vault.launcher_id),
                owner_solution(vault.coin,vault.inner,item.coin.name(),'LOCK',(output,),auth.expires_at),
                governance.inner().get_tree_hash(),[output.descriptor()]])))
        witnesses.append(witness); outputs.append(output)
    bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD,cats)
    ledger_spend = holdings.tip.spend(Program.to([b'UPDATE',witnesses]))
    ledger_tip = holdings.tip.advanced(ledger_spend,ledger_inner(bindings,tree,holdings.sequence+1))
    next_inputs = tuple(SGTInput(output.coin(bindings,item.coin.name()),output,spend)
        for item,output,spend in zip(inputs,outputs,bundle.coin_spends))
    return (ballots,tuple(bundle.coin_spends)+tuple(custody_spends)+(ledger_spend,),
        tuple(custody_tips),CurrentHoldings(bindings,tree,holdings.sequence+1,ledger_tip),next_inputs)


def open_proposal(governance: Governance, gov_tip: SingletonTip, registry: Registry, reg_tip: SingletonTip,
                  holdings: CurrentHoldings, bill: Program, administrator: SingletonTip,
                  publication_spends: tuple[CoinSpend,...], publication_issued_at: int,
                  sponsors: tuple[CustodyAuthorization,...]) -> BallotOperation:
    """Publication spends are the reviewed owner-plus-one authority operation.

    Native authority/cross-announcement and signature checks are not replaced
    by a coordinator boolean. The explicit publication issue time is part of
    the signed 24-hour intent; it is never refreshed while assembling a retry.
    """
    _authorities(governance,gov_tip,registry,reg_tip); holdings.validate(governance)
    if administrator.launcher_id != governance.admin_id:
        raise ValueError('publication authority belongs to another generation')
    administrator.validate()
    if (not publication_spends or sum(s.coin==administrator.coin for s in publication_spends)!=1
            or type(publication_issued_at) is not int
            or not 0 < publication_issued_at < 2**64-ADMIN_APPROVAL_SECONDS):
        raise ValueError('exact native publication consent and its issue time are required')
    ids=[a.holding.coin.name() for a in sponsors]
    opened,clock = governance.opened(gov_tip.coin,bill,holdings.tree,holdings.sequence,ids)
    proposal=opened.active.proposal_id
    snapshot_spend=holdings.tip.spend(Program.to([b'SNAPSHOT',[gov_tip.inner.get_tree_hash(),proposal]]))
    snapshot_tip=holdings.tip.advanced(snapshot_spend,holdings.tip.inner)
    snapshot_state=replace(holdings,tip=snapshot_tip)
    ballots,locks,custodies,updated,outputs=_lock(governance,snapshot_state,holdings.tree,proposal,sponsors)
    reg_spend=reg_tip.spend(inner_solution('AUTHORIZE_NEW',reg_tip.coin,[1,gov_tip.coin.puzzle_hash,proposal,bill]))
    gov_spend=gov_tip.spend(inner_solution('OPEN',gov_tip.coin,[administrator.inner.get_tree_hash(),
        publication_issued_at,publication_issued_at+ADMIN_APPROVAL_SECONDS,reg_tip.inner.get_tree_hash(),
        holdings.tip.inner.get_tree_hash(),holdings.tree.root.program(),holdings.sequence,bill,ballots]))
    authority_spend=next(s for s in publication_spends if s.coin==administrator.coin)
    authority_tip=_publication_continuation(administrator,authority_spend,generation=governance.sgt.generation,
        target=gov_tip.coin.puzzle_hash,proposal=proposal,issued_at=publication_issued_at)
    operation=NativeOperation(governance.sgt.generation,'OPEN_PROPOSAL',
        publication_spends+(reg_spend,gov_spend,snapshot_spend)+locks,
        (reg_tip.advanced(reg_spend,registry.inner()),gov_tip.advanced(gov_spend,opened.inner()),
         updated.tip,authority_tip,*custodies),(clock,))
    operation.bundle()
    return BallotOperation(operation,opened,updated,outputs)


def cast_vote(governance: Governance, gov_tip: SingletonTip, holdings: CurrentHoldings,
              opening_snapshot: HoldingsTree, authorizations: tuple[CustodyAuthorization,...]) -> BallotOperation:
    _tip(gov_tip,governance.sgt.governance_launcher_id,governance.inner());holdings.validate(governance)
    if not governance.active or not governance.active.opened_at or opening_snapshot.root!=governance.active.snapshot:
        raise ValueError('vote requires the exact confirmed opening snapshot')
    ballots,locks,custodies,updated,outputs=_lock(governance,holdings,opening_snapshot,
        governance.active.proposal_id,authorizations)
    voted=governance.voted(sum(i.holding.coin.amount for i in authorizations))
    vote=gov_tip.spend(inner_solution('VOTE',gov_tip.coin,ballots))
    operation=NativeOperation(governance.sgt.generation,'CAST_VOTE',(vote,)+locks,
        (gov_tip.advanced(vote,voted.inner()),updated.tip,*custodies))
    operation.bundle()
    return BallotOperation(operation,voted,updated,outputs)


def unlock_stakes(governance: Governance, gov_tip: SingletonTip, holdings: CurrentHoldings,
                  inputs: tuple[SGTInput,...]) -> BallotOperation:
    """Anyone can return closed stakes to their unchanged owners, with no key."""
    _tip(gov_tip,governance.sgt.governance_launcher_id,governance.inner());holdings.validate(governance);_selected(inputs)
    tree,bindings=holdings.tree,holdings.bindings
    cats,witnesses,claims,outputs=[],[],[],[]
    for item in inputs:
        lineage=item.validate(bindings); old=item.descriptor
        if (old.kind!=HoldingKind.LOCKED_HOLDER or old.lock_id not in governance.closed.keys
                or tree.holdings.get(item.coin.name())!=old.holding(bindings)):
            raise ValueError('unlock requires a current stake from a closed proposal')
        output=replace(old,kind=HoldingKind.HOLDER,lock_id=None)
        witness,tree=transition_witness(bindings,tree,item.coin,old,'UNLOCK',(output,))
        witnesses.append(witness)
        claims.append([item.coin.name(),old.holding(bindings).program(),governance.closed.proof(old.lock_id)])
        cats.append(SpendableCAT(coin=item.coin,limitations_program_hash=bindings.tail_hash,
            inner_puzzle=old.inner(bindings),lineage_proof=lineage,
            inner_solution=Program.to([b'UNLOCK',item.coin.name(),item.coin.amount,holdings.tip.inner.get_tree_hash(),
                [],[],gov_tip.inner.get_tree_hash(),[output.descriptor()]])))
        outputs.append(output)
    bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,cats)
    unlock=gov_tip.spend(inner_solution('UNLOCK',gov_tip.coin,claims))
    update=holdings.tip.spend(Program.to([b'UPDATE',witnesses]))
    updated=CurrentHoldings(bindings,tree,holdings.sequence+1,
        holdings.tip.advanced(update,ledger_inner(bindings,tree,holdings.sequence+1)))
    next_inputs=tuple(SGTInput(out.coin(bindings,item.coin.name()),out,spend)
        for item,out,spend in zip(inputs,outputs,bundle.coin_spends))
    operation=NativeOperation(bindings.generation,'UNLOCK_STAKES',(unlock,update,*bundle.coin_spends),
        (gov_tip.advanced(unlock,governance.inner()),updated.tip))
    operation.bundle()
    return BallotOperation(operation,governance,updated,next_inputs)
