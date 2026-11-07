"""Funded non-expiring SGT rewards from authenticated holder snapshots.

No node access, keys, fee selection or dispatch. Complete mature fee inputs
are conserved into exact claims. Multiple holdings of one owner are combined
before integer rounding, so splitting SGT cannot improve its reward share.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend,make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,construct_cat_puzzle,unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_ballots import CurrentHoldings
from solslot_puzzles.generation_governance import Governance
from solslot_puzzles.generation_registry import Registry,singleton_struct
from solslot_puzzles.generation_sgt import SGTBindings
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.generation_transactions import MAX_NATIVE_COST,NativeOperation,SingletonTip,_tip
from solslot_puzzles.holdings import HoldingKind
from solslot_puzzles.generation_vault import sgt_owner
from solslot_puzzles.vault_driver import puzzle_for_p2_vault

MAX_REWARD_FEE_INPUTS=64
MAX_REWARD_HOLDINGS=128


@dataclass(frozen=True)
class RewardCustody:
    bindings:SGTBindings
    statutes_id:bytes32
    asset_id:bytes32

    def inner(self)->Program:
        if any(value==bytes32.zeros for value in (self.bindings.generation,self.bindings.ledger_launcher_id,
                self.bindings.governance_launcher_id,self.bindings.tail_hash,self.statutes_id)):
            raise ValueError('reward custody requires exact nonzero generation and authority bindings')
        mod=load_puzzle('generation_reward_custody_v1.clsp')
        return mod.curry(mod.get_tree_hash(),self.bindings.program(),singleton_struct(self.statutes_id),self.asset_id,
            CAT_MOD.get_tree_hash(),load_puzzle('generation_reward_epoch_v1.clsp').get_tree_hash(),
            load_puzzle('generation_sgt_coin_v1.clsp').get_tree_hash(),
            load_puzzle('generation_reward_leaf_v1.clsp').get_tree_hash(),
            load_puzzle('generation_sgt_vault_owner_v1.clsp').get_tree_hash(),load_puzzle('p2_vault.clsp').get_tree_hash())

    def full(self)->Program:
        return self.inner() if self.asset_id==bytes32.zeros else construct_cat_puzzle(CAT_MOD,self.asset_id,self.inner())

    def epoch_inner(self)->Program:
        mod=load_puzzle('generation_reward_epoch_v1.clsp')
        return mod.curry(mod.get_tree_hash(),self.bindings.program(),singleton_struct(self.statutes_id),self.asset_id,
            CAT_MOD.get_tree_hash(),load_puzzle('generation_reward_custody_v1.clsp').get_tree_hash(),
            load_puzzle('generation_sgt_coin_v1.clsp').get_tree_hash(),
            load_puzzle('generation_reward_leaf_v1.clsp').get_tree_hash(),
            load_puzzle('generation_sgt_vault_owner_v1.clsp').get_tree_hash(),load_puzzle('p2_vault.clsp').get_tree_hash())


@dataclass(frozen=True)
class RewardFeeInput:
    coin:Coin
    parent:CoinSpend

    def lineage(self,custody:RewardCustody)->LineageProof|None:
        if self.coin.puzzle_hash!=custody.full().get_tree_hash() or not 0<self.coin.amount<2**64:
            raise ValueError('fee input differs from the exact reward custody and asset')
        reveal=Program.from_bytes(bytes(self.parent.puzzle_reveal));mod,args=reveal.uncurry()
        if custody.asset_id==bytes32.zeros:
            if self.coin.parent_coin_info!=self.parent.coin.name() or reveal.get_tree_hash()!=self.parent.coin.puzzle_hash:
                raise ValueError('native reward fee differs from its exact funding parent')
            additions,_=compute_additions_with_cost(self.parent,max_cost=MAX_NATIVE_COST)
            if additions.count(self.coin)!=1:raise ValueError('native fee parent does not create its exact input')
            return None
        values=list(args.as_iter())
        if (self.coin.parent_coin_info!=self.parent.coin.name() or reveal.get_tree_hash()!=self.parent.coin.puzzle_hash
                or mod!=CAT_MOD or len(values)!=3 or Program.to(values)!=args
                or values[0].as_atom()!=CAT_MOD.get_tree_hash() or values[1].as_atom()!=custody.asset_id):
            raise ValueError('reward fee input differs from its exact CAT parent')
        additions,_=compute_additions_with_cost(self.parent,max_cost=MAX_NATIVE_COST)
        if additions.count(self.coin)!=1:raise ValueError('reward fee parent does not create its exact input')
        return LineageProof(self.parent.coin.parent_coin_info,values[2].get_tree_hash(),self.parent.coin.amount)


@dataclass(frozen=True)
class EarnedReward:
    generation:bytes32
    asset_id:bytes32
    epoch_id:bytes32
    owner:bytes32
    amount:int

    def inner(self)->Program:
        if type(self.amount) is not int or not 0<self.amount<2**64:
            raise ValueError('earned reward must be a positive exact amount')
        if any(value==bytes32.zeros for value in (self.generation,self.epoch_id,self.owner)):
            raise ValueError('earned reward requires exact nonzero commitments')
        mod=load_puzzle('generation_reward_leaf_v1.clsp')
        return mod.curry(mod.get_tree_hash(),self.generation,self.asset_id,self.epoch_id,self.owner,self.owner,self.amount,
            load_puzzle('generation_sgt_vault_owner_v1.clsp').get_tree_hash(),load_puzzle('p2_vault.clsp').get_tree_hash())

    def full(self)->Program:return self.inner() if self.asset_id==bytes32.zeros else construct_cat_puzzle(CAT_MOD,self.asset_id,self.inner())


def reward_allocations(tree,total:int)->tuple[tuple[bytes32,int],...]:
    if type(total) is not int or not 0<total<2**64 or tree.root.eligible<=0:
        raise ValueError('rewards require positive funding and distributed holder supply')
    owners={}
    for holding in tree.holdings.values():
        if holding.kind in (HoldingKind.HOLDER,HoldingKind.LOCKED_HOLDER):
            owners[holding.owner_hash]=owners.get(holding.owner_hash,0)+holding.amount
    if sum(owners.values())!=tree.root.eligible:raise ValueError('reward owners differ from the authenticated supply')
    supply=tree.root.eligible
    amounts={owner:total*weight//supply for owner,weight in owners.items()}
    ranked=sorted(owners,key=lambda owner:(-(total*owners[owner]%supply),bytes(owner)))
    for owner in ranked[:total-sum(amounts.values())]:amounts[owner]+=1
    return tuple((owner,amount) for owner,amount in sorted(amounts.items()) if amount)


@dataclass(frozen=True)
class RewardEpoch:
    operation:NativeOperation
    epoch_id:bytes32
    claims:tuple[tuple[EarnedReward,RewardFeeInput],...]
    eligible_supply:int
    epoch_seconds:int
    continuation:object|None=None


def close_reward_epoch(custody:RewardCustody,governance:Governance,registry:Registry,
        holdings:CurrentHoldings,statutes:GenerationStatutes,statutes_tip:SingletonTip,
        fees:tuple[RewardFeeInput,...],*,_resumable=False)->RewardEpoch:
    holdings.validate(governance)
    if (custody.bindings!=holdings.bindings or registry.generation!=custody.bindings.generation
            or not isinstance(statutes,GenerationStatutes) or statutes.generation!=registry.generation
            or statutes.registry_id!=registry.launcher_id or statutes.governance_id!=registry.governance_id
            or custody.statutes_id!=statutes.launcher_id or statutes.component() not in registry.components
            or statutes.permanent_rules.sgt_tail_hash!=custody.bindings.tail_hash):
        raise ValueError('reward authorities differ from the active generation')
    _tip(statutes_tip,statutes.launcher_id,statutes.inner())
    if not 0<len(fees)<=MAX_REWARD_FEE_INPUTS or len({item.coin.name() for item in fees})!=len(fees):
        raise ValueError('rewards require one to 64 distinct complete funded fee inputs')
    fees=tuple(sorted(fees,key=lambda item:item.coin.name()))
    total=sum(item.coin.amount for item in fees)
    if not total<2**64:raise ValueError('reward funding exceeds the native integer bound')
    group=[[item.coin.parent_coin_info,int(item.coin.amount)] for item in fees]
    eligible=sorted((identity,holding) for identity,holding in holdings.tree.holdings.items()
        if holding.kind in (HoldingKind.HOLDER,HoldingKind.LOCKED_HOLDER))
    if not eligible:
        raise ValueError('rewards require distributed holder supply')
    _resumable = _resumable or len(eligible)>MAX_REWARD_HOLDINGS
    if not _resumable and not len(eligible)<=MAX_REWARD_HOLDINGS:
        raise ValueError('this reward epoch exceeds its bounded native holding proof capacity')
    rows=[] if _resumable else [[identity,holding.program(),holdings.tree.proof(identity)] for identity,holding in eligible]
    epoch=Program.to([b'SGT_FEE_EPOCH_V1',custody.bindings.generation,custody.asset_id,group,
        holdings.tree.root.program(),holdings.sequence,list(statutes.values),Program.to(rows).get_tree_hash()]).get_tree_hash()
    cats=[];native=[]
    for item in fees:
        solution=Program.to([item.coin.name(),item.coin.amount,fees[0].coin.name(),epoch,statutes.values[5]])
        lineage=item.lineage(custody)
        if custody.asset_id==bytes32.zeros:native.append(make_spend(item.coin,custody.inner(),solution))
        else:cats.append(SpendableCAT(item.coin,custody.asset_id,custody.inner(),solution,lineage_proof=lineage))
    receipt_inner=custody.epoch_inner()
    receipt=Coin(fees[0].coin.name(),(receipt_inner if custody.asset_id==bytes32.zeros else
        construct_cat_puzzle(CAT_MOD,custody.asset_id,receipt_inner)).get_tree_hash(),uint64(0))
    solution=Program.to([b'START' if _resumable else b'EPOCH',receipt.name(),group,holdings.tree.root.program(),holdings.sequence,
        holdings.tip.inner.get_tree_hash(),statutes_tip.inner.get_tree_hash(),list(statutes.values),rows])
    if custody.asset_id==bytes32.zeros:
        native.append(make_spend(receipt,receipt_inner,solution));spends=tuple(native)
    else:
        cats.append(SpendableCAT(receipt,custody.asset_id,receipt_inner,solution,
            lineage_proof=LineageProof(fees[0].coin.parent_coin_info,custody.inner().get_tree_hash(),fees[0].coin.amount)))
        spends=tuple(unsigned_spend_bundle_for_spendable_cats(CAT_MOD,cats).coin_spends)
    snapshot=holdings.tip.spend(Program.to([b'REWARD_SNAPSHOT',[receipt.puzzle_hash,epoch]]))
    evidence=statutes_tip.spend(Program.to([b'REWARD_EVIDENCE',[receipt.puzzle_hash,epoch]]))
    parent=spends[len(fees)]
    claims=[]
    for owner,amount in (() if _resumable else reward_allocations(holdings.tree,total)):
        claim=EarnedReward(custody.bindings.generation,custody.asset_id,epoch,owner,amount)
        coin=Coin(receipt.name(),claim.full().get_tree_hash(),uint64(amount))
        claims.append((claim,RewardFeeInput(coin,parent)))
    continuation=None
    if _resumable:
        from solslot_puzzles.holdings import HoldingsTree
        draft=RewardContinuation(custody,epoch,holdings.tree.root.eligible,total,0,holdings.tree,HoldingsTree({}),None)
        funded=Coin(receipt.name(),draft.full().get_tree_hash(),uint64(total))
        from dataclasses import replace
        continuation=replace(draft,source=RewardFeeInput(funded,parent))
    operation=NativeOperation(custody.bindings.generation,'CLOSE_REWARD_EPOCH',
        spends+(snapshot,evidence),
        (holdings.tip.advanced(snapshot,holdings.tip.inner),statutes_tip.advanced(evidence,statutes_tip.inner)),
        (continuation.source.coin,) if continuation else tuple(item.coin for _,item in claims))
    operation.bundle()
    return RewardEpoch(operation,epoch,tuple(claims),holdings.tree.root.eligible,statutes.values[5],continuation)


def claim_vault_reward(claim:EarnedReward,source:RewardFeeInput,vault_launcher:bytes32)->NativeOperation:
    if sgt_owner(claim.generation,vault_launcher).get_tree_hash()!=claim.owner:
        raise ValueError('reward payment must go to its exact unchanged custody vault')
    if source.coin.puzzle_hash!=claim.full().get_tree_hash() or source.coin.amount!=claim.amount:
        raise ValueError('reward claim input differs from its permanent entitlement')
    reveal=Program.from_bytes(bytes(source.parent.puzzle_reveal));mod,args=reveal.uncurry();values=list(args.as_iter())
    if (source.coin.parent_coin_info!=source.parent.coin.name() or reveal.get_tree_hash()!=source.parent.coin.puzzle_hash
            or claim.asset_id!=bytes32.zeros and (mod!=CAT_MOD or len(values)!=3 or values[1].as_atom()!=claim.asset_id)):
        raise ValueError('reward claim requires the exact funded CAT lineage')
    additions,_=compute_additions_with_cost(source.parent,max_cost=MAX_NATIVE_COST)
    if additions.count(source.coin)!=1:raise ValueError('reward parent does not create its exact entitlement')
    solution=Program.to([b'PAY_VAULT',source.coin.name(),vault_launcher,[],[]])
    if claim.asset_id==bytes32.zeros:
        paid=Coin(source.coin.name(),puzzle_for_p2_vault(vault_launcher).get_tree_hash(),uint64(claim.amount))
        return NativeOperation(claim.generation,'CLAIM_SGT_REWARD',(make_spend(source.coin,claim.inner(),solution),),(),(paid,))
    cat=SpendableCAT(source.coin,claim.asset_id,claim.inner(),solution,
        lineage_proof=LineageProof(source.parent.coin.parent_coin_info,values[2].get_tree_hash(),source.parent.coin.amount))
    bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat])
    paid=Coin(source.coin.name(),construct_cat_puzzle(CAT_MOD,claim.asset_id,puzzle_for_p2_vault(vault_launcher)).get_tree_hash(),uint64(claim.amount))
    return NativeOperation(claim.generation,'CLAIM_SGT_REWARD',tuple(bundle.coin_spends),(),(paid,))


@dataclass(frozen=True)
class RewardContinuation:
    """Recoverable indexes for an immutable, funded on-chain continuation.

    Merkle proofs authenticate every removal/update. Neither these indexes nor
    a processing operator can omit an entitlement or redirect its funds.
    """
    custody:RewardCustody
    epoch_id:bytes32
    eligible_supply:int
    budget:int
    phase:int
    remaining:object
    owners:object
    source:RewardFeeInput|None

    def inner(self):
        mod=load_puzzle('generation_reward_resume_v1.clsp')
        return mod.curry(mod.get_tree_hash(),self.custody.bindings.program(),self.custody.asset_id,
            CAT_MOD.get_tree_hash(),load_puzzle('generation_reward_leaf_v1.clsp').get_tree_hash(),
            load_puzzle('generation_sgt_vault_owner_v1.clsp').get_tree_hash(),load_puzzle('p2_vault.clsp').get_tree_hash(),
            self.custody.inner().get_tree_hash(),load_puzzle('generation_sgt_coin_v1.clsp').get_tree_hash(),
            self.epoch_id,self.eligible_supply,self.budget,self.phase,self.remaining.root.program(),self.owners.root.program())

    def full(self):
        return self.inner() if self.custody.asset_id==bytes32.zeros else construct_cat_puzzle(CAT_MOD,self.custody.asset_id,self.inner())

    def advance(self,identities=None,*,limit=16):
        from dataclasses import replace
        from solslot_puzzles.holdings import HoldingsTree,Holding
        if type(limit) is not int or not 1<=limit<=16 or self.phase not in (0,1) or self.source is None:
            raise ValueError('reward progress requires a funded exact continuation and bounded page')
        source=self.source
        if source.coin.puzzle_hash!=self.full().get_tree_hash():
            raise ValueError('reward continuation changed its funded state')
        parent=Program.from_bytes(bytes(source.parent.puzzle_reveal))
        if parent.get_tree_hash()!=source.parent.coin.puzzle_hash or source.coin.parent_coin_info!=source.parent.coin.name():
            raise ValueError('reward continuation requires its exact parent evidence')
        additions,_=compute_additions_with_cost(source.parent,max_cost=MAX_NATIVE_COST)
        if additions.count(source.coin)!=1:raise ValueError('reward parent does not create the exact funded continuation')
        remaining,owners=self.remaining,self.owners
        available=remaining.holdings if self.phase==0 else owners.holdings
        candidates=sorted(key for key,h in available.items() if self.phase==1 or h.kind in (HoldingKind.HOLDER,HoldingKind.LOCKED_HOLDER))
        identities=tuple(candidates[:limit] if identities is None else identities)
        if not 0<len(identities)<=limit or len(set(identities))!=len(identities):
            raise ValueError('reward page must contain distinct eligible records')
        rows=[];earned=[];paid=0
        for identity in identities:
            holding=available.get(identity)
            if holding is None:raise ValueError('reward page includes an absent or already processed record')
            if self.phase==0:
                if holding.kind not in (HoldingKind.HOLDER,HoldingKind.LOCKED_HOLDER):
                    raise ValueError('reserve and undelivered escrow receive no rewards')
                previous=owners.holdings.get(holding.owner_hash)
                weight=previous.amount if previous else 0
                rows.append([identity,holding.program(),remaining.proof(identity),weight,owners.proof(holding.owner_hash)])
                remaining=remaining.replace(identity,holding,None)
                owners=owners.replace(holding.owner_hash,previous,
                    Holding(bytes32.zeros,weight+holding.amount,HoldingKind.HOLDER,holding.owner_hash))
            else:
                rows.append([identity,holding.amount,owners.proof(identity)])
                owners=owners.replace(identity,holding,None)
                amount=self.budget*holding.amount//self.eligible_supply
                if amount:
                    earned.append(EarnedReward(self.custody.bindings.generation,self.custody.asset_id,self.epoch_id,identity,amount));paid+=amount
        phase=1 if remaining.root.eligible==0 else 0
        after=replace(self,phase=phase,remaining=remaining,owners=owners,source=None)
        continuing=self.phase==0 or owners.root.eligible>0
        balance=int(source.coin.amount)-paid
        if balance<0:raise ValueError('reward page exceeds its exact conserved budget')
        solution=Program.to([b'SCAN' if self.phase==0 else b'PAY',source.coin.name(),source.coin.amount,rows])
        if self.custody.asset_id==bytes32.zeros:
            spend=make_spend(source.coin,self.inner(),solution)
        else:
            mod,args=parent.uncurry();values=list(args.as_iter())
            if mod!=CAT_MOD or len(values)!=3 or values[1].as_atom()!=self.custody.asset_id:
                raise ValueError('reward continuation differs from its funded CAT lineage')
            cat=SpendableCAT(source.coin,self.custody.asset_id,self.inner(),solution,
                lineage_proof=LineageProof(source.parent.coin.parent_coin_info,values[2].get_tree_hash(),source.parent.coin.amount))
            native=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat]);spend=native.coin_spends[0]
        claims=tuple((claim,RewardFeeInput(Coin(source.coin.name(),claim.full().get_tree_hash(),uint64(claim.amount)),spend)) for claim in earned)
        outputs=[item.coin for _,item in claims]
        if continuing:
            next_coin=Coin(source.coin.name(),after.full().get_tree_hash(),uint64(balance))
            after=replace(after,source=RewardFeeInput(next_coin,spend));outputs.append(next_coin)
        else:
            after=None
            if balance:outputs.append(Coin(source.coin.name(),self.custody.full().get_tree_hash(),uint64(balance)))
        operation=NativeOperation(self.custody.bindings.generation,'ADVANCE_SGT_REWARDS',(spend,),(),tuple(outputs))
        if set(operation.bundle().additions())!=set(outputs):raise ValueError('reward progress differs from its native outputs')
        return operation,after,claims


def start_reward_epoch(*args,**kwargs):
    return close_reward_epoch(*args,**kwargs,_resumable=True)
