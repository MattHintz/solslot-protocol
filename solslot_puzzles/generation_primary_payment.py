"""Deterministic primary fee component, not an acquisition/matching authority.

Reuse the original mandatory USD fee/subtotal calculation. Rail base units
are allocated from that exact already-inclusive payment; rounding cannot add
a second fee or lose units. Zero asset identity means native TXCH, never a CAT.
The composite acquisition still must validate source inventory, quotes, buyer
offers and backing and emit the exact mutual authorization below.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,construct_cat_puzzle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_rewards import RewardCustody
from solslot_puzzles.generation_sgt import SGTBindings
from solslot_puzzles.payment_artifacts_v3 import technology_fee_minor


@dataclass(frozen=True)
class PrimaryFeeRouting:
    bindings:SGTBindings
    statutes_id:bytes32
    asset_id:bytes32
    source_puzzle_hash:bytes32
    route_id:bytes32
    base_usd_minor:int
    total_payment:int
    principal_destination:bytes32
    treasury_destination:bytes32
    statutes_inner_hash:bytes32
    parameters:tuple[int,int,int,int,int,int]

    @property
    def custody(self):return RewardCustody(self.bindings,self.statutes_id,self.asset_id)

    @property
    def fee_usd_minor(self):return technology_fee_minor(self.base_usd_minor,100)

    @property
    def subtotal_usd_minor(self):return self.base_usd_minor+self.fee_usd_minor

    def allocations(self)->tuple[int,int,int]:
        from solslot_puzzles.protocol_statutes_v1 import ProtocolParameters
        from solslot_puzzles.generation_parameters import GenerationParameters
        GenerationParameters.validate(self.parameters)
        p=ProtocolParameters(3600,5000,10000,*self.parameters).validate()
        if not p.exchange_fee_bps:raise ValueError('mandatory primary fee requires a ratified nonzero allocation ratio')
        if type(self.base_usd_minor) is not int or not 0<self.base_usd_minor<2**64:
            raise ValueError('primary price must be a positive exact USD minor amount')
        if type(self.total_payment) is not int or not 0<self.total_payment<2**64 or not self.subtotal_usd_minor<2**64:
            raise ValueError('primary subtotal and rail payment must fit native uint64')
        fee=(self.total_payment*self.fee_usd_minor+self.subtotal_usd_minor-1)//self.subtotal_usd_minor
        protocol=(fee*p.protocol_fee_bps+p.exchange_fee_bps-1)//p.exchange_fee_bps
        if self.total_payment<=fee:raise ValueError('primary payment has no positive principal after mandatory fee rounding')
        return self.total_payment-fee,protocol,fee-protocol

    def inner(self)->Program:
        self.allocations();self.custody.inner()
        if any(not isinstance(value,bytes32) or value==bytes32.zeros for value in
                (self.source_puzzle_hash,self.route_id,self.principal_destination,self.treasury_destination,self.statutes_inner_hash)):
            raise ValueError('primary payment requires exact nonzero source, route and destinations')
        mod=load_puzzle('generation_primary_payment_v1.clsp')
        return mod.curry(mod.get_tree_hash(),self.bindings.program(),singleton_struct(self.statutes_id),self.asset_id,
            CAT_MOD.get_tree_hash(),load_puzzle('generation_reward_custody_v1.clsp').get_tree_hash(),
            load_puzzle('generation_reward_epoch_v1.clsp').get_tree_hash(),load_puzzle('generation_sgt_coin_v1.clsp').get_tree_hash(),
            load_puzzle('generation_reward_leaf_v1.clsp').get_tree_hash(),load_puzzle('generation_sgt_vault_owner_v1.clsp').get_tree_hash(),
            load_puzzle('p2_vault.clsp').get_tree_hash(),self.source_puzzle_hash,self.route_id,self.base_usd_minor,
            self.fee_usd_minor,self.subtotal_usd_minor,self.total_payment,self.principal_destination,self.treasury_destination)

    def full(self)->Program:
        return self.inner() if self.asset_id==bytes32.zeros else construct_cat_puzzle(CAT_MOD,self.asset_id,self.inner())

    def messages(self,coin_id:bytes32)->tuple[bytes32,bytes32]:
        self.inner();principal,protocol,rewards=self.allocations()
        identity=[self.bindings.generation,self.route_id,coin_id,self.asset_id,self.total_payment]
        destinations=[Program.to(list(self.parameters)).get_tree_hash(),self.principal_destination,self.treasury_destination,self.custody.inner().get_tree_hash()]
        return (Program.to([b'PRIMARY_FEE_ROUTE_V1',*identity,self.base_usd_minor,self.fee_usd_minor,self.subtotal_usd_minor,*destinations]).get_tree_hash(),
            Program.to([b'PRIMARY_FEE_PAID_V1',*identity,principal,protocol,rewards,*destinations]).get_tree_hash())

    def source_conditions(self,coin_id:bytes32):
        authorized,paid=self.messages(coin_id)
        return [[66,18,authorized,self.full().get_tree_hash()],[67,18,paid,self.full().get_tree_hash()]]

    def solution(self,coin_id:bytes32)->Program:return Program.to([coin_id,self.total_payment,self.statutes_inner_hash,list(self.parameters)])
