"""Bounded parameter authority; the holder governance rules are immutable."""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import Component, singleton_struct
from solslot_puzzles.protocol_statutes_v1 import ProtocolParameters


# Confirmed user direction for the replacement Testnet generation:
# one percent total, of which 0.7% goes to protocol and 0.3% to SGT rewards.
# Historical ProtocolParameters defaults stay unchanged for old evidence.
GENERATION_EXCHANGE_FEE_BPS = 100
GENERATION_PROTOCOL_FEE_BPS = 70
GENERATION_SGT_REWARDS_FEE_BPS = 30


@dataclass(frozen=True)
class GenerationParameters:
    generation: bytes32
    registry_id: bytes32
    governance_id: bytes32
    launcher_id: bytes32
    component_id: bytes32
    # Generation economic defaults; voting fields are not mutable entries.
    values: tuple[int,...] = (86400,600,GENERATION_EXCHANGE_FEE_BPS,GENERATION_PROTOCOL_FEE_BPS,
                             GENERATION_SGT_REWARDS_FEE_BPS,86400)
    revision: int = 0
    version: int = 1
    compatibility: int = 1
    module_hash: bytes32 | None = None

    @staticmethod
    def validate(values):
        if len(values)!=6 or any(type(v) is not int for v in values):
            raise ValueError('parameters require exactly six integer economic values')
        ProtocolParameters(3600,5000,10000,*values).validate(sgt_total_supply=1_000_000)

    def economic_parameters(self) -> ProtocolParameters:
        self.validate(self.values)
        return ProtocolParameters(3600,5000,10000,*self.values)

    def fee_split(self, principal_sols_mojos: int):
        """Quote from this authority's values, never legacy default arguments."""
        from solslot_puzzles.sols_economics_v3 import fee_split_for_principal
        if type(principal_sols_mojos) is not int or not 0 < principal_sols_mojos < 2**64:
            raise ValueError('fee principal must be a positive uint64')
        p = self.economic_parameters()
        return fee_split_for_principal(principal_sols_mojos,
            exchange_fee_bps=p.exchange_fee_bps,
            protocol_fee_bps=p.protocol_fee_bps,
            sgt_rewards_fee_bps=p.sgt_rewards_fee_bps)

    def logic_hash(self):
        return self.module_hash or load_puzzle('generation_parameter_logic_v1.clsp').get_tree_hash()

    def component(self):
        return Component(self.component_id,self.launcher_id,load_puzzle('generation_parameters_v1.clsp').get_tree_hash(),
                         self.logic_hash(),self.version,self.compatibility)

    def state(self):
        self.validate(self.values)
        if type(self.revision) is not int or not 0<=self.revision<2**64:
            raise ValueError('parameter revision must be uint64')
        return Program.to([singleton_struct(self.launcher_id),singleton_struct(self.governance_id),self.revision,list(self.values)])

    def inner(self):
        mod=load_puzzle('generation_parameters_v1.clsp')
        return mod.curry(mod.get_tree_hash(),self.generation,singleton_struct(self.registry_id),self.component_id,
                         self.logic_hash(),self.version,self.compatibility,self.state())

    def bill(self,values):
        self.validate(values)
        if tuple(values)==self.values:raise ValueError('parameter proposal must change a value')
        return Program.to([b'PARAMETERS',self.component_id,self.launcher_id,self.revision,
                           Program.to(list(self.values)).get_tree_hash(),list(values)])

    def updated(self,values):
        self.bill(values)
        return replace(self,values=tuple(values),revision=self.revision+1)
