"""Exact canonical statutes and registry inputs for an explicit exchange.

This source is separate from the read-only economic view. A view or API cache
cannot provide the lineage, current authority or scoped-pause permission.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton,solution_for_singleton
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_registry import Registry,Component,inner_solution,singleton_struct
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.generation_pool import GenerationPoolConfig
from solslot_puzzles.generation_transactions import SingletonTip


@dataclass(frozen=True)
class GenerationStatutesSource:
    statutes: GenerationStatutes
    registry: Registry
    registry_tip: SingletonTip

    def build(self,*,config,view,parameters,collections,pauses,collection,pause,
              coin,launcher,lineage,consumer,operation):
        s,r,tip=self.statutes,self.registry,self.registry_tip
        if (not isinstance(config,GenerationPoolConfig) or not isinstance(s,GenerationStatutes)
                or s.generation!=config.generation or r.generation!=s.generation
                or r.launcher_id!=config.registry_id or s.registry_id!=r.launcher_id
                or s.governance_id!=r.governance_id or s.pool_id!=config.pool_launcher_id
                or config.statutes_singleton_struct!=singleton_struct(s.launcher_id)
                or config.governance_singleton_struct!=singleton_struct(r.governance_id)
                or s.permanent_rules!=config.permanent_rules or s.economic_view()!=view
                or s.economic_parameters()!=parameters or s.component() not in r.components
                or s.launcher_id!=launcher or s.component().kernel_hash!=config.statutes_inner_mod_hash
                or pauses or pause is not None or tip.launcher_id!=r.launcher_id or tip.inner!=r.inner()):
            raise ValueError('settlement requires the actual canonical generation statutes and pause registry')
        from solslot_puzzles import load_puzzle
        expected_pool=Component(config.component_id,config.pool_launcher_id,
            load_puzzle('generation_pool_v1.clsp').get_tree_hash(),config.module_hash,config.version,config.compatibility)
        if expected_pool not in r.components:
            raise ValueError('pool policy differs from the confirmed registry')
        tip.validate()
        inner=s.inner();full=puzzle_for_singleton(launcher,inner)
        if coin.amount!=1 or coin.puzzle_hash!=full.get_tree_hash():
            raise ValueError('statutes input differs from its actual confirmed current state')
        if sum(c==collection for c in collections)!=1:
            raise ValueError('collection quote differs from the canonical record witness')
        evidence=make_spend(coin,full,solution_for_singleton(lineage,uint64(1),
            s.sols_evidence_solution(consumer,collection.collection_id,collections,tip.inner.get_tree_hash(),operation)))
        permission=tip.spend(inner_solution('AUTHORIZE_NEW',tip.coin,
            [4,coin.puzzle_hash,operation,[b'SOLS_EXCHANGE',consumer,collection.collection_id]]))
        return inner,evidence,(permission,)
