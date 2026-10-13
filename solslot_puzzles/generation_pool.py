"""Stable pool authority with native V5 settlement and governed policy changes.

The eight market destinations/module pins and all statutes/economic state are
permanent. An upgrade changes only the policy commitment and monotonic version.
The pool authenticates statutes through their stable launcher and actual output,
so statutes policy changes need not replace pool/custody identities. This does
not make legacy statutes compatible with replacement governance; whole-genesis
integration must still supply the generation's canonical statutes authority.
"""
from dataclasses import dataclass, fields, replace

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import Component, singleton_struct
from solslot_puzzles.pool_v4_driver import PoolV4Config
from solslot_puzzles.sols_pool_v4 import SolsPoolStateV4


def reviewed_pool_policy(module_hash: bytes32) -> Program:
    for name in ('generation_pool_logic_v1.clsp', 'generation_pool_logic_v2.clsp'):
        program = load_puzzle(name)
        if program.get_tree_hash() == module_hash:
            return program
    raise ValueError('active pool policy is absent from the reviewed local source')


@dataclass(frozen=True, kw_only=True)
class GenerationPoolConfig(PoolV4Config):
    generation: bytes32
    registry_id: bytes32
    component_id: bytes32
    module_hash: bytes32
    version: int = 1
    compatibility: int = 1
    pool_puzzle_version: int = 6

    @property
    def market_config(self) -> Program:
        if self.pool_puzzle_version != 6:
            raise ValueError('generation pool requires its permanent generation kernel')
        if any(v == bytes32.zeros for v in (self.generation, self.registry_id,
                                           self.component_id, self.module_hash)):
            raise ValueError('pool generation bindings must be nonzero')
        if any(type(v) is not int or not 0 < v < 2**64 for v in (self.version, self.compatibility)):
            raise ValueError('pool versions must be positive uint64')
        base = list(super().market_config.as_iter())
        return Program.to([*base, [self.generation, singleton_struct(self.registry_id),
            self.component_id, self.module_hash, self.version, self.compatibility,
            load_puzzle('generation_sols_eve_v1.clsp').get_tree_hash()]])

    def policy(self) -> Program:
        return reviewed_pool_policy(self.module_hash)


@dataclass(frozen=True)
class GenerationPool:
    generation: bytes32
    registry_id: bytes32
    component_id: bytes32
    permanent: PoolV4Config
    economics: SolsPoolStateV4
    module_hash: bytes32 | None = None
    version: int = 1
    compatibility: int = 1

    @property
    def launcher_id(self):
        return self.permanent.pool_launcher_id

    @property
    def governance_id(self):
        return bytes32(self.permanent.governance_singleton_struct.rest().first().as_atom())

    def logic_hash(self):
        return self.module_hash or load_puzzle('generation_pool_logic_v1.clsp').get_tree_hash()

    def config(self) -> GenerationPoolConfig:
        if isinstance(self.permanent, GenerationPoolConfig):
            raise ValueError('pool permanent configuration cannot contain mutable policy fields')
        values = {f.name: getattr(self.permanent, f.name) for f in fields(PoolV4Config)
                  if f.name != 'pool_puzzle_version'}
        return GenerationPoolConfig(**values, generation=self.generation, registry_id=self.registry_id,
            component_id=self.component_id, module_hash=self.logic_hash(),
            version=self.version, compatibility=self.compatibility)

    def component(self):
        return Component(self.component_id, self.launcher_id,
            load_puzzle('generation_pool_v1.clsp').get_tree_hash(),
            self.logic_hash(), self.version, self.compatibility)

    def state(self):
        e = self.economics.economics.validate()
        if type(self.economics.state_version) is not int or not 0 < self.economics.state_version < 2**64:
            raise ValueError('pool state version must be positive uint64')
        return Program.to([singleton_struct(self.launcher_id), self.permanent.statutes_config, self.permanent.market_config,
            load_puzzle('generation_sols_eve_v1.clsp').get_tree_hash(),
            self.economics.inventory_root, int(e.bootstrap_complete), e.inventory_nav_micro_usd,
            e.treasury_assets_micro_usd, e.proven_liabilities_micro_usd, e.deed_count,
            e.total_sols_mojos, e.reserve_sols_mojos, self.economics.state_version])

    def inner(self):
        self.state()
        return generation_pool_inner(self.config(), self.economics)

    def solution(self, coin, action: str, args, *, policy: Program | None = None):
        if action not in ('UPGRADE', 'READ', 'SEED_SOLS'):
            raise ValueError('pool maintenance action is unsupported')
        # Activation authenticates the registry ticket directly. It must not
        # depend on running the old policy (which may be the reason for repair).
        program = (Program.to([]) if action in ('UPGRADE', 'SEED_SOLS')
                   else policy if policy is not None else reviewed_pool_policy(self.logic_hash()))
        return Program.to([coin.name(), self.inner().get_tree_hash(), int(coin.amount),
                           action.encode(), args, program, bytes32.zeros])

    def with_economics(self, economics):
        return replace(self, economics=economics)


def generation_pool_inner(config: GenerationPoolConfig, economics: SolsPoolStateV4) -> Program:
    if not isinstance(config, GenerationPoolConfig):
        raise ValueError('generation pool inner requires exact reviewed bindings')
    config.market_config  # Validate namespace and monotonic policy fields.
    base = PoolV4Config(**{f.name: getattr(config, f.name) for f in fields(PoolV4Config)
                          if f.name != 'pool_puzzle_version'})
    state = GenerationPool(config.generation, config.registry_id, config.component_id,
        base, economics, config.module_hash, config.version, config.compatibility).state()
    module = load_puzzle('generation_pool_v1.clsp')
    return module.curry(module.get_tree_hash(), config.generation, singleton_struct(config.registry_id),
        config.component_id, config.module_hash, config.version, config.compatibility, state)


def generation_pool_solution(config: PoolV4Config, solution: Program, statutes_inner_hash: bytes32) -> Program:
    """Append the pinned policy only for the stable generation kernel.

    Older swap solutions remain byte-for-byte unchanged. Unsupported policies
    fail before review instead of guessing an extension's behavior.
    """
    if config.pool_puzzle_version != 6:
        return solution
    if not isinstance(config, GenerationPoolConfig):
        raise ValueError('generation pool solution requires exact reviewed bindings')
    if not isinstance(statutes_inner_hash,bytes32) or statutes_inner_hash==bytes32.zeros:
        raise ValueError('generation pool settlement requires the actual statutes authority output')
    return Program.to([*solution.as_iter(), config.policy(), statutes_inner_hash])


def decode_pool_state(state: Program, **common) -> GenerationPool:
    from solslot_puzzles.generation_registry_reader import exact_list, uint
    from solslot_puzzles.protocol_statutes_v1 import PermanentRules
    from solslot_puzzles.sols_economics_v3 import SolsEconomicState
    mine, statutes, market, eve, root, bootstrap, nav, assets, liabilities, count, total, reserve, sequence = exact_list(state, 13)
    if eve.as_atom()!=load_puzzle('generation_sols_eve_v1.clsp').get_tree_hash():
        raise ValueError('pool anchor issuance differs from the permanent reviewed template')
    launcher = common.pop('launcher_id')
    governance = common.pop('governance_id')
    if mine != singleton_struct(launcher):
        raise ValueError('pool state changes its permanent authority identity')
    mod, statute_struct, gov_struct, sgt, supply, sols, zk, treasury, network = exact_list(statutes, 9)
    if gov_struct != singleton_struct(governance):
        raise ValueError('pool state binds another governance authority')
    cat, offer, p2_vault, vault, p2_pool, deed_launcher, reserve_puzzle, rewards = exact_list(market, 8)
    if uint(bootstrap) not in (0, 1):
        raise ValueError('pool bootstrap flag is not canonical')
    rules = PermanentRules(bytes32(sgt.as_atom()), uint(supply),
        *(bytes32(v.as_atom()) for v in (sols, zk, treasury, network)))
    permanent = PoolV4Config(launcher, bytes32(mod.as_atom()), statute_struct, gov_struct, rules,
        *(bytes32(v.as_atom()) for v in (cat, offer, p2_vault, vault, p2_pool, deed_launcher, reserve_puzzle, rewards)))
    economics = SolsPoolStateV4(bytes32(root.as_atom()), SolsEconomicState(bool(uint(bootstrap)),
        *(uint(v) for v in (nav, assets, liabilities, count, total, reserve))), uint(sequence))
    result = GenerationPool(**common, permanent=permanent, economics=economics)
    if result.state() != state:
        raise ValueError('pool state is not reproduced canonically')
    return result


def replay_pool_swap(pool: GenerationPool, direction: int, params: Program) -> GenerationPool:
    """Project only the immutable native settlement successor, never conditions.

    The caller executes the current reveal and compares its actual output with
    this projection, then separately proves primary-chain inclusion.
    """
    from solslot_puzzles.generation_registry_reader import exact_list, uint
    from solslot_puzzles.sols_economics_v3 import SolsEconomicState
    values = exact_list(params, 41 if direction == 3 else 39 if direction == 1 else 33 if direction == 2 else 0)
    if direction == 3: direction = 1
    old = pool.economics.economics
    if direction == 1:
        e = SolsEconomicState(True, old.inventory_nav_micro_usd + uint(values[29]),
            old.treasury_assets_micro_usd, old.proven_liabilities_micro_usd, old.deed_count + 1,
            old.total_sols_mojos + uint(values[33]), old.reserve_sols_mojos - uint(values[32]))
        root = bytes32(values[34].as_atom())
    elif direction == 2:
        e = SolsEconomicState(True, old.inventory_nav_micro_usd - uint(values[23]),
            old.treasury_assets_micro_usd, old.proven_liabilities_micro_usd, old.deed_count - 1,
            old.total_sols_mojos, old.reserve_sols_mojos + uint(values[25]))
        root = bytes32(values[28].as_atom())
    else:
        raise ValueError('unsupported native pool settlement')
    return pool.with_economics(SolsPoolStateV4(root, e, pool.economics.state_version + 1))
