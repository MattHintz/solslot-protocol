"""One stable authority for generation parameters and governed economic facts.

Parameter values are stored once. The legacy-shaped economic view is derived
for existing settlement checks; it is never a second mutable registry. Scoped
pauses belong to the generation registry, not an expiring statutes entry.
"""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_registry import Component, singleton_struct
from solslot_puzzles.protocol_statutes_v1 import (
    PermanentRules, StatutesState, CollectionStatute, OracleRound,
    BridgeRoute, LiquidityVenue, keyed_root,
)

EMPTY_ROOT = bytes32(Program.to([]).get_tree_hash())
RECORDS = {'COLLECTION': ('collections_root', CollectionStatute),
           'ORACLE': ('oracle_root', OracleRound),
           'ROUTE': ('routes_root', BridgeRoute),
           'LIQUIDITY': ('liquidity_root', LiquidityVenue)}


def canonical_records(kind, records):
    if kind not in RECORDS or not 0 <= len(records) <= 128:
        raise ValueError('statutes require a bounded supported record type')
    expected = RECORDS[kind][1]
    if any(type(r) is not expected for r in records):
        raise ValueError('statutes record type differs from the reviewed mutation')
    for record in records:
        record.validate()
        if record.as_program_value()[0] == bytes32.zeros:
            raise ValueError('statutes keys must be nonzero')
    ordered = tuple(sorted(records, key=lambda r: bytes(r.as_program_value()[0])))
    keyed_root(ordered)
    if tuple(records) != ordered:
        raise ValueError('statutes records must have canonical key order')
    return ordered


@dataclass(frozen=True, kw_only=True)
class GenerationStatutes(GenerationParameters):
    pool_id: bytes32
    permanent_rules: PermanentRules
    collections_root: bytes32 = EMPTY_ROOT
    oracle_root: bytes32 = EMPTY_ROOT
    routes_root: bytes32 = EMPTY_ROOT
    liquidity_root: bytes32 = EMPTY_ROOT

    def logic_hash(self):
        return self.module_hash or load_puzzle('generation_statutes_logic_v1.clsp').get_tree_hash()

    def component(self):
        return Component(self.component_id, self.launcher_id,
            load_puzzle('generation_statutes_v1.clsp').get_tree_hash(),
            self.logic_hash(), self.version, self.compatibility)

    @property
    def parameters_root(self):
        return bytes32(Program.to(list(self.economic_parameters().as_tuple())).get_tree_hash())

    @property
    def pauses_root(self):
        return EMPTY_ROOT

    @property
    def registry_version(self):
        return self.revision + 1

    @property
    def permanent_rules_hash(self):
        return self.permanent_rules.commitment_hash

    def economic_view(self):
        return StatutesState(self.parameters_root, self.collections_root, self.oracle_root,
            self.routes_root, self.liquidity_root, EMPTY_ROOT, self.registry_version,
            self.permanent_rules_hash).validate()

    def state(self):
        super().state()
        self.permanent_rules.validate()
        if self.permanent_rules.sgt_total_supply != 1_000_000:
            raise ValueError('generation statutes preserve the fixed SGT supply')
        for value in (self.pool_id, self.permanent_rules.sgt_tail_hash,
                      self.permanent_rules.sols_tail_hash, self.permanent_rules.zkpassport_policy_hash,
                      self.permanent_rules.protocol_treasury_puzzle_hash, self.permanent_rules.network_id):
            if not isinstance(value, bytes32) or value == bytes32.zeros:
                raise ValueError('statutes permanent bindings must be nonzero')
        for field, _ in RECORDS.values():
            if not isinstance(getattr(self, field), bytes32):
                raise ValueError('statutes roots must be exact bytes32 commitments')
        return Program.to([singleton_struct(self.launcher_id), singleton_struct(self.governance_id),
            singleton_struct(self.pool_id), self.permanent_rules.as_program(), self.revision,
            list(self.values), self.collections_root, self.oracle_root, self.routes_root, self.liquidity_root])

    def inner(self):
        module = load_puzzle('generation_statutes_v1.clsp')
        return module.curry(module.get_tree_hash(), self.generation, singleton_struct(self.registry_id),
            self.component_id, self.logic_hash(), self.version, self.compatibility, self.state())

    def record_change(self, kind, records, replacement):
        entries = canonical_records(kind, records)
        field, expected = RECORDS[kind]
        if type(replacement) is not expected:
            raise ValueError('replacement differs from the exact record type')
        replacement.validate()
        old_root = keyed_root(entries)
        if old_root != getattr(self, field):
            raise ValueError('record witness differs from the current statutes root')
        key = replacement.as_program_value()[0]
        if key == bytes32.zeros:
            raise ValueError('statutes keys must be nonzero')
        previous = next((r for r in entries if r.as_program_value()[0] == key), None)
        if kind == 'COLLECTION' and replacement.nav_version != (previous.nav_version + 1 if previous else 1):
            raise ValueError('collection NAV version must advance exactly once')
        if kind == 'ORACLE' and (replacement.round_id != (previous.round_id + 1 if previous else 1)
                or previous and replacement.observed_at < previous.observed_at):
            raise ValueError('oracle round must advance without reversing observation time')
        changed = [r for r in entries if r.as_program_value()[0] != key] + [replacement]
        updated = canonical_records(kind, sorted(changed, key=lambda r: bytes(r.as_program_value()[0])))
        new_root = keyed_root(updated)
        if new_root == old_root:
            raise ValueError('clean statutes changes do not create a new revision')
        bill = Program.to([b'STATUTES', self.component_id, self.launcher_id, self.revision,
            kind.encode(), key, replacement.as_program_value(), old_root, new_root])
        return bill, replace(self, revision=self.revision + 1, **{field: new_root}), updated

    def sols_evidence_solution(self, consumer, collection_id, collections, registry_inner_hash, operation):
        entries = canonical_records('COLLECTION', collections)
        if keyed_root(entries) != self.collections_root:
            raise ValueError('collection evidence differs from current statutes')
        if sum(r.collection_id == collection_id for r in entries) != 1:
            raise ValueError('settlement requires one exact governed collection')
        return Program.to([b'SOLS_EVIDENCE', [consumer, collection_id,
            [r.as_program_value() for r in entries], registry_inner_hash, operation]])
