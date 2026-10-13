"""New-generation registry driver. Never accepts a wall-clock activation time.

This module is intentionally separate from historical RC23 builders. The
registry consumes ratification from a stable governance singleton; producing
that ratification still requires the holder-governance kernel, not this driver.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntFlag

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, SINGLETON_MOD_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle

ACTIVATION_DELAY_SECONDS = 86_400


def singleton_struct(launcher_id: bytes32) -> Program:
    return Program.to((SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH)))


class PauseScope(IntFlag):
    NEW_PROPOSALS = 1
    MINT = 2
    NEW_OFFERS = 4
    NEW_UNFUNDED_OBLIGATIONS = 8
    UPGRADE_ACTIVATION = 16


@dataclass(frozen=True)
class Component:
    component_id: bytes32
    launcher_id: bytes32
    kernel_hash: bytes32
    module_hash: bytes32
    version: int
    compatibility: int

    def program(self) -> list:
        if not (0 < self.version < 2**64 and 0 < self.compatibility < 2**64):
            raise ValueError("component version and compatibility must be positive uint64")
        return [self.component_id, self.launcher_id, self.kernel_hash, self.module_hash,
                self.version, self.compatibility]


@dataclass(frozen=True)
class CodeChange:
    component_id: bytes32
    old_module_hash: bytes32
    new_module_hash: bytes32
    next_version: int
    compatibility: int

    def program(self) -> list:
        return [self.component_id, self.old_module_hash, self.new_module_hash,
                self.next_version, self.compatibility, b"PRESERVE_STATE"]


@dataclass(frozen=True)
class UpgradePlan:
    source_manifest_hash: bytes32
    changes: tuple[CodeChange, ...]

    def program(self) -> list:
        ids = [c.component_id for c in self.changes]
        if not ids or len(set(ids)) != len(ids):
            raise ValueError("upgrade requires unique affected components")
        return [self.source_manifest_hash, [c.program() for c in self.changes]]


@dataclass(frozen=True)
class Registry:
    generation: bytes32
    launcher_id: bytes32
    governance_id: bytes32
    administrator_id: bytes32
    components: tuple[Component, ...]
    nonce: int = 0
    pending: tuple[bytes32, bytes32] | tuple[()] = ()
    pause_mask: int = 0
    pause_epoch: int = 0
    reopening: tuple[bytes32, bytes32, int, int] | tuple[()] = ()

    def inner(self) -> Program:
        if len({c.component_id for c in self.components}) != len(self.components):
            raise ValueError("duplicate component")
        if not 0 <= self.pause_mask < 32:
            raise ValueError("pause scope includes protected operations")
        if not 0 <= self.nonce < 2**64 or not 0 <= self.pause_epoch < 2**64:
            raise ValueError("invalid registry sequence")
        mod = load_puzzle("generation_registry_v1.clsp")
        return mod.curry(mod.get_tree_hash(), self.generation,
                         singleton_struct(self.launcher_id), singleton_struct(self.governance_id),
                         singleton_struct(self.administrator_id),
                         load_puzzle("generation_delay_ticket_v1.clsp").get_tree_hash(),
                         [c.program() for c in self.components], self.nonce, list(self.pending),
                         self.pause_mask, self.pause_epoch, list(self.reopening))

    def commitment(self, plan: UpgradePlan, *, nonce: int | None = None) -> bytes32:
        return Program.to([b"CODE_UPGRADE", self.generation, self.nonce if nonce is None else nonce,
                           plan.program()]).get_tree_hash()

    def ratification_message(self, plan: UpgradePlan) -> bytes32:
        return Program.to([b"RATIFY_CODE_UPGRADE", self.generation, self.nonce,
                           plan.program()]).get_tree_hash()

    def ticket_puzzle(self, commitment: bytes32) -> Program:
        return load_puzzle("generation_delay_ticket_v1.clsp").curry(
            self.generation, singleton_struct(self.launcher_id), commitment, ACTIVATION_DELAY_SECONDS)

    def ratified(self, current_coin: Coin, plan: UpgradePlan) -> tuple[Registry, Coin]:
        if self.pending:
            raise ValueError("finish the pending upgrade first")
        self.updated_components(plan)  # Reject stale/incompatible plans before wallet review.
        commitment = self.commitment(plan)
        ticket = Coin(current_coin.name(), self.ticket_puzzle(commitment).get_tree_hash(), uint64(0))
        return replace(self, nonce=self.nonce + 1, pending=(commitment, ticket.name())), ticket

    def updated_components(self, plan: UpgradePlan) -> tuple[Component, ...]:
        plan.program()
        components = {c.component_id: c for c in self.components}
        for change in plan.changes:
            old = components.get(change.component_id)
            if old is None or old.module_hash != change.old_module_hash:
                raise ValueError("unknown component or stale old module")
            if (change.next_version != old.version + 1 or change.compatibility != old.compatibility
                    or change.new_module_hash == old.module_hash):
                raise ValueError("incompatible successor or implicit downgrade")
            components[old.component_id] = replace(old, module_hash=change.new_module_hash,
                                                   version=change.next_version)
        return tuple(components[c.component_id] for c in self.components)

    def activated(self, plan: UpgradePlan) -> Registry:
        if not self.pending or self.pending[0] != self.commitment(plan, nonce=self.nonce - 1):
            raise ValueError("plan does not match pending activation ticket")
        if self.pause_mask & PauseScope.UPGRADE_ACTIVATION:
            raise ValueError("upgrade activation is paused")
        return replace(self, components=self.updated_components(plan), pending=())

    def paused(self, scope: int) -> Registry:
        if isinstance(scope, bool) or not 0 < scope < 32:
            raise ValueError("pause scope includes protected operations")
        return replace(self, pause_mask=self.pause_mask | scope, pause_epoch=self.pause_epoch + 1, reopening=())

    def reopen_commitment(self, scope: int) -> bytes32:
        return Program.to([b"REOPEN", self.generation, self.pause_epoch, scope]).get_tree_hash()

    def reopen_ratification_message(self, scope: int) -> bytes32:
        return Program.to([b"RATIFY_REOPEN", self.generation, self.pause_epoch, scope]).get_tree_hash()

    def reopen_ratified(self, current_coin: Coin, scope: int) -> tuple[Registry, Coin]:
        if self.reopening or not 0 < scope < 32 or self.pause_mask & scope != scope:
            raise ValueError("scope is not paused or reopening is already pending")
        commitment = self.reopen_commitment(scope)
        ticket = Coin(current_coin.name(), self.ticket_puzzle(commitment).get_tree_hash(), uint64(0))
        return replace(self, reopening=(commitment, ticket.name(), scope, self.pause_epoch)), ticket

    def reopened(self) -> Registry:
        if not self.reopening or self.reopening[3] != self.pause_epoch:
            raise ValueError("no current ratified reopening")
        return replace(self, pause_mask=self.pause_mask ^ self.reopening[2], reopening=())

    def component_inner(self, component: Component, state: Program) -> Program:
        mod = load_puzzle("generation_component_v1.clsp")
        if component.kernel_hash != mod.get_tree_hash():
            raise ValueError("this builder supports the read-only extension kernel only")
        return mod.curry(mod.get_tree_hash(), self.generation, singleton_struct(self.launcher_id),
                         component.component_id, component.module_hash, component.version,
                         component.compatibility, state)


def inner_solution(action: str, coin: Coin, args: list) -> Program:
    return Program.to([action.encode(), coin.name(), args])
