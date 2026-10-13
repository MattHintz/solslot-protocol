"""Exact owner-plus-one actions for the recovery-aware generation authority.

Preparation returns public signing challenges. Completion accepts only the
two reviewed signatures; neither function selects coins, fetches network
state, requests keys or broadcasts. Callers must reconcile the same current
authority/identity inputs before admission. Recovery stays in its existing
policy and cannot be supplied as an operational delegated program here.
"""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (SINGLETON_LAUNCHER_HASH, SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol, puzzle_for_singleton, solution_for_singleton)
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v3_driver import (GenesisAdminAuthorityV3, IdentityVaultGenesis,
    IDENTITY_LAUNCHER_AMOUNTS, build_admin_identity_vault, build_authority_operational_mips_spend,
    build_identity_operational_action, build_identity_operational_solution, build_operational_solution,
    make_inner_puzzle, parse_inner_puzzle)
from solslot_puzzles.eip712_helpers import (TESTNET11_GENESIS_CHALLENGE, eip712_hash_to_sign,
    eip712_prefix_and_domain_separator, eip712_typed_data_for_coin_spend, normalize_eip712_member_signature)
from solslot_puzzles.generation_admin import publication_action, pause_action
from solslot_puzzles.generation_registry import Registry, inner_solution, singleton_struct
from solslot_puzzles.generation_registry_reader import exact_list, uint
from solslot_puzzles.generation_transactions import MAX_NATIVE_COST, NativeOperation, SingletonTip


@dataclass(frozen=True)
class AdministratorIdentityTip:
    identity: IdentityVaultGenesis
    coin: Coin
    parent: CoinSpend

    def validate(self, authority_id: bytes32):
        i = self.identity
        if type(i.slot) is not int or i.slot not in (0,1,2) or i.launcher_amount != IDENTITY_LAUNCHER_AMOUNTS[i.slot]:
            raise ValueError('administrator identity slot or conserved amount changed')
        rebuilt = build_admin_identity_vault(slot=i.slot,launcher_id=i.launcher_id,
            authority_launcher_id=authority_id,network='testnet11',
            daily_compressed_pubkey=i.daily_compressed_pubkey,recovery_bls_pubkey=i.recovery_bls_pubkey)
        if (rebuilt.custody_reveal != i.custody_reveal or rebuilt.custody_hash != i.custody_hash
                or rebuilt.full_puzzle_hash != i.full_puzzle_hash or rebuilt.daily_member_hash != i.daily_member_hash):
            raise ValueError('identity keys do not reconstruct their exact Testnet11 custody policy')
        if (self.coin.amount != i.launcher_amount or self.coin.puzzle_hash != i.full_puzzle_hash
                or self.coin.parent_coin_info != self.parent.coin.name()):
            raise ValueError('current identity coin differs from its reviewed policy and parent')
        reveal = Program.from_bytes(bytes(self.parent.puzzle_reveal))
        if reveal.get_tree_hash() != self.parent.coin.puzzle_hash:
            raise ValueError('identity parent reveal differs from its confirmed coin')
        if self.parent.coin.name() == i.launcher_id:
            if self.parent.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH or self.parent.coin.amount != i.launcher_amount:
                raise ValueError('identity launch is not its exact reserved singleton')
        else:
            mod, raw = reveal.uncurry(); structure, _ = exact_list(raw,2)
            if mod.get_tree_hash() != SINGLETON_MOD_HASH or structure != singleton_struct(i.launcher_id):
                raise ValueError('identity parent belongs to another singleton')
        additions, _ = compute_additions_with_cost(self.parent,max_cost=MAX_NATIVE_COST)
        if [coin for coin in additions if coin.amount % 2] != [self.coin]:
            raise ValueError('identity parent does not create this exact conserved output')
        return self


def validate_frozen_administrator(authority:GenesisAdminAuthorityV3):
    old=parse_inner_puzzle(authority.inner_puzzle)
    if (authority.authority_puzzle_version!=4 or old.authority_puzzle_version!=4
            or old.state.authority_version!=1 or old.state.pending_kind
            or old.authority_launcher_id!=authority.authority_launcher_id
            or old.source_manifest_hash!=authority.source_manifest_hash
            or old.operational_root_hash!=authority.operational_root_hash
            or old.lost_recovery_root_hashes!=authority.lost_recovery_root_hashes
            or old.identity_launcher_ids!=tuple(i.launcher_id for i in authority.identity_vaults)
            or old.state.current_identity_custody_hashes!=tuple(i.custody_hash for i in authority.identity_vaults)
            or authority.inner_puzzle_hash!=authority.inner_puzzle.get_tree_hash()
            or authority.full_puzzle_hash!=puzzle_for_singleton(authority.authority_launcher_id,
                authority.inner_puzzle).get_tree_hash()):
        raise ValueError('administrator differs from its frozen recovery policy')
    return old


def advance_operational_authority(administrator: SingletonTip, spend: CoinSpend, delegated: Program):
    """Follow V4's actual version increment; never assume its old output hash."""
    administrator.validate()
    parsed = parse_inner_puzzle(administrator.inner)
    if parsed.authority_puzzle_version != 4 or parsed.state.pending_kind:
        raise ValueError('operational action requires the current recovery-aware V4 authority')
    _, amount, solution = exact_list(Program.from_bytes(bytes(spend.solution)),3)
    tag, mine, version, proof = exact_list(solution,4)
    _, _, action_hash, _ = exact_list(proof,4)
    if (uint(amount) != administrator.coin.amount or uint(tag) != 1 or uint(mine) != administrator.coin.amount
            or uint(version) != parsed.state.authority_version+1 or action_hash.as_atom() != delegated.get_tree_hash()):
        raise ValueError('administrator consent does not bind this exact action and authority version')
    successor = make_inner_puzzle(authority_launcher_id=parsed.authority_launcher_id,
        operational_root_hash=parsed.operational_root_hash,lost_recovery_root_hashes=parsed.lost_recovery_root_hashes,
        identity_launcher_ids=parsed.identity_launcher_ids,source_manifest_hash=parsed.source_manifest_hash,
        state=replace(parsed.state,authority_version=parsed.state.authority_version+1),
        routine_delay_seconds=parsed.routine_delay_seconds,lost_key_delay_seconds=parsed.lost_key_delay_seconds,
        authority_puzzle_version=parsed.authority_puzzle_version)
    return administrator.advanced(spend,successor)


@dataclass(frozen=True)
class AdministratorChallenge:
    slot: int
    coin_id: bytes32
    delegated_hash: bytes32
    digest: bytes32
    public_key: bytes

    def typed_data(self):
        return eip712_typed_data_for_coin_spend(network='testnet11',coin_id=self.coin_id,
            delegated_puzzle_hash=self.delegated_hash)


@dataclass(frozen=True)
class PreparedAdministratorAction:
    generation: bytes32
    authority: GenesisAdminAuthorityV3
    administrator: SingletonTip
    identities: tuple[AdministratorIdentityTip,AdministratorIdentityTip,AdministratorIdentityTip]
    target: bytes32
    purpose: str
    subject: object
    issued_at: int
    coadministrator_slot: int

    def delegated(self):
        if self.purpose == 'PUBLICATION_APPROVAL' and isinstance(self.subject,bytes32):
            return publication_action(self.generation,self.target,self.subject,self.issued_at)
        if self.purpose == 'PAUSE_NEW_OPERATIONS' and self.issued_at == 0:
            if not isinstance(self.subject,tuple) or len(self.subject) != 2:
                raise ValueError('pause requires its exact epoch and bounded scope')
            return pause_action(self.generation,self.target,*self.subject)
        raise ValueError('unsupported operational action; code and recovery changes use their governed paths')

    def validate(self):
        if (not isinstance(self.generation,bytes32) or self.generation == bytes32.zeros
                or not isinstance(self.target,bytes32) or self.target == bytes32.zeros
                or type(self.coadministrator_slot) is not int or self.coadministrator_slot not in (1,2)
                or len(self.identities) != 3):
            raise ValueError('exact generation, target and owner-plus-one identities are required')
        self.administrator.validate()
        old = validate_frozen_administrator(self.authority)
        live = parse_inner_puzzle(self.administrator.inner)
        if (live.authority_puzzle_version != 4 or live.state.pending_kind
                or self.authority.authority_launcher_id != self.administrator.launcher_id
                or replace(live,state=old.state) != old):
            raise ValueError('operational authority differs from its frozen recovery policy')
        for slot, tip in enumerate(self.identities):
            tip.validate(self.administrator.launcher_id)
            if (tip.identity.slot != slot or tip.identity.launcher_id != live.identity_launcher_ids[slot]
                    or tip.identity.custody_hash != live.state.current_identity_custody_hashes[slot]):
                raise ValueError('identity is not current in this exact authority')
        self.delegated()
        return self

    def challenges(self):
        self.validate(); delegated = self.delegated()
        prefix = eip712_prefix_and_domain_separator(TESTNET11_GENESIS_CHALLENGE)
        result = []
        for slot in (0,self.coadministrator_slot):
            tip = self.identities[slot]
            action = build_identity_operational_action(identity=tip.identity,
                current_authority_inner_puzzle=self.administrator.inner,authority_delegated_puzzle=delegated)
            digest = eip712_hash_to_sign(prefix,tip.coin.name(),action.get_tree_hash())
            result.append(AdministratorChallenge(slot,tip.coin.name(),action.get_tree_hash(),digest,
                tip.identity.daily_compressed_pubkey))
        return tuple(result)


@dataclass(frozen=True)
class SignedAdministratorAction:
    spends: tuple[CoinSpend,...]
    administrator: SingletonTip
    identities: tuple[AdministratorIdentityTip,AdministratorIdentityTip,AdministratorIdentityTip]


def complete_administrator_action(prepared: PreparedAdministratorAction, signatures: dict[int,bytes]):
    """Verify both signatures against unchanged public challenges and assemble."""
    challenges = prepared.challenges()
    if (any(type(slot) is not int for slot in signatures)
            or set(signatures) != {c.slot for c in challenges}):
        raise ValueError('both and only the reviewed owner-plus-one signatures are required')
    delegated = prepared.delegated(); native = prepared.authority; administrator = prepared.administrator
    tips = prepared.identities
    mips = build_authority_operational_mips_spend(authority=native,current_authority_inner_puzzle=administrator.inner,
        current_identities=tuple(t.identity for t in tips),current_identity_coin_ids=tuple(t.coin.name() for t in tips),
        authority_delegated_puzzle=delegated,coadmin_slot=prepared.coadministrator_slot)
    current = parse_inner_puzzle(administrator.inner)
    authority_spend = administrator.spend(build_operational_solution(my_amount=1,
        new_authority_version=current.state.authority_version+1,mips_reveal=mips.reveal,mips_solution=mips.solution,
        authority_delegated_puzzle=delegated,identity_records=mips.identity_records))
    successor = advance_operational_authority(administrator,authority_spend,delegated)
    spends = [authority_spend]; identities = list(tips)
    for challenge in challenges:
        tip = tips[challenge.slot]; identity = tip.identity
        signature = normalize_eip712_member_signature(signature=signatures[challenge.slot],
            digest=challenge.digest,compressed_pubkey=challenge.public_key)
        member = Program.to([challenge.coin_id,challenge.digest,signature])
        solution = build_identity_operational_solution(identity=identity,current_authority_inner_puzzle=administrator.inner,
            current_identity_coin_id=challenge.coin_id,daily_member_solution=member,authority_delegated_puzzle=delegated)
        spend = make_spend(tip.coin,puzzle_for_singleton(identity.launcher_id,identity.custody_reveal),
            solution_for_singleton(lineage_proof_for_coinsol(tip.parent),tip.coin.amount,solution))
        coin = Coin(tip.coin.name(),identity.full_puzzle_hash,tip.coin.amount)
        identities[challenge.slot] = AdministratorIdentityTip(identity,coin,spend).validate(administrator.launcher_id)
        spends.append(spend)
    return SignedAdministratorAction(tuple(spends),successor,tuple(identities))


def scoped_pause(registry: Registry, tip: SingletonTip, prepared: PreparedAdministratorAction,
                 signatures: dict[int,bytes]):
    prepared.validate()
    if (tip.launcher_id != registry.launcher_id or tip.inner != registry.inner()
            or prepared.generation != registry.generation or prepared.target != tip.coin.puzzle_hash
            or prepared.administrator.launcher_id != registry.administrator_id
            or prepared.purpose != 'PAUSE_NEW_OPERATIONS' or prepared.subject[0] != registry.pause_epoch):
        raise ValueError('pause review differs from the exact current registry and epoch')
    updated = registry.paused(prepared.subject[1])
    consent = complete_administrator_action(prepared,signatures)
    spend = tip.spend(inner_solution('PAUSE',tip.coin,[prepared.administrator.inner.get_tree_hash(),prepared.subject[1]]))
    identity_outputs = tuple(t.coin for t in consent.identities if t.coin.name() not in {p.coin.name() for p in prepared.identities})
    return NativeOperation(registry.generation,'PAUSE_NEW_OPERATIONS',consent.spends+(spend,),
        (consent.administrator,tip.advanced(spend,updated.inner())),identity_outputs),updated,consent
