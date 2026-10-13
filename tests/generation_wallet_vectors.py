"""Deterministic public vectors for the browser's SGT signing boundary.

Synthetic keys are derived in memory, never serialized. Native execution is
included so the browser checks agree with compiled consensus effects, not with
another JavaScript implementation. This creates no network or wallet request.
"""
import json
from dataclasses import replace
from pathlib import Path

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol
from chia_rs import AugSchemeMPL, Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles.generation_sgt import GenesisIssuancePlan, build_initial_issuance, transition_digest
from solslot_puzzles.generation_vault import vault_inner, sgt_owner, authorization_hash, authorization_solution, signing_data
from solslot_puzzles.holdings import HoldingKind
from solslot_puzzles.generation_governance import ProposalSet
from tests.test_generation_registry_native import Singleton, b32


def hex_bytes(value):
    return '0x' + bytes(value).hex()


def coin_json(coin):
    return dict(parentCoinInfo=hex_bytes(coin.parent_coin_info), puzzleHash=hex_bytes(coin.puzzle_hash), amount=int(coin.amount))


def spend_json(spend):
    return dict(coin=coin_json(spend.coin), puzzleReveal=hex_bytes(spend.puzzle_reveal), solution=hex_bytes(spend.solution))


def public_vectors():
    now, generation, pool, vaults, owners, public_keys = 2_000_000_000, b32(1), b32(10), [], [], []
    for slot, kind in enumerate((1, 3, 1)):
        origin = Coin(b32(50+slot), Program.to(1).get_tree_hash(), uint64(100))
        launcher = Coin(origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        if kind == 1:
            public_key = bytes(AugSchemeMPL.key_gen(bytes([71+slot])*32).get_g1())
        else:
            public_key = keys.PrivateKey(bytes([71+slot])*32).public_key.to_compressed_bytes()
        inner = vault_inner(vault_launcher_id=launcher, owner_pubkey=public_key, auth_type=kind,
            members_merkle_root=Program.to(public_key).get_tree_hash(), pool_launcher_id=pool)
        _, launch = launch_conditions_and_coinsol(origin, inner, [], uint64(1))
        vaults.append(Singleton(inner, launch)); owners.append(sgt_owner(generation, launcher)); public_keys.append(public_key)
    plan = GenesisIssuancePlan(b32(6), generation, b32(7), b32(8), b32(9),
                              tuple(owner.get_tree_hash() for owner in owners), b32(11))
    b, issuance = plan.bindings(), build_initial_issuance(plan)
    vectors = []
    for slot, kind in enumerate((1, 3)):
        vault, original_coin, original_source, public_key = vaults[slot], issuance.coins[slot], issuance.outputs[slot], public_keys[slot]
        args = list(vault.inner.uncurry()[1].as_iter())
        for label in ('TRANSFER', 'LOCK', 'RELOCK'):
            action='LOCK' if label=='RELOCK' else label
            coin,source,tree=original_coin,original_source,issuance.holdings
            if label=='RELOCK':
                source=replace(original_source,kind=HoldingKind.LOCKED_HOLDER,lock_id=b32(98))
                coin=source.coin(b,original_coin.name())
                tree=tree.replace(original_coin.name(),original_source.holding(b),None).replace(coin.name(),None,source.holding(b))
            outputs = (replace(source, owner=owners[2].get_tree_hash()),) if action == 'TRANSFER' else (
                replace(source, kind=HoldingKind.LOCKED_HOLDER, lock_id=b32(99)),)
            digest = transition_digest(b, coin, action, outputs)
            expiry = now + 600
            request = dict(generationId=hex_bytes(generation), action=action, expiresAt=expiry,
                vaultCoinId=hex_bytes(vault.coin.name()), sgtCoinId=hex_bytes(coin.name()),
                outputs=[dict(kind=int(o.kind), owner=hex_bytes(o.owner), amount=o.amount,
                              lockId=hex_bytes(o.lock_id) if o.lock_id else None) for o in outputs])
            conditions, cost = None, None
            if kind == 1:
                spend = vault.spend(authorization_solution(generation, vault.coin, vault.inner, coin.name(), digest, expiry))
                request['vaultCoinSpend'] = spend_json(spend)
                cost, conditions = Program.from_bytes(bytes(spend.puzzle_reveal)).run_with_cost(
                    100_000_000, Program.from_bytes(bytes(spend.solution)))
            else:
                request['typedData'] = signing_data(generation, vault.coin.name(), coin.name(), digest, expiry)
            selection = dict(action=action, destinations=[dict(vaultLauncherId=hex_bytes(vaults[2].launcher), amount=10_000)])
            if action == 'LOCK':
                selection = dict(action=action, proposalId=hex_bytes(b32(99)), snapshotRoot=hex_bytes(tree.root.hash),
                    eligibleSupply=30_000, snapshotProof=[[hex_bytes(h), e, total] for h, e, total in tree.proof(coin.name())],
                    votingClosesAt=now+3600)
            context = dict(generationId=hex_bytes(generation), network='testnet11',
                bindings=dict(ledgerLauncherId=hex_bytes(b.ledger_launcher_id), governanceLauncherId=hex_bytes(b.governance_launcher_id),
                    reserveOwner=hex_bytes(b.reserve_owner), tailHash=hex_bytes(b.tail_hash), poolLauncherId=hex_bytes(pool),
                    bridgePolicyHash=hex_bytes(args[5].as_atom())),
                owner=dict(authType=kind, publicKey=hex_bytes(public_key), address=hex_bytes(public_key) if kind==1 else
                    keys.PublicKey.from_compressed_bytes(public_key).to_address()),
                vault=dict(launcherId=hex_bytes(vault.launcher), identityRoot=hex_bytes(args[4].as_atom()),
                    current=dict(coin=coin_json(vault.coin), confirmedHeight=10, spentHeight=0), parentSpend=spend_json(vault.parent)),
                holding=dict(current=dict(coin=coin_json(coin), confirmedHeight=11, spentHeight=0)), selection=selection)
            if label=='RELOCK':
                closed=ProposalSet((b32(98),))
                context['holding']['priorLock']=dict(proposalId=hex_bytes(b32(98)),closedRoot=hex_bytes(closed.root),
                    closedProof=[hex_bytes(v) for v in closed.proof(b32(98))])
            vectors.append(dict(name=('bls' if kind==1 else 'evm')+'-'+label.lower(), context=context, request=request,
                expected=dict(transitionDigest=hex_bytes(digest), authorizationHash=hex_bytes(authorization_hash(
                    generation, vault.coin.name(), coin.name(), digest, expiry)), innerHash=hex_bytes(vault.inner.get_tree_hash()),
                    nativeConditions=hex_bytes(conditions) if conditions else None, nativeCost=cost)))
    return dict(schemaVersion=1, purpose='SYNTHETIC_SIGNING_BOUNDARY_TEST_ONLY', nowSeconds=now, generationId=hex_bytes(generation), vectors=vectors)


if __name__ == '__main__':
    import sys
    target = Path(sys.argv[1])
    target.write_text(json.dumps(public_vectors(), indent=2)+'\n')
    print('Wrote six synthetic native signing vectors: '+str(target))
