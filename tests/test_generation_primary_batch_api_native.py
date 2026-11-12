"""The API resolves actual native history and the original signed offers."""
from types import SimpleNamespace
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint32

from solslot_puzzles.generation_sgt import GenesisIssuancePlan
from solslot_puzzles.payment_artifacts_v2 import oracle_round_to_json
from solslot_api.generation_chain_evidence import GenerationChainAnchor
from solslot_api.generation_sols_batch_execution import PrimaryBatchClaim,BatchBuyer,resolve_batch,delivery_messages
from tests.test_generation_governance_native import generation
from tests.test_generation_primary_batch_native import prepare
from tests.test_generation_registry_native import b32


class NativeProvider:
    def __init__(self,c):self.c=c
    async def get_network_info_primary(self):return {'network_name':'testnet11'}
    async def get_coin_record_by_name_primary(self,identity):
        value=await self.c['client'].get_coin_record_by_name(bytes32.from_hexstr(identity))
        return value.to_json_dict() if value else None
    async def get_puzzle_and_solution_primary(self,identity,height):
        return (await self.c['client'].get_puzzle_and_solution(bytes32.from_hexstr(identity),uint32(height))).to_json_dict()
    async def get_coin_records_by_puzzle_hash_primary(self,puzzle_hash,*,include_spent=False):
        return [r.to_json_dict() for r in await self.c['client'].get_coin_records_by_puzzle_hash(bytes32.from_hexstr(puzzle_hash),include_spent_coins=include_spent)]


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['batch'],indirect=True)
async def test_independent_api_reconstruction_matches_native_two_deed_batch(generation,tmp_path,monkeypatch):
    c=generation;sgt=c['bindings']
    issuance=GenesisIssuancePlan(c['issue'].eve_coin.parent_coin_info,sgt.generation,sgt.ledger_launcher_id,
        sgt.governance_launcher_id,sgt.reserve_owner,tuple(v.get_tree_hash() for v in c['owners']),b32(88))
    anchor=GenerationChainAnchor(issuance,c['registry'],c['gov'],(c['parameters'],c['mint'],c['pool']))
    settlement,_,kwargs,_,_,_=await prepare(c,True,deeds=2,wanted_offset=1)
    price=kwargs['signed_price'];h=lambda value:'0x'+value.hex()
    # build_primary_batches's source context uses immutable mint outputs.
    claim=PrimaryBatchClaim(generationId=h(sgt.generation),anchorHash=h(b32(77)),
        primaryCoinIds=tuple(h(s.coin.name()) for s in settlement.primary_spends),
        buyers=tuple(BatchBuyer(offer=o.offer().to_bech32(),destination=h(o.destination_inner_hash),
            paymentAsset=h(o.payment_asset) if o.payment_asset else None) for o in kwargs['orders']),
        signedPrice={'round':oracle_round_to_json(price.round),
            'signatures':[{'signerIndex':i,'signature':'0x'+raw.hex()} for i,raw in price.signatures]},
        expiresAt=kwargs['expires_at'],signerIndices=(0,1),registryCoinId=h(kwargs['registry_tip'].coin.name()),
        poolCoinId=h(kwargs['pool_tip'].coin.name()),statutesCoinId=h(kwargs['statutes_tip'].coin.name()))
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=h(sgt.generation),generation_chain_anchor_hash=h(b32(77)))
    resolved,evidence=await resolve_batch(claim,settings=settings,anchor=anchor,provider=NativeProvider(c),
        clock=lambda:int(c['sim'].timestamp),signature_data=DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    assert resolved.bundle==settlement.bundle
    messages=delivery_messages(resolved,additional_data=DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    assert len(messages[0])==len(messages[1])==2 and messages[2]==[]
    assert resolved.backing_coins==settlement.backing_coins
    assert resolved.batch.commitment==settlement.batch.commitment
    # Crash after the operation journal's commit but before the order book's
    # commit: restarting must repair exact links, without another builder or
    # validator signature round.
    from contextlib import contextmanager
    from solslot_api.generation_sols_batches import GenerationSolsOrderBook
    from solslot_api.generation_operations import GenerationOperationJournal
    book=GenerationSolsOrderBook(tmp_path/'orders.db',h(sgt.generation),kwargs['pool'].permanent.permanent_rules.sols_tail_hash,
        signature_data=DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
    for order in resolved.batch.orders:
        book.place(order.offer(),payment_asset=order.payment_asset,destination=order.destination_inner_hash,now=int(c['sim'].timestamp))
    journal=GenerationOperationJournal(tmp_path/'operations.db',h(sgt.generation))
    db_before=book.db
    @contextmanager
    def crash_after_journal(write=False):
        with db_before(write) as db:
            yield db
            if write:raise OSError('synthetic power loss before book commit')
    monkeypatch.setattr(book,'db',crash_after_journal)
    with pytest.raises(OSError):
        book.retain_settlement(resolved,journal=journal,pool_tip=kwargs['pool_tip'],statutes_tip=kwargs['statutes_tip'],
            registry_tip=kwargs['registry_tip'],fee_cap=100,now=int(c['sim'].timestamp))
    monkeypatch.setattr(book,'db',db_before)
    assert len(journal.batch_operations())==1
    identities=tuple(h(order.order_id) for order in resolved.batch.orders)
    assert all(book.status(identity)['operationId'] is None for identity in identities)
    saved=book.linked_operation(identities,journal)
    from solslot_puzzles.generation_transactions import NativeOperation
    native=NativeOperation(resolved.generation,'PRIMARY_SOLS_BATCH',tuple(resolved.bundle.coin_spends),
        resolved.successors,resolved.backing_coins,resolved.bundle.aggregated_signature)
    assert saved['intentHash']==h(native.commitment)
    assert all(book.status(identity)['operationId']==saved['operationId'] for identity in identities)
    assert journal.protocol_bundle(saved['operationId'])==resolved.bundle
    assert len(journal.batch_operations())==1
