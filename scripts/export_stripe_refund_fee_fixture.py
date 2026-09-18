"""Public synthetic native-chain refund vector, generated with real builders."""
import json
from pathlib import Path
import sys
import asyncio
from types import SimpleNamespace
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root.parent / 'api'))
sys.path.insert(0, str(root))
from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from chia_rs import AugSchemeMPL, Coin, SpendBundle, validate_clvm_and_signature, MEMPOOL_MODE, ENABLE_SECP_OPS, ENABLE_KECCAK_OPS_OUTSIDE_GUARD
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from tests.test_voucher_presale_v3_driver import issued_voucher, b32
from solslot_api.faucet import AGG_SIG_ME_DATA
from solslot_api.voucher_refund_authorization import build_vault_refund_spend
from solslot_puzzles.vault_driver import puzzle_for_vault_full, one_leaf_merkle_root
from solslot_puzzles.voucher_presale_v3_driver import build_stripe_voucher_terminal_spends
from solslot_puzzles.voucher_presale_v2_driver import VoucherAction


def vector(browser_output=None):
    terms,voucher,receipt,issuance = issued_voucher()
    owner = AugSchemeMPL.key_gen(b'o'*32)
    key = bytes(owner.get_g1())
    vault_id = voucher.approved_vault_launcher_id
    full = puzzle_for_vault_full(vault_id,key,1,one_leaf_merkle_root(key),b32(43),
        identity_attest_root=b32(42),zkpassport_bridge_policy_hash=b32(44))
    inner = list(full.uncurry()[1].as_iter())[1]
    parent = Coin(vault_id,full.get_tree_hash(),1)
    vault = Coin(parent.name(),full.get_tree_hash(),1)
    owner_spend = build_vault_refund_spend(vault_coin=vault,vault_launcher_id=vault_id,owner_pubkey=key,
        auth_type=1,members_merkle_root=one_leaf_merkle_root(key),pool_launcher_id=b32(43),identity_attest_root=b32(42),
        zkpassport_bridge_policy_hash=b32(44),voucher_launcher_id=issuance.voucher_launcher_id,
        current_timestamp=terms.sale_open+200,lineage_proof=LineageProof(parent.parent_coin_info,inner.get_tree_hash(),uint64(1)))
    terminal = build_stripe_voucher_terminal_spends(terms=terms,state=issuance.next_series_state,
        series_coin=issuance.next_series_coin,series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
        voucher=voucher,artifact=receipt.artifact,voucher_launcher_id=issuance.voucher_launcher_id,
        voucher_coin=issuance.voucher_coin,voucher_lineage_proof=lineage_proof_for_coinsol(issuance.voucher_launcher_spend),
        receipt_coin=issuance.receipt_coin,vault_coin_id=vault.name(),vault_inner_puzzle_hash=inner.get_tree_hash(),
        action=VoucherAction.REFUND_PRESALE,terminal_evidence_hash=b32(20),signer_indices=(0,1))
    spends = [owner_spend,*terminal.coin_spends]
    keys = [owner,*(AugSchemeMPL.key_gen(bytes([i])*32) for i in (31,32,33))]
    private = {bytes(sk.get_g1()):sk for sk in keys}
    signatures = []
    for spend in spends:
        conditions = conditions_dict_for_solution(Program.from_bytes(bytes(spend.puzzle_reveal)),Program.from_bytes(bytes(spend.solution)),11_000_000_000)
        for pk,msg in pkm_pairs_for_conditions_dict(conditions,spend.coin,AGG_SIG_ME_DATA['testnet11']):
            signatures.append(AugSchemeMPL.sign(private[bytes(pk)],msg))
    bundle = SpendBundle(spends,AugSchemeMPL.aggregate(signatures))
    validate_clvm_and_signature(bundle,11_000_000_000,DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(AGG_SIG_ME_DATA['testnet11'])),
        MEMPOOL_MODE|ENABLE_SECP_OPS|ENABLE_KECCAK_OPS_OUTSIDE_GUARD)
    assert sum(c.amount for c in bundle.removals())-sum(c.amount for c in bundle.additions())==1
    if browser_output:
        context = SimpleNamespace(terms=terms,voucher=voucher,purchase=receipt.artifact,is_stripe=True,
            vault_spend=owner_spend,provisional=terminal,vault_coin=vault,refund_action=VoucherAction.REFUND_PRESALE)
        review_vector = asyncio.run(browser_vector(context,key))
        Path(browser_output).write_text(json.dumps(review_vector,sort_keys=True,separators=(',',':'))+'\n')
    return {'synthetic':True,**({'reviewVector':review_vector} if browser_output else {}),
        'spendBundle':bundle.to_json_dict(),'receiptCoinId':'0x'+issuance.receipt_coin.name().hex(),
        'purchaseId':'0x'+receipt.artifact.purchase_id.hex(),'artifactHash':'0x'+receipt.artifact.artifact_hash.hex(),
        'termsHash':'0x'+terms.terms_hash.hex(),'serial':voucher.serial,
        'outputs':{key:coin.to_json_dict() for key,coin in {'series':terminal.next_series_coin,
            'terminalVoucher':terminal.terminal_voucher_coin,'vault':Coin(vault.name(),vault.puzzle_hash,1)}.items()},
        'bindings':{'seriesInputCoinId':'0x'+issuance.next_series_coin.name().hex(),'vaultInputCoinId':'0x'+vault.name().hex(),
            'externalSettlementEvidenceHash':'0x'+b32(20).hex()}}


async def browser_vector(context,key):
    import pytest
    import time
    from solslot_api.chia_provider import ChiaProvider, ChiaProviderConfig
    from solslot_api.chia_snapshot import PrimaryReadSnapshot
    from solslot_api.faucet import Faucet
    from solslot_api.presale_endpoints import PresaleStore, _coin_spend_json
    from solslot_api.protocol_submission import ProtocolBundleSubmitter, ProtocolFeePolicy
    from solslot_api.voucher_refund_review import refund_execution_evidence
    from solslot_api.voucher_refund_funding import reserve_refund_funding
    from solslot_api.sols_swap_funding import digest,hx
    now=context.terms.sale_open+200
    faucet=Faucet.from_seed_hex('77'*32,'testnet11')
    fee=Coin(b32(80),faucet.address_puzzle_hash,10000)
    class Node:
        async def get_network_info(self):return dict(success=True,network_name='testnet11')
        async def get_blockchain_state(self):return dict(success=True,blockchain_state=dict(peak=dict(height=100,header_hash=hx(b32(81))),sync=dict(synced=True,sync_mode=False)))
        async def get_block_record(self,digest):return dict(success=True,block_record=dict(height=100,header_hash=digest,timestamp=now,prev_hash=hx(b32(82))))
        async def get_coin_record_by_name(self,name):return records.get(name)
        async def get_coin_records_by_puzzle_hash(self,*args,**kwargs):return [records[hx(fee.name())]]
        async def get_mempool_items_by_coin_name(self,name):return []
        async def get_fee_estimate(self,**kwargs):return dict(estimates=[100],target_times=kwargs['target_times'])
    records={hx(coin.name()):dict(coin=coin.to_json_dict(),confirmed_block_index=10,spent_block_index=0,spent=False)
        for coin in [context.vault_coin,*(s.coin for s in context.provisional.coin_spends),fee]}
    node=ChiaProvider(Node(),None,ChiaProviderConfig(network='testnet11',primary_url='https://synthetic.invalid',fallback_url=''))
    submitter=ProtocolBundleSubmitter(provider=node,faucet=faucet,policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,maximum_mojos=10000))
    store=PresaleStore(':memory:')
    artifact=dict(network='testnet11',launcherIds={'pool':hx(b32(43))},bridgePolicy={'policyHash':hx(b32(44))},
        validatorSet={'threshold':2,'pubkeys':[hx(k) for k in context.terms.validator_pubkeys]})
    evidence=refund_execution_evidence(context)
    binding=dict(action='VOUCHER_REFUND',vaultLauncherId=hx(context.voucher.approved_vault_launcher_id),ownerKey=hx(key),authType='chia_bls',network='testnet11',
        sessionFingerprint=hx(b32(83)),sessionExpiresAt=now+1800,artifactHash=digest(artifact),purchaseId=hx(context.purchase.purchase_id),
        termsHash=hx(context.terms.terms_hash),serial=context.voucher.serial,candidateHash=evidence['candidateHash'],quoteExpiresAt=now+90)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(time,'time',lambda:now)
            patch.setattr('solslot_api.voucher_refund_funding.time',lambda:now)
            async with PrimaryReadSnapshot(node,'testnet11') as snapshot:
                funding=await reserve_refund_funding(submitter,store,context,evidence,binding,lambda:binding)
                evidence['fundingEvidence']=funding
                evidence['currentStateEvidence']=await snapshot.finish([*[(s['role'],coin) for s,coin in zip(evidence['coinSpends'],
                    [context.vault_coin,*(s.coin for s in context.provisional.coin_spends)])],('fee',fee)],{**binding,'fundingReservationHash':funding['reservationHash']})
    finally:store._conn.close()
    v=context.voucher
    selected=dict(termsHash=hx(context.terms.terms_hash),serial=v.serial,purchaseId=hx(context.purchase.purchase_id),paymentRail='STRIPE_USD',
        paymentPrincipal=v.payment_principal,processingChargeMinor=v.processing_charge_minor,originalPayer=hx(v.original_payer),vaultLauncherId=hx(v.approved_vault_launcher_id),
        vaultP2PuzzleHash=hx(v.approved_vault_p2_puzzle_hash),commitmentHash=hx(v.commitment_hash),globalPaymentId=hx(v.global_payment_id),
        voucherLauncherId=hx(context.provisional.voucher_spend.coin.parent_coin_info),voucherOutputCoinId=hx(context.provisional.voucher_spend.coin.name()),
        paymentCommitmentCoinId=hx(context.provisional.receipt_spend.coin.name()),seriesSingletonId=hx(context.terms.series_singleton_id),
        collectionId=hx(v.collection_id),deedLauncherId=hx(v.deed_launcher_id),refundDeadline=v.refund_deadline,state='ESCROWED',seriesState='PRESALE')
    intent=dict(termsHash=selected['termsHash'],serial=v.serial,purchaseId=selected['purchaseId'],paymentRail='STRIPE_USD',authType='chia_bls',action='REFUND_PRESALE',
        vaultCoinId=hx(context.vault_coin.name()),voucherCoinId=selected['voucherOutputCoinId'],seriesCoinId=hx(context.provisional.series_spend.coin.name()),
        currentTimestamp=now,expiresAt=now+90,coinSpends=[_coin_spend_json(context.vault_spend)],typedData=None,reviewEvidence=evidence)
    return dict(synthetic=True,intent=intent,selected=selected,artifact=artifact,
        session=dict(authType='chia_bls',address=hx(key),vaultLauncherId=selected['vaultLauncherId'],network='testnet11'),
        vault=dict(confirmed=True,current_coin_id=hx(context.vault_coin.name()),vault_full_puzhash=hx(context.vault_coin.puzzle_hash),identity_attest_root=hx(b32(42))))

if __name__=='__main__':
    Path(sys.argv[1]).write_text(json.dumps(vector(sys.argv[2] if len(sys.argv)>2 else None),sort_keys=True,separators=(',',':'))+'\n')
