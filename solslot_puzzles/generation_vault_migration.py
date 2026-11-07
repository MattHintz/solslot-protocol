"""Exact recipient-co-signed deed transfer; no keys, node, or submission."""
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_transactions import NativeOperation,SingletonTip
from solslot_puzzles.vault_driver import puzzle_for_p2_vault,DEFAULT_IDENTITY_ATTEST_ROOT,eip712_typed_data_for_vault_spend
from solslot_puzzles.generation_deed_custody import HeldSmartDeedTip


def _transfer_context(*,generation,sender,recipient,deed,timestamp):
    if not isinstance(deed,HeldSmartDeedTip):
        raise ValueError('transfer requires the actual SmartDeed mint launcher and current lineage')
    for tip in (sender,recipient,deed):tip.validate()
    module=load_puzzle('vault_singleton_inner_generation_v1.clsp')
    values=[]
    for tip in (sender,recipient):
        mod,args=tip.inner.uncurry();parts=list(args.as_iter())
        if mod!=module or len(parts)!=9:raise ValueError('transfer requires both exact generation vault modules')
        values.append(parts)
    source,destination=values
    if source[5:]!=destination[5:]:
        raise ValueError('recipient must preserve the trusted bridge and generation pool')
    if destination[4].as_atom() in (bytes(DEFAULT_IDENTITY_ATTEST_ROOT),bytes(32)):
        raise ValueError('recipient must hold a stamped identity')
    if source[5].as_atom()==bytes(32) or sender.launcher_id==recipient.launcher_id:
        raise ValueError('transfer requires distinct vaults and a trusted bridge')
    if type(timestamp) is not int or not 0<timestamp<2**64-120:
        raise ValueError('transfer requires an unsigned timestamp with room for its expiry')
    held=puzzle_for_p2_vault(sender.launcher_id);target=puzzle_for_p2_vault(recipient.launcher_id)
    if deed.inner!=held:raise ValueError('selected deed is not held by this exact source vault')
    operation=Program.to([b'GEN_VERIFIED_DEED_TRANSFER_V1',source[7],sender.coin.puzzle_hash,sender.coin.name(),
        deed.launcher_id,deed.coin.name(),recipient.coin.puzzle_hash,recipient.coin.name(),target.get_tree_hash(),timestamp]).get_tree_hash()
    if generation==bytes(32):raise ValueError('transfer requires an explicit generation')
    return module,source,destination,held,target,operation


def review_verified_deed_transfer(*,generation,sender,recipient,deed,timestamp):
    *_,operation=_transfer_context(generation=generation,sender=sender,recipient=recipient,deed=deed,timestamp=timestamp)
    return {'operationHash':operation,
        'sender':eip712_typed_data_for_vault_spend(b'm',operation,sender.coin.name()),
        'recipient':eip712_typed_data_for_vault_spend(b't',operation,recipient.coin.name())}


def verified_deed_transfer(*,generation,sender,recipient,deed,timestamp,sender_signature=b'',recipient_signature=b''):
    module,source,destination,held,target,operation=_transfer_context(
        generation=generation,sender=sender,recipient=recipient,deed=deed,timestamp=timestamp)
    sender_spend=sender.spend(Program.to([sender.coin.name(),sender.inner.get_tree_hash(),sender.coin.amount,b'm',
        [deed.launcher_id,deed.coin.name(),timestamp,sender_signature,module.get_tree_hash(),
            [*destination[:5],recipient.inner.get_tree_hash(),recipient.coin.name()]]]))
    recipient_spend=recipient.spend(Program.to([recipient.coin.name(),recipient.inner.get_tree_hash(),recipient.coin.amount,b't',
        [sender.coin.puzzle_hash,sender.coin.name(),deed.launcher_id,deed.coin.name(),timestamp,recipient_signature]]))
    deed_spend=deed.spend(Program.to([sender.inner.get_tree_hash(),sender.coin.name(),deed.launcher_id,
        held.get_tree_hash(),deed.coin.amount,target.get_tree_hash(),deed.coin.name()]))
    result=NativeOperation(generation,'TRANSFER_VERIFIED_DEED',(sender_spend,recipient_spend,deed_spend),
        (sender.advanced(sender_spend,sender.inner),recipient.advanced(recipient_spend,recipient.inner),deed.advanced(deed_spend,target)))
    return result,{'sender':eip712_typed_data_for_vault_spend(b'm',operation,sender.coin.name()),
        'recipient':eip712_typed_data_for_vault_spend(b't',operation,recipient.coin.name())}
