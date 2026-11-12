"""The existing native economic boundary pays the candidate's 70/30 split.

This validates complete signed pool/CAT settlement construction, not live
generation binding or new-genesis readiness. The new stable pool authority
must preserve these executable invariants when it is integrated.
"""
from dataclasses import replace
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import SpendBundle

from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.sols_swap_v4_driver import (
    aggregate_sols_to_deed_swap,build_sols_to_deed_protocol_offer,
    prepare_vault_sols_buyer_offer,
)
from tests.test_sols_swap_v4_driver import (
    CONFIG,STATUTES_STATE,RULES,VAULT_LAUNCHER,b32,
    _fixture,_forward_arguments,_assert_signed_consensus,
)


def candidate_swap():
    parameters=GenerationParameters(*(b32(n) for n in range(210,215))).economic_parameters()
    config=replace(CONFIG,pool_puzzle_version=5)
    statutes=replace(STATUTES_STATE,
        parameters_root=Program.to(list(parameters.as_tuple())).get_tree_hash())
    fixture=_fixture(parameters=parameters,config=config,statutes_state=statutes)
    buyer=prepare_vault_sols_buyer_offer(payment_coin=fixture.payment_coin,
        payment_lineage_proof=fixture.payment_lineage,receipt=fixture.receipt,
        config=config,vault_launcher_id=VAULT_LAUNCHER)
    protocol=build_sols_to_deed_protocol_offer(**_forward_arguments(fixture,
        parameters=parameters,config=config,statutes_state=statutes),vault_signature_data=None)
    aggregate=aggregate_sols_to_deed_swap(buyer_offer=buyer.offer,protocol_offer=protocol,
        receipt=fixture.receipt,config=config,vault_launcher_id=VAULT_LAUNCHER)
    return fixture,config,protocol,aggregate.aggregate_offer.to_valid_spend()


def test_actual_signed_pool_settlement_pays_seventy_protocol_thirty_sgt():
    fixture,config,protocol,bundle=candidate_swap()
    _assert_signed_consensus(bundle)
    quote=fixture.receipt.sols_to_deed_quote
    assert quote.principal_sols_mojos==30000
    assert (quote.fee_split.total_fee_sols_mojos,
        quote.fee_split.protocol_fee_sols_mojos,quote.fee_split.sgt_rewards_fee_sols_mojos)==(300,210,90)
    additions=[coin for spend in bundle.coin_spends for coin in compute_additions(spend)]
    # Fees are destinations expressed as inner puzzle HASHES. Compute the
    # full CAT hash without inventing a reveal for these treasury policies.
    from chia.wallet.util.curry_and_treehash import curry_and_treehash,calculate_hash_of_quoted_mod_hash
    def cat_hash(inner_hash):
        return curry_and_treehash(calculate_hash_of_quoted_mod_hash(CAT_MOD.get_tree_hash()),
            Program.to(CAT_MOD.get_tree_hash()).get_tree_hash(),
            Program.to(RULES.sols_tail_hash).get_tree_hash(),inner_hash)
    expected={cat_hash(config.reserve_puzzle_hash):30000,
        cat_hash(RULES.protocol_treasury_puzzle_hash):210,
        cat_hash(config.sgt_rewards_puzzle_hash):90}
    for puzzle,amount in expected.items():
        assert [int(c.amount) for c in additions if c.puzzle_hash==puzzle]==[amount]
    assert fixture.receipt.next_state.economics.total_sols_mojos==fixture.receipt.current_state.economics.total_sols_mojos
    assert fixture.receipt.next_state.economics.reserve_sols_mojos==30001


@pytest.mark.parametrize('fees',[(90,210),(211,89),(209,91),(300,0),(0,300)])
def test_native_pool_rejects_reassigned_fee_shares_even_when_total_is_unchanged(fees):
    _,_,protocol,bundle=candidate_swap()
    spend=protocol.pool_spend
    raw=Program.from_bytes(bytes(spend.solution)).as_python()
    # Singleton outer solution wraps (my_id inner_hash amount action params).
    raw[2][4][26],raw[2][4][27]=fees
    changed=make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),Program.to(raw))
    tampered=SpendBundle([changed if s.coin==spend.coin else s for s in bundle.coin_spends],bundle.aggregated_signature)
    with pytest.raises(Exception):_assert_signed_consensus(tampered)
