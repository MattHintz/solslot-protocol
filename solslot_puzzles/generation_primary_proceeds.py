"""Permissionless gross -> principal + existing 70/30 technology fee.

R1 candidate only. The route must be bound as the primary payment destination
before issuance, or installed by an actually supported, separately reviewed
migration. It cannot redirect an existing NFT's immutable wallet destination.
No hosted SplitXCH API, extra service charge, custody key or standing withdrawal.
"""
from dataclasses import dataclass
from math import gcd
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_revenue import PrimaryFeeSplitter, nonzero
from solslot_puzzles.generation_transactions import NativeOperation


@dataclass(frozen=True)
class PrimaryProceedsSplitter:
    issuer: bytes32
    fees: PrimaryFeeSplitter
    principal_weight: int = 100
    fee_weight: int = 1

    @property
    def generation(self):return self.fees.bindings.generation

    def inner(self):
        nonzero(self.issuer,'primary issuer proceeds')
        if (any(type(v)is not int or not 0<v<2**64 for v in (self.principal_weight,self.fee_weight))
                or self.principal_weight+self.fee_weight>=2**64
                or gcd(self.principal_weight,self.fee_weight)!=1):
            raise ValueError('primary split weights must be canonical positive exact uint64')
        fee_hash=self.fees.inner().get_tree_hash()
        if self.issuer==fee_hash:raise ValueError('issuer and technology fees require distinct custody')
        return load_puzzle('generation_primary_proceeds_v1.clsp').curry(
            self.generation,self.issuer,fee_hash,self.principal_weight,self.fee_weight)

    @classmethod
    def for_terms(cls,issuer,fees,base_minor,fee_minor):
        from solslot_puzzles.payment_artifacts_v3 import technology_fee_minor
        if (type(base_minor)is not int or type(fee_minor)is not int
                or not 0<base_minor<2**64 or not 0<fee_minor<2**64
                or base_minor+fee_minor>=2**64
                or fee_minor!=technology_fee_minor(base_minor,100)):
            raise ValueError('primary split must retain the exact already-inclusive 1% USD fee')
        divisor=gcd(base_minor,fee_minor)
        result=cls(issuer,fees,base_minor//divisor,fee_minor//divisor)
        result.inner()
        return result

    def allocations(self,amount):
        self.inner()
        if type(amount)is not int or not 1<amount<2**64:
            raise ValueError('primary gross payment must be an exact native uint64 with positive principal')
        principal=amount*self.principal_weight//(self.principal_weight+self.fee_weight)
        if not principal:raise ValueError('primary gross payment has no positive principal')
        fee=amount-principal
        company=(fee*70+99)//100
        return principal,company,fee-company

    def operation(self,coin):
        if not isinstance(coin,Coin):
            raise ValueError('primary proceeds input must be an exact native coin')
        principal,company,rewards=self.allocations(int(coin.amount))
        if coin.puzzle_hash!=self.inner().get_tree_hash():
            raise ValueError('primary proceeds input differs from the reviewed contract destination')
        spend=make_spend(coin,self.inner(),Program.to([int(coin.amount)]))
        fee_outputs=[value for value in compute_additions(spend)
            if value.puzzle_hash==self.fees.inner().get_tree_hash()]
        if len(fee_outputs)!=1 or int(fee_outputs[0].amount)!=company+rewards:
            raise ValueError('native primary proceeds split differs from the exact fee')
        fee_operation=self.fees.operation(fee_outputs[0])
        return NativeOperation(self.generation,'ROUTE_PRIMARY_PROCEEDS',
            (spend,*fee_operation.spends),())

    def review(self):
        return {'schema':'solslot.primary-proceeds-route.v1','generationId':'0x'+self.generation.hex(),
            'network':'testnet11','paymentDestination':'0x'+self.inner().get_tree_hash().hex(),
            'issuerDestination':'0x'+self.issuer.hex(),
            'technologyFeeDestination':'0x'+self.fees.inner().get_tree_hash().hex(),
            'principalWeight':self.principal_weight,'technologyFeeWeight':self.fee_weight,'feeAlreadyIncluded':True,
            'companyShareOfFeeBps':7000,'sgtShareOfFeeBps':3000,
            'financialSigningKey':False,'hostedService':False,
            'existingInventoryDestinationChanged':False}
