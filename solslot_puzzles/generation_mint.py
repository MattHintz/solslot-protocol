"""Deterministic TEST_ONLY SmartDeed issuance under stable governed authority.

This builder has no provider, keys or submission method. The caller must prove
source, preview, review and governance commitments before requesting signatures.
The native kernel independently derives every inventory output and consumes a
single-use collection receipt. Existing delivery/identity puzzles stay intact.
"""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia_rs import CoinSpend, G1Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import ProposalSet
from solslot_puzzles.generation_registry import Component, singleton_struct
from solslot_puzzles.mint_publish_driver import make_smart_deed_inner
from solslot_puzzles.payment_artifacts_v3 import technology_fee_minor
from solslot_puzzles.stripe_settlement_v1_driver import PrimaryMintTermsV3, make_inventory_available_inner


def positive(value, name, maximum=2**64-1):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError(f'{name} must be a positive bounded integer')


def nonzero(value, name):
    if not isinstance(value,bytes32) or value==bytes32.zeros:
        raise ValueError(f'{name} must be a nonzero bytes32')


@dataclass(frozen=True)
class MintRow:
    launcher_parent: bytes32
    share_ppm: int
    base_usd_minor: int
    sealed_par_mojos: int

    def program(self):
        nonzero(self.launcher_parent,'launcher parent')
        positive(self.share_ppm,'share',1_000_000)
        positive(self.base_usd_minor,'purchase amount')
        positive(self.sealed_par_mojos,'sealed XCH par value')
        return [self.launcher_parent,self.share_ppm,self.base_usd_minor,self.sealed_par_mojos]


@dataclass(frozen=True)
class TestMintEdition:
    __test__ = False
    generation: bytes32
    collection: bytes32
    metadata_root: bytes32
    preview_hash: bytes32
    property_id: bytes32
    pricing_round: bytes32
    technology_fee_bps: int
    asset_class: int
    jurisdiction: bytes
    rows: tuple[MintRow,...]

    def program(self):
        for name in ('generation','collection','metadata_root','preview_hash','property_id','pricing_round'):
            nonzero(getattr(self,name),name)
        if type(self.technology_fee_bps) is not int or not 0<=self.technology_fee_bps<=1000:
            raise ValueError('technology fee exceeds its permanent 10% ceiling')
        if type(self.asset_class) is not int or not 0<=self.asset_class<2**64:
            raise ValueError('asset class must be uint64')
        if not isinstance(self.jurisdiction,bytes) or not 0<len(self.jurisdiction)<=32:
            raise ValueError('jurisdiction requires 1 to 32 bytes')
        positive(len(self.rows),'inventory count',100)
        if (len({r.launcher_parent for r in self.rows})!=len(self.rows)
                or sum(r.share_ppm for r in self.rows)!=1_000_000):
            raise ValueError('unique launcher parents and exactly 100% allocation are required')
        positive(sum(r.base_usd_minor for r in self.rows),'total purchase amount')
        return [b'TEST_ONLY',self.generation,self.collection,self.metadata_root,self.preview_hash,
            self.property_id,self.pricing_round,self.technology_fee_bps,self.asset_class,self.jurisdiction,
            [row.program() for row in self.rows]]

    @property
    def commitment(self):return Program.to([b'SOLSLOT_TEST_EDITION_V1',self.program()]).get_tree_hash()

    def bill(self):return Program.to([b'MINT_TEST_ONLY',self.collection,self.commitment,len(self.rows)])


@dataclass(frozen=True)
class MintedInventory:
    launcher_spend: CoinSpend
    coin: Coin
    terms: PrimaryMintTermsV3
    inner: Program
    smart_deed: Program


@dataclass(frozen=True)
class GenerationMint:
    generation: bytes32
    registry_id: bytes32
    governance_id: bytes32
    launcher_id: bytes32
    component_id: bytes32
    pool_id: bytes32
    treasury_puzzle_hash: bytes32
    protocol_puzzle_hash: bytes32
    validator_pubkeys: tuple[bytes,bytes,bytes]
    provider_id: bytes32
    issued: ProposalSet | None = None
    issued_count: int = 0
    version: int = 1
    compatibility: int = 1
    module_hash: bytes32 | None = None
    primary_batch_bindings: Program | None = None

    def __post_init__(self):
        if self.issued is None:object.__setattr__(self,'issued',ProposalSet())
        for name in ('generation','registry_id','governance_id','launcher_id','component_id','pool_id',
                     'treasury_puzzle_hash','protocol_puzzle_hash','provider_id'):
            nonzero(getattr(self,name),name)
        if len(self.validator_pubkeys)!=3 or len(set(self.validator_pubkeys))!=3:
            raise ValueError('three distinct delivery validators are required')
        for key in self.validator_pubkeys:
            if G1Element.from_bytes(key)==G1Element():raise ValueError('validator public key must not be infinity')
        if type(self.issued_count) is not int or not 0<=self.issued_count<2**64:
            raise ValueError('issued count must be uint64')

    def logic_hash(self):return self.module_hash or load_puzzle('generation_mint_logic_v1.clsp').get_tree_hash()

    def component(self):
        return Component(self.component_id,self.launcher_id,load_puzzle('generation_mint_v1.clsp').get_tree_hash(),
                         self.logic_hash(),self.version,self.compatibility)

    def bindings(self):
        from solslot_puzzles.generation_primary_inventory import inventory_module
        inventory = inventory_module(self.primary_batch_bindings or Program.to([]))
        return [singleton_struct(self.launcher_id),singleton_struct(self.governance_id),singleton_struct(self.pool_id),
            self.treasury_puzzle_hash,self.protocol_puzzle_hash,list(self.validator_pubkeys),self.provider_id,
            [load_puzzle(name).get_tree_hash() for name in ('singleton_launcher_with_did.clsp',
                'generation_primary_inventory_v2.clsp' if inventory == load_puzzle('generation_primary_inventory_v2.clsp') else 'generation_primary_inventory_v1.clsp','mint_offer_delegate_v6.clsp','smart_deed_inner_v2.clsp',
                'p2_pool_v2.clsp','p2_vault.clsp')]+[CAT_MOD.get_tree_hash(),OFFER_MOD_HASH],self.primary_batch_bindings or Program.to([])]

    def state(self):return Program.to([self.bindings(),self.issued.root,self.issued_count])

    def inner(self):
        mod=load_puzzle('generation_mint_v1.clsp')
        return mod.curry(mod.get_tree_hash(),self.generation,singleton_struct(self.registry_id),self.component_id,
            self.logic_hash(),self.version,self.compatibility,self.state())

    def minted(self,edition: TestMintEdition):
        edition.program()
        if edition.generation!=self.generation:raise ValueError('edition belongs to another generation')
        if edition.collection in self.issued.keys:raise ValueError('collection inventory already minted')
        return replace(self,issued=self.issued.add(edition.collection),issued_count=self.issued_count+len(edition.rows))

    def inventories(self,edition: TestMintEdition) -> tuple[MintedInventory,...]:
        self.minted(edition) # Validate without changing state.
        launcher=load_puzzle('singleton_launcher_with_did.clsp').curry(singleton_struct(self.launcher_id))
        output=[]
        for row in edition.rows:
            coin=Coin(row.launcher_parent,launcher.get_tree_hash(),uint64(1))
            structure=Program.to((SINGLETON_MOD_HASH,(coin.name(),launcher.get_tree_hash())))
            deed=make_smart_deed_inner(deed_singleton_struct_program=structure,
                protocol_did_puzhash=singleton_struct(self.launcher_id).get_tree_hash(),
                par_value_mojos=row.sealed_par_mojos,asset_class=edition.asset_class,
                property_id_canon=edition.property_id,collection_id_canon=edition.collection,
                share_ppm=row.share_ppm,jurisdiction=edition.jurisdiction,
                royalty_puzhash=self.treasury_puzzle_hash,royalty_bps=0,
                pool_singleton_launcher_id=self.pool_id,pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
                p2_pool_mod_hash=load_puzzle('p2_pool_v2.clsp').get_tree_hash(),
                p2_vault_mod_hash=load_puzzle('p2_vault.clsp').get_tree_hash())
            fee=technology_fee_minor(row.base_usd_minor,edition.technology_fee_bps)
            terms=PrimaryMintTermsV3(network='testnet11',smart_deed_inner_hash=deed.get_tree_hash(),
                deed_launcher_id=coin.name(),deed_launcher_puzzle_hash=launcher.get_tree_hash(),
                collection_id=edition.collection,metadata_root=edition.metadata_root,metadata_anchor_id=edition.commitment,
                share_ppm=row.share_ppm,base_amount_minor=row.base_usd_minor,technology_fee_bps=edition.technology_fee_bps,
                technology_fee_minor=fee,subtotal_minor=row.base_usd_minor+fee,
                protocol_treasury_puzzle_hash=self.treasury_puzzle_hash,protocol_puzhash=self.protocol_puzzle_hash,
                validator_pubkeys=self.validator_pubkeys,provider_id=self.provider_id,inventory_version=4,
                generation_batch_bindings=bytes(self.primary_batch_bindings or Program.to([])))
            from solslot_puzzles.generation_primary_inventory import inventory_inner
            inner=inventory_inner(terms,self.primary_batch_bindings or Program.to([]))
            full=SINGLETON_MOD.curry(structure,inner)
            solution=Program.to([self.inner().get_tree_hash(),full.get_tree_hash(),1,
                [b'TEST_ONLY',self.generation,edition.collection,edition.commitment]])
            output.append(MintedInventory(make_spend(coin,launcher,solution),
                Coin(coin.name(),full.get_tree_hash(),uint64(1)),terms,inner,deed))
        return tuple(output)

    def mint_solution(self,edition: TestMintEdition,governance_inner_hash: bytes32, *, policy: Program | None = None) -> Program:
        self.minted(edition)
        policy=policy if policy is not None else load_puzzle('generation_mint_logic_v1.clsp')
        if not isinstance(policy,Program) or policy.get_tree_hash()!=self.logic_hash():raise ValueError('load the active reviewed mint policy')
        return Program.to([b'MINT',[governance_inner_hash,edition.program(),self.issued.proof(edition.collection),policy]])
