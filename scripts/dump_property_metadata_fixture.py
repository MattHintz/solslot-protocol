"""Regenerate the cross-language PropertyDossierV1 commitment fixture."""
from __future__ import annotations

import json
from pathlib import Path

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.mint_proposal_v2_driver import compute_proposal_data_hash
from solslot_puzzles.mint_publish_driver import BILL_MINT_TAG
from solslot_puzzles.property_metadata import build_metadata_memos, commit_metadata


ROOT = Path(__file__).parents[1]
FIXTURE_PATH = ROOT / "fixtures" / "property-metadata-v1.fixture.json"


def main() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    commitment = commit_metadata(fixture["dossier"])
    anchor_id = bytes32(bytes.fromhex("aa" * 32))
    property_id = bytes32(bytes.fromhex("22" * 32))
    collection_id = bytes32(bytes.fromhex("44" * 32))
    deed_full_puzhash = bytes32(bytes.fromhex("11" * 32))
    registry_puzhash = bytes32(bytes.fromhex("33" * 32))
    proposal_data_hash = compute_proposal_data_hash(
        property_id_canon=property_id,
        collection_id_canon=collection_id,
        share_ppm=600_000,
        par_value_mojos=150_000_000_000,
        royalty_bps=250,
        quorum_threshold=5000,
        metadata_root=commitment.metadata_root,
        metadata_anchor_id=anchor_id,
    )
    bill = Program.to(
        [
            BILL_MINT_TAG,
            deed_full_puzhash,
            property_id,
            registry_puzhash,
            commitment.metadata_root,
            anchor_id,
        ]
    )
    fixture.update(
        {
            "metadataRoot": "0x" + commitment.metadata_root.hex(),
            "canonicalByteSize": commitment.byte_size,
            "canonicalJson": commitment.canonical_json.decode("utf-8"),
            "memoHex": [
                "0x" + memo.hex() for memo in build_metadata_memos(commitment)
            ],
            "mintVector": {
                "inputs": {
                    "propertyIdCanon": "0x" + property_id.hex(),
                    "collectionIdCanon": "0x" + collection_id.hex(),
                    "sharePpm": 600000,
                    "parValueMojos": "150000000000",
                    "royaltyBps": 250,
                    "quorumThreshold": 5000,
                    "deedFullPuzhash": "0x" + deed_full_puzhash.hex(),
                    "propertyRegistryPuzhash": "0x" + registry_puzhash.hex(),
                    "metadataAnchorId": "0x" + anchor_id.hex(),
                },
                "expected": {
                    "proposalDataHash": "0x" + proposal_data_hash.hex(),
                    "billProgramHex": "0x" + bytes(bill).hex(),
                    "billProgramHash": "0x" + bill.get_tree_hash().hex(),
                },
            },
        }
    )
    FIXTURE_PATH.write_text(
        json.dumps(fixture, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
