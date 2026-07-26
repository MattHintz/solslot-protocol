"""Canonical real-estate classification and diligence profiles for RC20.

The on-chain class is intentionally broad and stable.  Marketing subtypes and
project stages live in metadata, while this registry defines the minimum
decision-grade diligence keys required before a collection can be sealed.
"""
from __future__ import annotations

from enum import IntEnum
from typing import Final


class RealEstateAssetClass(IntEnum):
    RESIDENTIAL = 1
    MULTIFAMILY = 2
    COMMERCIAL = 3
    INDUSTRIAL = 4
    HOSPITALITY = 5
    LAND = 6
    MIXED_USE = 7


ASSET_CLASS_CODES: Final[dict[str, int]] = {
    "RWA-RE-RES": RealEstateAssetClass.RESIDENTIAL,
    "RWA-RE-MFR": RealEstateAssetClass.MULTIFAMILY,
    "RWA-RE-COM": RealEstateAssetClass.COMMERCIAL,
    "RWA-RE-IND": RealEstateAssetClass.INDUSTRIAL,
    "RWA-RE-HOS": RealEstateAssetClass.HOSPITALITY,
    "RWA-RE-LAND": RealEstateAssetClass.LAND,
    "RWA-RE-MIX": RealEstateAssetClass.MIXED_USE,
}

PROJECT_STAGES: Final[frozenset[str]] = frozenset(
    {
        "stabilized",
        "vacant",
        "renovation",
        "ground-up",
        "construction-in-progress",
    }
)

PROPERTY_SUBTYPES: Final[dict[str, frozenset[str]]] = {
    "RWA-RE-RES": frozenset(
        {
            "single-family",
            "duplex",
            "two-to-four-unit",
            "condominium",
            "townhouse",
            "manufactured-housing",
            "residential-portfolio",
        }
    ),
    "RWA-RE-MFR": frozenset(
        {"garden", "mid-rise", "high-rise", "student", "senior", "multifamily-portfolio"}
    ),
    "RWA-RE-COM": frozenset(
        {"office", "retail", "medical-office", "self-storage", "service", "commercial-portfolio"}
    ),
    "RWA-RE-IND": frozenset(
        {"warehouse", "logistics", "manufacturing", "flex", "data-center", "industrial-portfolio"}
    ),
    "RWA-RE-HOS": frozenset(
        {"hotel", "motel", "resort", "short-term-rental-portfolio"}
    ),
    "RWA-RE-LAND": frozenset(
        {"residential-land", "commercial-land", "industrial-land", "agricultural-land", "entitled-land"}
    ),
    "RWA-RE-MIX": frozenset({"residential-retail", "residential-office", "multi-component"}),
}

PROGRAM_OVERLAYS: Final[frozenset[str]] = frozenset(
    {"affordable-housing", "senior-housing"}
)

COMMON_DILIGENCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "title",
        "insurance",
        "debt",
        "valuation",
        "property-condition",
    }
)

ASSET_CLASS_DILIGENCE_KEYS: Final[dict[str, frozenset[str]]] = {
    "RWA-RE-RES": frozenset({"building-details", "occupancy", "comparable-sales"}),
    "RWA-RE-MFR": frozenset(
        {"unit-mix", "rent-roll", "trailing-operations", "occupancy", "noi", "cap-rate", "leases", "reserves", "deferred-maintenance"}
    ),
    "RWA-RE-COM": frozenset(
        {"gross-leasable-area", "tenants", "rent-roll", "lease-expirations", "lease-options", "operating-statements", "noi", "cap-rate", "zoning", "environmental"}
    ),
    "RWA-RE-IND": frozenset(
        {"building-specifications", "loading", "power", "access", "zoning", "environmental", "tenants", "lease-economics"}
    ),
    "RWA-RE-HOS": frozenset(
        {"key-count", "adr", "occupancy", "revpar", "seasonality", "management-agreement", "franchise-agreement", "operating-history", "capital-improvement-plan"}
    ),
    "RWA-RE-LAND": frozenset(
        {"acreage", "survey", "access", "utilities", "zoning", "entitlements", "environmental", "feasibility", "intended-development"}
    ),
    "RWA-RE-MIX": frozenset(
        {"component-breakdown", "income-by-use", "shared-expenses", "blended-valuation", "tenant-concentration"}
    ),
}

STAGE_DILIGENCE_KEYS: Final[dict[str, frozenset[str]]] = {
    "stabilized": frozenset({"operating-history"}),
    "vacant": frozenset({"carrying-costs", "lease-up-or-disposition-plan"}),
    "renovation": frozenset(
        {"plans", "dated-site-media", "permits", "contractor", "budget", "bids", "sources-and-uses", "schedule", "milestones", "contingency", "as-completed-valuation"}
    ),
    "ground-up": frozenset(
        {"plans", "dated-site-media", "permits", "contractor", "budget", "bids", "sources-and-uses", "schedule", "milestones", "contingency", "as-completed-valuation"}
    ),
    "construction-in-progress": frozenset(
        {"percent-complete", "draw-history", "remaining-cost", "inspections", "change-orders", "lien-waivers", "completion-forecast"}
    ),
}

OVERLAY_DILIGENCE_KEYS: Final[dict[str, frozenset[str]]] = {
    "affordable-housing": frozenset({"program-restrictions", "subsidies", "recorded-covenants"}),
    "senior-housing": frozenset({"program-restrictions", "operating-licenses", "care-services"}),
}


def normalize_asset_class(value: str) -> str:
    key = value.strip().upper()
    if key not in ASSET_CLASS_CODES:
        raise ValueError(f"unsupported real-estate asset class {value!r}")
    return key


def validate_classification(
    *, asset_class: str, property_subtype: str, project_stage: str, overlays: list[str]
) -> None:
    asset_class = normalize_asset_class(asset_class)
    if property_subtype not in PROPERTY_SUBTYPES[asset_class]:
        raise ValueError(f"unsupported subtype {property_subtype!r} for {asset_class}")
    if project_stage not in PROJECT_STAGES:
        raise ValueError(f"unsupported project stage {project_stage!r}")
    unknown = set(overlays) - PROGRAM_OVERLAYS
    if unknown:
        raise ValueError(f"unsupported program overlays: {', '.join(sorted(unknown))}")
    if len(overlays) != len(set(overlays)):
        raise ValueError("program overlays must be unique")


def required_diligence_keys(
    *, asset_class: str, project_stage: str, overlays: list[str]
) -> frozenset[str]:
    asset_class = normalize_asset_class(asset_class)
    if project_stage not in PROJECT_STAGES:
        raise ValueError(f"unsupported project stage {project_stage!r}")
    required = set(COMMON_DILIGENCE_KEYS)
    required.update(ASSET_CLASS_DILIGENCE_KEYS[asset_class])
    required.update(STAGE_DILIGENCE_KEYS[project_stage])
    for overlay in overlays:
        if overlay not in OVERLAY_DILIGENCE_KEYS:
            raise ValueError(f"unsupported program overlay {overlay!r}")
        required.update(OVERLAY_DILIGENCE_KEYS[overlay])
    return frozenset(required)


__all__ = [
    "ASSET_CLASS_DILIGENCE_KEYS",
    "ASSET_CLASS_CODES",
    "COMMON_DILIGENCE_KEYS",
    "OVERLAY_DILIGENCE_KEYS",
    "PROJECT_STAGES",
    "PROPERTY_SUBTYPES",
    "PROGRAM_OVERLAYS",
    "RealEstateAssetClass",
    "STAGE_DILIGENCE_KEYS",
    "normalize_asset_class",
    "required_diligence_keys",
    "validate_classification",
]
