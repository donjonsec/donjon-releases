from __future__ import annotations

import logging
from typing import Callable, TypeVar, Any

from lib.config import load_config

logger = logging.getLogger(__name__)

TIER_ORDER: list[str] = ["community", "pro", "enterprise", "mssp"]

F = TypeVar("F", bound=Callable[..., Any])


class LicenseError(Exception):
    pass


def _current_tier() -> str:
    cfg = load_config()
    tier: str = cfg.get("license", {}).get("tier", "community")
    return tier


def _tier_index(tier: str) -> int:
    try:
        return TIER_ORDER.index(tier.lower())
    except ValueError:
        raise LicenseError(f"Unknown tier: {tier!r}. Valid tiers: {TIER_ORDER}") from None


def _feature_min_tier(feature: str) -> str:
    cfg = load_config()
    feature_tiers: dict[str, str] = cfg.get("license", {}).get("feature_tiers", {})
    if feature not in feature_tiers:
        raise LicenseError(f"Unknown feature: {feature!r}")
    return feature_tiers[feature]


def require_tier(tier: str) -> None:
    required_idx = _tier_index(tier)
    current = _current_tier()
    current_idx = _tier_index(current)
    if current_idx < required_idx:
        raise LicenseError(
            f"Feature requires tier {tier!r}; current license tier is {current!r}"
        )
    logger.debug("Tier check passed: required=%r current=%r", tier, current)


def require_feature(feature: str) -> None:
    min_tier = _feature_min_tier(feature)
    require_tier(min_tier)
    logger.debug("Feature check passed: feature=%r min_tier=%r", feature, min_tier)


def check_or_raise(feature: str, tier: str | None) -> None:
    require_feature(feature)
    if tier is not None:
        require_tier(tier)
