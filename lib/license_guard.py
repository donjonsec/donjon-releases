from __future__ import annotations

import logging
from typing import Callable, TypeVar, Any

logger = logging.getLogger(__name__)

TIER_ORDER: list[str] = ["community", "pro", "enterprise", "managed"]

F = TypeVar("F", bound=Callable[..., Any])


class LicenseError(Exception):
    pass


def _current_tier() -> str:
    """Get current license tier from LicenseManager (reads data/license.json)."""
    try:
        from lib.licensing import get_license_manager
        lm = get_license_manager()
        if lm is not None:
            return lm.get_tier()
    except Exception:
        pass
    return "community"


def _tier_index(tier: str) -> int:
    try:
        return TIER_ORDER.index(tier.lower())
    except ValueError:
        raise LicenseError(f"Unknown tier: {tier!r}. Valid tiers: {TIER_ORDER}") from None


_FEATURE_TIERS: dict[str, str] = {
    "sso": "enterprise",
    "rbac": "enterprise",
    "multi_tenant": "enterprise",
    "zero_retention": "enterprise",
    "audit-api": "enterprise",
    "audit_trail": "enterprise",
    "settings": "pro",
    "white_label": "managed",
    "client_provisioning": "managed",
    "mssp": "managed",
}


def _feature_min_tier(feature: str) -> str:
    if feature in _FEATURE_TIERS:
        return _FEATURE_TIERS[feature]
    # Default: enterprise for unknown features (fail closed)
    return "enterprise"


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
