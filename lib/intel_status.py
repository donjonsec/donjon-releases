from __future__ import annotations

import logging
from typing import TypedDict

logger = logging.getLogger(__name__)

_FRESH_THRESHOLD = 7
_STALE_THRESHOLD = 30


class IntelInput(TypedDict):
    source: str
    count: int


class IntelOutput(TypedDict):
    staleness: str
    age_days: int


def _classify_staleness(age_days: int) -> str:
    if age_days < 0:
        raise ValueError(f"age_days cannot be negative, got {age_days}")
    if age_days < _FRESH_THRESHOLD:
        return "fresh"
    if age_days < _STALE_THRESHOLD:
        return "stale"
    return "very_stale"


def assess(source: str, count: int) -> IntelOutput:
    """Return staleness classification and age in days for an intel source.

    Args:
        source: Identifier of the intel source.
        count:  Number of days since the source was last updated.

    Returns:
    """
    if not source or not source.strip():
        raise ValueError("source must be a non-empty string")
    if count < 0:
        raise ValueError(f"count must be >= 0, got {count}")

    age_days: int = count
    staleness: str = _classify_staleness(age_days)

    logger.debug("source=%r age_days=%d staleness=%s", source, age_days, staleness)

    return IntelOutput(staleness=staleness, age_days=age_days)
