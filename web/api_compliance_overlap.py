"""Compliance framework overlap analysis — cross-framework control mapping."""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _build_overlap_matrix(
    framework_controls: dict[str, set[str]],
) -> dict[str, Any]:
    """Build overlap matrix showing shared controls between each framework pair."""
    frameworks = list(framework_controls.keys())
    matrix: dict[str, dict[str, int]] = {}
    for fw_a in frameworks:
        matrix[fw_a] = {}
        for fw_b in frameworks:
            overlap = len(framework_controls[fw_a] & framework_controls[fw_b])
            matrix[fw_a][fw_b] = overlap

    # Count controls shared across ALL frameworks
    shared = 0
    if len(framework_controls) >= 2:
        sets = list(framework_controls.values())
        common = sets[0].copy()
        for s in sets[1:]:
            common &= s
        shared = len(common)

    unique = set()
    for controls in framework_controls.values():
        unique |= controls

    return {
        "frameworks": frameworks,
        "total_unique_controls": len(unique),
        "shared_across_all": shared,
        "overlap_matrix": matrix,
    }
