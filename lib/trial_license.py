from __future__ import annotations

import logging
from typing import Any

from lib.licensing import get_license_manager  # type: ignore[import]

logger = logging.getLogger(__name__)


def handle(input_data: dict[str, Any]) -> dict[str, Any]:
    action: str = input_data["action"]

    if not isinstance(action, str) or not action.strip():
        raise ValueError(f"Invalid action: {action!r}")

    manager = get_license_manager()

    if action == "activate":
        result = manager.activate_trial()
        return {
            "activated": bool(getattr(result, "activated", True)),
            "expires": str(getattr(result, "expires", "")),
            "tier": str(getattr(result, "tier", "trial")),
        }
    elif action == "status":
        result = manager.get_trial_status()
        return {
            "activated": bool(getattr(result, "activated", False)),
            "expires": str(getattr(result, "expires", "")),
            "tier": str(getattr(result, "tier", "")),
        }
    elif action == "deactivate":
        result = manager.deactivate_trial()
        return {
            "activated": bool(getattr(result, "activated", False)),
            "expires": str(getattr(result, "expires", "")),
            "tier": str(getattr(result, "tier", "")),
        }
    else:
        raise ValueError(f"Unknown action: {action!r}")
