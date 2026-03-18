"""Trial license — 14-day self-service Pro trial.

Stored as data/trial-license.json. Machine-bound, one-time per install.
Not cryptographically signed — this is a convenience feature for conversion.
Real enforcement is the v2 signed license for paid tiers.
"""
from __future__ import annotations

import hashlib
import json
import logging
import platform
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TRIAL_DAYS = 14
TRIAL_TIER = "pro"


def _get_data_dir() -> Path:
    """Get the data directory."""
    try:
        from lib.paths import paths
        return paths.data
    except Exception:
        return Path("data")


def _machine_fingerprint() -> str:
    """Simple machine fingerprint for trial binding."""
    parts = [platform.node(), platform.machine(), platform.system()]
    raw = ":".join(parts).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _trial_path() -> Path:
    return _get_data_dir() / "trial-license.json"


def _marker_path() -> Path:
    return _get_data_dir() / ".trial-used"


def _load_trial() -> dict[str, Any] | None:
    """Load existing trial license if present."""
    path = _trial_path()
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def handle(input_data: dict[str, Any]) -> dict[str, Any]:
    """Handle trial license actions: activate, status, deactivate."""
    action = input_data.get("action", "status")

    if action == "activate":
        return _activate()
    elif action == "status":
        return _status()
    elif action == "deactivate":
        return _deactivate()
    else:
        return {"error": f"Unknown action: {action}", "status": 400}


def _activate() -> dict[str, Any]:
    """Activate a 14-day Pro trial."""
    # Check if already used
    if _marker_path().exists():
        return {"error": "Trial already used on this machine", "status": 400}

    # Check if real license exists (takes priority)
    real_license = _get_data_dir() / "license.json"
    if real_license.exists():
        return {"error": "A license is already active — trial not needed", "status": 400}

    # Check if trial already active
    existing = _load_trial()
    if existing:
        return {"error": "Trial already active", "status": 400}

    # Create trial
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=TRIAL_DAYS)
    trial = {
        "trial": True,
        "tier": TRIAL_TIER,
        "activated_at": now.isoformat(),
        "expires": expires.isoformat(),
        "machine_fingerprint": _machine_fingerprint(),
        "trial_id": f"TRIAL-{uuid.uuid4().hex[:8].upper()}",
    }

    # Write trial license
    _get_data_dir().mkdir(parents=True, exist_ok=True)
    with open(_trial_path(), "w") as f:
        json.dump(trial, f, indent=2)

    # Write marker (prevents re-trial after expiry)
    _marker_path().touch()

    logger.info("Trial activated: %s (expires %s)", trial["trial_id"], expires.date())

    return {
        "activated": True,
        "expires": expires.isoformat(),
        "tier": TRIAL_TIER,
        "days_remaining": TRIAL_DAYS,
        "trial_id": trial["trial_id"],
    }


def _status() -> dict[str, Any]:
    """Check trial status."""
    trial = _load_trial()
    if not trial:
        return {
            "active": False,
            "trial_available": not _marker_path().exists(),
            "tier": "community",
            "days_remaining": 0,
            "expired": False,
        }

    # Check expiry
    try:
        expires = datetime.fromisoformat(trial["expires"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        remaining = (expires - now).days
        expired = expires < now
    except Exception:
        remaining = 0
        expired = True

    return {
        "active": not expired,
        "trial_available": False,
        "tier": TRIAL_TIER if not expired else "community",
        "days_remaining": max(0, remaining),
        "expired": expired,
        "expires": trial.get("expires", ""),
        "trial_id": trial.get("trial_id", ""),
    }


def _deactivate() -> dict[str, Any]:
    """Deactivate trial (remove trial license file)."""
    path = _trial_path()
    if path.exists():
        path.unlink()
    return {"activated": False, "tier": "community"}
