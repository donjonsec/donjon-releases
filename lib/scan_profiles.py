from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

_PROFILES: dict[str, dict[str, Any]] = {}

_VALID_ACTIONS = {"create", "get", "update", "delete", "list"}


def _generate_profile_id(profile: dict[str, Any]) -> str:
    raw = json.dumps(profile, sort_keys=True, default=str) + str(time.monotonic_ns())
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _validate_action(action: str) -> None:
    if not isinstance(action, str):
        raise TypeError(f"action must be str, got {type(action).__name__}")
    if action not in _VALID_ACTIONS:
        raise ValueError(f"Unknown action '{action}'. Valid actions: {sorted(_VALID_ACTIONS)}")


def _validate_profile(profile: Any) -> dict[str, Any]:
    if not isinstance(profile, dict):
        raise TypeError(f"profile must be dict, got {type(profile).__name__}")
    return dict(profile)


def handle(action: str, profile: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a scan-profile action and return {profile_id, profiles}."""
    _validate_action(action)
    profile = _validate_profile(profile)

    if action == "create":
        return _create(profile)
    if action == "get":
        return _get(profile)
    if action == "update":
        return _update(profile)
    if action == "delete":
        return _delete(profile)
    # action == "list"
    return _list(profile)


def _create(profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = profile.get("profile_id") or _generate_profile_id(profile)
    profile_id = str(profile_id)

    if profile_id in _PROFILES:
        raise ValueError(f"Profile '{profile_id}' already exists. Use 'update' to modify it.")

    stored: dict[str, Any] = {**profile, "profile_id": profile_id}
    _PROFILES[profile_id] = stored
    logger.info("Created profile %s", profile_id)
    return {"profile_id": profile_id, "profiles": [stored]}


def _get(profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(profile.get("profile_id", ""))
    if not profile_id:
        raise ValueError("'profile_id' is required for action 'get'")
    if profile_id not in _PROFILES:
        raise KeyError(f"Profile '{profile_id}' not found")
    stored = _PROFILES[profile_id]
    return {"profile_id": profile_id, "profiles": [stored]}


def _update(profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(profile.get("profile_id", ""))
    if not profile_id:
        raise ValueError("'profile_id' is required for action 'update'")
    if profile_id not in _PROFILES:
        raise KeyError(f"Profile '{profile_id}' not found. Use 'create' to add it.")

    existing = _PROFILES[profile_id]
    merged: dict[str, Any] = {**existing, **profile, "profile_id": profile_id}
    _PROFILES[profile_id] = merged
    logger.info("Updated profile %s", profile_id)
    return {"profile_id": profile_id, "profiles": [merged]}


def _delete(profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(profile.get("profile_id", ""))
    if not profile_id:
        raise ValueError("'profile_id' is required for action 'delete'")
    if profile_id not in _PROFILES:
        raise KeyError(f"Profile '{profile_id}' not found")

    removed = _PROFILES.pop(profile_id)
    logger.info("Deleted profile %s", profile_id)
    return {"profile_id": profile_id, "profiles": [removed]}


def _list(profile: dict[str, Any]) -> dict[str, Any]:
    # Optionally filter by top-level keys present in `profile`
    filters: dict[str, Any] = {k: v for k, v in profile.items() if k != "profile_id"}

    if filters:
        results = [p for p in _PROFILES.values() if all(p.get(k) == v for k, v in filters.items())]
    else:
        results = list(_PROFILES.values())

    return {"profile_id": "", "profiles": results}
