from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

VALID_ACTIONS = frozenset({"start", "pause", "resume", "cancel", "complete"})

_ACTION_STATUS_MAP: dict[str, str] = {
    "start": "running",
    "pause": "paused",
    "resume": "running",
    "cancel": "cancelled",
    "complete": "completed",
}

_PROGRESS_MAP: dict[str, float] = {
    "start": 0.0,
    "pause": 0.0,
    "resume": 0.0,
    "cancel": 0.0,
    "complete": 1.0,
}

_scan_store: dict[str, dict[str, Any]] = {}


def _get_evidence_store() -> dict[str, Any]:
    try:
        from lib.evidence import get_evidence_manager

        manager = get_evidence_manager()
        # Use the evidence manager's store if available, else fall back
        return getattr(manager, "store", lambda: _scan_store)()
    except Exception as exc:
        logger.warning("lib.evidence store unavailable: %s", exc)
        return _scan_store


def _validate_input(action: str, scan_id: str) -> None:
    if not isinstance(action, str) or not action:
        raise ValueError("action must be a non-empty string")
    if not isinstance(scan_id, str) or not scan_id:
        raise ValueError("scan_id must be a non-empty string")
    if action not in VALID_ACTIONS:
        raise ValueError(f"action '{action}' is not valid; expected one of {sorted(VALID_ACTIONS)}")


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    action: str = payload.get("action", "")
    scan_id: str = payload.get("scan_id", "")

    _validate_input(action, scan_id)

    store = _get_evidence_store()

    current: dict[str, Any] = store.get(scan_id, {})
    current_status: str = current.get("status", "idle")

    # Guard illegal transitions
    if current_status == "cancelled" and action != "start":
        raise ValueError(f"Cannot apply action '{action}' to a cancelled scan")
    if current_status == "completed" and action not in {"start"}:
        raise ValueError(f"Cannot apply action '{action}' to a completed scan")
    if current_status == "running" and action == "start":
        raise ValueError("Scan is already running; use 'resume' or 'pause'")

    new_status: str = _ACTION_STATUS_MAP[action]
    progress: float = _PROGRESS_MAP[action]

    # Preserve progress on pause/resume
    if action in {"pause", "resume"}:
        progress = float(current.get("progress", 0.0))

    entry: dict[str, Any] = {"status": new_status, "progress": progress}
    store[scan_id] = entry

    logger.info(
        "scan_manager: scan_id=%s action=%s status=%s progress=%s",
        scan_id,
        action,
        new_status,
        progress,
    )

    return {"status": new_status, "progress": progress}
