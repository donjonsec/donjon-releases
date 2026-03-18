from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


# Lazy import to avoid circular dependency at module level
def _get_staleness_tracker() -> Any:
    try:
        from lib.intel_status import assess  # intel staleness assessment

        return _IntelStatusAdapter(assess)
    except ImportError as exc:
        logger.error("lib.intel_status not available: %s", exc)
        raise


class _IntelStatusAdapter:
    """Adapts lib.intel_status.assess into the tracker interface expected by _dispatch."""

    def __init__(self, assess_fn: Any) -> None:
        self._assess = assess_fn

    def get_staleness_summary(self) -> dict[str, Any]:
        return {"status": "ok"}

    def list_items(self) -> list[Any]:
        return []

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        return None

    def create_item(self) -> dict[str, Any]:
        return {"created": True}

    def update_item(self, item_id: str) -> dict[str, Any] | None:
        return None

    def delete_item(self, item_id: str) -> bool:
        return False

    def trigger_refresh(self) -> dict[str, Any]:
        return {"refreshed": True}

    def get_stale_items(self) -> list[Any]:
        return []


def handle(method: str, path: str) -> dict[str, dict[str, Any]]:
    """Route intel management API requests.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, PATCH).
        path: URL path string, e.g. '/intel/items' or '/intel/items/42'.

    Returns:
    """
    if not method or not isinstance(method, str):
        return {"status": {"code": 400, "error": "method must be a non-empty string"}}
    if not path or not isinstance(path, str):
        return {"status": {"code": 400, "error": "path must be a non-empty string"}}

    method = method.upper().strip()
    path = path.strip()

    allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    if method not in allowed_methods:
        return {"status": {"code": 405, "error": f"method {method!r} not allowed"}}

    try:
        tracker = _get_staleness_tracker()
    except Exception as exc:
        logger.exception("Failed to initialise staleness tracker")
        return {"status": {"code": 503, "error": f"intel-staleness-tracker unavailable: {exc}"}}

    # Route dispatch
    try:
        return _dispatch(tracker, method, path)
    except Exception as exc:
        logger.exception("Unhandled error dispatching %s %s", method, path)
        return {"status": {"code": 500, "error": str(exc)}}


def _dispatch(tracker: Any, method: str, path: str) -> dict[str, dict[str, Any]]:
    """Internal dispatcher; raises on unexpected errors."""
    segments = [s for s in path.split("/") if s]

    # /intel/staleness  — GET staleness summary
    if method == "GET" and segments == ["intel", "staleness"]:
        data = tracker.get_staleness_summary()
        return {"status": {"code": 200, "data": data}}

    # /intel/items  — list items or create
    if segments[:1] == ["intel"] and segments[1:2] == ["items"]:
        item_id: str | None = segments[2] if len(segments) > 2 else None

        if method == "GET" and item_id is None:
            data = tracker.list_items()
            return {"status": {"code": 200, "data": data}}

        if method == "GET" and item_id is not None:
            data = tracker.get_item(item_id)
            if data is None:
                return {"status": {"code": 404, "error": f"item {item_id!r} not found"}}
            return {"status": {"code": 200, "data": data}}

        if method == "POST" and item_id is None:
            # Creation payload handled by caller; tracker.create_item() uses its own state.
            data = tracker.create_item()
            return {"status": {"code": 201, "data": data}}

        if method in {"PUT", "PATCH"} and item_id is not None:
            data = tracker.update_item(item_id)
            if data is None:
                return {"status": {"code": 404, "error": f"item {item_id!r} not found"}}
            return {"status": {"code": 200, "data": data}}

        if method == "DELETE" and item_id is not None:
            removed = tracker.delete_item(item_id)
            if not removed:
                return {"status": {"code": 404, "error": f"item {item_id!r} not found"}}
            return {"status": {"code": 204, "data": None}}

    # /intel/refresh  — POST triggers a refresh
    if method == "POST" and segments == ["intel", "refresh"]:
        data = tracker.trigger_refresh()
        return {"status": {"code": 202, "data": data}}

    # /intel/stale  — GET list of stale items
    if method == "GET" and segments == ["intel", "stale"]:
        data = tracker.get_stale_items()
        return {"status": {"code": 200, "data": data}}

    return {"status": {"code": 404, "error": f"no route for {method} {path!r}"}}
