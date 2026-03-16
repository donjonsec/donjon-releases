from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


def handle_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[[], Any]]:
    """Route MSSP reporting API requests and return a json_response callable."""
    try:
        handler = _route(request_path, request_body)
    except Exception as exc:
        logger.error("MSSP reporting request failed: path=%s error=%s", request_path, exc)
        raise

    return {"json_response": handler}


def _route(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> Callable[[], Any]:
    path = request_path.strip("/")

    if path == "mssp/clients/dashboard":
        return _client_dashboard(request_body)
    if path == "mssp/reports/rollup":
        return _rollup_report(request_body)
    if path == "mssp/reports/cross-client":
        return _cross_client_report(request_body)
    if path == "mssp/license/status":
        return _license_status(request_body)

    raise ValueError(f"Unknown MSSP reporting path: {request_path!r}")


def _client_dashboard(
    body: dict[str, Any] | None,
) -> Callable[[], dict[str, Any]]:
    from darkfactory.client_dashboard import get_client_dashboard  # type: ignore[import]

    client_id: str | None = (body or {}).get("client_id")
    if not client_id:
        raise ValueError("client_id is required for client dashboard")

    def _call() -> dict[str, Any]:
        return get_client_dashboard(client_id=client_id)

    return _call


def _rollup_report(
    body: dict[str, Any] | None,
) -> Callable[[], dict[str, Any]]:
    from darkfactory.rollup_reporting import generate_rollup_report  # type: ignore[import]

    params: dict[str, Any] = body or {}

    def _call() -> dict[str, Any]:
        return generate_rollup_report(**params)

    return _call


def _cross_client_report(
    body: dict[str, Any] | None,
) -> Callable[[], dict[str, Any]]:
    from darkfactory.cross_client_reporting import generate_cross_client_report  # type: ignore[import]

    params: dict[str, Any] = body or {}

    def _call() -> dict[str, Any]:
        return generate_cross_client_report(**params)

    return _call


def _license_status(
    body: dict[str, Any] | None,
) -> Callable[[], dict[str, Any]]:
    from darkfactory.license_guard import check_license_status  # type: ignore[import]

    params: dict[str, Any] = body or {}

    def _call() -> dict[str, Any]:
        return check_license_status(**params)

    return _call
