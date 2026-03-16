from __future__ import annotations

import logging
from typing import Any, Callable

from mssp.orchestration import schedule_bulk_scan, get_bulk_status, cancel_bulk
from mssp.templates import list_templates, create_template, apply_template
from mssp.metering import create_metering
from lib.license_guard import require_tier, require_feature, LicenseError

logger = logging.getLogger(__name__)

_ROUTE_TABLE: dict[str, Callable[[dict[str, Any] | None], dict[str, Any]]] = {}


def _route(path: str) -> Callable[[Callable[[dict[str, Any] | None], dict[str, Any]]], Callable[[dict[str, Any] | None], dict[str, Any]]]:
    def decorator(fn: Callable[[dict[str, Any] | None], dict[str, Any]]) -> Callable[[dict[str, Any] | None], dict[str, Any]]:
        _ROUTE_TABLE[path] = fn
        return fn

    return decorator


def _enforce_mssp_license() -> None:
    require_tier("managed")


@_route("/mssp/bulk-scan")
def _handle_bulk_scan(body: dict[str, Any] | None) -> dict[str, Any]:
    _enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    client_ids: list[str] | None = body.get("client_ids")
    scan_config: dict[str, Any] = body.get("scan_config", {})
    if not client_ids or not isinstance(client_ids, list):
        return {"error": "client_ids must be a non-empty list", "status": 400}
    result = schedule_bulk_scan(client_ids=client_ids, scan_config=scan_config)
    return {"status": 202, "data": result}


@_route("/mssp/templates")
def _handle_list_templates(body: dict[str, Any] | None) -> dict[str, Any]:
    _enforce_mssp_license()
    templates = list_templates()
    return {"status": 200, "data": templates}


@_route("/mssp/templates/create")
def _handle_create_template(body: dict[str, Any] | None) -> dict[str, Any]:
    _enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    name: str | None = body.get("name")
    scan_config: dict[str, Any] | None = body.get("config")
    if not name:
        return {"error": "name is required", "status": 400}
    if not scan_config or not isinstance(scan_config, dict):
        return {"error": "config must be a non-empty dict", "status": 400}
    template = create_template(template_name=name, scan_config=scan_config)
    return {"status": 201, "data": template}


@_route("/mssp/usage")
def _handle_usage_report(body: dict[str, Any] | None) -> dict[str, Any]:
    _enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    client_id: str | None = body.get("client_id")
    if not client_id:
        return {"error": "client_id is required", "status": 400}
    report = create_metering(client_id=client_id)
    return {"status": 200, "data": report}


@_route("/mssp/license/check")
def _handle_license_check(body: dict[str, Any] | None) -> dict[str, Any]:
    try:
        require_tier("managed")
        return {"status": 200, "data": {"licensed": True, "tier": "mssp"}}
    except LicenseError as exc:
        return {"status": 200, "data": {"licensed": False, "error": str(exc)}}


def handle_request(request_path: str, request_body: dict[str, Any] | None) -> Callable[[], dict[str, Any]]:
    handler = _ROUTE_TABLE.get(request_path)

    if handler is None:

        def not_found() -> dict[str, Any]:
            return {"error": f"route not found: {request_path}", "status": 404}

        return not_found

    def json_response() -> dict[str, Any]:
        try:
            return handler(request_body)
        except LicenseError as exc:
            logger.warning("license enforcement blocked request to %s: %s", request_path, exc)
            return {"error": str(exc), "status": 403}
        except ValueError as exc:
            logger.warning("validation error for %s: %s", request_path, exc)
            return {"error": str(exc), "status": 422}
        except Exception as exc:
            logger.exception("unhandled error processing %s", request_path)
            return {"error": "internal server error", "status": 500, "detail": str(exc)}

    return json_response
