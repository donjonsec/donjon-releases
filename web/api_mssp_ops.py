from __future__ import annotations

import logging
from typing import Any, Callable

from darkfactory.bulk_orchestration import dispatch_bulk_scan
from darkfactory.scan_templates import list_templates, get_template, create_template, update_template, delete_template
from darkfactory.usage_metering import record_usage, get_usage_report
from darkfactory.license_guard import check_license, enforce_mssp_license

logger = logging.getLogger(__name__)

_ROUTE_TABLE: dict[str, Callable[[dict[str, Any] | None], dict[str, Any]]] = {}


def _route(path: str) -> Callable[[Callable[[dict[str, Any] | None], dict[str, Any]]], Callable[[dict[str, Any] | None], dict[str, Any]]]:
    def decorator(fn: Callable[[dict[str, Any] | None], dict[str, Any]]) -> Callable[[dict[str, Any] | None], dict[str, Any]]:
        _ROUTE_TABLE[path] = fn
        return fn

    return decorator


@_route("/mssp/bulk-scan")
def _handle_bulk_scan(body: dict[str, Any] | None) -> dict[str, Any]:
    enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    tenant_id: str | None = body.get("tenant_id")
    targets: list[Any] | None = body.get("targets")
    template_id: str | None = body.get("template_id")
    if not tenant_id:
        return {"error": "tenant_id is required", "status": 400}
    if not targets or not isinstance(targets, list):
        return {"error": "targets must be a non-empty list", "status": 400}
    record_usage(tenant_id=tenant_id, operation="bulk_scan", quantity=len(targets))
    result = dispatch_bulk_scan(tenant_id=tenant_id, targets=targets, template_id=template_id)
    return {"status": 202, "data": result}


@_route("/mssp/templates")
def _handle_list_templates(body: dict[str, Any] | None) -> dict[str, Any]:
    enforce_mssp_license()
    tenant_id: str | None = (body or {}).get("tenant_id")
    templates = list_templates(tenant_id=tenant_id)
    return {"status": 200, "data": templates}


@_route("/mssp/templates/create")
def _handle_create_template(body: dict[str, Any] | None) -> dict[str, Any]:
    enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    tenant_id: str | None = body.get("tenant_id")
    name: str | None = body.get("name")
    config: dict[str, Any] | None = body.get("config")
    if not tenant_id:
        return {"error": "tenant_id is required", "status": 400}
    if not name:
        return {"error": "name is required", "status": 400}
    if not config or not isinstance(config, dict):
        return {"error": "config must be a non-empty dict", "status": 400}
    template = create_template(tenant_id=tenant_id, name=name, config=config)
    return {"status": 201, "data": template}


@_route("/mssp/templates/update")
def _handle_update_template(body: dict[str, Any] | None) -> dict[str, Any]:
    enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    template_id: str | None = body.get("template_id")
    updates: dict[str, Any] | None = body.get("updates")
    if not template_id:
        return {"error": "template_id is required", "status": 400}
    if not updates or not isinstance(updates, dict):
        return {"error": "updates must be a non-empty dict", "status": 400}
    template = update_template(template_id=template_id, updates=updates)
    return {"status": 200, "data": template}


@_route("/mssp/templates/delete")
def _handle_delete_template(body: dict[str, Any] | None) -> dict[str, Any]:
    enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    template_id: str | None = body.get("template_id")
    if not template_id:
        return {"error": "template_id is required", "status": 400}
    delete_template(template_id=template_id)
    return {"status": 204, "data": None}


@_route("/mssp/templates/get")
def _handle_get_template(body: dict[str, Any] | None) -> dict[str, Any]:
    enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    template_id: str | None = body.get("template_id")
    if not template_id:
        return {"error": "template_id is required", "status": 400}
    template = get_template(template_id=template_id)
    if template is None:
        return {"error": "template not found", "status": 404}
    return {"status": 200, "data": template}


@_route("/mssp/usage")
def _handle_usage_report(body: dict[str, Any] | None) -> dict[str, Any]:
    enforce_mssp_license()
    if not body:
        return {"error": "request body required", "status": 400}
    tenant_id: str | None = body.get("tenant_id")
    if not tenant_id:
        return {"error": "tenant_id is required", "status": 400}
    period: str | None = body.get("period")
    report = get_usage_report(tenant_id=tenant_id, period=period)
    return {"status": 200, "data": report}


@_route("/mssp/license/check")
def _handle_license_check(body: dict[str, Any] | None) -> dict[str, Any]:
    tenant_id: str | None = (body or {}).get("tenant_id")
    status = check_license(tenant_id=tenant_id)
    return {"status": 200, "data": status}


def handle_request(request_path: str, request_body: dict[str, Any] | None) -> Callable[[], dict[str, Any]]:
    handler = _ROUTE_TABLE.get(request_path)

    if handler is None:

        def not_found() -> dict[str, Any]:
            return {"error": f"route not found: {request_path}", "status": 404}

        return not_found

    def json_response() -> dict[str, Any]:
        try:
            return handler(request_body)
        except PermissionError as exc:
            logger.warning("license enforcement blocked request to %s: %s", request_path, exc)
            return {"error": str(exc), "status": 403}
        except ValueError as exc:
            logger.warning("validation error for %s: %s", request_path, exc)
            return {"error": str(exc), "status": 422}
        except Exception as exc:
            logger.exception("unhandled error processing %s", request_path)
            return {"error": "internal server error", "status": 500, "detail": str(exc)}

    return json_response
