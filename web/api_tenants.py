from __future__ import annotations

import logging
from typing import Any, Callable

from lib.multi_tenant import create_tenant, get_tenant_context
from lib.license_guard import require_feature, require_tier, LicenseError

logger = logging.getLogger(__name__)


def _json(data: dict[str, Any], status: int = 200) -> dict[str, Any]:
    return {"status": status, "body": data}


def handle_tenants_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[[], dict[str, Any]]]:
    """Route tenant-related API requests and return a json_response callable."""

    def json_response() -> dict[str, Any]:
        try:
            require_tier("enterprise")
        except LicenseError as exc:
            return _json({"error": str(exc)}, 403)

        path = request_path.rstrip("/")

        # POST /api/tenants — create tenant
        if path == "/api/tenants" and request_body is not None:
            name = request_body.get("name")
            if not name or not isinstance(name, str):
                return _json({"error": "field 'name' is required and must be a string"}, 400)
            try:
                tenant = create_tenant(tenant_id=name, name=name)
                return _json({"tenant": tenant}, 201)
            except ValueError as exc:
                return _json({"error": str(exc)}, 409)
            except Exception as exc:
                logger.error("create_tenant failed: %s", exc)
                return _json({"error": str(exc)}, 500)

        # GET /api/tenants/{id}
        parts = [p for p in path.strip("/").split("/") if p]
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "tenants":
            tenant_id = parts[2]
            try:
                ctx = get_tenant_context(tenant_id)
                return _json({"tenant": ctx})
            except Exception as exc:
                logger.error("get_tenant failed: %s", exc)
                return _json({"error": str(exc)}, 500)

        return _json({"error": f"tenant route not found: {request_path}"}, 404)

    return {"json_response": json_response}
