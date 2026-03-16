from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


def handle_rbac_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[[], Any]]:
    """Route RBAC API requests and return a json_response callable."""
    from lib.rbac import list_roles, create_role, assign_role, check_permission
    from lib.license_guard import require_tier, LicenseError

    def json_response() -> dict[str, Any]:
        try:
            require_tier("enterprise")
        except LicenseError as exc:
            return {"error": str(exc), "status": 403}

        path = request_path.rstrip("/")

        # GET /rbac/roles — list all roles (optionally filtered by user_id)
        if path in ("/rbac/roles", "/api/rbac/roles") and request_body is None:
            roles = list_roles()
            return {"roles": roles}

        # POST /rbac/roles — create a new role
        if path in ("/rbac/roles", "/api/rbac/roles") and request_body is not None:
            name = request_body.get("name", "")
            description = request_body.get("description", "")
            permissions = request_body.get("permissions", [])
            try:
                role = create_role(name=name, permissions=permissions, description=description)
                return {"status": 201, "role": role}
            except ValueError as exc:
                return {"error": str(exc), "status": 400}

        # POST /rbac/assign — assign a role to a user
        if path in ("/rbac/assign", "/api/rbac/assign") and request_body is not None:
            user_id = request_body.get("user_id", "")
            role_name = request_body.get("role_name", "")
            try:
                assign_role(user_id=user_id, role_name=role_name)
                return {"status": 200, "assigned": True}
            except (ValueError, KeyError) as exc:
                return {"error": str(exc), "status": 400}

        # POST /rbac/check — check a permission
        if path in ("/rbac/check", "/api/rbac/check") and request_body is not None:
            user_id = request_body.get("user_id", "")
            action = request_body.get("action", "")
            resource = request_body.get("resource", "")
            try:
                allowed = check_permission(user_id=user_id, action=action, resource=resource)
                return {"allowed": allowed}
            except ValueError as exc:
                return {"error": str(exc), "status": 400}

        # GET /rbac/roles/{user_id}
        parts = [p for p in path.strip("/").split("/") if p]
        if len(parts) >= 3 and parts[-2] == "roles":
            user_id = parts[-1]
            roles = list_roles(user_id=user_id)
            return {"user_id": user_id, "roles": roles}

        return {"error": f"RBAC route not found: {request_path}", "status": 404}

    return {"json_response": json_response}
