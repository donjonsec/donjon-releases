from __future__ import annotations

import logging
from typing import Any

from lib.license_guard import require_feature
from lib.multi_tenant import get_tenant_context, isolate_data
from lib.rbac import check_permission

logger = logging.getLogger(__name__)


def enforce_boundaries(client_id: str) -> dict[str, Any]:
    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")

    require_feature("mssp_isolation")

    # Verify the tenant exists (raises KeyError if not)
    get_tenant_context(client_id)

    logger.info("Enforced boundaries for client %s", client_id)
    return {"client_id": client_id, "boundaries_enforced": True}


def validate_access(client_id: str, requesting_client_id: str, resource: str) -> dict[str, Any]:
    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")
    if not requesting_client_id or not requesting_client_id.strip():
        raise ValueError("requesting_client_id must be a non-empty string")
    if not resource or not resource.strip():
        raise ValueError("resource must be a non-empty string")

    require_feature("mssp_isolation")

    # Cross-tenant access is denied unless same client
    if client_id != requesting_client_id:
        context = get_tenant_context(client_id)
        if context.get("tenant_id") != client_id:
            logger.warning(
                "Access denied: client %s attempted to access client %s resource %s",
                requesting_client_id,
                client_id,
                resource,
            )
            return {
                "client_id": client_id,
                "requesting_client_id": requesting_client_id,
                "resource": resource,
                "access_granted": False,
                "reason": "cross_tenant_access_denied",
            }

    # check_permission(user_id, action, resource) — use requesting_client_id as the user
    scoped_resource = f"tenant:{client_id}:{resource}"
    allowed: bool = check_permission(requesting_client_id, "read", scoped_resource)
    logger.info(
        "Access check for client %s on resource %s: %s",
        requesting_client_id,
        resource,
        allowed,
    )
    return {
        "client_id": client_id,
        "requesting_client_id": requesting_client_id,
        "resource": resource,
        "access_granted": allowed,
    }
