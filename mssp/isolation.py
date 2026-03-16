from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def enforce_boundaries(client_id: str) -> dict[str, Any]:
    from darkfactory.multi_tenant import set_tenant_context
    from darkfactory.rbac import enforce_rbac
    from darkfactory.license_guard import check_license

    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")

    check_license("mssp_isolation")
    set_tenant_context(client_id)
    enforce_rbac(client_id, scope=client_id)

    logger.info("Enforced boundaries for client %s", client_id)
    return {"client_id": client_id, "boundaries_enforced": True}


def validate_access(client_id: str, requesting_client_id: str, resource: str) -> dict[str, Any]:
    from darkfactory.multi_tenant import get_tenant_context
    from darkfactory.rbac import check_permission
    from darkfactory.license_guard import check_license

    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")
    if not requesting_client_id or not requesting_client_id.strip():
        raise ValueError("requesting_client_id must be a non-empty string")
    if not resource or not resource.strip():
        raise ValueError("resource must be a non-empty string")

    check_license("mssp_isolation")

    # Cross-tenant access is denied unless same client
    if client_id != requesting_client_id:
        context = get_tenant_context()
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

    allowed: bool = check_permission(requesting_client_id, resource, scope=client_id)
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
