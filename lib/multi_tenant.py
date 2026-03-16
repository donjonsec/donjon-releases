from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from lib.database import get_connection
from lib.license_guard import assert_licensed
from lib.paths import DATA_DIR
from lib.rbac import create_role, list_roles

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT        PRIMARY KEY,
    name        TEXT        NOT NULL,
    data_path   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

_schema_ready: bool = False


def _ensure_schema() -> None:
    global _schema_ready
    if _schema_ready:
        return
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(_DDL)
        conn.commit()
        _schema_ready = True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _tenant_data_path(tenant_id: str) -> Path:
    return DATA_DIR / "tenants" / tenant_id


def create_tenant(tenant_id: str, name: str = "") -> dict[str, Any]:
    """Create a new tenant with isolated storage and default RBAC roles.

    Requires license feature 'multi_tenant'.
    """
    if not tenant_id:
        raise ValueError("tenant_id must be non-empty")

    assert_licensed("multi_tenant")
    _ensure_schema()

    tenant_name = name if name else tenant_id
    data_path = _tenant_data_path(tenant_id)
    data_path.mkdir(parents=True, exist_ok=True)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tenants (id, name, data_path)
                VALUES (%s, %s, %s)
                """,
                (tenant_id, tenant_name, str(data_path)),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    # Provision default roles scoped to this tenant
    tenant_resource = f"tenant:{tenant_id}:*"
    existing_role_names = {r["name"] for r in list_roles()}

    admin_role_name = f"tenant_{tenant_id}_admin"
    viewer_role_name = f"tenant_{tenant_id}_viewer"

    if admin_role_name not in existing_role_names:
        try:
            create_role(
                name=admin_role_name,
                permissions=[
                    {"action": "read", "resource": tenant_resource},
                    {"action": "write", "resource": tenant_resource},
                    {"action": "delete", "resource": tenant_resource},
                    {"action": "admin", "resource": tenant_resource},
                ],
                description=f"Admin role for tenant {tenant_id}",
            )
        except Exception:
            logger.exception("Failed to create admin role for tenant %s", tenant_id)
            raise

    if viewer_role_name not in existing_role_names:
        try:
            create_role(
                name=viewer_role_name,
                permissions=[
                    {"action": "read", "resource": tenant_resource},
                ],
                description=f"Viewer role for tenant {tenant_id}",
            )
        except Exception:
            logger.exception("Failed to create viewer role for tenant %s", tenant_id)
            raise

    logger.info("Created tenant '%s' at %s", tenant_id, data_path)

    return {
        "tenant_id": tenant_id,
        "name": tenant_name,
        "data_path": str(data_path),
        "admin_role": admin_role_name,
        "viewer_role": viewer_role_name,
    }


def get_tenant_context(tenant_id: str) -> dict[str, Any]:
    """Return the stored context for an existing tenant.

    Raises ValueError if tenant_id is empty.
    """
    if not tenant_id:
        raise ValueError("tenant_id must be non-empty")

    _ensure_schema()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, data_path, created_at FROM tenants WHERE id = %s",
                (tenant_id,),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        raise KeyError(f"Tenant '{tenant_id}' does not exist")

    tid: str = row[0]
    tname: str = row[1]
    tdata_path: str = row[2]
    tcreated_at: Any = row[3]

    tenant_resource = f"tenant:{tenant_id}:*"
    roles = [r for r in list_roles() if any(p["resource"] == tenant_resource or p["resource"] == "*" for p in r["permissions"])]

    return {
        "tenant_id": tid,
        "name": tname,
        "data_path": tdata_path,
        "created_at": tcreated_at.isoformat() if hasattr(tcreated_at, "isoformat") else str(tcreated_at),
        "roles": roles,
    }


def isolate_data(tenant_id: str, user_id: str, action: str, resource: str) -> dict[str, Any]:
    """Enforce tenant data isolation by verifying user access within the tenant boundary.

    Checks that:
    1. The tenant exists.
    2. The user holds a role granting `action` on the scoped `resource` within the tenant.


    """
    if not tenant_id:
        raise ValueError("tenant_id must be non-empty")
    if not user_id:
        raise ValueError("user_id must be non-empty")
    if not action:
        raise ValueError("action must be non-empty")
    if not resource:
        raise ValueError("resource must be non-empty")

    _ensure_schema()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, data_path FROM tenants WHERE id = %s",
                (tenant_id,),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        raise KeyError(f"Tenant '{tenant_id}' does not exist")

    tenant_data_path: str = row[1]

    # Scope the resource to the tenant namespace
    scoped_resource = f"tenant:{tenant_id}:{resource}"

    # Check permission against both scoped and wildcard tenant resource
    from lib.rbac import check_permission  # local import avoids top-level circular risk

    allowed = check_permission(user_id, action, scoped_resource) or check_permission(user_id, action, f"tenant:{tenant_id}:*")

    logger.debug(
        "isolate_data: tenant=%s user=%s action=%s resource=%s allowed=%s",
        tenant_id,
        user_id,
        action,
        resource,
        allowed,
    )

    return {
        "allowed": allowed,
        "tenant_id": tenant_id,
        "tenant_path": tenant_data_path,
        "user_id": user_id,
        "action": action,
        "resource": scoped_resource,
    }
