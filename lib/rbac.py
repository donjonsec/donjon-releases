from __future__ import annotations

import logging
from typing import Any

from lib.database import get_connection
from lib.license_guard import assert_licensed
from lib.paths import DATA_DIR  # noqa: F401

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS rbac_roles (
    id          SERIAL  PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS rbac_permissions (
    id          SERIAL  PRIMARY KEY,
    role_id     INTEGER NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    action      TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    UNIQUE (role_id, action, resource)
);
CREATE TABLE IF NOT EXISTS rbac_user_roles (
    user_id     TEXT    NOT NULL,
    role_id     INTEGER NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS rbac_ur_user_idx ON rbac_user_roles (user_id);
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


def check_permission(user_id: str, action: str, resource: str) -> bool:
    """Return True iff user_id holds a role granting action on resource."""
    if not user_id:
        raise ValueError("user_id must be non-empty")
    if not action:
        raise ValueError("action must be non-empty")
    if not resource:
        raise ValueError("resource must be non-empty")

    _ensure_schema()

    sql = """
        SELECT 1
        FROM   rbac_user_roles ur
        JOIN   rbac_permissions p ON p.role_id = ur.role_id
        WHERE  ur.user_id = %s
          AND  p.action   = %s
          AND  (p.resource = %s OR p.resource = '*')
        LIMIT 1
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (user_id, action, resource))
            return cur.fetchone() is not None
    finally:
        conn.close()


def assign_role(user_id: str, role_name: str) -> None:
    """Assign role_name to user_id.  Idempotent."""
    if not user_id:
        raise ValueError("user_id must be non-empty")
    if not role_name:
        raise ValueError("role_name must be non-empty")

    _ensure_schema()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM rbac_roles WHERE name = %s", (role_name,))
            row = cur.fetchone()
            if row is None:
                raise KeyError(f"Role '{role_name}' does not exist")
            role_id: int = row[0]
            cur.execute(
                """
                INSERT INTO rbac_user_roles (user_id, role_id)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
                """,
                (user_id, role_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_roles(user_id: str | None = None) -> list[dict[str, Any]]:
    """Return all roles, or only those held by user_id when provided.

    Each item: {"id": int, "name": str, "description": str, "permissions": list}.
    """
    _ensure_schema()

    if user_id is not None:
        roles_sql = """
            SELECT r.id, r.name, r.description
            FROM   rbac_roles r
            JOIN   rbac_user_roles ur ON ur.role_id = r.id
            WHERE  ur.user_id = %s
            ORDER  BY r.name
        """
        params: tuple[Any, ...] = (user_id,)
    else:
        roles_sql = "SELECT id, name, description FROM rbac_roles ORDER BY name"
        params = ()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(roles_sql, params)
            role_rows: list[tuple[int, str, str]] = cur.fetchall()
            if not role_rows:
                return []
            role_ids = [r[0] for r in role_rows]
            cur.execute(
                "SELECT role_id, action, resource FROM rbac_permissions WHERE role_id = ANY(%s) ORDER BY role_id, action, resource",
                (role_ids,),
            )
            perm_rows: list[tuple[int, str, str]] = cur.fetchall()
    finally:
        conn.close()

    perms_by_role: dict[int, list[dict[str, str]]] = {}
    for role_id, action, resource in perm_rows:
        perms_by_role.setdefault(role_id, []).append({"action": action, "resource": resource})

    return [
        {
            "id": rid,
            "name": name,
            "description": desc,
            "permissions": perms_by_role.get(rid, []),
        }
        for rid, name, desc in role_rows
    ]


def create_role(
    name: str,
    permissions: list[dict[str, str]],
    description: str = "",
) -> dict[str, Any]:
    """Create a new role with the given permissions.

    Returns the created role dict (same shape as list_roles items).
    """
    if not name:
        raise ValueError("name must be non-empty")

    assert_licensed("rbac.custom_roles")
    _ensure_schema()

    for i, perm in enumerate(permissions):
        if "action" not in perm or "resource" not in perm:
            raise ValueError(f"permissions[{i}] must have 'action' and 'resource' keys")
        if not perm["action"]:
            raise ValueError(f"permissions[{i}]['action'] must be non-empty")
        if not perm["resource"]:
            raise ValueError(f"permissions[{i}]['resource'] must be non-empty")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO rbac_roles (name, description) VALUES (%s, %s) RETURNING id",
                (name, description),
            )
            result = cur.fetchone()
            if result is None:
                raise RuntimeError("INSERT INTO rbac_roles returned no id")
            role_id: int = result[0]

            if permissions:
                cur.executemany(
                    "INSERT INTO rbac_permissions (role_id, action, resource) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                    [(role_id, p["action"], p["resource"]) for p in permissions],
                )
        conn.commit()
        logger.info("Created role '%s' (id=%d) with %d permissions", name, role_id, len(permissions))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "id": role_id,
        "name": name,
        "description": description,
        "permissions": [{"action": p["action"], "resource": p["resource"]} for p in permissions],
    }
