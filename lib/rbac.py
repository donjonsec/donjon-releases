from __future__ import annotations

import logging
from typing import Any

from lib.database import get_database
from lib.license_guard import require_feature
from lib.paths import paths

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS rbac_roles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS rbac_permissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
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

_db = get_database("rbac", schema=_DDL)


def check_permission(user_id: str, action: str, resource: str) -> bool:
    """Return True iff user_id holds a role granting action on resource."""
    if not user_id:
        raise ValueError("user_id must be non-empty")
    if not action:
        raise ValueError("action must be non-empty")
    if not resource:
        raise ValueError("resource must be non-empty")

    sql = """
        SELECT 1
        FROM   rbac_user_roles ur
        JOIN   rbac_permissions p ON p.role_id = ur.role_id
        WHERE  ur.user_id = ?
          AND  p.action   = ?
          AND  (p.resource = ? OR p.resource = '*')
        LIMIT 1
    """
    row = _db.execute_one(sql, (user_id, action, resource))
    return row is not None


def assign_role(user_id: str, role_name: str) -> None:
    """Assign role_name to user_id.  Idempotent."""
    if not user_id:
        raise ValueError("user_id must be non-empty")
    if not role_name:
        raise ValueError("role_name must be non-empty")

    row = _db.execute_one("SELECT id FROM rbac_roles WHERE name = ?", (role_name,))
    if row is None:
        raise KeyError(f"Role '{role_name}' does not exist")
    role_id: int = row["id"]
    _db.execute_write(
        "INSERT OR IGNORE INTO rbac_user_roles (user_id, role_id) VALUES (?, ?)",
        (user_id, role_id),
    )


def list_roles(user_id: str | None = None) -> list[dict[str, Any]]:
    """Return all roles, or only those held by user_id when provided.

    Each item: {"id": int, "name": str, "description": str, "permissions": list}.
    """
    if user_id is not None:
        role_rows = _db.execute(
            """
            SELECT r.id, r.name, r.description
            FROM   rbac_roles r
            JOIN   rbac_user_roles ur ON ur.role_id = r.id
            WHERE  ur.user_id = ?
            ORDER  BY r.name
            """,
            (user_id,),
        )
    else:
        role_rows = _db.execute("SELECT id, name, description FROM rbac_roles ORDER BY name")

    if not role_rows:
        return []

    role_ids = [r["id"] for r in role_rows]
    # Build IN clause with positional params
    placeholders = ",".join("?" for _ in role_ids)
    perm_rows = _db.execute(
        f"SELECT role_id, action, resource FROM rbac_permissions WHERE role_id IN ({placeholders}) ORDER BY role_id, action, resource",
        tuple(role_ids),
    )

    perms_by_role: dict[int, list[dict[str, str]]] = {}
    for prow in perm_rows:
        perms_by_role.setdefault(prow["role_id"], []).append(
            {"action": prow["action"], "resource": prow["resource"]}
        )

    return [
        {
            "id": r["id"],
            "name": r["name"],
            "description": r["description"],
            "permissions": perms_by_role.get(r["id"], []),
        }
        for r in role_rows
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

    require_feature("rbac.custom_roles")

    for i, perm in enumerate(permissions):
        if "action" not in perm or "resource" not in perm:
            raise ValueError(f"permissions[{i}] must have 'action' and 'resource' keys")
        if not perm["action"]:
            raise ValueError(f"permissions[{i}]['action'] must be non-empty")
        if not perm["resource"]:
            raise ValueError(f"permissions[{i}]['resource'] must be non-empty")

    _db.execute_write(
        "INSERT INTO rbac_roles (name, description) VALUES (?, ?)",
        (name, description),
    )
    row = _db.execute_one("SELECT id FROM rbac_roles WHERE name = ?", (name,))
    if row is None:
        raise RuntimeError("INSERT INTO rbac_roles returned no id")
    role_id: int = row["id"]

    if permissions:
        for p in permissions:
            _db.execute_write(
                "INSERT OR IGNORE INTO rbac_permissions (role_id, action, resource) VALUES (?, ?, ?)",
                (role_id, p["action"], p["resource"]),
            )

    logger.info("Created role '%s' (id=%d) with %d permissions", name, role_id, len(permissions))

    return {
        "id": role_id,
        "name": name,
        "description": description,
        "permissions": [{"action": p["action"], "resource": p["resource"]} for p in permissions],
    }
