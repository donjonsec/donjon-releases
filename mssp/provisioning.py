from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from lib.database import get_database
from lib.license_guard import require_feature
from lib.paths import paths

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS mssp_clients (
    client_id   TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    config      TEXT,
    status      TEXT NOT NULL DEFAULT 'active'
);
"""

_db = get_database("mssp_provisioning", schema=_DDL)


def create_client(client_name: str, client_config: dict[str, Any]) -> dict[str, Any]:
    from lib.multi_tenant import create_tenant
    from lib.rbac import assign_role

    if not client_name or not client_name.strip():
        raise ValueError("client_name must be a non-empty string")
    if not isinstance(client_config, dict):
        raise TypeError("client_config must be a dict")

    require_feature("mssp")

    tenant = create_tenant(client_name, client_config)
    client_id: str = tenant["tenant_id"]

    assign_role(client_id, "client_admin")

    client_dir: Path = paths.data / "clients" / client_id
    client_dir.mkdir(parents=True, exist_ok=True)

    _db.execute_write(
        "INSERT INTO mssp_clients (client_id, client_name, config, status) VALUES (?, ?, ?, ?)",
        (client_id, client_name, json.dumps(client_config), "active"),
    )
    logger.info("Created client %s with id %s", client_name, client_id)

    return {
        "client_id": client_id,
        "client_name": client_name,
        "client_config": client_config,
        "status": "active",
    }


def update_client(client_id: str, client_config: dict[str, Any]) -> dict[str, Any]:
    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")
    if not isinstance(client_config, dict):
        raise TypeError("client_config must be a dict")

    require_feature("mssp")

    row = _db.execute_one("SELECT client_id FROM mssp_clients WHERE client_id = ?", (client_id,))
    if row is None:
        raise KeyError(f"Client not found: {client_id}")

    _db.execute_write(
        "UPDATE mssp_clients SET config = ? WHERE client_id = ?",
        (json.dumps(client_config), client_id),
    )
    logger.info("Updated client %s", client_id)
    return {"client_id": client_id, "client_config": client_config, "status": "updated"}


def delete_client(client_id: str) -> dict[str, Any]:
    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")

    require_feature("mssp")

    row = _db.execute_one("SELECT client_id FROM mssp_clients WHERE client_id = ?", (client_id,))
    if row is None:
        raise KeyError(f"Client not found: {client_id}")

    _db.execute_write("DELETE FROM mssp_clients WHERE client_id = ?", (client_id,))
    logger.info("Deleted client %s", client_id)
    return {"client_id": client_id, "status": "deleted"}


def list_clients() -> list[dict[str, Any]]:
    require_feature("mssp")

    rows = _db.execute("SELECT client_id, client_name, config, status FROM mssp_clients")
    return [
        {
            "client_id": row["client_id"],
            "client_name": row["client_name"],
            "client_config": json.loads(row["config"]) if row["config"] else {},
            "status": row["status"],
        }
        for row in rows
    ]


def get_client(client_id: str) -> dict[str, Any]:
    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")

    require_feature("mssp")

    row = _db.execute_one(
        "SELECT client_id, client_name, config, status FROM mssp_clients WHERE client_id = ?",
        (client_id,),
    )
    if row is None:
        raise KeyError(f"Client not found: {client_id}")

    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "client_config": json.loads(row["config"]) if row["config"] else {},
        "status": row["status"],
    }
