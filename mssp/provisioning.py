from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def create_client(client_name: str, client_config: dict[str, Any]) -> dict[str, Any]:
    from darkfactory.multi_tenant import create_tenant
    from darkfactory.rbac import assign_role
    from darkfactory.license_guard import check_license
    from darkfactory.paths import get_client_path
    from darkfactory.db import get_db

    if not client_name or not client_name.strip():
        raise ValueError("client_name must be a non-empty string")
    if not isinstance(client_config, dict):
        raise TypeError("client_config must be a dict")

    check_license("mssp_provisioning")

    db = get_db()
    tenant = create_tenant(client_name, client_config)
    client_id: str = tenant["tenant_id"]

    assign_role(client_id, "client_admin", scope=client_id)

    client_dir: Path = get_client_path(client_id)
    client_dir.mkdir(parents=True, exist_ok=True)

    record: dict[str, Any] = {
        "client_id": client_id,
        "client_name": client_name,
        "client_config": client_config,
        "status": "active",
    }
    db.execute(
        "INSERT INTO mssp_clients (client_id, client_name, config, status) VALUES (%s, %s, %s, %s)",
        (client_id, client_name, client_config, "active"),
    )
    logger.info("Created client %s with id %s", client_name, client_id)
    return record


def update_client(client_id: str, client_config: dict[str, Any]) -> dict[str, Any]:
    from darkfactory.multi_tenant import update_tenant
    from darkfactory.license_guard import check_license
    from darkfactory.db import get_db

    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")
    if not isinstance(client_config, dict):
        raise TypeError("client_config must be a dict")

    check_license("mssp_provisioning")

    db = get_db()
    row = db.fetchone("SELECT client_id FROM mssp_clients WHERE client_id = %s", (client_id,))
    if row is None:
        raise KeyError(f"Client not found: {client_id}")

    update_tenant(client_id, client_config)
    db.execute(
        "UPDATE mssp_clients SET config = %s WHERE client_id = %s",
        (client_config, client_id),
    )
    logger.info("Updated client %s", client_id)
    return {"client_id": client_id, "client_config": client_config, "status": "updated"}


def delete_client(client_id: str) -> dict[str, Any]:
    from darkfactory.multi_tenant import delete_tenant
    from darkfactory.license_guard import check_license
    from darkfactory.db import get_db

    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")

    check_license("mssp_provisioning")

    db = get_db()
    row = db.fetchone("SELECT client_id FROM mssp_clients WHERE client_id = %s", (client_id,))
    if row is None:
        raise KeyError(f"Client not found: {client_id}")

    delete_tenant(client_id)
    db.execute("DELETE FROM mssp_clients WHERE client_id = %s", (client_id,))
    logger.info("Deleted client %s", client_id)
    return {"client_id": client_id, "status": "deleted"}


def list_clients() -> list[dict[str, Any]]:
    from darkfactory.license_guard import check_license
    from darkfactory.db import get_db

    check_license("mssp_provisioning")

    db = get_db()
    rows = db.fetchall("SELECT client_id, client_name, config, status FROM mssp_clients")
    return [
        {
            "client_id": row["client_id"],
            "client_name": row["client_name"],
            "client_config": row["config"],
            "status": row["status"],
        }
        for row in rows
    ]


def get_client(client_id: str) -> dict[str, Any]:
    from darkfactory.license_guard import check_license
    from darkfactory.db import get_db

    if not client_id or not client_id.strip():
        raise ValueError("client_id must be a non-empty string")

    check_license("mssp_provisioning")

    db = get_db()
    row = db.fetchone(
        "SELECT client_id, client_name, config, status FROM mssp_clients WHERE client_id = %s",
        (client_id,),
    )
    if row is None:
        raise KeyError(f"Client not found: {client_id}")

    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "client_config": row["config"],
        "status": row["status"],
    }
