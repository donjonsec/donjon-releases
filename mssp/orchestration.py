from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def schedule_bulk_scan(client_ids: list[str], scan_config: dict[str, Any]) -> dict[str, Any]:
    from mssp.provisioning import get_client
    from mssp.isolation import enforce_boundaries
    from darkfactory.license_guard import check_license
    from darkfactory.paths import get_scan_path

    if not client_ids:
        raise ValueError("client_ids must be a non-empty list")
    if not isinstance(scan_config, dict):
        raise TypeError("scan_config must be a dict")

    check_license("mssp_bulk_orchestration")

    bulk_id: str = str(uuid.uuid4())
    scheduled_clients: list[dict[str, Any]] = []
    failed_clients: list[dict[str, Any]] = []

    for client_id in client_ids:
        if not client_id or not client_id.strip():
            failed_clients.append({"client_id": client_id, "error": "invalid client_id"})
            continue
        try:
            get_client(client_id)
            enforce_boundaries(client_id)
            scan_dir: Path = get_scan_path(client_id, bulk_id)
            scan_dir.mkdir(parents=True, exist_ok=True)
            scheduled_clients.append({"client_id": client_id, "status": "scheduled"})
        except KeyError as exc:
            failed_clients.append({"client_id": client_id, "error": str(exc)})
        except Exception as exc:
            logger.error("Failed to schedule scan for client %s: %s", client_id, exc)
            failed_clients.append({"client_id": client_id, "error": str(exc)})

    logger.info(
        "Bulk scan %s scheduled for %d clients, %d failed",
        bulk_id,
        len(scheduled_clients),
        len(failed_clients),
    )
    return {
        "bulk_id": bulk_id,
        "status": "scheduled",
        "scheduled_clients": scheduled_clients,
        "failed_clients": failed_clients,
        "scan_config": scan_config,
    }


def get_bulk_status(bulk_id: str) -> dict[str, Any]:
    from darkfactory.license_guard import check_license
    from darkfactory.paths import get_bulk_status_path

    if not bulk_id or not bulk_id.strip():
        raise ValueError("bulk_id must be a non-empty string")

    check_license("mssp_bulk_orchestration")

    status_path: Path = get_bulk_status_path(bulk_id)
    if not status_path.exists():
        raise KeyError(f"Bulk scan not found: {bulk_id}")

    import json

    with status_path.open("r") as fh:
        data: dict[str, Any] = json.load(fh)

    return {
        "bulk_id": bulk_id,
        "status": data.get("status", "unknown"),
        "clients": data.get("clients", []),
    }


def cancel_bulk(bulk_id: str) -> dict[str, Any]:
    from darkfactory.license_guard import check_license
    from darkfactory.paths import get_bulk_status_path

    if not bulk_id or not bulk_id.strip():
        raise ValueError("bulk_id must be a non-empty string")

    check_license("mssp_bulk_orchestration")

    status_path: Path = get_bulk_status_path(bulk_id)
    if not status_path.exists():
        raise KeyError(f"Bulk scan not found: {bulk_id}")

    import json

    with status_path.open("r") as fh:
        data: dict[str, Any] = json.load(fh)

    if data.get("status") in ("completed", "cancelled"):
        return {
            "bulk_id": bulk_id,
            "status": data["status"],
            "message": f"Cannot cancel: scan already {data['status']}",
        }

    data["status"] = "cancelled"
    with status_path.open("w") as fh:
        json.dump(data, fh)

    logger.info("Cancelled bulk scan %s", bulk_id)
    return {"bulk_id": bulk_id, "status": "cancelled"}
