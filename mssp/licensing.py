from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from license_guard import check_license, reserve_seats, release_seats
from client_provisioning import get_client
from paths import get_allocation_path

logger = logging.getLogger(__name__)


def allocate_license(parent_license: dict[str, Any], client_id: str, allocation: dict[str, Any]) -> dict[str, Any]:
    license_id: str = parent_license["id"]
    check_license(license_id)
    get_client(client_id)  # validate client exists

    allocation_path: Path = get_allocation_path(license_id, client_id)

    if allocation_path.exists():
        existing: dict[str, Any] = json.loads(allocation_path.read_text())
        current_seats: int = existing.get("seats", 0)
    else:
        current_seats = 0

    requested_seats: int = allocation.get("seats", 0)
    if requested_seats <= 0:
        raise ValueError(f"Invalid seat count: {requested_seats}")

    reserve_seats(license_id, requested_seats - current_seats)

    record: dict[str, Any] = {
        "license_id": license_id,
        "client_id": client_id,
        "seats": requested_seats,
        "features": allocation.get("features", []),
        "expires_at": allocation.get("expires_at"),
    }

    allocation_path.parent.mkdir(parents=True, exist_ok=True)
    allocation_path.write_text(json.dumps(record))
    logger.info("Allocated %d seats of license %s to client %s", requested_seats, license_id, client_id)
    return record


def get_allocation(parent_license: dict[str, Any], client_id: str) -> dict[str, Any] | None:
    license_id: str = parent_license["id"]
    allocation_path: Path = get_allocation_path(license_id, client_id)

    if not allocation_path.exists():
        return None

    return json.loads(allocation_path.read_text())  # type: ignore[no-any-return]


def revoke_allocation(parent_license: dict[str, Any], client_id: str) -> None:
    license_id: str = parent_license["id"]
    allocation_path: Path = get_allocation_path(license_id, client_id)

    if not allocation_path.exists():
        raise FileNotFoundError(f"No allocation found for client {client_id} under license {license_id}")

    record: dict[str, Any] = json.loads(allocation_path.read_text())
    seats: int = record.get("seats", 0)

    release_seats(license_id, seats)
    allocation_path.unlink()
    logger.info("Revoked allocation of license %s from client %s", license_id, client_id)
