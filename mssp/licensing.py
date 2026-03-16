from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from lib.license_guard import require_feature
from lib.paths import paths

logger = logging.getLogger(__name__)


def _get_allocation_path(license_id: str, client_id: str) -> Path:
    """Get the file path for a license allocation record."""
    alloc_dir = paths.data / "license_allocations" / license_id
    return alloc_dir / f"{client_id}.json"


def allocate_license(parent_license: dict[str, Any], client_id: str, allocation: dict[str, Any]) -> dict[str, Any]:
    license_id: str = parent_license["id"]
    require_feature("mssp")

    allocation_path: Path = _get_allocation_path(license_id, client_id)

    if allocation_path.exists():
        existing: dict[str, Any] = json.loads(allocation_path.read_text())
        current_seats: int = existing.get("seats", 0)
    else:
        current_seats = 0

    requested_seats: int = allocation.get("seats", 0)
    if requested_seats <= 0:
        raise ValueError(f"Invalid seat count: {requested_seats}")

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
    allocation_path: Path = _get_allocation_path(license_id, client_id)

    if not allocation_path.exists():
        return None

    return json.loads(allocation_path.read_text())  # type: ignore[no-any-return]


def revoke_allocation(parent_license: dict[str, Any], client_id: str) -> None:
    license_id: str = parent_license["id"]
    allocation_path: Path = _get_allocation_path(license_id, client_id)

    if not allocation_path.exists():
        raise FileNotFoundError(f"No allocation found for client {client_id} under license {license_id}")

    allocation_path.unlink()
    logger.info("Revoked allocation of license %s from client %s", license_id, client_id)
