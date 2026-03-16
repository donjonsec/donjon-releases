from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from mssp.provisioning import create_client, update_client, delete_client, list_clients, get_client
from mssp.isolation import enforce_boundaries
from lib.license_guard import require_tier, LicenseError

logger = logging.getLogger(__name__)


def handle_mssp_clients(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[[], Any]]:

    def json_response() -> Any:
        try:
            require_tier("managed")
        except LicenseError as exc:
            return {"error": str(exc), "status": 403}

        parts = [p for p in request_path.strip("/").split("/") if p]

        # POST /clients — provision new client
        if parts == ["clients"] and request_body is not None:
            client_name = request_body.get("name", "")
            client_config = request_body.get("config", {})
            client = create_client(client_name=client_name, client_config=client_config)
            enforce_boundaries(client["client_id"])
            return {"status": "created", "client": client}

        # GET /clients — list all clients
        if parts == ["clients"] and request_body is None:
            clients = list_clients()
            return {"clients": clients}

        # GET /clients/{id}
        if len(parts) == 2 and parts[0] == "clients" and request_body is None:
            client_id = parts[1]
            client = get_client(client_id)
            return {"client": client}

        # PUT /clients/{id}
        if len(parts) == 2 and parts[0] == "clients" and request_body is not None:
            client_id = parts[1]
            updated = update_client(client_id, client_config=request_body)
            return {"status": "updated", "client": updated}

        # DELETE /clients/{id}
        if len(parts) == 2 and parts[0] == "clients":
            client_id = parts[1]
            delete_client(client_id)
            return {"status": "deleted", "client_id": client_id}

        # GET /clients/{id}/isolation
        if len(parts) == 3 and parts[0] == "clients" and parts[2] == "isolation":
            client_id = parts[1]
            status = enforce_boundaries(client_id)
            return {"client_id": client_id, "isolation": status}

        logger.warning("Unmatched MSSP client route: %s", request_path)
        return {"error": "not_found", "path": request_path}

    return {"json_response": json_response}
