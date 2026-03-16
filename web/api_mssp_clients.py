from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from services.client_provisioning import ClientProvisioningService
from services.client_isolation import ClientIsolationService
from services.license_guard import LicenseGuardService

logger = logging.getLogger(__name__)


def handle_mssp_clients(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[[], Any]]:
    provisioning = ClientProvisioningService()
    isolation = ClientIsolationService()
    license_guard = LicenseGuardService()

    def json_response() -> Any:
        parts = [p for p in request_path.strip("/").split("/") if p]

        # POST /clients — provision new client
        if parts == ["clients"] and request_body is not None:
            license_guard.check_client_seat_available()
            client = provisioning.provision_client(request_body)
            isolation.initialize_tenant(client["client_id"])
            return {"status": "created", "client": client}

        # GET /clients — list all clients
        if parts == ["clients"] and request_body is None:
            clients = provisioning.list_clients()
            return {"clients": clients}

        # GET /clients/{id}
        if len(parts) == 2 and parts[0] == "clients" and request_body is None:
            client_id = parts[1]
            client = provisioning.get_client(client_id)
            return {"client": client}

        # PUT /clients/{id}
        if len(parts) == 2 and parts[0] == "clients" and request_body is not None:
            client_id = parts[1]
            updated = provisioning.update_client(client_id, request_body)
            return {"status": "updated", "client": updated}

        # DELETE /clients/{id}
        if len(parts) == 2 and parts[0] == "clients":
            client_id = parts[1]
            isolation.teardown_tenant(client_id)
            provisioning.deprovision_client(client_id)
            license_guard.release_client_seat(client_id)
            return {"status": "deleted", "client_id": client_id}

        # GET /clients/{id}/isolation
        if len(parts) == 3 and parts[0] == "clients" and parts[2] == "isolation":
            client_id = parts[1]
            status = isolation.get_tenant_status(client_id)
            return {"client_id": client_id, "isolation": status}

        # GET /clients/{id}/license
        if len(parts) == 3 and parts[0] == "clients" and parts[2] == "license":
            client_id = parts[1]
            info = license_guard.get_client_license(client_id)
            return {"client_id": client_id, "license": info}

        logger.warning("Unmatched MSSP client route: %s", request_path)
        return {"error": "not_found", "path": request_path}

    return {"json_response": json_response}
