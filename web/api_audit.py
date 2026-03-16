from __future__ import annotations

import logging
from typing import Any, Callable

from lib.audit import get_audit_trail
from lib.license_guard import require_feature

logger = logging.getLogger(__name__)


def handle_audit_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[..., Any]]:
    require_feature("audit-api")

    audit_trail = get_audit_trail()
    audit_trail.log(
        action="api_request",
        target_type="system",
        details={"path": request_path, "body": request_body},
    )

    def json_response() -> dict[str, Any]:
        return {"status": "ok", "path": request_path}

    return {"json_response": json_response}
