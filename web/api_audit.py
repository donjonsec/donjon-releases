from __future__ import annotations

import logging
from typing import Any, Callable

from darkfactory.audit_trail import record_audit_event
from darkfactory.license_guard import check_license

logger = logging.getLogger(__name__)


def handle_audit_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[..., Any]]:
    check_license(feature="audit-api")

    record_audit_event(
        path=request_path,
        body=request_body,
    )

    def json_response() -> dict[str, Any]:
        return {"status": "ok", "path": request_path}

    return {"json_response": json_response}
