from __future__ import annotations

import logging
from typing import Any, Callable

from darkfactory.config import get_config
from darkfactory.paths import get_paths
from darkfactory.license_guard import LicenseGuard

logger = logging.getLogger(__name__)


def make_api_license_router() -> Callable[[str, dict[str, Any] | None], Callable[[], Any]]:
    config = get_config()
    paths = get_paths()
    guard = LicenseGuard(config=config, paths=paths)

    def handle(request_path: str, request_body: dict[str, Any] | None) -> Callable[[], Any]:
        if not request_path:
            raise ValueError("request_path must not be empty")

        normalized = request_path.rstrip("/")

        if normalized == "/api/license/status":
            return _handle_status(guard)
        elif normalized == "/api/license/validate":
            return _handle_validate(guard, request_body)
        elif normalized == "/api/license/activate":
            return _handle_activate(guard, request_body)
        elif normalized == "/api/license/deactivate":
            return _handle_deactivate(guard, request_body)
        else:
            raise ValueError(f"Unknown license route: {request_path!r}")

    return handle


def _handle_status(guard: LicenseGuard) -> Callable[[], dict[str, Any]]:
    def json_response() -> dict[str, Any]:
        status = guard.get_status()
        return {"ok": True, "status": status}

    return json_response


def _handle_validate(
    guard: LicenseGuard,
    body: dict[str, Any] | None,
) -> Callable[[], dict[str, Any]]:
    def json_response() -> dict[str, Any]:
        if body is None:
            raise ValueError("Request body required for /api/license/validate")
        license_key = body.get("license_key")
        if not license_key or not isinstance(license_key, str):
            raise ValueError("Field 'license_key' (str) is required")
        result = guard.validate(license_key=license_key)
        return {"ok": True, "valid": result.valid, "detail": result.detail}

    return json_response


def _handle_activate(
    guard: LicenseGuard,
    body: dict[str, Any] | None,
) -> Callable[[], dict[str, Any]]:
    def json_response() -> dict[str, Any]:
        if body is None:
            raise ValueError("Request body required for /api/license/activate")
        license_key = body.get("license_key")
        if not license_key or not isinstance(license_key, str):
            raise ValueError("Field 'license_key' (str) is required")
        result = guard.activate(license_key=license_key)
        return {"ok": True, "activated": result.activated, "detail": result.detail}

    return json_response


def _handle_deactivate(
    guard: LicenseGuard,
    body: dict[str, Any] | None,
) -> Callable[[], dict[str, Any]]:
    def json_response() -> dict[str, Any]:
        if body is None:
            raise ValueError("Request body required for /api/license/deactivate")
        license_key = body.get("license_key")
        if not license_key or not isinstance(license_key, str):
            raise ValueError("Field 'license_key' (str) is required")
        result = guard.deactivate(license_key=license_key)
        return {"ok": True, "deactivated": result.deactivated, "detail": result.detail}

    return json_response


def handle_license_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> Callable[[], Any]:
    router = make_api_license_router()
    return router(request_path, request_body)
