from __future__ import annotations

import logging
from typing import Any, Callable

from lib.config import get_config
from lib.paths import get_paths
from lib.license_guard import require_feature

logger = logging.getLogger(__name__)


def handle_settings_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[[], Any]]:
    cfg = get_config()
    paths = get_paths()
    require_feature("settings")

    def _route() -> Any:
        if request_path == "/settings/config":
            return _handle_config(cfg, request_body)
        elif request_path == "/settings/paths":
            return _handle_paths(paths, request_body)
        elif request_path == "/settings/license":
            return _handle_license(cfg, request_body)
        else:
            raise ValueError(f"Unknown settings path: {request_path!r}")

    return {"json_response": _route}


def _handle_config(
    cfg: Any,
    body: dict[str, Any] | None,
) -> dict[str, Any]:
    if body is not None:
        for key, value in body.items():
            cfg.set(key, value)
        logger.info("Updated config keys: %s", list(body.keys()))
    return {"config": cfg.as_dict()}


def _handle_paths(
    paths: Any,
    body: dict[str, Any] | None,
) -> dict[str, Any]:
    if body is not None:
        for key, value in body.items():
            paths.set(key, value)
        logger.info("Updated path keys: %s", list(body.keys()))
    return {"paths": paths.as_dict()}


def _handle_license(
    cfg: Any,
    body: dict[str, Any] | None,
) -> dict[str, Any]:
    if body is not None and "license_key" in body:
        license_key = body["license_key"]
        if not isinstance(license_key, str) or not license_key.strip():
            raise ValueError("license_key must be a non-empty string")
        cfg.set("license_key", license_key.strip())
        logger.info("License key updated")
    return {"license": {"status": "active"}}
