from __future__ import annotations

import logging
from typing import Any, Callable

from lib.config import get_config
from lib.paths import get_paths
from lib.license_guard import require_feature

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowlists — only these keys may be set via the Settings API.
# Anything not listed here is rejected with 400.
# ---------------------------------------------------------------------------
_ALLOWED_CONFIG_KEYS = frozenset({
    'scan.default_timeout', 'scan.max_concurrent', 'scan.retry_count',
    'reporting.company_name', 'reporting.logo_path', 'reporting.output_format',
    'notifications.enabled', 'notifications.email', 'notifications.slack_webhook',
    'ai.provider', 'ai.model', 'ai.temperature', 'ai.max_tokens',
    'dashboard.refresh_interval', 'dashboard.theme',
    'logging.level', 'logging.file',
})

_ALLOWED_PATH_KEYS = frozenset({
    'data_dir', 'reports_dir', 'exports_dir', 'scans_dir', 'plugins_dir',
    'templates_dir', 'evidence_dir', 'backup_dir',
})


def _validate_keys(keys: set[str], allowed: frozenset[str], category: str) -> None:
    """Raise ValueError if any key is not in the allowlist."""
    rejected = keys - allowed
    if rejected:
        raise ValueError(
            f"Unknown {category} key(s): {', '.join(sorted(rejected))}. "
            f"Allowed keys: {', '.join(sorted(allowed))}"
        )


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
        _validate_keys(set(body.keys()), _ALLOWED_CONFIG_KEYS, "config")
        for key, value in body.items():
            cfg.set(key, value)
        logger.info("Updated config keys: %s", list(body.keys()))
    return {"config": cfg.as_dict()}


def _handle_paths(
    paths: Any,
    body: dict[str, Any] | None,
) -> dict[str, Any]:
    if body is not None:
        _validate_keys(set(body.keys()), _ALLOWED_PATH_KEYS, "path")
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
