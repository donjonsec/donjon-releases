from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _resolve_license_guard() -> Any:
    try:
        from license_guard import LicenseGuard  # type: ignore[import]

        return LicenseGuard()
    except Exception:
        try:
            from darkfactory.license_guard import LicenseGuard  # type: ignore[import]

            return LicenseGuard()
        except Exception as exc:
            raise ImportError(f"license-guard-v1 not available: {exc}") from exc


def _resolve_client_provisioning() -> Any:
    try:
        from client_provisioning import ClientProvisioning  # type: ignore[import]

        return ClientProvisioning()
    except Exception:
        try:
            from darkfactory.client_provisioning import ClientProvisioning  # type: ignore[import]

            return ClientProvisioning()
        except Exception as exc:
            raise ImportError(f"client-provisioning-v1 not available: {exc}") from exc


def _resolve_paths() -> Any:
    try:
        from paths import Paths  # type: ignore[import]

        return Paths()
    except Exception:
        try:
            from darkfactory.paths import Paths  # type: ignore[import]

            return Paths()
        except Exception as exc:
            raise ImportError(f"paths-v1 not available: {exc}") from exc


class WhiteLabelManager:
    _branding_store: dict[str | None, dict[str, Any]]
    _client_id: str | None
    _branding: dict[str, Any]
    _license_guard: Any
    _client_provisioning: Any
    _paths: Any

    def __init__(self, client_id: str | None, branding: dict[str, Any]) -> None:
        if not isinstance(branding, dict):
            raise TypeError(f"branding must be a dict, got {type(branding).__name__}")

        self._client_id = client_id
        self._branding = dict(branding)
        self._branding_store = {}
        self._license_guard = _resolve_license_guard()
        self._client_provisioning = _resolve_client_provisioning()
        self._paths = _resolve_paths()

    def set_branding(self, client_id: str | None, branding: dict[str, Any]) -> None:
        if not isinstance(branding, dict):
            raise TypeError(f"branding must be a dict, got {type(branding).__name__}")

        self._license_guard.check("white_label")
        if client_id is not None:
            self._client_provisioning.validate_client(client_id)

        self._branding_store[client_id] = dict(branding)
        logger.info("Branding set for client_id=%r", client_id)

    def get_branding(self, client_id: str | None) -> dict[str, Any]:
        self._license_guard.check("white_label")

        if client_id in self._branding_store:
            return dict(self._branding_store[client_id])

        if None in self._branding_store:
            logger.debug("Falling back to default branding for client_id=%r", client_id)
            return dict(self._branding_store[None])

        raise KeyError(f"No branding found for client_id={client_id!r}")

    def apply_branding(self, client_id: str | None, target_path: str | Path) -> Path:
        self._license_guard.check("white_label")

        resolved: dict[str, Any] = self.get_branding(client_id)
        base_path: Path = Path(self._paths.get_branding_dir(client_id))
        output_path: Path = base_path / Path(target_path).name

        output_path.parent.mkdir(parents=True, exist_ok=True)

        import json

        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(resolved, fh, indent=2)

        logger.info("Branding applied to %s for client_id=%r", output_path, client_id)
        return output_path


def white_label(
    client_id: str | None,
    branding: dict[str, Any],
) -> dict[str, Callable[..., Any]]:
    manager = WhiteLabelManager(client_id=client_id, branding=branding)

    if branding:
        manager.set_branding(client_id, branding)

    return {
        "set_branding": manager.set_branding,
        "get_branding": manager.get_branding,
        "apply_branding": manager.apply_branding,
    }
