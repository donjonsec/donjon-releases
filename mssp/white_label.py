from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from lib.license_guard import require_feature
from lib.paths import paths
from mssp.provisioning import get_client

logger = logging.getLogger(__name__)


class WhiteLabelManager:
    _branding_store: dict[str | None, dict[str, Any]]
    _client_id: str | None
    _branding: dict[str, Any]

    def __init__(self, client_id: str | None, branding: dict[str, Any]) -> None:
        if not isinstance(branding, dict):
            raise TypeError(f"branding must be a dict, got {type(branding).__name__}")

        self._client_id = client_id
        self._branding = dict(branding)
        self._branding_store = {}

    def set_branding(self, client_id: str | None, branding: dict[str, Any]) -> None:
        if not isinstance(branding, dict):
            raise TypeError(f"branding must be a dict, got {type(branding).__name__}")

        require_feature("white_label")
        if client_id is not None:
            get_client(client_id)  # raises KeyError if client doesn't exist

        self._branding_store[client_id] = dict(branding)
        logger.info("Branding set for client_id=%r", client_id)

    def get_branding(self, client_id: str | None) -> dict[str, Any]:
        require_feature("white_label")

        if client_id in self._branding_store:
            return dict(self._branding_store[client_id])

        if None in self._branding_store:
            logger.debug("Falling back to default branding for client_id=%r", client_id)
            return dict(self._branding_store[None])

        raise KeyError(f"No branding found for client_id={client_id!r}")

    def apply_branding(self, client_id: str | None, target_path: str | Path) -> Path:
        require_feature("white_label")

        resolved: dict[str, Any] = self.get_branding(client_id)
        # Store branding output under data/branding/<client_id>/
        branding_dir = paths.data / "branding" / (client_id or "default")
        output_path: Path = branding_dir / Path(target_path).name

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
