from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from lib.config import get_config
from lib.paths import get_paths

logger = logging.getLogger(__name__)


def generate_settings() -> dict[str, Any]:
    config = get_config()
    paths = get_paths()

    settings: dict[str, Any] = {
        "version": config.get("version", ""),
        "environment": config.get("environment", "production"),
        "base_dir": str(paths.home),
        "data_dir": str(paths.data),
        "log_dir": str(paths.logs),
        "debug": config.get("debug", False),
        "features": config.get("features", {}),
        "ui": config.get("ui", {}),
    }

    logger.debug("Dashboard settings generated: %s keys", len(settings))
    return settings
