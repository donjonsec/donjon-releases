from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from lib.paths import get_paths

logger = logging.getLogger(__name__)


def generate_schedules() -> dict[str, Any]:
    paths = get_paths()
    schedules_path: Path = paths.config / "schedules"

    schedules: list[dict[str, Any]] = []

    if not schedules_path.exists():
        logger.warning("Schedules directory does not exist: %s", schedules_path)
        return {"schedules": schedules}

    for schedule_file in sorted(schedules_path.glob("*.toml")):
        try:
            import tomllib

            with schedule_file.open("rb") as fh:
                data: dict[str, Any] = tomllib.load(fh)
            data["_source"] = str(schedule_file)
            schedules.append(data)
        except Exception:
            logger.exception("Failed to load schedule file: %s", schedule_file)

    logger.debug("Loaded %d schedules from %s", len(schedules), schedules_path)
    return {"schedules": schedules}
