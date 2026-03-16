from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_overview() -> dict[str, Any]:
    """Generate a dashboard overview by collecting stats from project paths."""
    try:
        from paths import get_paths  # type: ignore[import]

        paths = get_paths()
    except Exception as exc:
        logger.warning("Could not load paths-v1: %s", exc)
        paths = {}

    overview: dict[str, Any] = {
        "sections": [],
        "stats": {},
    }

    for name, raw_path in paths.items():
        path = Path(raw_path) if isinstance(raw_path, str) else raw_path
        if not isinstance(path, Path):
            continue
        entry: dict[str, Any] = {
            "name": name,
            "path": str(path),
            "exists": path.exists(),
        }
        if path.exists() and path.is_dir():
            try:
                children = list(path.iterdir())
                entry["child_count"] = len(children)
            except PermissionError:
                entry["child_count"] = None
        elif path.exists() and path.is_file():
            try:
                entry["size_bytes"] = path.stat().st_size
            except OSError:
                entry["size_bytes"] = None
        overview["sections"].append(entry)

    overview["stats"]["total_paths"] = len(overview["sections"])
    overview["stats"]["existing_paths"] = sum(1 for s in overview["sections"] if s.get("exists"))

    return overview
