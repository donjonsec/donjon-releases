from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_overview() -> dict[str, Any]:
    """Generate a dashboard overview by collecting stats from project paths."""
    try:
        from lib.paths import get_paths

        p = get_paths()
        paths_map: dict[str, Path] = {
            "home": p.home,
            "data": p.data,
            "results": p.results,
            "evidence": p.evidence,
            "logs": p.logs,
            "reports": p.reports,
            "config": p.config,
            "scanners": p.scanners,
        }
    except Exception as exc:
        logger.warning("Could not load paths: %s", exc)
        paths_map = {}

    overview: dict[str, Any] = {
        "sections": [],
        "stats": {},
    }

    for name, path in paths_map.items():
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
