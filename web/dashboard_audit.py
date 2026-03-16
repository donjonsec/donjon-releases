from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_audit(paths: Any) -> dict[str, Any]:
    """Generate an audit report of the dashboard directory structure."""
    audit: dict[str, Any] = {
        "files": [],
        "directories": [],
        "missing": [],
        "errors": [],
    }

    required_paths: list[str] = getattr(paths, "REQUIRED_PATHS", [])
    base_dir: Path = Path(getattr(paths, "BASE_DIR", "."))

    for rel in required_paths:
        full: Path = base_dir / rel
        if not full.exists():
            audit["missing"].append(str(full))
            logger.warning("Missing path: %s", full)
        elif full.is_dir():
            audit["directories"].append(str(full))
        elif full.is_file():
            audit["files"].append(str(full))

    if base_dir.exists():
        for item in base_dir.rglob("*"):
            entry = str(item.relative_to(base_dir))
            if item.is_file() and entry not in audit["files"]:
                audit["files"].append(entry)
            elif item.is_dir() and entry not in audit["directories"]:
                audit["directories"].append(entry)

    return audit
