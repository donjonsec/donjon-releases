from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_compliance() -> dict[str, Any]:
    """Generate compliance dashboard data by scanning compliance-related paths."""
    try:
        from paths import get_paths  # type: ignore[import]

        paths = get_paths()
    except ImportError:
        logger.warning("paths-v1 not found, using defaults")
        paths = {}

    specs_path: Path = Path(paths.get("specs", "specs"))
    compliance_files: list[dict[str, Any]] = []

    if specs_path.exists():
        for spec_file in sorted(specs_path.glob("*compliance*")):
            if spec_file.is_file():
                try:
                    content = spec_file.read_text(encoding="utf-8")
                    compliance_files.append(
                        {
                            "name": spec_file.name,
                            "path": str(spec_file),
                            "size": spec_file.stat().st_size,
                            "content_preview": content[:500],
                        }
                    )
                except OSError as exc:
                    logger.error("Failed to read %s: %s", spec_file, exc)

    return {
        "compliance_files": compliance_files,
        "total_files": len(compliance_files),
        "specs_path": str(specs_path),
    }


def get_exports() -> dict[str, Callable[[], dict[str, Any]]]:
    return {"generate_compliance": generate_compliance}
