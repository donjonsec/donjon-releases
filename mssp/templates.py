from __future__ import annotations

import json
import logging
from typing import Any

from lib.database import get_database
from lib.license_guard import require_feature
from lib.paths import paths

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS scan_templates (
    name TEXT PRIMARY KEY,
    config TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_db = get_database("mssp_templates", schema=_DDL)


def create_template(template_name: str, scan_config: dict[str, Any]) -> dict[str, Any]:
    require_feature("mssp")
    if not template_name or not template_name.strip():
        raise ValueError("template_name must be a non-empty string")
    if not isinstance(scan_config, dict):
        raise TypeError("scan_config must be a dict")

    _db.execute_write(
        "INSERT OR REPLACE INTO scan_templates (name, config) VALUES (?, ?)",
        (template_name.strip(), json.dumps(scan_config)),
    )

    logger.info("Created scan template: %s", template_name)
    return {"name": template_name.strip(), "scan_config": scan_config}


def apply_template(template_name: str, target: dict[str, Any]) -> dict[str, Any]:
    require_feature("mssp")
    if not template_name or not template_name.strip():
        raise ValueError("template_name must be a non-empty string")

    row = _db.execute_one(
        "SELECT config FROM scan_templates WHERE name = ?",
        (template_name.strip(),),
    )

    if row is None:
        raise KeyError(f"Template not found: {template_name!r}")

    scan_config: dict[str, Any] = json.loads(row["config"])
    merged: dict[str, Any] = {**scan_config, **target}
    logger.info("Applied template %s to target", template_name)
    return {"template_name": template_name.strip(), "scan_config": scan_config, "merged_config": merged}


def list_templates() -> list[dict[str, Any]]:
    require_feature("mssp")

    rows = _db.execute("SELECT name, config, created_at FROM scan_templates ORDER BY created_at DESC")

    return [{"name": row["name"], "scan_config": json.loads(row["config"]), "created_at": row["created_at"]} for row in rows]
