from __future__ import annotations

import logging
from typing import Any

from darkfactory.paths import get_data_path
from darkfactory.db import get_connection
from darkfactory.license import require_feature

logger = logging.getLogger(__name__)


def create_template(template_name: str, scan_config: dict[str, Any]) -> dict[str, Any]:
    require_feature("mssp")
    if not template_name or not template_name.strip():
        raise ValueError("template_name must be a non-empty string")
    if not isinstance(scan_config, dict):
        raise TypeError("scan_config must be a dict")

    data_path = get_data_path()
    db_path = data_path / "mssp_templates.db"

    with get_connection(str(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_templates (
                name TEXT PRIMARY KEY,
                config TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        import json

        conn.execute(
            "INSERT OR REPLACE INTO scan_templates (name, config) VALUES (?, ?)",
            (template_name.strip(), json.dumps(scan_config)),
        )
        conn.commit()

    logger.info("Created scan template: %s", template_name)
    return {"name": template_name.strip(), "scan_config": scan_config}


def apply_template(template_name: str, target: dict[str, Any]) -> dict[str, Any]:
    require_feature("mssp")
    if not template_name or not template_name.strip():
        raise ValueError("template_name must be a non-empty string")

    data_path = get_data_path()
    db_path = data_path / "mssp_templates.db"

    with get_connection(str(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_templates (
                name TEXT PRIMARY KEY,
                config TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        row = conn.execute(
            "SELECT config FROM scan_templates WHERE name = ?",
            (template_name.strip(),),
        ).fetchone()

    if row is None:
        raise KeyError(f"Template not found: {template_name!r}")

    import json

    scan_config: dict[str, Any] = json.loads(row[0])
    merged: dict[str, Any] = {**scan_config, **target}
    logger.info("Applied template %s to target", template_name)
    return {"template_name": template_name.strip(), "scan_config": scan_config, "merged_config": merged}


def list_templates() -> list[dict[str, Any]]:
    require_feature("mssp")
    data_path = get_data_path()
    db_path = data_path / "mssp_templates.db"

    with get_connection(str(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_templates (
                name TEXT PRIMARY KEY,
                config TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        rows = conn.execute("SELECT name, config, created_at FROM scan_templates ORDER BY created_at DESC").fetchall()

    import json

    return [{"name": row[0], "scan_config": json.loads(row[1]), "created_at": row[2]} for row in rows]
