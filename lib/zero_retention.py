from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pathlib import Path

from lib.database import get_database
from lib.license_guard import require_feature
from lib.paths import paths

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS ephemeral_sessions (
    id                  TEXT PRIMARY KEY,
    parent_session_id   TEXT NOT NULL,
    retention_mode      TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    purged              INTEGER NOT NULL DEFAULT 0,
    purged_at           TEXT
);
"""

_db = get_database("zero_retention", schema=_DDL)


def create_module(
    session_id: str,
    retention_mode: str,
) -> dict[str, Any]:
    require_feature("zero-retention")

    def create_ephemeral_session() -> dict[str, Any]:
        ephemeral_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)

        _db.execute_write(
            "INSERT INTO ephemeral_sessions (id, parent_session_id, retention_mode, created_at, purged) VALUES (?, ?, ?, ?, 0)",
            (ephemeral_id, session_id, retention_mode, created_at.isoformat()),
        )

        logger.info(
            "ephemeral_session_created",
            extra={
                "ephemeral_id": ephemeral_id,
                "session_id": session_id,
                "retention_mode": retention_mode,
            },
        )

        return {
            "ephemeral_id": ephemeral_id,
            "session_id": session_id,
            "retention_mode": retention_mode,
            "created_at": created_at.isoformat(),
        }

    def finalize_and_purge(ephemeral_id: str) -> dict[str, Any]:
        purged_at = datetime.now(timezone.utc)

        # Remove any ephemeral files written during the session
        ephemeral_dir = paths.data / "ephemeral" / ephemeral_id
        files_removed: list[str] = []
        if ephemeral_dir.exists():
            for f in ephemeral_dir.rglob("*"):
                if f.is_file():
                    files_removed.append(str(f))
                    f.unlink()
            try:
                ephemeral_dir.rmdir()
            except OSError:
                pass

        _db.execute_write(
            "UPDATE ephemeral_sessions SET purged = 1, purged_at = ? WHERE id = ?",
            (purged_at.isoformat(), ephemeral_id),
        )

        logger.info(
            "ephemeral_session_purged",
            extra={
                "ephemeral_id": ephemeral_id,
                "files_removed": len(files_removed),
                "purged_at": purged_at.isoformat(),
            },
        )

        return {
            "ephemeral_id": ephemeral_id,
            "purged_at": purged_at.isoformat(),
            "files_removed": files_removed,
        }

    return {
        "create_ephemeral_session": create_ephemeral_session,
        "finalize_and_purge": finalize_and_purge,
    }
