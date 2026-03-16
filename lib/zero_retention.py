from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pathlib import Path

logger = logging.getLogger(__name__)


def create_module(
    session_id: str,
    retention_mode: str,
) -> dict[str, Any]:
    from lib.database import get_engine, get_session
    from lib.paths import get_data_dir
    from lib.license_guard import require_feature

    require_feature("zero-retention")

    def create_ephemeral_session() -> dict[str, Any]:
        import sqlalchemy as sa

        engine = get_engine()
        ephemeral_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)

        with get_session(engine) as db:
            db.execute(
                sa.insert(sa.table(
                    "ephemeral_sessions",
                    sa.column("id"),
                    sa.column("parent_session_id"),
                    sa.column("retention_mode"),
                    sa.column("created_at"),
                    sa.column("purged"),
                )).values(
                    id=ephemeral_id,
                    parent_session_id=session_id,
                    retention_mode=retention_mode,
                    created_at=created_at,
                    purged=False,
                )
            )
            db.commit()

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
        import sqlalchemy as sa

        engine = get_engine()
        purged_at = datetime.now(timezone.utc)
        data_dir = get_data_dir()

        # Remove any ephemeral files written during the session
        ephemeral_dir = Path(data_dir) / "ephemeral" / ephemeral_id
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

        with get_session(engine) as db:
            db.execute(
                sa.update(sa.table(
                    "ephemeral_sessions",
                    sa.column("id"),
                    sa.column("purged"),
                    sa.column("purged_at"),
                )).where(
                    sa.column("id") == ephemeral_id
                ).values(
                    purged=True,
                    purged_at=purged_at,
                )
            )
            db.commit()

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
