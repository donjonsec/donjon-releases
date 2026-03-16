from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sqlalchemy as sa

logger = logging.getLogger(__name__)

_AUDIT_TABLE = sa.table(
    "audit_events",
    sa.column("id", sa.Integer),
    sa.column("actor", sa.String),
    sa.column("action", sa.String),
    sa.column("resource", sa.String),
    sa.column("detail", sa.JSON),
    sa.column("occurred_at", sa.DateTime(timezone=True)),
)


def create_module(
    actor: str,
    action: str,
    resource: str,
    detail: dict[str, Any] | None,
) -> dict[str, Any]:
    from lib.database import get_engine, get_session
    from lib.paths import get_data_dir
    from lib.license_guard import require_feature

    require_feature("audit-trail")

    def log_event(
        override_actor: str | None = None,
        override_action: str | None = None,
        override_resource: str | None = None,
        override_detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        effective_actor = override_actor if override_actor is not None else actor
        effective_action = override_action if override_action is not None else action
        effective_resource = override_resource if override_resource is not None else resource
        effective_detail = override_detail if override_detail is not None else detail

        if not effective_actor:
            raise ValueError("actor must not be empty")
        if not effective_action:
            raise ValueError("action must not be empty")
        if not effective_resource:
            raise ValueError("resource must not be empty")

        occurred_at = datetime.now(timezone.utc)
        engine = get_engine()

        with get_session(engine) as db:
            result = db.execute(
                sa.insert(_AUDIT_TABLE).values(
                    actor=effective_actor,
                    action=effective_action,
                    resource=effective_resource,
                    detail=effective_detail,
                    occurred_at=occurred_at,
                ).returning(sa.column("id"))
            )
            row = result.fetchone()
            db.commit()
            event_id: int = row[0] if row is not None else -1

        logger.info(
            "audit_event_logged",
            extra={
                "event_id": event_id,
                "actor": effective_actor,
                "action": effective_action,
                "resource": effective_resource,
            },
        )

        return {
            "event_id": event_id,
            "actor": effective_actor,
            "action": effective_action,
            "resource": effective_resource,
            "detail": effective_detail,
            "occurred_at": occurred_at.isoformat(),
        }

    def query_events(
        filter_actor: str | None = None,
        filter_action: str | None = None,
        filter_resource: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        engine = get_engine()

        stmt = sa.select(_AUDIT_TABLE).order_by(
            sa.column("occurred_at").desc()
        )

        if filter_actor is not None:
            stmt = stmt.where(sa.column("actor") == filter_actor)
        if filter_action is not None:
            stmt = stmt.where(sa.column("action") == filter_action)
        if filter_resource is not None:
            stmt = stmt.where(sa.column("resource") == filter_resource)
        if since is not None:
            stmt = stmt.where(sa.column("occurred_at") >= since)
        if until is not None:
            stmt = stmt.where(sa.column("occurred_at") <= until)

        stmt = stmt.limit(limit).offset(offset)

        with get_session(engine) as db:
            rows = db.execute(stmt).fetchall()

        return [
            {
                "event_id": row[0],
                "actor": row[1],
                "action": row[2],
                "resource": row[3],
                "detail": row[4],
                "occurred_at": row[5].isoformat() if isinstance(row[5], datetime) else str(row[5]),
            }
            for row in rows
        ]

    def export_audit_log(
        output_path: Path | None = None,
        filter_actor: str | None = None,
        filter_action: str | None = None,
        filter_resource: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> Path:
        import csv
        import io

        if output_path is None:
            data_dir = Path(get_data_dir())
            exports_dir = data_dir / "audit_exports"
            exports_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            output_path = exports_dir / f"audit_{ts}.csv"

        events = query_events(
            filter_actor=filter_actor,
            filter_action=filter_action,
            filter_resource=filter_resource,
            since=since,
            until=until,
            limit=100_000,
            offset=0,
        )

        fieldnames = ["event_id", "actor", "action", "resource", "detail", "occurred_at"]
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow({k: ev.get(k, "") for k in fieldnames})

        logger.info(
            "audit_log_exported",
            extra={"path": str(output_path), "event_count": len(events)},
        )

        return output_path

    return {
        "log_event": log_event,
        "query_events": query_events,
        "export_audit_log": export_audit_log,
    }
