from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.database import get_database
from lib.license_guard import require_feature
from lib.paths import paths

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    detail      TEXT,
    occurred_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON audit_events (actor);
CREATE INDEX IF NOT EXISTS audit_events_action_idx ON audit_events (action);
CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx ON audit_events (occurred_at);
"""

_db = get_database("audit_trail", schema=_DDL)


def create_module(
    actor: str,
    action: str,
    resource: str,
    detail: dict[str, Any] | None,
) -> dict[str, Any]:
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
        detail_json = json.dumps(effective_detail) if effective_detail is not None else None

        _db.execute_write(
            """
            INSERT INTO audit_events (actor, action, resource, detail, occurred_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (effective_actor, effective_action, effective_resource, detail_json, occurred_at.isoformat()),
        )

        # Retrieve the inserted row to get the id
        row = _db.execute_one(
            "SELECT id FROM audit_events WHERE actor = ? AND action = ? AND occurred_at = ? ORDER BY id DESC LIMIT 1",
            (effective_actor, effective_action, occurred_at.isoformat()),
        )
        event_id: int = row["id"] if row else -1

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
        conditions: list[str] = []
        params: list[Any] = []

        if filter_actor is not None:
            conditions.append("actor = ?")
            params.append(filter_actor)
        if filter_action is not None:
            conditions.append("action = ?")
            params.append(filter_action)
        if filter_resource is not None:
            conditions.append("resource = ?")
            params.append(filter_resource)
        if since is not None:
            conditions.append("occurred_at >= ?")
            params.append(since.isoformat())
        if until is not None:
            conditions.append("occurred_at <= ?")
            params.append(until.isoformat())

        where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = f"SELECT id, actor, action, resource, detail, occurred_at FROM audit_events{where_clause} ORDER BY occurred_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = _db.execute(sql, params)

        return [
            {
                "event_id": row["id"],
                "actor": row["actor"],
                "action": row["action"],
                "resource": row["resource"],
                "detail": json.loads(row["detail"]) if row["detail"] else None,
                "occurred_at": row["occurred_at"],
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
        if output_path is None:
            exports_dir = paths.data / "audit_exports"
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
