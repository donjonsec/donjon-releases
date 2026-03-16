from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from lib.database import get_database
from lib.license_guard import require_feature

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS usage_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   TEXT    NOT NULL,
    feature     TEXT    NOT NULL,
    quantity    REAL    NOT NULL,
    unit        TEXT    NOT NULL DEFAULT 'count',
    metadata    TEXT,
    recorded_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_records_client_idx ON usage_records (client_id);
CREATE INDEX IF NOT EXISTS usage_records_recorded_at_idx ON usage_records (recorded_at);
"""

_db = get_database("mssp_metering", schema=_DDL)


def create_metering(client_id: str) -> dict[str, Any]:
    if not client_id:
        raise ValueError("client_id must be non-empty")

    def record_usage(
        feature: str,
        quantity: float,
        unit: str = "count",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        import json

        now = datetime.now(timezone.utc)
        require_feature(feature)
        metadata_json = json.dumps(metadata) if metadata else None
        _db.execute_write(
            """
            INSERT INTO usage_records
                (client_id, feature, quantity, unit, metadata, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (client_id, feature, quantity, unit, metadata_json, now.isoformat()),
        )
        logger.info("Recorded usage: client=%s feature=%s quantity=%s", client_id, feature, quantity)

    def get_usage_report(
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        if start is None:
            start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
        if end is None:
            end = now
        rows = _db.execute(
            """
            SELECT feature, unit, SUM(quantity) AS total_quantity,
                   COUNT(*) AS event_count, MIN(recorded_at) AS first_at, MAX(recorded_at) AS last_at
            FROM usage_records
            WHERE client_id = ? AND recorded_at >= ? AND recorded_at <= ?
            GROUP BY feature, unit
            ORDER BY feature
            """,
            (client_id, start.isoformat(), end.isoformat()),
        )
        return [
            {
                "feature": row["feature"],
                "unit": row["unit"],
                "total_quantity": float(row["total_quantity"]),
                "event_count": int(row["event_count"]),
                "period_start": start.isoformat(),
                "period_end": end.isoformat(),
                "first_recorded_at": row["first_at"],
                "last_recorded_at": row["last_at"],
            }
            for row in rows
        ]

    def export_billing_data(
        period_start: datetime | None = None,
        period_end: datetime | None = None,
        format: str = "json",
    ) -> dict[str, Any]:
        report = get_usage_report(period_start, period_end)
        now = datetime.now(timezone.utc)
        if period_start is None:
            period_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
        if period_end is None:
            period_end = now
        billing: dict[str, Any] = {
            "client_id": client_id,
            "export_format": format,
            "exported_at": now.isoformat(),
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "line_items": report,
            "total_events": sum(item["event_count"] for item in report),
        }
        logger.info(
            "Exported billing data: client=%s period=%s/%s items=%d",
            client_id,
            period_start.date(),
            period_end.date(),
            len(report),
        )
        return billing

    return {
        "record_usage": record_usage,
        "get_usage_report": get_usage_report,
        "export_billing_data": export_billing_data,
    }
