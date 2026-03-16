from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from darkfactory.db import get_db
from mssp.provisioning import get_client
from mssp.licensing import check_license

logger = logging.getLogger(__name__)


def create_metering(client_id: str) -> dict[str, Any]:
    client = get_client(client_id)
    if client is None:
        raise ValueError(f"Client not found: {client_id}")

    def record_usage(
        feature: str,
        quantity: float,
        unit: str = "count",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        db = get_db()
        now = datetime.now(timezone.utc)
        check_license(client_id, feature)
        db.execute(
            """
            INSERT INTO usage_records
                (client_id, feature, quantity, unit, metadata, recorded_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (client_id, feature, quantity, unit, metadata or {}, now),
        )
        logger.info("Recorded usage: client=%s feature=%s quantity=%s", client_id, feature, quantity)

    def get_usage_report(
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        db = get_db()
        now = datetime.now(timezone.utc)
        if start is None:
            start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
        if end is None:
            end = now
        rows = db.fetchall(
            """
            SELECT feature, unit, SUM(quantity) AS total_quantity,
                   COUNT(*) AS event_count, MIN(recorded_at) AS first_at, MAX(recorded_at) AS last_at
            FROM usage_records
            WHERE client_id = %s AND recorded_at >= %s AND recorded_at <= %s
            GROUP BY feature, unit
            ORDER BY feature
            """,
            (client_id, start, end),
        )
        return [
            {
                "feature": row["feature"],
                "unit": row["unit"],
                "total_quantity": float(row["total_quantity"]),
                "event_count": int(row["event_count"]),
                "period_start": start.isoformat(),
                "period_end": end.isoformat(),
                "first_recorded_at": row["first_at"].isoformat() if row["first_at"] else None,
                "last_recorded_at": row["last_at"].isoformat() if row["last_at"] else None,
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
            "client_name": client.get("name", client_id),
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
