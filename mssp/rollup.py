from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


def generate_rollup(
    client_ids: list[str] | None,
    report_type: str,
    *,
    db: Any,
    provisioning: Any,
    isolation: Any,
    license_guard: Any,
) -> dict[str, Any]:
    if not report_type:
        raise ValueError("report_type must be a non-empty string")

    # Resolve client list
    if client_ids is None:
        all_clients = provisioning.list_clients()
        resolved_ids: list[str] = [c["client_id"] for c in all_clients]
    else:
        if not isinstance(client_ids, list):
            raise TypeError("client_ids must be a list or None")
        resolved_ids = client_ids

    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for cid in resolved_ids:
        try:
            # Verify isolation boundary
            isolation.verify_client(cid)
            # Verify license allows reporting
            license_guard.check_feature(cid, "reporting")
            # Query per-client data
            rows = db.query(
                "SELECT metric_key, metric_value, recorded_at FROM client_metrics WHERE client_id = %s AND report_type = %s",
                (cid, report_type),
            )
            results.append(
                {
                    "client_id": cid,
                    "report_type": report_type,
                    "metrics": rows,
                    "generated_at": datetime.utcnow().isoformat(),
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping client %s in rollup: %s", cid, exc)
            errors.append({"client_id": cid, "error": str(exc)})

    return {
        "report_type": report_type,
        "client_count": len(results),
        "results": results,
        "errors": errors,
        "generated_at": datetime.utcnow().isoformat(),
    }


def get_trend_data(
    client_ids: list[str] | None,
    report_type: str,
    *,
    db: Any,
    provisioning: Any,
    isolation: Any,
    license_guard: Any,
    days: int = 30,
) -> dict[str, Any]:
    if not report_type:
        raise ValueError("report_type must be a non-empty string")
    if days < 1:
        raise ValueError("days must be a positive integer")

    if client_ids is None:
        all_clients = provisioning.list_clients()
        resolved_ids: list[str] = [c["client_id"] for c in all_clients]
    else:
        if not isinstance(client_ids, list):
            raise TypeError("client_ids must be a list or None")
        resolved_ids = client_ids

    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    trends: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for cid in resolved_ids:
        try:
            isolation.verify_client(cid)
            license_guard.check_feature(cid, "reporting")
            rows = db.query(
                "SELECT metric_key, metric_value, recorded_at FROM client_metrics WHERE client_id = %s AND report_type = %s AND recorded_at >= %s ORDER BY recorded_at ASC",
                (cid, report_type, since),
            )
            # Group by metric_key for trend series
            series: dict[str, list[dict[str, Any]]] = {}
            for row in rows:
                key = row["metric_key"]
                if key not in series:
                    series[key] = []
                series[key].append({"value": row["metric_value"], "timestamp": row["recorded_at"]})
            trends.append(
                {
                    "client_id": cid,
                    "report_type": report_type,
                    "period_days": days,
                    "series": series,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping client %s in trend data: %s", cid, exc)
            errors.append({"client_id": cid, "error": str(exc)})

    return {
        "report_type": report_type,
        "period_days": days,
        "since": since,
        "client_count": len(trends),
        "trends": trends,
        "errors": errors,
        "generated_at": datetime.utcnow().isoformat(),
    }
