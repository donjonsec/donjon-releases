from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def compare_clients(
    client_ids: list[str],
    comparison_type: str,
    *,
    db: Any,
    provisioning: Any,
    isolation: Any,
    license_guard: Any,
) -> dict[str, Any]:
    if not client_ids:
        raise ValueError("client_ids must not be empty")
    if not comparison_type:
        raise ValueError("comparison_type must not be empty")

    license_guard.require_feature("cross-client-reporting")

    clients: list[dict[str, Any]] = []
    for client_id in client_ids:
        isolation.assert_access(client_id)
        client = provisioning.get_client(client_id)
        clients.append(client)

    rows = db.query(
        """
        SELECT client_id, metric_key, metric_value, recorded_at
        FROM client_metrics
        WHERE client_id = ANY(%(client_ids)s)
        ORDER BY client_id, metric_key, recorded_at DESC
        """,
        {"client_ids": client_ids},
    )

    metrics_by_client: dict[str, dict[str, Any]] = {cid: {} for cid in client_ids}
    for row in rows:
        cid = row["client_id"]
        key = row["metric_key"]
        if key not in metrics_by_client[cid]:
            metrics_by_client[cid][key] = row["metric_value"]

    result: dict[str, Any] = {
        "comparison_type": comparison_type,
        "clients": clients,
        "metrics": metrics_by_client,
    }

    if comparison_type == "delta":
        if len(client_ids) < 2:
            raise ValueError("delta comparison requires at least 2 clients")
        base = metrics_by_client[client_ids[0]]
        deltas: dict[str, dict[str, Any]] = {}
        for other_id in client_ids[1:]:
            other = metrics_by_client[other_id]
            all_keys = set(base) | set(other)
            deltas[other_id] = {}
            for k in all_keys:
                base_val = base.get(k)
                other_val = other.get(k)
                if isinstance(base_val, (int, float)) and isinstance(other_val, (int, float)):
                    deltas[other_id][k] = other_val - base_val
                else:
                    deltas[other_id][k] = {"base": base_val, "other": other_val}
        result["deltas"] = deltas

    logger.info(
        "compare_clients: comparison_type=%s clients=%s",
        comparison_type,
        client_ids,
    )
    return result


def benchmark_client(
    client_id: str,
    comparison_type: str,
    *,
    db: Any,
    provisioning: Any,
    isolation: Any,
    license_guard: Any,
) -> dict[str, Any]:
    if not client_id:
        raise ValueError("client_id must not be empty")
    if not comparison_type:
        raise ValueError("comparison_type must not be empty")

    license_guard.require_feature("cross-client-reporting")
    isolation.assert_access(client_id)

    client = provisioning.get_client(client_id)

    client_rows = db.query(
        """
        SELECT metric_key, metric_value
        FROM client_metrics
        WHERE client_id = %(client_id)s
        ORDER BY metric_key, recorded_at DESC
        """,
        {"client_id": client_id},
    )

    client_metrics: dict[str, Any] = {}
    for row in client_rows:
        key = row["metric_key"]
        if key not in client_metrics:
            client_metrics[key] = row["metric_value"]

    aggregate_rows = db.query(
        """
        SELECT
            metric_key,
            AVG(metric_value::numeric) AS mean,
            PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY metric_value::numeric) AS median,
            MIN(metric_value::numeric) AS min,
            MAX(metric_value::numeric) AS max,
            COUNT(DISTINCT client_id) AS sample_size
        FROM client_metrics
        WHERE recorded_at >= NOW() - INTERVAL '30 days'
        GROUP BY metric_key
        """,
        {},
    )

    benchmarks: dict[str, dict[str, Any]] = {}
    for row in aggregate_rows:
        key = row["metric_key"]
        benchmarks[key] = {
            "mean": float(row["mean"]) if row["mean"] is not None else None,
            "median": float(row["median"]) if row["median"] is not None else None,
            "min": float(row["min"]) if row["min"] is not None else None,
            "max": float(row["max"]) if row["max"] is not None else None,
            "sample_size": int(row["sample_size"]),
        }

    scores: dict[str, Any] = {}
    for key, client_val in client_metrics.items():
        if key not in benchmarks:
            continue
        bm = benchmarks[key]
        if not isinstance(client_val, (int, float)) or bm["mean"] is None:
            continue
        mean = bm["mean"]
        client_float = float(client_val)
        if mean != 0:
            scores[key] = {
                "client_value": client_float,
                "benchmark_mean": mean,
                "pct_vs_mean": round((client_float - mean) / mean * 100, 2),
            }
        else:
            scores[key] = {
                "client_value": client_float,
                "benchmark_mean": mean,
                "pct_vs_mean": None,
            }

    logger.info(
        "benchmark_client: client_id=%s comparison_type=%s",
        client_id,
        comparison_type,
    )
    return {
        "comparison_type": comparison_type,
        "client": client,
        "client_metrics": client_metrics,
        "benchmarks": benchmarks,
        "scores": scores,
    }


def build(
    db: Any,
    provisioning: Any,
    isolation: Any,
    license_guard: Any,
) -> dict[str, Any]:
    def _compare_clients(
        client_ids: list[str],
        comparison_type: str,
    ) -> dict[str, Any]:
        return compare_clients(
            client_ids,
            comparison_type,
            db=db,
            provisioning=provisioning,
            isolation=isolation,
            license_guard=license_guard,
        )

    def _benchmark_client(
        client_id: str,
        comparison_type: str,
    ) -> dict[str, Any]:
        return benchmark_client(
            client_id,
            comparison_type,
            db=db,
            provisioning=provisioning,
            isolation=isolation,
            license_guard=license_guard,
        )

    return {
        "compare_clients": _compare_clients,
        "benchmark_client": _benchmark_client,
    }
