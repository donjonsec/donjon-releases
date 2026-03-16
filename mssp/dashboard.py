from __future__ import annotations

import logging
from typing import Any

from lib.database import get_database

logger = logging.getLogger(__name__)

_db = get_database("mssp_dashboard")


def get_client_summary(client_id: str | None) -> dict[str, Any]:
    if not client_id:
        return {
            "client_id": None,
            "status": "no_client",
            "license": None,
            "isolation": None,
            "resources": [],
        }

    row = _db.execute_one(
        """
        SELECT
            c.client_id,
            c.name,
            c.status,
            c.created_at,
            l.tier,
            l.expires_at,
            l.features,
            i.namespace,
            i.network_policy,
            i.storage_quota_gb
        FROM clients c
        LEFT JOIN client_licenses l ON l.client_id = c.client_id
        LEFT JOIN client_isolation i ON i.client_id = c.client_id
        WHERE c.client_id = ?
        """,
        (client_id,),
    )

    if row is None:
        return {
            "client_id": client_id,
            "status": "not_found",
            "license": None,
            "isolation": None,
            "resources": [],
        }

    resource_rows = _db.execute(
        """
        SELECT resource_type, resource_name, resource_status
        FROM client_resources
        WHERE client_id = ?
        ORDER BY resource_type, resource_name
        """,
        (client_id,),
    )
    resources = [
        {
            "type": r["resource_type"],
            "name": r["resource_name"],
            "status": r["resource_status"],
        }
        for r in resource_rows
    ]

    return {
        "client_id": row["client_id"],
        "name": row["name"],
        "status": row["status"],
        "created_at": row["created_at"],
        "license": {
            "tier": row["tier"],
            "expires_at": row["expires_at"],
            "features": row["features"] or [],
        }
        if row["tier"] is not None
        else None,
        "isolation": {
            "namespace": row["namespace"],
            "network_policy": row["network_policy"],
            "storage_quota_gb": row["storage_quota_gb"],
        }
        if row["namespace"] is not None
        else None,
        "resources": resources,
    }


def get_portfolio_overview(client_id: str | None) -> dict[str, Any]:
    if client_id:
        rows = _db.execute(
            """
            SELECT
                c.client_id,
                c.name,
                c.status,
                l.tier,
                l.expires_at,
                COUNT(r.resource_id) AS resource_count
            FROM clients c
            LEFT JOIN client_licenses l ON l.client_id = c.client_id
            LEFT JOIN client_resources r ON r.client_id = c.client_id
            WHERE c.client_id = ?
            GROUP BY c.client_id, c.name, c.status, l.tier, l.expires_at
            """,
            (client_id,),
        )
    else:
        rows = _db.execute(
            """
            SELECT
                c.client_id,
                c.name,
                c.status,
                l.tier,
                l.expires_at,
                COUNT(r.resource_id) AS resource_count
            FROM clients c
            LEFT JOIN client_licenses l ON l.client_id = c.client_id
            LEFT JOIN client_resources r ON r.client_id = c.client_id
            GROUP BY c.client_id, c.name, c.status, l.tier, l.expires_at
            ORDER BY c.name
            """
        )

    clients: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    tier_counts: dict[str, int] = {}

    for row in rows:
        clients.append(
            {
                "client_id": row["client_id"],
                "name": row["name"],
                "status": row["status"],
                "tier": row["tier"],
                "expires_at": row["expires_at"],
                "resource_count": int(row["resource_count"]) if row["resource_count"] is not None else 0,
            }
        )
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
        if row["tier"]:
            tier_counts[row["tier"]] = tier_counts.get(row["tier"], 0) + 1

    return {
        "total_clients": len(clients),
        "clients": clients,
        "status_breakdown": status_counts,
        "tier_breakdown": tier_counts,
        "filtered_by_client": client_id,
    }


__all__ = ["get_client_summary", "get_portfolio_overview"]
