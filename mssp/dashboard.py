from __future__ import annotations

import logging
from typing import Any

from darkfactory.db import get_db_connection

logger = logging.getLogger(__name__)


def get_client_summary(client_id: str | None) -> dict[str, Any]:
    if not client_id:
        return {
            "client_id": None,
            "status": "no_client",
            "license": None,
            "isolation": None,
            "resources": [],
        }

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
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
                WHERE c.client_id = %s
                """,
                (client_id,),
            )
            row = cur.fetchone()

    if row is None:
        return {
            "client_id": client_id,
            "status": "not_found",
            "license": None,
            "isolation": None,
            "resources": [],
        }

    (
        cid,
        name,
        status,
        created_at,
        tier,
        expires_at,
        features,
        namespace,
        network_policy,
        storage_quota_gb,
    ) = row

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT resource_type, resource_name, resource_status
                FROM client_resources
                WHERE client_id = %s
                ORDER BY resource_type, resource_name
                """,
                (client_id,),
            )
            resources = [
                {
                    "type": r[0],
                    "name": r[1],
                    "status": r[2],
                }
                for r in cur.fetchall()
            ]

    return {
        "client_id": cid,
        "name": name,
        "status": status,
        "created_at": created_at.isoformat() if created_at is not None else None,
        "license": {
            "tier": tier,
            "expires_at": expires_at.isoformat() if expires_at is not None else None,
            "features": features or [],
        }
        if tier is not None
        else None,
        "isolation": {
            "namespace": namespace,
            "network_policy": network_policy,
            "storage_quota_gb": storage_quota_gb,
        }
        if namespace is not None
        else None,
        "resources": resources,
    }


def get_portfolio_overview(client_id: str | None) -> dict[str, Any]:
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            if client_id:
                cur.execute(
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
                    WHERE c.client_id = %s
                    GROUP BY c.client_id, c.name, c.status, l.tier, l.expires_at
                    """,
                    (client_id,),
                )
            else:
                cur.execute(
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
            rows = cur.fetchall()

    clients: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    tier_counts: dict[str, int] = {}

    for row in rows:
        cid, name, status, tier, expires_at, resource_count = row
        clients.append(
            {
                "client_id": cid,
                "name": name,
                "status": status,
                "tier": tier,
                "expires_at": expires_at.isoformat() if expires_at is not None else None,
                "resource_count": int(resource_count) if resource_count is not None else 0,
            }
        )
        status_counts[status] = status_counts.get(status, 0) + 1
        if tier:
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

    return {
        "total_clients": len(clients),
        "clients": clients,
        "status_breakdown": status_counts,
        "tier_breakdown": tier_counts,
        "filtered_by_client": client_id,
    }


__all__ = ["get_client_summary", "get_portfolio_overview"]
