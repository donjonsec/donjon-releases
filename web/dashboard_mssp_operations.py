from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_mssp_operations(output_dir: Path | None = None) -> dict[str, Any]:
    """Generate MSSP operations dashboard content."""
    from lib.paths import get_paths

    paths = get_paths()
    base_dir = output_dir or (paths.home / "web")

    dashboard: dict[str, Any] = {
        "title": "MSSP Operations Dashboard",
        "sections": [
            {
                "id": "tenant-overview",
                "label": "Tenant Overview",
                "metrics": [
                    {"key": "active_tenants", "label": "Active Tenants"},
                    {"key": "total_agents", "label": "Total Agents"},
                    {"key": "pipeline_runs_24h", "label": "Pipeline Runs (24h)"},
                ],
            },
            {
                "id": "health-status",
                "label": "Health & Alerts",
                "metrics": [
                    {"key": "critical_alerts", "label": "Critical Alerts"},
                    {"key": "degraded_tenants", "label": "Degraded Tenants"},
                    {"key": "sla_breaches", "label": "SLA Breaches"},
                ],
            },
            {
                "id": "capacity",
                "label": "Capacity",
                "metrics": [
                    {"key": "cpu_utilization", "label": "CPU Utilization (%)"},
                    {"key": "memory_utilization", "label": "Memory Utilization (%)"},
                    {"key": "queue_depth", "label": "Queue Depth"},
                ],
            },
            {
                "id": "billing",
                "label": "Billing & Licensing",
                "metrics": [
                    {"key": "licensed_seats", "label": "Licensed Seats"},
                    {"key": "consumed_seats", "label": "Consumed Seats"},
                    {"key": "overage_tenants", "label": "Tenants in Overage"},
                ],
            },
        ],
        "refresh_interval_seconds": 30,
        "base_dir": str(base_dir),
    }

    logger.info("Generated MSSP operations dashboard with %d sections", len(dashboard["sections"]))
    return dashboard


__all__ = ["generate_mssp_operations"]
