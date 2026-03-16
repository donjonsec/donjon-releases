from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_risk() -> dict[str, Any]:
    """Generate risk dashboard data by reading risk-related paths and aggregating findings."""
    from lib.paths import get_paths

    p = get_paths()

    risk_data: dict[str, Any] = {
        "findings": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "sources": [],
    }

    # Check evidence directory for findings
    findings_dir: Path = p.evidence
    if findings_dir.exists():
        for findings_file in sorted(findings_dir.glob("*.json")):
            try:
                raw = findings_file.read_text(encoding="utf-8")
                data = json.loads(raw)
                items: list[dict[str, Any]] = data if isinstance(data, list) else data.get("findings", [])
                for item in items:
                    severity = str(item.get("severity", "low")).lower()
                    if severity in risk_data["summary"]:
                        risk_data["summary"][severity] += 1
                    risk_data["findings"].append(item)
                risk_data["sources"].append(str(findings_file))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not load findings from %s: %s", findings_file, exc)

    # Check reports directory
    reports_dir: Path = p.reports
    if reports_dir.exists():
        for report_file in sorted(reports_dir.glob("*.json")):
            try:
                raw = report_file.read_text(encoding="utf-8")
                report = json.loads(raw)
                for item in report if isinstance(report, list) else report.get("findings", []):
                    severity = str(item.get("severity", "low")).lower()
                    if severity in risk_data["summary"]:
                        risk_data["summary"][severity] += 1
                    risk_data["findings"].append(item)
                risk_data["sources"].append(str(report_file))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not load report %s: %s", report_file, exc)

    total = sum(risk_data["summary"].values())
    risk_data["total"] = total

    return risk_data
