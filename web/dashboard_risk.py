from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_risk() -> dict[str, Any]:
    """Generate risk dashboard data by reading risk-related paths and aggregating findings."""
    from paths import get_paths  # type: ignore[import]

    paths = get_paths()

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

    findings_path: Path | None = paths.get("findings")
    if findings_path is not None and Path(findings_path).exists():
        import json

        findings_file = Path(findings_path)
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

    reports_path: Path | None = paths.get("reports")
    if reports_path is not None and Path(reports_path).exists():
        import json

        reports_dir = Path(reports_path)
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
