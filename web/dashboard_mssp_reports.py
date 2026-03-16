from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_mssp_reports(
    output_dir: Path | None = None,
    tenant_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Generate MSSP (Managed Security Service Provider) reports.

    Args:
        output_dir: Directory to write report files. Defaults to paths-v1 reports dir.
        tenant_ids: Optional list of tenant IDs to filter reports. None means all tenants.

    Returns:
        A dict with keys: success (bool), reports (list of report metadata dicts),
        output_dir (str path), errors (list of str).
    """
    from lib.paths import get_paths

    paths = get_paths()
    resolved_output_dir: Path = output_dir if output_dir is not None else paths.reports
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    reports: list[dict[str, Any]] = []
    errors: list[str] = []

    tenants_to_process: list[str] = tenant_ids if tenant_ids is not None else _discover_tenants(paths)

    for tenant_id in tenants_to_process:
        if not tenant_id or not isinstance(tenant_id, str):
            errors.append(f"Invalid tenant_id: {tenant_id!r}")
            continue
        try:
            report_meta = _generate_tenant_report(tenant_id, resolved_output_dir, paths)
            reports.append(report_meta)
        except Exception as exc:
            msg = f"Failed to generate report for tenant {tenant_id!r}: {exc}"
            logger.error(msg)
            errors.append(msg)

    return {
        "success": len(errors) == 0,
        "reports": reports,
        "output_dir": str(resolved_output_dir),
        "errors": errors,
    }


def _discover_tenants(paths: Any) -> list[str]:
    """Discover tenant IDs from the data directory."""
    tenants_dir: Path = paths.data / "tenants"
    if not tenants_dir.exists():
        logger.warning("Tenants directory does not exist: %s", tenants_dir)
        return []
    return [entry.name for entry in sorted(tenants_dir.iterdir()) if entry.is_dir() and not entry.name.startswith(".")]


def _generate_tenant_report(
    tenant_id: str,
    output_dir: Path,
    paths: Any,
) -> dict[str, Any]:
    """Generate a single MSSP report for one tenant.

    Args:
        tenant_id: The tenant identifier.
        output_dir: Directory to write the report file.
        paths: The resolved paths-v1 object.

    Returns:
        Report metadata dict with keys: tenant_id, report_file, status.
    """
    import json
    import datetime

    tenant_data_dir: Path = paths.data / "tenants" / tenant_id
    report_file: Path = output_dir / f"mssp_report_{tenant_id}.json"

    summary: dict[str, Any] = {
        "tenant_id": tenant_id,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "findings": [],
        "risk_score": None,
        "status": "ok",
    }

    findings_file: Path = tenant_data_dir / "findings.json"
    if findings_file.exists():
        raw = findings_file.read_text(encoding="utf-8")
        findings_data: Any = json.loads(raw)
        if isinstance(findings_data, list):
            summary["findings"] = findings_data
        elif isinstance(findings_data, dict) and "findings" in findings_data:
            summary["findings"] = findings_data["findings"]

    findings_list: list[Any] = summary["findings"]  # type: ignore[assignment]
    if isinstance(findings_list, list) and findings_list:
        severities: list[float] = []
        for f in findings_list:
            if isinstance(f, dict) and "severity" in f:
                try:
                    severities.append(float(f["severity"]))
                except (TypeError, ValueError):
                    pass
        if severities:
            summary["risk_score"] = round(sum(severities) / len(severities), 2)

    report_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("Report written: %s", report_file)

    return {
        "tenant_id": tenant_id,
        "report_file": str(report_file),
        "status": summary["status"],
    }
