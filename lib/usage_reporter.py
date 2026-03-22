"""
Donjon Platform - Usage Telemetry Reporter

Tracks scanner usage and client counts for billing verification (MSSP/managed tier).

Privacy constraints:
- Telemetry is OFF by default
- Only enabled with explicit env var DONJON_TELEMETRY=1
- Only reports to license server for managed tier
- Never sends finding details, target IPs, or customer data
- Only counts: scans performed, scanners used, findings by severity, client count
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("donjon.usage_reporter")

# ---------------------------------------------------------------------------
# UsageReporter
# ---------------------------------------------------------------------------


class UsageReporter:
    """Collects anonymised usage stats and optionally reports to the license server.

    Usage data is always written to ``data/usage_report.json`` for local audit.
    Remote telemetry is opt-in only (DONJON_TELEMETRY=1 + managed tier).
    """

    def __init__(self) -> None:
        try:
            from paths import paths
        except ImportError:
            from lib.paths import paths

        self._data_dir: Path = paths.data
        self._report_path: Path = self._data_dir / "usage_report.json"
        self._report: Dict[str, Any] = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> Dict[str, Any]:
        """Load existing report from disk, or return a fresh skeleton."""
        if self._report_path.exists():
            try:
                with open(self._report_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    return data
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Corrupt usage report, starting fresh: %s", exc)
        return self._empty_report()

    def _save(self) -> None:
        """Persist the current report to disk."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._report["updated_at"] = datetime.now(timezone.utc).isoformat()
        tmp = self._report_path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._report, fh, indent=2, default=str)
            tmp.replace(self._report_path)
        except OSError as exc:
            logger.error("Failed to save usage report: %s", exc)
            if tmp.exists():
                tmp.unlink(missing_ok=True)

    @staticmethod
    def _empty_report() -> Dict[str, Any]:
        return {
            "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_scans": 0,
            "scanners_used": {},
            "findings_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
            "total_findings": 0,
            "client_count": 0,
        }

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_scan(
        self,
        scanner_name: str,
        finding_count: int = 0,
        findings_by_severity: Optional[Dict[str, int]] = None,
    ) -> None:
        """Record that a scan completed.

        Args:
            scanner_name: Identifier of the scanner (e.g. "network", "web").
            finding_count: Total number of findings produced.
            findings_by_severity: Optional breakdown ``{"HIGH": 3, ...}``.
        """
        self._report["total_scans"] = self._report.get("total_scans", 0) + 1

        scanners = self._report.setdefault("scanners_used", {})
        scanners[scanner_name] = scanners.get(scanner_name, 0) + 1

        self._report["total_findings"] = (
            self._report.get("total_findings", 0) + finding_count
        )

        if findings_by_severity:
            sev = self._report.setdefault("findings_by_severity", {})
            for level, count in findings_by_severity.items():
                key = level.upper()
                sev[key] = sev.get(key, 0) + count

        self._save()
        logger.info(
            "Recorded scan: scanner=%s findings=%d", scanner_name, finding_count
        )

    def update_client_count(self, count: int) -> None:
        """Update the MSSP client count."""
        self._report["client_count"] = count
        self._save()

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_report(self) -> Dict[str, Any]:
        """Return the current usage report (safe copy)."""
        return dict(self._report)

    def get_summary(self) -> str:
        """Return a human-readable one-liner for startup display."""
        r = self._report
        return (
            f"Usage: {r.get('total_scans', 0)} scans, "
            f"{r.get('total_findings', 0)} findings, "
            f"{len(r.get('scanners_used', {}))} scanner types, "
            f"{r.get('client_count', 0)} clients"
        )

    # ------------------------------------------------------------------
    # Remote telemetry (opt-in only)
    # ------------------------------------------------------------------

    def maybe_send_telemetry(self) -> bool:
        """Send anonymised summary to the license server if conditions are met.

        Conditions (ALL must be true):
        1. DONJON_TELEMETRY=1 environment variable is set
        2. License tier is "managed"

        Returns True if telemetry was sent, False otherwise.
        """
        if os.environ.get("DONJON_TELEMETRY") != "1":
            logger.debug("Telemetry disabled (DONJON_TELEMETRY not set)")
            return False

        # Check tier
        try:
            try:
                from licensing import get_license_manager
            except ImportError:
                from lib.licensing import get_license_manager
            lm = get_license_manager()
            tier = lm.get_tier()
        except Exception as exc:
            logger.debug("Cannot determine tier, skipping telemetry: %s", exc)
            return False

        if tier != "managed":
            logger.debug("Telemetry skipped: tier=%s (managed required)", tier)
            return False

        # Build anonymised payload — counts only, no PII
        payload = {
            "version": self._report.get("version", 1),
            "total_scans": self._report.get("total_scans", 0),
            "scanners_used": self._report.get("scanners_used", {}),
            "findings_by_severity": self._report.get("findings_by_severity", {}),
            "total_findings": self._report.get("total_findings", 0),
            "client_count": self._report.get("client_count", 0),
            "reported_at": datetime.now(timezone.utc).isoformat(),
        }

        # Resolve license server URL from config
        try:
            try:
                from config import get_config
            except ImportError:
                from lib.config import get_config
            cfg = get_config()
            server_url = cfg.get_value("license_server_url", "")
        except Exception:
            server_url = ""

        if not server_url:
            server_url = os.environ.get("DONJON_LICENSE_SERVER", "")

        if not server_url:
            logger.warning("Telemetry enabled but no license server URL configured")
            return False

        url = server_url.rstrip("/") + "/api/v1/telemetry/usage"

        try:
            import urllib.request

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status < 300:
                    logger.info("Telemetry sent successfully to %s", url)
                    return True
                else:
                    logger.warning("Telemetry POST returned %d", resp.status)
                    return False
        except Exception as exc:
            logger.warning("Telemetry send failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Reset (for testing)
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset usage data to an empty report. For testing only."""
        self._report = self._empty_report()
        self._save()


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: Optional[UsageReporter] = None


def get_usage_reporter() -> UsageReporter:
    """Return the module-level UsageReporter singleton."""
    global _instance
    if _instance is None:
        _instance = UsageReporter()
    return _instance
