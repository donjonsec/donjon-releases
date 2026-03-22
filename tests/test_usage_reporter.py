#!/usr/bin/env python3
"""
Test suite: Usage Reporter (telemetry for MSSP/managed tier billing verification).

Verifies:
- Recording scans writes to data/usage_report.json
- API endpoint returns the report
- Telemetry does NOT phone home when DONJON_TELEMETRY is not set
- Telemetry does NOT phone home when tier is not managed
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure project root is on the path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(_PROJECT_ROOT))


class TestUsageReporter(unittest.TestCase):
    """Test the UsageReporter module."""

    def setUp(self):
        """Create a temp dir and patch paths.data to use it."""
        self.tmpdir = tempfile.mkdtemp()
        self.tmppath = Path(self.tmpdir)

        # Patch the paths singleton so usage_reporter writes to our temp dir
        self.paths_patcher = patch('lib.usage_reporter.paths')

        # We need to handle the import carefully
        mock_paths_mod = MagicMock()
        mock_paths_mod.data = self.tmppath

        # Patch at module level in usage_reporter
        import lib.usage_reporter as ur_mod
        self._orig_instance = ur_mod._instance
        ur_mod._instance = None  # Reset singleton

        self.reporter = ur_mod.UsageReporter.__new__(ur_mod.UsageReporter)
        self.reporter._data_dir = self.tmppath
        self.reporter._report_path = self.tmppath / "usage_report.json"
        self.reporter._report = self.reporter._empty_report()

        self.ur_mod = ur_mod

    def tearDown(self):
        """Restore singleton and clean up."""
        self.ur_mod._instance = self._orig_instance
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_record_scan_creates_report_file(self):
        """Recording a scan must create usage_report.json on disk."""
        self.reporter.record_scan("network", finding_count=5)

        report_path = self.tmppath / "usage_report.json"
        self.assertTrue(report_path.exists(), "usage_report.json was not created")

        with open(report_path) as f:
            data = json.load(f)

        self.assertEqual(data["total_scans"], 1)
        self.assertEqual(data["total_findings"], 5)
        self.assertIn("network", data["scanners_used"])
        self.assertEqual(data["scanners_used"]["network"], 1)

    def test_record_multiple_scans_accumulates(self):
        """Multiple scan recordings accumulate correctly."""
        self.reporter.record_scan("network", finding_count=3, findings_by_severity={"HIGH": 2, "LOW": 1})
        self.reporter.record_scan("web", finding_count=7, findings_by_severity={"CRITICAL": 1, "MEDIUM": 4, "INFO": 2})
        self.reporter.record_scan("network", finding_count=1, findings_by_severity={"LOW": 1})

        report = self.reporter.get_report()
        self.assertEqual(report["total_scans"], 3)
        self.assertEqual(report["total_findings"], 11)
        self.assertEqual(report["scanners_used"]["network"], 2)
        self.assertEqual(report["scanners_used"]["web"], 1)
        self.assertEqual(report["findings_by_severity"]["HIGH"], 2)
        self.assertEqual(report["findings_by_severity"]["CRITICAL"], 1)
        self.assertEqual(report["findings_by_severity"]["LOW"], 2)

    def test_get_report_returns_copy(self):
        """get_report returns data, not a mutable reference."""
        self.reporter.record_scan("ssl", finding_count=0)
        report = self.reporter.get_report()
        self.assertIsInstance(report, dict)
        self.assertEqual(report["total_scans"], 1)

    def test_update_client_count(self):
        """MSSP client count is tracked."""
        self.reporter.update_client_count(12)
        report = self.reporter.get_report()
        self.assertEqual(report["client_count"], 12)

    def test_get_summary_string(self):
        """Summary returns a human-readable string."""
        self.reporter.record_scan("network", finding_count=3)
        summary = self.reporter.get_summary()
        self.assertIn("1 scans", summary)
        self.assertIn("3 findings", summary)

    def test_reset_clears_data(self):
        """Reset should zero out all counters."""
        self.reporter.record_scan("network", finding_count=10)
        self.reporter.reset()
        report = self.reporter.get_report()
        self.assertEqual(report["total_scans"], 0)
        self.assertEqual(report["total_findings"], 0)

    def test_persistence_across_load(self):
        """Data persists to disk and can be reloaded."""
        self.reporter.record_scan("vulnerability", finding_count=4)

        # Create a new reporter pointing at the same path
        reporter2 = self.ur_mod.UsageReporter.__new__(self.ur_mod.UsageReporter)
        reporter2._data_dir = self.tmppath
        reporter2._report_path = self.tmppath / "usage_report.json"
        reporter2._report = reporter2._load()

        report = reporter2.get_report()
        self.assertEqual(report["total_scans"], 1)
        self.assertEqual(report["total_findings"], 4)


class TestTelemetryOptIn(unittest.TestCase):
    """Verify telemetry is opt-in only and respects tier checks."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tmppath = Path(self.tmpdir)

        import lib.usage_reporter as ur_mod
        self.ur_mod = ur_mod

        self.reporter = ur_mod.UsageReporter.__new__(ur_mod.UsageReporter)
        self.reporter._data_dir = self.tmppath
        self.reporter._report_path = self.tmppath / "usage_report.json"
        self.reporter._report = self.reporter._empty_report()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_telemetry_disabled_by_default(self):
        """When DONJON_TELEMETRY is not set, no remote call is made."""
        env = os.environ.copy()
        env.pop("DONJON_TELEMETRY", None)
        with patch.dict(os.environ, env, clear=True):
            result = self.reporter.maybe_send_telemetry()
        self.assertFalse(result)

    def test_telemetry_disabled_when_env_not_1(self):
        """When DONJON_TELEMETRY is set to something other than 1, no call."""
        with patch.dict(os.environ, {"DONJON_TELEMETRY": "0"}):
            result = self.reporter.maybe_send_telemetry()
        self.assertFalse(result)

    def test_telemetry_skipped_for_non_managed_tier(self):
        """Even with DONJON_TELEMETRY=1, non-managed tiers don't phone home."""
        mock_lm = MagicMock()
        mock_lm.get_tier.return_value = "pro"

        with patch.dict(os.environ, {"DONJON_TELEMETRY": "1"}):
            with patch.dict("sys.modules", {"licensing": MagicMock(get_license_manager=lambda: mock_lm)}):
                result = self.reporter.maybe_send_telemetry()
        self.assertFalse(result)

    @patch("urllib.request.urlopen")
    def test_telemetry_sends_for_managed_tier(self, mock_urlopen):
        """With DONJON_TELEMETRY=1 and managed tier, telemetry is sent."""
        mock_lm = MagicMock()
        mock_lm.get_tier.return_value = "managed"

        mock_cfg = MagicMock()
        mock_cfg.get_value.return_value = "https://license.example.com"

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        self.reporter.record_scan("network", finding_count=2)

        with patch.dict(os.environ, {"DONJON_TELEMETRY": "1"}):
            with patch.dict("sys.modules", {
                "licensing": MagicMock(get_license_manager=lambda: mock_lm),
                "config": MagicMock(get_config=lambda: mock_cfg),
            }):
                result = self.reporter.maybe_send_telemetry()

        self.assertTrue(result)
        mock_urlopen.assert_called_once()

        # Verify the payload contains only counts, no PII
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        self.assertIn("total_scans", payload)
        self.assertIn("scanners_used", payload)
        self.assertIn("findings_by_severity", payload)
        self.assertIn("client_count", payload)
        # Must NOT contain any finding details or IPs
        self.assertNotIn("findings", payload)
        self.assertNotIn("targets", payload)
        self.assertNotIn("target_ips", payload)

    @patch("urllib.request.urlopen")
    def test_telemetry_payload_is_anonymised(self, mock_urlopen):
        """The telemetry payload must be strictly anonymised: counts only."""
        mock_lm = MagicMock()
        mock_lm.get_tier.return_value = "managed"

        mock_cfg = MagicMock()
        mock_cfg.get_value.return_value = "https://license.example.com"

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        self.reporter.record_scan("web", finding_count=5, findings_by_severity={"HIGH": 3, "MEDIUM": 2})
        self.reporter.update_client_count(8)

        with patch.dict(os.environ, {"DONJON_TELEMETRY": "1"}):
            with patch.dict("sys.modules", {
                "licensing": MagicMock(get_license_manager=lambda: mock_lm),
                "config": MagicMock(get_config=lambda: mock_cfg),
            }):
                self.reporter.maybe_send_telemetry()

        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))

        # Verify expected fields
        self.assertEqual(payload["total_scans"], 1)
        self.assertEqual(payload["total_findings"], 5)
        self.assertEqual(payload["client_count"], 8)
        self.assertEqual(payload["findings_by_severity"]["HIGH"], 3)

        # Verify NO sensitive fields leak
        allowed_keys = {
            "version", "total_scans", "scanners_used", "findings_by_severity",
            "total_findings", "client_count", "reported_at",
        }
        for key in payload:
            self.assertIn(key, allowed_keys, f"Unexpected key in telemetry payload: {key}")


if __name__ == "__main__":
    unittest.main()
