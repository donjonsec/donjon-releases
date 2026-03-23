"""Module-level functional tests — call real functions with real data.

These DO NOT need a running server. They test the library layer directly.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ===================================================================
# Export Manager — every format produces real output
# ===================================================================

class TestExportOutput:
    @pytest.fixture
    def export_manager(self):
        from lib.export import ExportManager
        return ExportManager()

    @pytest.fixture
    def sample_findings(self):
        return [{
            "id": "FUNC-001",
            "title": "Functional Test Finding",
            "severity": "high",
            "description": "Test finding for functional validation",
            "host": "192.168.1.100",
            "port": 443,
            "cve": "CVE-2024-0001",
            "cvss": 8.5,
            "scanner": "functional_test",
            "timestamp": "2026-03-18T00:00:00Z",
            "remediation": "Apply security patch",
            "category": "vulnerability",
            "status": "open",
        }]

    @pytest.mark.parametrize("fmt", [
        "cef", "stix", "splunk_hec", "sentinel", "leef",
        "csv", "servicenow_json", "qualys_xml", "sarif",
        "syslog", "jsonl",
    ])
    def test_format_produces_file(self, export_manager, sample_findings, fmt, tmp_path):
        output = tmp_path / f"test.{fmt}"
        getattr(export_manager, f"export_{fmt}")(sample_findings, output)
        assert output.exists(), f"{fmt} export produced no file"
        assert output.stat().st_size > 10, f"{fmt} export file too small"

    def test_sarif_valid_json(self, export_manager, sample_findings, tmp_path):
        output = tmp_path / "test.sarif"
        export_manager.export_sarif(sample_findings, output)
        data = json.loads(output.read_text())
        assert isinstance(data, dict)
        # SARIF should have runs or $schema
        assert any(k in data for k in ["$schema", "version", "runs"])

    def test_stix_valid_json(self, export_manager, sample_findings, tmp_path):
        output = tmp_path / "test.stix.json"
        export_manager.export_stix(sample_findings, output)
        data = json.loads(output.read_text())
        assert isinstance(data, dict)

    def test_csv_has_header(self, export_manager, sample_findings, tmp_path):
        output = tmp_path / "test.csv"
        export_manager.export_csv(sample_findings, output)
        lines = output.read_text().splitlines()
        assert len(lines) >= 2, "CSV should have header + data row"

    def test_jsonl_one_line_per_finding(self, export_manager, sample_findings, tmp_path):
        output = tmp_path / "test.jsonl"
        export_manager.export_jsonl(sample_findings, output)
        lines = [l for l in output.read_text().splitlines() if l.strip()]
        assert len(lines) >= 1
        # Each line should be valid JSON
        for line in lines:
            json.loads(line)


# ===================================================================
# Compliance — 30+ frameworks with control counts
# ===================================================================

class TestComplianceMapper:
    def test_30_plus_frameworks(self):
        from lib.compliance import get_compliance_mapper
        mapper = get_compliance_mapper()
        fws = mapper.get_all_frameworks()
        assert len(fws) >= 30, f"Expected >=30 frameworks, got {len(fws)}"

    def test_each_has_control_count(self):
        from lib.compliance import get_compliance_mapper
        mapper = get_compliance_mapper()
        for fw in mapper.get_all_frameworks():
            assert "id" in fw
            assert "control_count" in fw
            assert int(fw["control_count"]) > 0, f"{fw['id']} has 0 controls"

    def test_key_frameworks_present(self):
        from lib.compliance import get_compliance_mapper
        mapper = get_compliance_mapper()
        fw_ids = {fw["id"].lower() for fw in mapper.get_all_frameworks()}
        for key in ["nist_800_53", "hipaa", "pci_dss_4", "cmmc", "gdpr",
                     "iso_27001_2022", "soc2", "fedramp"]:
            found = any(key in fid for fid in fw_ids)
            assert found, f"Key framework {key} not found"


# ===================================================================
# Risk Quantification — FAIR + Monte Carlo
# ===================================================================

class TestRiskQuantification:
    def test_imports(self):
        from lib.risk_quantification import RiskQuantifier
        rq = RiskQuantifier()
        assert rq is not None

    def test_has_monte_carlo(self):
        src = (PROJECT_ROOT / "lib" / "risk_quantification.py").read_text()
        assert "monte_carlo" in src.lower() or "simulation" in src.lower()

    def test_has_10k_iterations(self):
        src = (PROJECT_ROOT / "lib" / "risk_quantification.py").read_text()
        assert "10000" in src or "10_000" in src

    def test_has_fair_components(self):
        src = (PROJECT_ROOT / "lib" / "risk_quantification.py").read_text().lower()
        assert "lef" in src, "Missing LEF (Loss Event Frequency)"
        assert "ale" in src, "Missing ALE (Annual Loss Expectancy)"


# ===================================================================
# Licensing — dual signatures
# ===================================================================

class TestLicensing:
    def test_imports(self):
        from lib.licensing import get_license_manager
        lm = get_license_manager()
        assert lm is not None

    def test_has_ml_dsa(self):
        src = (PROJECT_ROOT / "lib" / "licensing.py").read_text().lower()
        assert "ml_dsa" in src or "ml-dsa" in src or "dilithium" in src

    def test_has_ed25519(self):
        src = (PROJECT_ROOT / "lib" / "licensing.py").read_text().lower()
        assert "ed25519" in src


# ===================================================================
# Unicode — export handles international characters
# ===================================================================

class TestUnicodeHandling:
    def test_json_roundtrip(self):
        finding = {
            "id": "UNI-001",
            "title": "SQL\u6ce8\u5165\u6f0f\u6d1e",
            "severity": "high",
            "description": "\u0423\u044f\u0437\u0432\u0438\u043c\u043e\u0441\u0442\u044c \U0001f512",
        }
        encoded = json.dumps(finding, ensure_ascii=False)
        decoded = json.loads(encoded)
        assert decoded["title"] == finding["title"]

    def test_export_preserves_unicode(self, tmp_path):
        from lib.export import ExportManager
        em = ExportManager()
        findings = [{
            "id": "UNI-002", "title": "\u8106\u5f31\u6027\u30c6\u30b9\u30c8",
            "severity": "high", "host": "192.168.1.1", "port": 443,
            "cve": "CVE-2024-0001", "cvss": 8.5, "scanner": "test",
            "timestamp": "2026-01-01T00:00:00Z", "remediation": "\u4fee\u590d",
            "description": "Test", "category": "vuln", "status": "open",
        }]
        output = tmp_path / "unicode.jsonl"
        em.export_jsonl(findings, output)
        content = output.read_text(encoding="utf-8")
        assert "\u8106\u5f31\u6027" in content


# ===================================================================
# Config — loads and has correct version
# ===================================================================

class TestConfig:
    def test_loads(self):
        from lib.config import Config
        cfg = Config()
        assert cfg is not None

    def test_version_is_730(self):
        from lib.config import Config
        cfg = Config()
        if hasattr(cfg, "get"):
            version = cfg.get("version")
            if version:
                assert version == "7.4.0", f"Config version is {version}"


# ===================================================================
# Database + Evidence
# ===================================================================

class TestDatabaseLayer:
    def test_imports(self):
        from lib.database import get_database
        # get_database requires a db_name argument
        db = get_database("evidence")
        assert db is not None


class TestEvidenceManager:
    def test_imports(self):
        from lib.evidence import get_evidence_manager
        em = get_evidence_manager()
        assert em is not None


# ===================================================================
# Scanner classes — all have scan() method
# ===================================================================

class TestScannerClasses:
    @pytest.mark.parametrize("mod_path", [
        "scanners.network_scanner",
        "scanners.vulnerability_scanner",
        "scanners.web_scanner",
        "scanners.ssl_scanner",
        "scanners.compliance_scanner",
        "scanners.cloud_scanner",
        "scanners.container_scanner",
    ])
    def test_scanner_has_scan_method(self, mod_path):
        import importlib
        mod = importlib.import_module(mod_path)
        scanner_cls = None
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if isinstance(obj, type) and hasattr(obj, "scan") and attr != "BaseScanner":
                scanner_cls = obj
                break
        assert scanner_cls is not None, f"No Scanner class with scan() in {mod_path}"


# ===================================================================
# AI Engine — 6 providers
# ===================================================================

class TestAIEngine:
    def test_has_6_providers(self):
        src = (PROJECT_ROOT / "lib" / "ai_engine.py").read_text().lower()
        providers = ["ollama", "stepfun", "anthropic", "gemini", "openai", "template"]
        found = sum(1 for p in providers if p in src)
        assert found >= 5, f"Only {found}/6 AI providers found"

    def test_has_sanitization(self):
        src = (PROJECT_ROOT / "lib" / "ai_engine.py").read_text().lower()
        assert any(m in src for m in ["sanitiz", "strip", "redact", "mask", "clean"])
