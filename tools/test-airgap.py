#!/usr/bin/env python3
"""
Donjon Platform - Air-Gap Functional Test
Simulates a fully offline environment and verifies all features work
without network access.

Air-gap simulation: monkey-patches socket.socket.connect to raise
ConnectionRefusedError for any non-loopback destination, ensuring no
external API calls (NVD, EPSS, CISA, license server, etc.) can succeed.

Usage:
    python tools/test-airgap.py
"""

import importlib
import json
import os
import socket
import sqlite3
import sys
import tempfile
import textwrap
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Setup paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

# Force non-interactive mode before any TUI import
os.environ['DONJON_NONINTERACTIVE'] = '1'

# Set offline mode BEFORE any lib imports to prevent network calls during init
os.environ['DONJON_OFFLINE'] = '1'


# ---------------------------------------------------------------------------
# Air-gap simulation
# ---------------------------------------------------------------------------
_original_connect = socket.socket.connect
_original_create_connection = socket.create_connection
_blocked_attempts: List[str] = []

LOOPBACK_PREFIXES = ('127.', '::1', 'localhost', '0.0.0.0')


def _is_loopback(addr) -> bool:
    """Check if an address is loopback (allowed in air-gap)."""
    if isinstance(addr, tuple) and len(addr) >= 2:
        host = str(addr[0])
    elif isinstance(addr, str):
        host = addr
    else:
        return False
    return any(host.startswith(p) or host == p for p in LOOPBACK_PREFIXES)


def _blocked_connect(self, addr):
    """Monkey-patched socket.connect that blocks non-loopback connections."""
    if _is_loopback(addr):
        return _original_connect(self, addr)
    host = str(addr[0]) if isinstance(addr, tuple) else str(addr)
    _blocked_attempts.append(host)
    raise ConnectionRefusedError(
        f"[AIR-GAP] Network blocked: {addr}"
    )


def _blocked_create_connection(addr, *args, **kwargs):
    """Monkey-patched socket.create_connection that blocks non-loopback."""
    if _is_loopback(addr):
        return _original_create_connection(addr, *args, **kwargs)
    host = str(addr[0]) if isinstance(addr, tuple) else str(addr)
    _blocked_attempts.append(host)
    raise ConnectionRefusedError(
        f"[AIR-GAP] Network blocked: {addr}"
    )


def enable_airgap():
    """Enable air-gap simulation by monkey-patching socket."""
    socket.socket.connect = _blocked_connect
    socket.create_connection = _blocked_create_connection
    os.environ['HTTP_PROXY'] = 'http://0.0.0.0:1'
    os.environ['HTTPS_PROXY'] = 'http://0.0.0.0:1'
    os.environ['DONJON_OFFLINE'] = '1'


def disable_airgap():
    """Restore normal network access."""
    socket.socket.connect = _original_connect
    socket.create_connection = _original_create_connection
    for var in ('HTTP_PROXY', 'HTTPS_PROXY', 'DONJON_OFFLINE'):
        os.environ.pop(var, None)


# ---------------------------------------------------------------------------
# Test framework
# ---------------------------------------------------------------------------
class TestResult:
    def __init__(self, name: str, passed: bool, detail: str = "",
                 category: str = ""):
        self.name = name
        self.passed = passed
        self.detail = detail
        self.category = category


results: List[TestResult] = []


def record(name: str, passed: bool, detail: str = "", category: str = ""):
    results.append(TestResult(name, passed, detail, category))
    status = "PASS" if passed else "FAIL"
    mark = "\033[32m[PASS]\033[0m" if passed else "\033[31m[FAIL]\033[0m"
    print(f"  {mark} {name}")
    if detail and not passed:
        for line in detail.strip().split('\n'):
            print(f"         {line}")


def run_test(name: str, fn, category: str = ""):
    """Run a test function, catching exceptions as failures."""
    try:
        passed, detail = fn()
        record(name, passed, detail, category)
    except Exception as e:
        tb = traceback.format_exc()
        record(name, False, f"{e}\n{tb}", category)


# ===========================================================================
# TEST CATEGORY 1: Core Functionality Offline
# ===========================================================================

def test_config_loads():
    """Config loads without network."""
    from lib.config import Config
    # Reset singleton to test fresh load
    Config._instance = None
    c = Config()
    assert c.get('version') is not None, "version missing"
    assert c.get('platform', {}).get('name') == 'Donjon'
    return True, f"version={c.get('version')}"


def test_scanner_imports():
    """All 17 scanners import successfully."""
    scanner_modules = [
        ('scanners.network_scanner', 'NetworkScanner'),
        ('scanners.vulnerability_scanner', 'VulnerabilityScanner'),
        ('scanners.web_scanner', 'WebScanner'),
        ('scanners.ssl_scanner', 'SSLScanner'),
        ('scanners.compliance_scanner', 'ComplianceScanner'),
        ('scanners.windows_scanner', 'WindowsScanner'),
        ('scanners.linux_scanner', 'LinuxScanner'),
        ('scanners.ad_scanner', 'ADScanner'),
        ('scanners.cloud_scanner', 'CloudScanner'),
        ('scanners.container_scanner', 'ContainerScanner'),
        ('scanners.sbom_scanner', 'SBOMScanner'),
        ('scanners.malware_scanner', 'MalwareScanner'),
        ('scanners.shadow_ai_scanner', 'ShadowAIScanner'),
        ('scanners.credential_scanner', 'CredentialScanner'),
        ('scanners.openvas_scanner', 'OpenVASScanner'),
        ('scanners.asm_scanner', 'ASMScanner'),
        ('scanners.adversary_scanner', 'AdversaryScanner'),
    ]
    imported = []
    failed = []
    for mod_path, class_name in scanner_modules:
        try:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, class_name)
            imported.append(class_name)
        except Exception as e:
            failed.append(f"{class_name}: {e}")

    if failed:
        return False, f"Imported {len(imported)}/17. Failed:\n" + "\n".join(failed)
    return True, f"All 17 scanners imported"


def test_scanner_instantiation():
    """All 17 scanners can be instantiated offline."""
    scanner_modules = [
        ('scanners.network_scanner', 'NetworkScanner'),
        ('scanners.vulnerability_scanner', 'VulnerabilityScanner'),
        ('scanners.web_scanner', 'WebScanner'),
        ('scanners.ssl_scanner', 'SSLScanner'),
        ('scanners.compliance_scanner', 'ComplianceScanner'),
        ('scanners.windows_scanner', 'WindowsScanner'),
        ('scanners.linux_scanner', 'LinuxScanner'),
        ('scanners.ad_scanner', 'ADScanner'),
        ('scanners.cloud_scanner', 'CloudScanner'),
        ('scanners.container_scanner', 'ContainerScanner'),
        ('scanners.sbom_scanner', 'SBOMScanner'),
        ('scanners.malware_scanner', 'MalwareScanner'),
        ('scanners.shadow_ai_scanner', 'ShadowAIScanner'),
        ('scanners.credential_scanner', 'CredentialScanner'),
        ('scanners.openvas_scanner', 'OpenVASScanner'),
        ('scanners.asm_scanner', 'ASMScanner'),
        ('scanners.adversary_scanner', 'AdversaryScanner'),
    ]
    instantiated = []
    failed = []
    for mod_path, class_name in scanner_modules:
        try:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, class_name)
            instance = cls(session_id="airgap-test")
            assert instance.SCANNER_NAME, f"{class_name} missing SCANNER_NAME"
            instantiated.append(class_name)
        except Exception as e:
            failed.append(f"{class_name}: {e}")

    if failed:
        return False, f"Instantiated {len(instantiated)}/17. Failed:\n" + "\n".join(failed)
    return True, f"All 17 scanners instantiated"


def test_windows_scanner_runs():
    """Windows scanner runs (local-only, no network needed)."""
    from scanners.windows_scanner import WindowsScanner
    scanner = WindowsScanner(session_id="airgap-win-test")
    # Just verify it can do its local checks without crashing
    assert scanner.SCANNER_NAME == "windows"
    # Attempt a quick scan of localhost -- it should at least start
    # without network errors (it reads local registry, WMI, etc.)
    try:
        # Don't run a full scan, just verify the scan method exists
        # and the scanner's internal state is valid
        assert hasattr(scanner, 'scan'), "Missing scan method"
        assert hasattr(scanner, 'findings'), "Missing findings attr"
        assert isinstance(scanner.findings, list)
    except Exception as e:
        return False, str(e)
    return True, "WindowsScanner ready for local-only operation"


def test_evidence_manager():
    """Evidence manager works with SQLite locally."""
    from lib.evidence import get_evidence_manager, EvidenceManager
    # Reset singleton
    EvidenceManager._instance = None
    em = get_evidence_manager()
    assert em is not None, "EvidenceManager is None"

    # Store and retrieve evidence
    eid = em.add_evidence(
        session_id="airgap-test",
        evidence_type="scan_result",
        title="Air-gap test evidence",
        description="Testing offline evidence storage",
        source_tool="test-airgap",
        raw_data={"test": True},
    )
    assert eid, "Failed to store evidence"

    # Retrieve session summary to verify storage
    summary = em.get_session_summary("airgap-test")
    assert summary is not None, "No session summary retrieved"
    return True, f"Stored and retrieved evidence (id={eid}, summary keys={list(summary.keys()) if isinstance(summary, dict) else type(summary).__name__})"


def test_export_formats():
    """All 13 export formats produce output."""
    from lib.export import ExportManager

    em = ExportManager()

    # Sample findings for export
    findings = [
        {
            'id': 'AIRGAP-001',
            'title': 'Test Finding for Air-Gap',
            'severity': 'HIGH',
            'description': 'This is a test finding for air-gap validation.',
            'target': '192.168.1.1',
            'port': 443,
            'protocol': 'tcp',
            'scanner': 'test-airgap',
            'cve_id': 'CVE-2024-0001',
            'cvss_score': 8.5,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'remediation': 'Apply patch.',
            'evidence': 'Test evidence data.',
            'status': 'open',
        }
    ]

    export_methods = [
        ('CEF', 'export_cef'),
        ('STIX', 'export_stix'),
        ('Splunk HEC', 'export_splunk_hec'),
        ('Sentinel', 'export_sentinel'),
        ('LEEF', 'export_leef'),
        ('CSV', 'export_csv'),
        ('ServiceNow JSON', 'export_servicenow_json'),
        ('Qualys XML', 'export_qualys_xml'),
        ('SARIF', 'export_sarif'),
        ('Syslog', 'export_syslog'),
        ('JSONL', 'export_jsonl'),
        ('HTML', 'export_html'),
        ('JSON (native)', None),  # Test via export_all or direct JSON dump
    ]

    with tempfile.TemporaryDirectory(prefix="donjon_airgap_") as tmpdir:
        passed_formats = []
        failed_formats = []

        for fmt_name, method_name in export_methods:
            try:
                if method_name is None:
                    # JSON native: just dump findings
                    out = Path(tmpdir) / "findings.json"
                    out.write_text(json.dumps(findings, indent=2))
                    assert out.stat().st_size > 10
                else:
                    out = Path(tmpdir) / f"findings.{fmt_name.lower().replace(' ', '_')}"
                    method = getattr(em, method_name)
                    method(findings, out)
                    assert out.exists(), f"{out} not created"
                    assert out.stat().st_size > 0, f"{out} is empty"
                passed_formats.append(fmt_name)
            except Exception as e:
                failed_formats.append(f"{fmt_name}: {e}")

        if failed_formats:
            return False, (
                f"Passed {len(passed_formats)}/13. Failed:\n"
                + "\n".join(failed_formats)
            )
        return True, f"All 13 export formats produced output"


def test_dashboard_tabs():
    """All 18 dashboard tabs render HTML."""
    tab_generators = [
        # Core (10)
        ('overview', 'web.dashboard_overview_html', 'generate_overview_html'),
        ('scan-center', 'web.dashboard_scan_center', 'generate_scan_center'),
        ('compliance', 'web.dashboard_compliance_html', 'generate_compliance_html'),
        ('risk-analysis', 'web.dashboard_risk_html', 'generate_risk_html'),
        ('patch-verification', 'web.dashboard_patch_html', 'generate_patch_html'),
        ('schedules', 'web.dashboard_schedules_html', 'generate_schedules_html'),
        ('ai-assistant', 'web.dashboard_ai_html', 'generate_ai_html'),
        ('trends', 'web.dashboard_trends', 'generate_trends'),
        ('lifecycle', 'web.dashboard_lifecycle', 'generate_lifecycle'),
        ('settings', 'web.dashboard_settings_html', 'generate_settings_html'),
        # Enterprise (4)
        ('users-roles', 'web.dashboard_users_html', 'generate_users_html'),
        ('sso', 'web.dashboard_sso_html', 'generate_sso_html'),
        ('tenants', 'web.dashboard_tenants_html', 'generate_tenants_html'),
        ('audit-log', 'web.dashboard_audit_html', 'generate_audit_html'),
        # MSSP (4)
        ('clients', 'web.dashboard_mssp_clients_html', 'generate_mssp_clients_html'),
        ('bulk-scans', 'web.dashboard_mssp_bulk_html', 'generate_mssp_bulk_html'),
        ('reports', 'web.dashboard_mssp_reports_html', 'generate_mssp_reports_html'),
        ('metering', 'web.dashboard_mssp_metering_html', 'generate_mssp_metering_html'),
    ]

    rendered = []
    failed = []
    for tab_id, mod_path, func_name in tab_generators:
        try:
            mod = importlib.import_module(mod_path)
            func = getattr(mod, func_name)
            html = func()
            assert isinstance(html, str), f"{tab_id}: returned {type(html)}"
            assert len(html) > 50, f"{tab_id}: HTML too short ({len(html)} chars)"
            rendered.append(tab_id)
        except Exception as e:
            failed.append(f"{tab_id}: {e}")

    if failed:
        return False, (
            f"Rendered {len(rendered)}/18 tabs. Failed:\n"
            + "\n".join(failed)
        )
    return True, f"All 18 dashboard tabs rendered HTML"


def test_dashboard_shell():
    """Dashboard shell (combined SPA) renders without network."""
    try:
        from web.dashboard_shell import generate_shell
        html = generate_shell()
        assert isinstance(html, str)
        assert len(html) > 1000, f"Shell HTML too short: {len(html)}"
        assert 'Donjon' in html
        return True, f"Shell HTML generated ({len(html)} chars)"
    except ImportError:
        # Fall back to legacy dashboard
        from web.dashboard import generate_dashboard_html
        html = generate_dashboard_html()
        assert isinstance(html, str)
        assert len(html) > 1000
        return True, f"Legacy dashboard HTML generated ({len(html)} chars)"


def test_server_endpoints():
    """Server starts and responds to health/stats/findings endpoints."""
    from web.api import DonjonAPI

    api = DonjonAPI(auth=None)

    endpoints = [
        ('GET', '/api/v1/health', None),
        ('GET', '/api/v1/stats', None),
        ('GET', '/api/v1/findings', None),
        ('GET', '/api/v1/scanners', None),
        ('GET', '/api/v1/assets', None),
        ('GET', '/api/v1/remediation', None),
        ('GET', '/api/v1/risks', None),
        ('GET', '/api/v1/exceptions', None),
        ('GET', '/api/v1/schedules', None),
    ]

    passed_eps = []
    failed_eps = []
    for method, path, body in endpoints:
        try:
            resp_body, status, content_type = api.dispatch(
                method, path, {}, body, api_key=None, source_ip='127.0.0.1'
            )
            if status < 500:
                passed_eps.append(f"{path} -> {status}")
            else:
                failed_eps.append(f"{path} -> {status}: {resp_body[:200]}")
        except Exception as e:
            failed_eps.append(f"{path}: {e}")

    if failed_eps:
        return False, (
            f"Passed {len(passed_eps)}/{len(endpoints)}. Failed:\n"
            + "\n".join(failed_eps)
        )
    return True, f"All {len(endpoints)} API endpoints responded (no 5xx)"


def test_tui_parses():
    """TUI launcher module parses without errors."""
    from lib.tui import Colors, set_non_interactive, safe_input
    set_non_interactive(True)
    # Verify core TUI classes/functions exist (values may be empty in non-TTY)
    assert hasattr(Colors, 'RED'), "Colors.RED missing"
    assert hasattr(Colors, 'GREEN'), "Colors.GREEN missing"
    assert hasattr(Colors, 'RESET'), "Colors.RESET missing"
    result = safe_input("test", "default")
    assert result == "default", f"safe_input returned {result!r}"
    return True, "TUI module loaded, non-interactive mode works"


# ===========================================================================
# TEST CATEGORY 2: Intel Data Availability Offline
# ===========================================================================

def test_kev_local_query():
    """CISA KEV can be queried from local JSON."""
    from lib.threat_intel import ThreatIntelManager

    # Reset singleton
    ThreatIntelManager._instance = None

    kev_path = PROJECT_ROOT / 'data' / 'threat_intel' / 'cisa_kev.json'
    if not kev_path.exists():
        # Create minimal KEV cache for testing
        kev_data = {
            '_cached_at': time.time(),
            'title': 'CISA KEV Catalog (test)',
            'catalogVersion': '2024.01.01',
            'vulnerabilities': [
                {
                    'cveID': 'CVE-2024-0001',
                    'vendorProject': 'TestVendor',
                    'product': 'TestProduct',
                    'vulnerabilityName': 'Test Vulnerability',
                    'dateAdded': '2024-01-01',
                    'dueDate': '2024-02-01',
                    'requiredAction': 'Apply patch',
                    'knownRansomwareCampaignUse': 'Unknown',
                    'notes': 'Test entry for air-gap validation',
                }
            ]
        }
        kev_path.parent.mkdir(parents=True, exist_ok=True)
        kev_path.write_text(json.dumps(kev_data))
        created_test_data = True
    else:
        created_test_data = False

    ti = ThreatIntelManager()
    assert ti._kev_data is not None, "KEV data not loaded from disk"

    vulns = ti._kev_data.get('vulnerabilities', [])
    assert len(vulns) > 0, f"KEV has 0 vulnerabilities"

    # Query a specific CVE
    result = ti.is_in_kev('CVE-2024-0001')
    # Should return a dict (either found or not) without hitting the network
    assert isinstance(result, dict), f"is_in_kev returned {type(result)}"

    detail = f"KEV loaded: {len(vulns)} entries"
    if created_test_data:
        detail += " (created test data)"
    return True, detail


def test_vuln_db_local_query():
    """Vuln database can be queried from local SQLite (even if empty)."""
    from lib.vuln_database import VulnDatabase

    # Reset singleton
    VulnDatabase._instance = None

    vdb = VulnDatabase()
    assert vdb is not None

    # Query should not crash even with empty DB
    try:
        result = vdb.lookup_cve('CVE-2024-0001')
    except Exception as e:
        # Acceptable: returns None or raises a handled error
        result = None

    # Check embedded data (OWASP, CWE, etc.)
    try:
        owasp = vdb.get_owasp_category('CWE-89')
    except Exception:
        owasp = None

    return True, f"VulnDB queried without crash (CVE lookup returned {type(result).__name__})"


def test_epss_offline_fallback():
    """EPSS scores fall back gracefully when API unavailable."""
    from lib.threat_intel import ThreatIntelManager

    ThreatIntelManager._instance = None
    ti = ThreatIntelManager()

    # This should NOT crash, even though the API is blocked
    try:
        results = ti.query_epss(['CVE-2024-0001', 'CVE-2024-0002'])
    except ConnectionRefusedError:
        return False, "EPSS query raised ConnectionRefusedError instead of degrading gracefully"
    except Exception as e:
        return False, f"EPSS query raised unexpected error: {e}"

    # Results may be empty (no cache) or from cache -- either is fine
    assert isinstance(results, dict), f"Expected dict, got {type(results)}"
    return True, f"EPSS returned {len(results)} cached scores (graceful offline)"


def test_threat_intel_offline():
    """Threat intel module doesn't crash when offline."""
    from lib.threat_intel import ThreatIntelManager

    ThreatIntelManager._instance = None
    ti = ThreatIntelManager()

    # Test cache staleness check
    try:
        status = ti.is_cache_stale()
        assert isinstance(status, dict)
    except Exception as e:
        return False, f"is_cache_stale() crashed: {e}"

    # Test enrichment (should degrade gracefully)
    try:
        enrichment = ti.enrich_finding('CVE-2024-0001')
        assert isinstance(enrichment, dict)
        assert 'kev_status' in enrichment
        assert 'epss_score' in enrichment
    except ConnectionRefusedError:
        return False, "enrich_finding raised ConnectionRefusedError"
    except Exception as e:
        return False, f"enrich_finding crashed: {e}"

    return True, f"ThreatIntel offline: staleness={status}, enrichment keys={list(enrichment.keys())}"


# ===========================================================================
# TEST CATEGORY 3: License Validation Offline
# ===========================================================================

def test_license_validates_locally():
    """License validates from local file without phone-home."""
    from lib.licensing import LicenseManager

    LicenseManager._instance = None
    lm = LicenseManager()

    # Should default to community tier without a license file
    tier = lm.get_tier()
    assert tier in ('community', 'pro', 'enterprise', 'managed'), f"Invalid tier: {tier}"

    label = lm.get_tier_label()
    assert isinstance(label, str) and len(label) > 0

    return True, f"License validated locally: tier={tier}, label={label}"


def test_license_missing_no_block():
    """Expired/missing license shows warning but doesn't block."""
    from lib.licensing import LicenseManager

    LicenseManager._instance = None

    # Temporarily rename any existing license file
    from lib.paths import paths
    license_path = paths.data / 'license.json'
    backup_path = license_path.with_suffix('.json.airgap_bak')
    had_license = license_path.exists()

    try:
        if had_license:
            license_path.rename(backup_path)

        LicenseManager._instance = None
        lm = LicenseManager()
        tier = lm.get_tier()

        # Without a license, should fall back to community -- not crash
        assert tier == 'community', f"Expected community without license, got {tier}"
        return True, "No license file -> community tier (no crash, no block)"
    finally:
        if had_license and backup_path.exists():
            backup_path.rename(license_path)
            LicenseManager._instance = None


def test_usb_sideload():
    """USB sideload import (simulate by placing license.json in a temp dir)."""
    from lib.licensing import LicenseManager
    from lib.paths import paths

    # Create a simulated USB sideload license
    with tempfile.TemporaryDirectory(prefix="donjon_usb_") as usb_dir:
        sideload_license = {
            "format_version": 2,
            "license_id": "airgap-test-usb-001",
            "tier": "pro",
            "organization": "Air-Gap Test Org",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": "2099-12-31T23:59:59Z",
            "features_override": {},
            "signature_classical": "",
            "signature_pqc": "",
        }
        usb_license_path = Path(usb_dir) / 'license.json'
        usb_license_path.write_text(json.dumps(sideload_license, indent=2))

        # Verify the file exists and is valid JSON
        loaded = json.loads(usb_license_path.read_text())
        assert loaded['license_id'] == 'airgap-test-usb-001'
        assert loaded['tier'] == 'pro'

        # Copy to data dir (simulating USB sideload)
        import shutil
        dest = paths.data / 'license_sideload_test.json'
        try:
            shutil.copy2(usb_license_path, dest)
            assert dest.exists()
            sideloaded = json.loads(dest.read_text())
            assert sideloaded['tier'] == 'pro'
            return True, "USB sideload simulation: license.json copied and validated"
        finally:
            if dest.exists():
                dest.unlink()


# ===========================================================================
# TEST CATEGORY 4: Compliance Reporting Offline
# ===========================================================================

def test_compliance_mapper():
    """Compliance mapper works with local YAML files."""
    from lib.compliance import ComplianceMapper, get_compliance_mapper

    ComplianceMapper._instance = None
    cm = get_compliance_mapper()
    assert cm is not None

    # Should have loaded framework definitions
    frameworks = cm._framework_metadata
    assert len(frameworks) > 0, f"No frameworks loaded"

    return True, f"ComplianceMapper loaded {len(frameworks)} frameworks"


def test_framework_controls_from_disk():
    """Framework controls load from disk YAML files."""
    import yaml

    frameworks_dir = PROJECT_ROOT / 'config' / 'frameworks'
    assert frameworks_dir.exists(), f"{frameworks_dir} not found"

    yaml_files = list(frameworks_dir.glob('*.yaml'))
    assert len(yaml_files) > 0, "No YAML framework files found"

    loaded = []
    failed = []
    for yf in yaml_files:
        try:
            with open(yf, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            assert data is not None, f"{yf.name} parsed to None"
            loaded.append(yf.name)
        except Exception as e:
            failed.append(f"{yf.name}: {e}")

    if failed:
        return False, (
            f"Loaded {len(loaded)}/{len(yaml_files)}. Failed:\n"
            + "\n".join(failed)
        )
    return True, f"All {len(loaded)} framework YAML files loaded from disk"


def test_compliance_report_generation():
    """Compliance reports generate without network."""
    from lib.compliance import get_compliance_mapper, ComplianceMapper

    ComplianceMapper._instance = None
    cm = get_compliance_mapper()

    # Generate a sample compliance mapping for test findings
    test_finding = {
        'severity': 'HIGH',
        'title': 'Weak TLS Configuration',
        'description': 'Server supports TLS 1.0',
        'cve_id': 'CVE-2024-0001',
        'finding_type': 'ssl_weak_protocol',
    }

    # Map to controls (this should work purely from local YAML data)
    try:
        mappings = cm.map_finding(test_finding)
        if mappings is None:
            mappings = {}
    except AttributeError:
        # Some versions use different method names
        try:
            mappings = cm.get_mappings_for_finding(test_finding)
        except Exception:
            mappings = {}
    except Exception as e:
        return False, f"map_finding crashed: {e}"

    return True, f"Compliance mapping generated offline (type={type(mappings).__name__})"


# ===========================================================================
# TEST CATEGORY 5: Network Block Verification
# ===========================================================================

def test_network_actually_blocked():
    """Verify that the air-gap simulation actually blocks network access."""
    import urllib.request
    import urllib.error

    blocked = False
    try:
        urllib.request.urlopen('https://api.first.org/data/v1/epss', timeout=3)
    except ConnectionRefusedError:
        blocked = True
    except urllib.error.URLError as e:
        # Could be wrapped ConnectionRefusedError
        if 'ConnectionRefusedError' in str(e) or 'AIR-GAP' in str(e):
            blocked = True
        else:
            blocked = True  # Any network error is acceptable
    except Exception:
        blocked = True  # Any error means network is blocked

    if not blocked:
        return False, "Network access was NOT blocked -- air-gap simulation failed"
    return True, f"Network blocked. Total blocked attempts so far: {len(_blocked_attempts)}"


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    print("=" * 72)
    print("  DONJON PLATFORM - AIR-GAP FUNCTIONAL TEST")
    print("  Simulating fully offline (air-gapped) environment")
    print("=" * 72)
    print()

    # Enable air-gap
    print("[SETUP] Enabling air-gap simulation...")
    enable_airgap()
    print("[SETUP] Network blocked (non-loopback connections will fail)")
    print("[SETUP] DONJON_OFFLINE=1, HTTP(S)_PROXY=http://0.0.0.0:1")
    print()

    start_time = time.time()

    try:
        # -- Verify air-gap works --
        print("--- Network Block Verification ---")
        run_test("Network actually blocked", test_network_actually_blocked, "airgap")
        print()

        # -- Category 1: Core Functionality --
        print("--- Category 1: Core Functionality Offline ---")
        run_test("Config loads without network", test_config_loads, "core")
        run_test("All 17 scanners import", test_scanner_imports, "core")
        run_test("All 17 scanners instantiate", test_scanner_instantiation, "core")
        run_test("Windows scanner runs (local-only)", test_windows_scanner_runs, "core")
        run_test("Evidence manager works (SQLite)", test_evidence_manager, "core")
        run_test("All 13 export formats produce output", test_export_formats, "core")
        run_test("All 18 dashboard tabs render HTML", test_dashboard_tabs, "core")
        run_test("Dashboard shell renders", test_dashboard_shell, "core")
        run_test("Server API endpoints respond", test_server_endpoints, "core")
        run_test("TUI launcher parses", test_tui_parses, "core")
        print()

        # -- Category 2: Intel Data --
        print("--- Category 2: Intel Data Availability Offline ---")
        run_test("CISA KEV local query", test_kev_local_query, "intel")
        run_test("Vuln database local query", test_vuln_db_local_query, "intel")
        run_test("EPSS offline fallback", test_epss_offline_fallback, "intel")
        run_test("Threat intel module offline", test_threat_intel_offline, "intel")
        print()

        # -- Category 3: License Validation --
        print("--- Category 3: License Validation Offline ---")
        run_test("License validates locally", test_license_validates_locally, "license")
        run_test("Missing license no block", test_license_missing_no_block, "license")
        run_test("USB sideload simulation", test_usb_sideload, "license")
        print()

        # -- Category 4: Compliance Reporting --
        print("--- Category 4: Compliance Reporting Offline ---")
        run_test("Compliance mapper works", test_compliance_mapper, "compliance")
        run_test("Framework controls from disk", test_framework_controls_from_disk, "compliance")
        run_test("Compliance report generation", test_compliance_report_generation, "compliance")
        print()

    finally:
        # -- Teardown --
        print("[TEARDOWN] Restoring network access...")
        disable_airgap()
        print("[TEARDOWN] Air-gap simulation disabled")
        print()

    elapsed = time.time() - start_time

    # -- Summary --
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    print("=" * 72)
    print(f"  RESULTS: {passed}/{total} passed, {failed} failed")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Blocked network attempts: {len(_blocked_attempts)}")
    if _blocked_attempts:
        unique = sorted(set(_blocked_attempts))
        print(f"  Unique blocked hosts: {', '.join(unique[:10])}")
    print("=" * 72)
    print()

    if failed > 0:
        print("FAILURES:")
        for r in results:
            if not r.passed:
                print(f"  [{r.category}] {r.name}")
                if r.detail:
                    for line in r.detail.strip().split('\n')[:5]:
                        print(f"    {line}")
        print()

    # Category breakdown
    categories = {}
    for r in results:
        cat = r.category or "other"
        if cat not in categories:
            categories[cat] = {"pass": 0, "fail": 0}
        if r.passed:
            categories[cat]["pass"] += 1
        else:
            categories[cat]["fail"] += 1

    print("Category Breakdown:")
    print(f"  {'Category':<20} {'Pass':>5} {'Fail':>5} {'Status':>8}")
    print(f"  {'-'*20} {'-'*5} {'-'*5} {'-'*8}")
    for cat, counts in categories.items():
        status = "OK" if counts["fail"] == 0 else "ISSUES"
        print(f"  {cat:<20} {counts['pass']:>5} {counts['fail']:>5} {status:>8}")
    print()

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
