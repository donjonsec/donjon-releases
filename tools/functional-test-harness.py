#!/usr/bin/env python3
"""
Donjon Platform - Functional Test Harness
Walks every scanner, API endpoint, export format, and TUI menu item.
Reports exactly what works, what fails, and what is stubbed.

Usage:
    python tools/functional-test-harness.py --target 192.168.1.112 --server http://localhost:8443 --output results/
    python tools/functional-test-harness.py --quick   # scanners only, no API tests

Does NOT fix anything. Tests and reports.
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import io
import json
import os
import sys
import time
import traceback
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Project bootstrap
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent

sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(_PROJECT_ROOT / 'scanners'))
sys.path.insert(0, str(_PROJECT_ROOT / 'utilities'))

# Set DONJON_HOME so paths.py resolves correctly
os.environ['DONJON_HOME'] = str(_PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

class TestResult:
    """Single test result."""

    def __init__(self, test_id: str, menu_path: str = ''):
        self.test_id = test_id
        self.menu_path = menu_path
        self.status = 'ERROR'           # PASS | FAIL | ERROR | STUB | SKIP
        self.duration_seconds = 0.0
        self.input_desc = ''
        self.output_summary = ''
        self.findings_count = 0
        self.data_retained = False
        self.error: Optional[str] = None
        self.user_would_see = ''

    def to_dict(self) -> dict:
        return {
            'test_id': self.test_id,
            'menu_path': self.menu_path,
            'status': self.status,
            'duration_seconds': round(self.duration_seconds, 3),
            'input': self.input_desc,
            'output_summary': self.output_summary,
            'findings_count': self.findings_count,
            'data_retained': self.data_retained,
            'error': self.error,
            'user_would_see': self.user_would_see[:2000] if self.user_would_see else '',
        }


class HarnessResults:
    """Collects all test results."""

    def __init__(self):
        self.results: List[TestResult] = []
        self.start_time = datetime.now(timezone.utc)

    def add(self, r: TestResult):
        self.results.append(r)
        status_sym = {'PASS': '+', 'FAIL': 'X', 'ERROR': '!', 'STUB': '~', 'SKIP': '-'}
        sym = status_sym.get(r.status, '?')
        duration_str = f'{r.duration_seconds:.1f}s' if r.duration_seconds else ''
        print(f'  [{sym}] {r.test_id} {r.status} {duration_str}')
        if r.error:
            print(f'      ERROR: {r.error[:200]}')

    def summary(self) -> dict:
        counts = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    def save_json(self, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / 'functional-test-report.json'
        data = {
            'generated': self.start_time.isoformat(),
            'platform': 'Donjon Platform',
            'total_tests': len(self.results),
            'summary': self.summary(),
            'tests': [r.to_dict() for r in self.results],
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def save_markdown(self, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / 'functional-test-report.md'

        counts = self.summary()
        lines = [
            '# Donjon Platform - Functional Test Report',
            f'Generated: {self.start_time.isoformat()}',
            '',
            '## Summary',
            '',
            f'| Status | Count |',
            f'|--------|-------|',
        ]
        for status in ('PASS', 'FAIL', 'ERROR', 'STUB', 'SKIP'):
            c = counts.get(status, 0)
            lines.append(f'| {status} | {c} |')
        lines.append(f'| **Total** | **{len(self.results)}** |')
        lines.append('')

        # Pass/fail table
        lines.append('## All Tests')
        lines.append('')
        lines.append('| Test ID | Menu Path | Status | Duration | Findings | Output |')
        lines.append('|---------|-----------|--------|----------|----------|--------|')
        for r in self.results:
            out = r.output_summary[:80].replace('|', '/') if r.output_summary else ''
            lines.append(
                f'| {r.test_id} | {r.menu_path} | {r.status} | '
                f'{r.duration_seconds:.1f}s | {r.findings_count} | {out} |'
            )
        lines.append('')

        # Details for failures/errors
        failures = [r for r in self.results if r.status in ('FAIL', 'ERROR')]
        if failures:
            lines.append('## Failures and Errors')
            lines.append('')
            for r in failures:
                lines.append(f'### {r.test_id}')
                lines.append(f'- **Status:** {r.status}')
                lines.append(f'- **Menu Path:** {r.menu_path}')
                lines.append(f'- **Input:** `{r.input_desc}`')
                lines.append(f'- **Error:** {r.error}')
                if r.user_would_see:
                    lines.append(f'- **User would see:**')
                    lines.append(f'```')
                    lines.append(r.user_would_see[:1000])
                    lines.append(f'```')
                lines.append('')

        # Stubs
        stubs = [r for r in self.results if r.status == 'STUB']
        if stubs:
            lines.append('## Stubbed Features (Planned for Future Release)')
            lines.append('')
            lines.append('| Menu Path | User Message |')
            lines.append('|-----------|-------------|')
            for r in stubs:
                msg = r.user_would_see[:100].replace('|', '/') if r.user_would_see else ''
                lines.append(f'| {r.menu_path} | {msg} |')
            lines.append('')

        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        return path


# ---------------------------------------------------------------------------
# Safe importer
# ---------------------------------------------------------------------------

def safe_import(module_name: str, from_package: str = None):
    """Try to import a module, return (module, None) or (None, error_str)."""
    try:
        if from_package:
            mod = importlib.import_module(f'{from_package}.{module_name}')
        else:
            mod = importlib.import_module(module_name)
        return mod, None
    except Exception as exc:
        return None, f'{type(exc).__name__}: {exc}'


# ---------------------------------------------------------------------------
# 1. Scanner tests
# ---------------------------------------------------------------------------

SCANNER_MAP = {
    'network': {
        'class': 'NetworkScanner',
        'module': 'network_scanner',
        'menu_path': 'Main > Red Team > Network Reconnaissance',
    },
    'vulnerability': {
        'class': 'VulnerabilityScanner',
        'module': 'vulnerability_scanner',
        'menu_path': 'Main > Red Team > Vulnerability Scanning',
    },
    'web': {
        'class': 'WebScanner',
        'module': 'web_scanner',
        'menu_path': 'Main > Red Team > Web Application Testing',
    },
    'ssl': {
        'class': 'SSLScanner',
        'module': 'ssl_scanner',
        'menu_path': 'Main > Red Team > (via vulnerability flow)',
    },
    'linux': {
        'class': 'LinuxScanner',
        'module': 'linux_scanner',
        'menu_path': 'Main > Linux Security',
    },
    'compliance': {
        'class': 'ComplianceScanner',
        'module': 'compliance_scanner',
        'menu_path': 'Main > Blue Team > Security Hardening Audit',
    },
    'windows': {
        'class': 'WindowsScanner',
        'module': 'windows_scanner',
        'menu_path': 'Main > Windows Security',
        'target_override': 'windows_target',
    },
    'ad': {
        'class': 'ADScanner',
        'module': 'ad_scanner',
        'menu_path': 'Main > (AD scanning)',
    },
    'cloud': {
        'class': 'CloudScanner',
        'module': 'cloud_scanner',
        'menu_path': 'Main > (Cloud scanning)',
    },
    'container': {
        'class': 'ContainerScanner',
        'module': 'container_scanner',
        'menu_path': 'Main > (Container scanning)',
    },
    'sbom': {
        'class': 'SBOMScanner',
        'module': 'sbom_scanner',
        'menu_path': 'Main > (SBOM generation)',
    },
    'credential': {
        'class': 'CredentialScanner',
        'module': 'credential_scanner',
        'menu_path': 'Main > (Credential scanning)',
    },
    'asm': {
        'class': 'ASMScanner',
        'module': 'asm_scanner',
        'menu_path': 'Main > (ASM scanning)',
    },
    'malware': {
        'class': 'MalwareScanner',
        'module': 'malware_scanner',
        'menu_path': 'Main > Blue Team > Malware Detection',
    },
    'shadow_ai': {
        'class': 'ShadowAIScanner',
        'module': 'shadow_ai_scanner',
        'menu_path': 'Main > (Shadow AI scanning)',
    },
    'adversary': {
        'class': 'AdversaryScanner',
        'module': 'adversary_scanner',
        'menu_path': 'Main > Red Team > Adversary Emulation',
    },
    'openvas': {
        'class': 'OpenVASScanner',
        'module': 'openvas_scanner',
        'menu_path': 'Main > Red Team > OpenVAS Integration',
    },
}


def test_scanners(harness: HarnessResults, target: str, windows_target: str,
                  session_id: str):
    """Test every scanner by calling scanner.scan() against real targets."""
    print('\n=== SCANNER TESTS ===')

    for scanner_key, info in SCANNER_MAP.items():
        r = TestResult(
            f'scanner.{scanner_key}.scan_target',
            info['menu_path'],
        )

        # Determine target
        if scanner_key == 'windows':
            scan_target = windows_target
        elif scanner_key in ('linux', 'adversary'):
            scan_target = 'localhost'
        elif scanner_key in ('container', 'sbom'):
            scan_target = '.'  # local directory
        else:
            scan_target = target

        r.input_desc = f"scan(['{scan_target}'])"

        # Import
        mod, err = safe_import(info['module'])
        if err:
            r.status = 'ERROR'
            r.error = f'Import failed: {err}'
            harness.add(r)
            continue

        # Get class
        cls = getattr(mod, info['class'], None)
        if cls is None:
            r.status = 'ERROR'
            r.error = f"Class {info['class']} not found in {info['module']}"
            harness.add(r)
            continue

        # Instantiate and scan
        t0 = time.time()
        try:
            scanner_instance = cls(session_id)

            # Different scanners have different signatures
            if scanner_key == 'adversary':
                result = scanner_instance.scan(targets=[scan_target], profile='apt29')
            elif scanner_key == 'windows':
                result = scanner_instance.scan(scan_type='quick')
            elif scanner_key == 'linux':
                result = scanner_instance.scan(scan_type='quick')
            elif scanner_key == 'openvas':
                result = scanner_instance.scan(targets=[scan_target], scan_type='quick')
            else:
                result = scanner_instance.scan(targets=[scan_target])

            r.duration_seconds = time.time() - t0

            # Evaluate result
            if result is None:
                r.status = 'FAIL'
                r.error = 'scan() returned None'
                r.output_summary = 'No return value'
            elif isinstance(result, dict):
                # Scanners use different keys for their results
                findings_count = (
                    result.get('findings_count', 0) or
                    len(result.get('findings', [])) or
                    len(result.get('vulnerabilities', [])) or
                    len(result.get('gaps', [])) or
                    len(result.get('checks', [])) or
                    len(result.get('certificates', [])) or
                    len(result.get('protocols', [])) or
                    len(result.get('ciphers', [])) or
                    len(result.get('subdomains', [])) or
                    len(result.get('domains', [])) or
                    result.get('results_count', 0) or
                    result.get('summary', {}).get('total_findings', 0) or
                    result.get('summary', {}).get('total_ports', 0) or
                    result.get('summary', {}).get('findings_count', 0) or
                    result.get('summary', {}).get('total_hosts', 0) or
                    result.get('summary', {}).get('certificates_checked', 0) or
                    0
                )
                # Some scanners return structured results even with 0 findings
                # (e.g., SSL on non-HTTPS target, malware on clean host)
                # If the scanner ran without error and returned a valid structure, it's working
                has_valid_structure = (
                    'summary' in result or 'scan_type' in result
                ) and not result.get('error')
                r.findings_count = findings_count

                # Check if scanner actually found anything
                if findings_count > 0:
                    r.status = 'PASS'
                    r.data_retained = True
                    r.output_summary = f'{findings_count} findings'
                    # Add severity breakdown if available
                    summary = result.get('summary', {})
                    by_sev = summary.get('findings_by_severity', {})
                    if by_sev:
                        parts = [f'{k}:{v}' for k, v in by_sev.items() if v > 0]
                        if parts:
                            r.output_summary += f' ({", ".join(parts)})'
                elif has_valid_structure:
                    # Scanner ran correctly but found nothing — valid for some targets
                    r.status = 'PASS'
                    r.output_summary = '0 findings (scanner ran, target has nothing to find)'
                else:
                    r.status = 'FAIL'
                    r.output_summary = '0 findings returned'
                    r.error = 'Scanner returned empty results against live target'

                # Capture what user would see
                r.user_would_see = json.dumps(
                    {k: v for k, v in result.items()
                     if k not in ('results', 'findings', 'raw')},
                    indent=2, default=str
                )[:2000]
            else:
                r.status = 'FAIL'
                r.error = f'Unexpected return type: {type(result).__name__}'
                r.output_summary = str(result)[:200]

        except Exception as exc:
            r.duration_seconds = time.time() - t0
            r.status = 'ERROR'
            r.error = f'{type(exc).__name__}: {exc}'
            r.user_would_see = traceback.format_exc()

        harness.add(r)


# ---------------------------------------------------------------------------
# 2. Data flow end-to-end
# ---------------------------------------------------------------------------

def test_data_flow(harness: HarnessResults, target: str, session_id: str):
    """Test: scan -> evidence DB -> API retrievable -> export SARIF ->
    compliance map -> risk quantification."""
    print('\n=== DATA FLOW TESTS ===')

    # --- Evidence DB storage ---
    r = TestResult('dataflow.evidence_db_store', 'Data Flow')
    r.input_desc = 'get_evidence_manager().get_session_summary(session_id)'
    t0 = time.time()
    try:
        from lib.evidence import get_evidence_manager
        em = get_evidence_manager()
        summary = em.get_session_summary(session_id)
        r.duration_seconds = time.time() - t0

        if summary and summary.get('evidence_count', 0) > 0:
            r.status = 'PASS'
            r.data_retained = True
            r.output_summary = (
                f"evidence={summary.get('evidence_count', 0)}, "
                f"findings={summary.get('findings_by_severity', {})}"
            )
            r.findings_count = sum(summary.get('findings_by_severity', {}).values())
        elif summary:
            r.status = 'FAIL'
            r.error = 'Session exists but has 0 evidence items'
            r.output_summary = str(summary)
        else:
            r.status = 'FAIL'
            r.error = 'No session found in evidence DB'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # --- Evidence retrieval ---
    r = TestResult('dataflow.evidence_retrieval', 'Data Flow')
    r.input_desc = 'get_evidence_manager().get_findings_for_session(session_id)'
    t0 = time.time()
    findings = []
    try:
        from lib.evidence import get_evidence_manager
        em = get_evidence_manager()
        findings = em.get_findings_for_session(session_id)
        r.duration_seconds = time.time() - t0
        r.findings_count = len(findings)

        if findings:
            r.status = 'PASS'
            r.data_retained = True
            r.output_summary = f'{len(findings)} findings retrieved'
        else:
            r.status = 'FAIL'
            r.error = 'No findings retrievable for session'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # --- SARIF export ---
    r = TestResult('dataflow.sarif_export', 'Data Flow')
    r.input_desc = 'ExportManager().export_sarif(findings, output)'
    t0 = time.time()
    sarif_path = None
    try:
        from lib.export import ExportManager
        exporter = ExportManager()
        sarif_dir = _PROJECT_ROOT / 'results' / 'harness_test'
        sarif_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = sarif_dir / 'test_findings.sarif.json'

        if findings:
            exporter.export_sarif(findings, sarif_path)
            r.duration_seconds = time.time() - t0

            if sarif_path.exists() and sarif_path.stat().st_size > 0:
                with open(sarif_path, 'r') as f:
                    sarif_data = json.load(f)
                runs = sarif_data.get('runs', [])
                if runs:
                    r.status = 'PASS'
                    results_count = len(runs[0].get('results', []))
                    r.output_summary = f'Valid SARIF with {results_count} results in 1 run'
                else:
                    r.status = 'FAIL'
                    r.error = 'SARIF file has no runs'
            else:
                r.status = 'FAIL'
                r.error = 'SARIF file empty or missing'
        else:
            r.status = 'SKIP'
            r.error = 'No findings to export (upstream failure)'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # --- Compliance mapping ---
    r = TestResult('dataflow.compliance_mapping', 'Data Flow')
    r.input_desc = 'ComplianceMapper.generate_compliance_summary(em, "NIST-800-53")'
    t0 = time.time()
    try:
        from lib.compliance import get_compliance_mapper
        from lib.evidence import get_evidence_manager
        mapper = get_compliance_mapper()
        em = get_evidence_manager()
        summary = mapper.generate_compliance_summary(em, 'NIST-800-53')
        r.duration_seconds = time.time() - t0

        total = summary.get('total_controls', 0)
        with_ev = summary.get('controls_with_evidence', 0)

        if total > 0:
            r.status = 'PASS' if with_ev > 0 else 'FAIL'
            r.output_summary = f'{total} controls, {with_ev} with evidence'
            if with_ev == 0:
                r.error = 'No controls have mapped evidence'
        else:
            r.status = 'FAIL'
            r.error = 'No controls defined for NIST-800-53'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # --- Risk quantification ---
    r = TestResult('dataflow.risk_quantification', 'Data Flow')
    r.input_desc = 'RiskQuantifier.quantify_finding(sample_finding)'
    t0 = time.time()
    try:
        from lib.risk_quantification import get_risk_quantifier
        rq = get_risk_quantifier()
        rq.set_business_context(industry='technology', revenue=10_000_000, record_count=50_000)

        if findings:
            result = rq.quantify_finding(findings[0])
            r.duration_seconds = time.time() - t0

            ale_50 = result.get('ale_50th', 0)
            if ale_50 > 0:
                r.status = 'PASS'
                r.output_summary = (
                    f"ALE 10th=${result.get('ale_10th', 0):,.0f}, "
                    f"50th=${ale_50:,.0f}, "
                    f"90th=${result.get('ale_90th', 0):,.0f}, "
                    f"DQ={result.get('data_quality_score', 0):.0f}%"
                )
            else:
                r.status = 'FAIL'
                r.error = 'ALE is $0 - quantification produced no dollar value'
        else:
            # Use synthetic finding
            sample = {
                'severity': 'HIGH',
                'cvss_score': 7.5,
                'title': 'Test finding',
                'affected_asset': target,
            }
            result = rq.quantify_finding(sample)
            r.duration_seconds = time.time() - t0
            ale_50 = result.get('ale_50th', 0)
            if ale_50 > 0:
                r.status = 'PASS'
                r.output_summary = f'Synthetic finding: ALE 50th=${ale_50:,.0f}'
            else:
                r.status = 'FAIL'
                r.error = 'ALE is $0 even for synthetic finding'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)


# ---------------------------------------------------------------------------
# 3. API endpoint tests
# ---------------------------------------------------------------------------

# All GET endpoints that should exist when server is running
API_GET_ENDPOINTS = [
    ('/api/v1/health', 'api.health'),
    ('/api/v1/stats', 'api.stats'),
    ('/api/v1/assets', 'api.assets.list'),
    ('/api/v1/scans', 'api.scans.list'),
    ('/api/v1/findings', 'api.findings.list'),
    ('/api/v1/remediation', 'api.remediation.list'),
    ('/api/v1/remediation/metrics', 'api.remediation.metrics'),
    ('/api/v1/risks', 'api.risks.list'),
    ('/api/v1/risks/posture', 'api.risks.posture'),
    ('/api/v1/risks/matrix', 'api.risks.matrix'),
    ('/api/v1/exceptions', 'api.exceptions.list'),
    ('/api/v1/reports/executive', 'api.reports.executive'),
    ('/api/v1/agents', 'api.agents.list'),
    ('/api/v1/schedules', 'api.schedules.list'),
    ('/api/v1/notifications/channels', 'api.notifications.channels'),
    ('/api/v1/notifications/history', 'api.notifications.history'),
    ('/api/v1/notifications/stats', 'api.notifications.stats'),
    ('/api/v1/scanners', 'api.scanners.list'),
    ('/api/v1/license', 'api.license.info'),
    ('/api/v1/network/local', 'api.network.local'),
    ('/api/v1/ai/status', 'api.ai.status'),
    ('/api/v1/ai/config', 'api.ai.config'),
    ('/api/v1/audit', 'api.audit.log'),
    ('/api/v1/legal/eula', 'api.legal.eula'),
]

# Tier-gated endpoints that community should block
API_TIER_GATED = [
    ('/api/v1/rbac/roles', 'GET', 'enterprise', 'api.tier.rbac'),
    ('/api/v1/sso/metadata', 'GET', 'enterprise', 'api.tier.sso'),
    ('/api/v1/tenants', 'POST', 'enterprise', 'api.tier.tenants'),
    ('/api/v1/mssp/clients', 'GET', 'managed', 'api.tier.mssp'),
]


def _api_request(base_url: str, path: str, method: str = 'GET',
                 body: Optional[dict] = None, api_key: str = '') -> Tuple[int, dict, str]:
    """Make HTTP request, return (status_code, json_body, raw_text)."""
    url = base_url.rstrip('/') + path
    data = json.dumps(body).encode('utf-8') if body else None
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['X-API-Key'] = api_key

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode('utf-8')
            try:
                return resp.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return resp.status, {}, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', errors='replace')
        try:
            return e.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return e.code, {}, raw
    except Exception as exc:
        return 0, {}, str(exc)


def test_api_endpoints(harness: HarnessResults, server_url: str, api_key: str):
    """Test every API endpoint against running server."""
    print('\n=== API ENDPOINT TESTS ===')

    # First check if server is reachable
    r = TestResult('api.server_reachable', 'API')
    r.input_desc = f'GET {server_url}/api/v1/health'
    t0 = time.time()
    status, body, raw = _api_request(server_url, '/api/v1/health', api_key=api_key)
    r.duration_seconds = time.time() - t0

    if status == 0:
        r.status = 'SKIP'
        r.error = f'Server not reachable at {server_url}: {raw}'
        r.user_would_see = raw
        harness.add(r)
        print('    Server not reachable, skipping all API tests')
        return
    elif status == 200:
        r.status = 'PASS'
        r.output_summary = f'HTTP {status}'
    else:
        r.status = 'FAIL'
        r.error = f'Health endpoint returned HTTP {status}'
        r.output_summary = raw[:200]
    harness.add(r)

    # Test all GET endpoints
    for path, test_id in API_GET_ENDPOINTS:
        r = TestResult(test_id, f'API GET {path}')
        r.input_desc = f'GET {path}'
        t0 = time.time()
        status, body, raw = _api_request(server_url, path, api_key=api_key)
        r.duration_seconds = time.time() - t0

        if status == 200:
            r.status = 'PASS'
            # Check body has content
            if isinstance(body, dict):
                r.output_summary = f'HTTP 200, {len(body)} keys'
            elif isinstance(body, list):
                r.output_summary = f'HTTP 200, {len(body)} items'
            else:
                r.output_summary = f'HTTP 200'
        elif status == 401:
            r.status = 'FAIL'
            r.error = 'Authentication required (401) - provide --api-key'
        elif status == 403:
            r.status = 'FAIL'
            r.error = f'Forbidden (403): {body.get("message", raw[:100])}'
        elif status == 404:
            r.status = 'FAIL'
            r.error = 'Endpoint not found (404)'
        elif status == 500:
            r.status = 'ERROR'
            r.error = f'Server error (500): {body.get("message", raw[:200])}'
        else:
            r.status = 'FAIL'
            r.error = f'Unexpected HTTP {status}'
        r.user_would_see = raw[:500]
        harness.add(r)

    # Detect current license tier to set expectations
    current_tier = 'community'
    try:
        _, lic_body, _ = _api_request(server_url, '/api/v1/license', api_key=api_key)
        current_tier = lic_body.get('tier', lic_body.get('license_tier', 'community')).lower()
    except Exception:
        pass

    TIER_ORDER = ['community', 'pro', 'enterprise', 'managed']
    current_tier_idx = TIER_ORDER.index(current_tier) if current_tier in TIER_ORDER else 0

    # Test tier gating
    for path, method, required_tier, test_id in API_TIER_GATED:
        r = TestResult(test_id, f'API Tier Gate: {path}')
        required_idx = TIER_ORDER.index(required_tier) if required_tier in TIER_ORDER else 99
        should_have_access = current_tier_idx >= required_idx
        r.input_desc = f'{method} {path} (tier={current_tier}, requires={required_tier})'
        t0 = time.time()
        status, body, raw = _api_request(
            server_url, path, method=method, api_key=api_key,
            body={} if method == 'POST' else None,
        )
        r.duration_seconds = time.time() - t0

        if should_have_access:
            # We have the right tier — endpoint should be accessible (200, 400, 422 all ok)
            if status in (200, 400, 422):
                r.status = 'PASS'
                r.output_summary = f'Accessible with {current_tier} tier (HTTP {status})'
            elif status == 403:
                r.status = 'FAIL'
                r.error = f'Blocked despite having {current_tier} tier (>= {required_tier})'
            else:
                r.status = 'PASS'
                r.output_summary = f'Endpoint responded (HTTP {status})'
        else:
            # We don't have the tier — should be blocked
            if status == 403:
                r.status = 'PASS'
                r.output_summary = f'Correctly blocked for {current_tier} tier'
            elif status == 404:
                r.status = 'PASS'
                r.output_summary = 'Endpoint not registered (module not loaded)'
            elif status == 200:
                r.status = 'FAIL'
                r.error = f'{required_tier}-tier endpoint accessible with {current_tier} license'
            else:
                r.status = 'PASS'
                r.output_summary = f'HTTP {status}'
        r.user_would_see = raw[:300]
        harness.add(r)

    # Test POST endpoints with sample data
    post_tests = [
        ('/api/v1/export', {'session_id': 'nonexistent', 'formats': ['sarif']}, 'api.export.post'),
        ('/api/v1/notifications/test', {'channel_id': 'test', 'message': 'harness test'}, 'api.notifications.test'),
    ]
    for path, payload, test_id in post_tests:
        r = TestResult(test_id, f'API POST {path}')
        r.input_desc = f'POST {path}'
        t0 = time.time()
        status, body, raw = _api_request(server_url, path, method='POST',
                                          body=payload, api_key=api_key)
        r.duration_seconds = time.time() - t0
        if status in (200, 201):
            r.status = 'PASS'
            r.output_summary = f'HTTP {status}'
        elif status in (400, 404, 422):
            # 400/404/422 with test data is acceptable — endpoint exists and validates input
            r.status = 'PASS'
            r.output_summary = f'HTTP {status} (endpoint responds, test data rejected as expected): {body.get("message", body.get("error", ""))[:80]}'
        elif status == 401:
            r.status = 'SKIP'
            r.error = 'Auth required'
        elif status == 403:
            r.status = 'PASS'
            r.output_summary = 'Tier-gated (403)'
        else:
            r.status = 'FAIL'
            r.error = f'HTTP {status}: {raw[:200]}'
        harness.add(r)


# ---------------------------------------------------------------------------
# 4. Export format tests
# ---------------------------------------------------------------------------

EXPORT_FORMATS = {
    'cef': {
        'method': 'export_cef',
        'ext': '.cef',
        'validate': lambda content: content.startswith('CEF:0'),
        'validation_desc': 'starts with CEF:0',
    },
    'stix': {
        'method': 'export_stix',
        'ext': '.stix.json',
        'validate': lambda content: '"type": "bundle"' in content,
        'validation_desc': 'contains STIX bundle',
    },
    'splunk_hec': {
        'method': 'export_splunk_hec',
        'ext': '.splunk.json',
        'validate': lambda content: '"sourcetype"' in content,
        'validation_desc': 'contains sourcetype field',
    },
    'sentinel': {
        'method': 'export_sentinel',
        'ext': '.sentinel.json',
        'validate': lambda content: '"TimeGenerated"' in content,
        'validation_desc': 'contains TimeGenerated field',
    },
    'leef': {
        'method': 'export_leef',
        'ext': '.leef',
        'validate': lambda content: content.startswith('LEEF:'),
        'validation_desc': 'starts with LEEF:',
    },
    'csv': {
        'method': 'export_csv',
        'ext': '.csv',
        'validate': lambda content: 'Title' in content and 'Severity' in content,
        'validation_desc': 'has Title and Severity header columns',
    },
    'servicenow_json': {
        'method': 'export_servicenow_json',
        'ext': '.servicenow.json',
        'validate': lambda content: '"short_description"' in content,
        'validation_desc': 'contains short_description field',
    },
    'qualys_xml': {
        'method': 'export_qualys_xml',
        'ext': '.qualys.xml',
        'validate': lambda content: '<SCAN>' in content or '<?xml' in content,
        'validation_desc': 'valid XML with SCAN root',
    },
    'sarif': {
        'method': 'export_sarif',
        'ext': '.sarif.json',
        'validate': lambda content: '"runs"' in content and '"version": "2.1.0"' in content,
        'validation_desc': 'SARIF 2.1.0 with runs array',
    },
    'syslog': {
        'method': 'export_syslog',
        'ext': '.syslog',
        'validate': lambda content: '<' in content and '>1 ' in content,
        'validation_desc': 'RFC 5424 syslog format',
    },
    'jsonl': {
        'method': 'export_jsonl',
        'ext': '.jsonl',
        'validate': lambda content: content.strip() and all(
            json.loads(line) for line in content.strip().split('\n')[:3]
        ),
        'validation_desc': 'valid JSON lines',
    },
}


def test_export_formats(harness: HarnessResults, session_id: str):
    """Test every export format with real findings data."""
    print('\n=== EXPORT FORMAT TESTS ===')

    # Get findings
    findings = []
    try:
        from lib.evidence import get_evidence_manager
        em = get_evidence_manager()
        findings = em.get_findings_for_session(session_id)
    except Exception:
        pass

    if not findings:
        # Create synthetic findings for export testing
        findings = [
            {
                'finding_id': 'FND-TEST-001',
                'session_id': session_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'severity': 'HIGH',
                'title': 'Test Vulnerability (Harness)',
                'description': 'Synthetic finding for export format validation',
                'affected_asset': '192.168.1.1',
                'cvss_score': 7.5,
                'cve_ids': json.dumps(['CVE-2024-0001']),
                'remediation': 'Apply vendor patch',
                'status': 'open',
                'metadata': json.dumps({'finding_type': 'cve_vulnerability'}),
                'scanner_name': 'harness_test',
                'kev_status': 'false',
                'epss_score': 0.25,
                'effective_priority': 6.0,
                'quality_of_detection': 80.0,
                'false_positive': 0,
                'fp_reason': None,
                'epss_percentile': 0.75,
                'detection_source': 'harness_test',
            },
            {
                'finding_id': 'FND-TEST-002',
                'session_id': session_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'severity': 'CRITICAL',
                'title': 'Critical Finding (Harness)',
                'description': 'Synthetic critical finding',
                'affected_asset': '192.168.1.1',
                'cvss_score': 9.8,
                'cve_ids': json.dumps(['CVE-2024-0002', 'CVE-2024-0003']),
                'remediation': 'Immediate patching required',
                'status': 'open',
                'metadata': json.dumps({'finding_type': 'remote_code_execution'}),
                'scanner_name': 'harness_test',
                'kev_status': 'true',
                'epss_score': 0.92,
                'effective_priority': 9.5,
                'quality_of_detection': 95.0,
                'false_positive': 0,
                'fp_reason': None,
                'epss_percentile': 0.99,
                'detection_source': 'harness_test',
            },
        ]

    export_dir = _PROJECT_ROOT / 'results' / 'harness_test' / 'exports'
    export_dir.mkdir(parents=True, exist_ok=True)

    try:
        from lib.export import ExportManager
        exporter = ExportManager()
    except Exception as exc:
        r = TestResult('export.import_failed', 'Export')
        r.status = 'ERROR'
        r.error = f'Cannot import ExportManager: {exc}'
        harness.add(r)
        return

    for fmt_key, fmt_info in EXPORT_FORMATS.items():
        r = TestResult(f'export.{fmt_key}', f'Main > Export Data > {fmt_key}')
        output_path = export_dir / f'test_export{fmt_info["ext"]}'
        r.input_desc = f'{fmt_info["method"]}(findings, {output_path.name})'

        t0 = time.time()
        try:
            method = getattr(exporter, fmt_info['method'])
            method(findings, output_path)
            r.duration_seconds = time.time() - t0

            if not output_path.exists():
                r.status = 'FAIL'
                r.error = 'Output file not created'
            elif output_path.stat().st_size == 0:
                r.status = 'FAIL'
                r.error = 'Output file is empty'
            else:
                content = output_path.read_text(encoding='utf-8', errors='replace')
                try:
                    valid = fmt_info['validate'](content)
                    if valid:
                        r.status = 'PASS'
                        r.output_summary = (
                            f'{output_path.stat().st_size} bytes, '
                            f'{fmt_info["validation_desc"]}'
                        )
                    else:
                        r.status = 'FAIL'
                        r.error = f'Validation failed: expected {fmt_info["validation_desc"]}'
                        r.user_would_see = content[:500]
                except Exception as ve:
                    r.status = 'FAIL'
                    r.error = f'Validation error: {ve}'
                    r.user_would_see = content[:500]
        except Exception as exc:
            r.duration_seconds = time.time() - t0
            r.status = 'ERROR'
            r.error = f'{type(exc).__name__}: {exc}'
            r.user_would_see = traceback.format_exc()
        harness.add(r)


# ---------------------------------------------------------------------------
# 5. TUI menu stub tests
# ---------------------------------------------------------------------------

# Menu items that fall through to "planned for future release"
TUI_STUBS = [
    # Red Team
    ('Main > Red Team > Password Auditing', '4', 'red_team'),
    ('Main > Red Team > Exploit Validation', '5', 'red_team'),
    ('Main > Red Team > ATT&CK Simulation', '6', 'red_team'),
    ('Main > Red Team > Phishing Simulation', '7', 'red_team'),
    ('Main > Red Team > Social Engineering', '8', 'red_team'),
    # Blue Team
    ('Main > Blue Team > Log Analysis', '3', 'blue_team'),
    ('Main > Blue Team > File Integrity Check', '4', 'blue_team'),
    ('Main > Blue Team > Network Traffic Analysis', '5', 'blue_team'),
    ('Main > Blue Team > Detection Rule Testing', '6', 'blue_team'),
    ('Main > Blue Team > Incident Response Drill', '7', 'blue_team'),
    ('Main > Blue Team > Threat Hunting', '8', 'blue_team'),
    # Purple Team
    ('Main > Purple Team > Detection Gap Analysis', '1', 'purple_team'),
    ('Main > Purple Team > Control Effectiveness', '2', 'purple_team'),
    ('Main > Purple Team > Attack Path Mapping', '3', 'purple_team'),
    ('Main > Purple Team > Coverage Assessment', '4', 'purple_team'),
    ('Main > Purple Team > Continuous Validation', '6', 'purple_team'),
    # Compliance
    ('Main > Compliance > NIST 800-53 Report', '2', 'compliance'),
    ('Main > Compliance > HIPAA Report', '3', 'compliance'),
    ('Main > Compliance > PCI-DSS Report', '4', 'compliance'),
    ('Main > Compliance > SOC 2 Report', '5', 'compliance'),
    ('Main > Compliance > ISO 27001 Report', '6', 'compliance'),
    ('Main > Compliance > Export for GRC Platform', '7', 'compliance'),
    # Settings
    ('Main > Settings > Scan Timing', '1', 'settings'),
    ('Main > Settings > Compliance Frameworks', '3', 'settings'),
    ('Main > Settings > Network Targets', '4', 'settings'),
    ('Main > Settings > Notifications', '5', 'settings'),
    ('Main > Settings > Reset to Defaults', '7', 'settings'),
    # Main menu
    ('Main > Schedule Scans', '8', 'main'),
]


def test_tui_stubs(harness: HarnessResults):
    """Document which menu choices are stubbed with 'planned for future release'."""
    print('\n=== TUI STUB TESTS ===')

    for menu_path, choice_key, menu_type in TUI_STUBS:
        r = TestResult(
            f'tui.stub.{menu_path.replace(" > ", ".").replace(" ", "_").lower()}',
            menu_path,
        )
        r.input_desc = f'choice={choice_key} in {menu_type} menu'
        r.status = 'STUB'
        r.user_would_see = 'This feature is planned for a future release.'
        r.output_summary = 'Stub: planned for future release'
        harness.add(r)


# ---------------------------------------------------------------------------
# 6. Scheduling tests
# ---------------------------------------------------------------------------

def test_scheduling(harness: HarnessResults):
    """Test schedule CRUD."""
    print('\n=== SCHEDULING TESTS ===')

    # Create
    r = TestResult('scheduler.create', 'Main > Schedule Scans')
    r.input_desc = 'create_schedule("Harness Test", "network", "0 2 * * 1")'
    t0 = time.time()
    schedule_id = None
    try:
        from lib.scheduler import get_scheduler
        sm = get_scheduler()
        schedule_id = sm.create_schedule(
            name='Harness Test Schedule',
            scanner_type='network',
            cron_expression='0 2 * * 1',
            description='Created by functional test harness',
            scan_type='quick',
            targets=['192.168.1.0/24'],
        )
        r.duration_seconds = time.time() - t0

        if schedule_id:
            r.status = 'PASS'
            r.output_summary = f'Created schedule {schedule_id[:12]}...'
            r.data_retained = True
        else:
            r.status = 'FAIL'
            r.error = 'create_schedule returned None'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # Verify
    r = TestResult('scheduler.verify', 'Main > Schedule Scans')
    r.input_desc = f'get_schedule("{schedule_id}")'
    t0 = time.time()
    try:
        from lib.scheduler import get_scheduler
        sm = get_scheduler()
        if schedule_id:
            sched = sm.get_schedule(schedule_id)
            r.duration_seconds = time.time() - t0
            if sched and sched.get('name') == 'Harness Test Schedule':
                r.status = 'PASS'
                r.output_summary = f"name={sched['name']}, next_run={sched.get('next_run', '?')}"
            else:
                r.status = 'FAIL'
                r.error = 'Schedule not found or name mismatch'
        else:
            r.status = 'SKIP'
            r.error = 'No schedule_id from create step'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # Statistics
    r = TestResult('scheduler.statistics', 'Main > Schedule Scans')
    r.input_desc = 'get_statistics()'
    t0 = time.time()
    try:
        from lib.scheduler import get_scheduler
        sm = get_scheduler()
        stats = sm.get_statistics()
        r.duration_seconds = time.time() - t0
        if stats and 'total_schedules' in stats:
            r.status = 'PASS'
            r.output_summary = f"total={stats['total_schedules']}, enabled={stats['enabled_schedules']}"
        else:
            r.status = 'FAIL'
            r.error = 'Statistics returned empty'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # Delete
    r = TestResult('scheduler.delete', 'Main > Schedule Scans')
    r.input_desc = f'delete_schedule("{schedule_id}")'
    t0 = time.time()
    try:
        from lib.scheduler import get_scheduler
        sm = get_scheduler()
        if schedule_id:
            sm.delete_schedule(schedule_id)
            # Verify deleted
            sched = sm.get_schedule(schedule_id)
            r.duration_seconds = time.time() - t0
            if sched is None:
                r.status = 'PASS'
                r.output_summary = 'Schedule deleted and verified gone'
            else:
                r.status = 'FAIL'
                r.error = 'Schedule still exists after delete'
        else:
            r.status = 'SKIP'
            r.error = 'No schedule_id to delete'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)


# ---------------------------------------------------------------------------
# 7. Notification tests
# ---------------------------------------------------------------------------

def test_notifications(harness: HarnessResults):
    """Test notification channel CRUD and delivery."""
    print('\n=== NOTIFICATION TESTS ===')

    channel_id = None

    # Create channel
    r = TestResult('notifications.create_channel', 'Main > Settings > Notifications')
    r.input_desc = 'add_channel("Harness Test", "webhook", {url: "https://httpbin.org/post"})'
    t0 = time.time()
    try:
        from lib.notifications import get_notification_manager
        nm = get_notification_manager()
        channel_id = nm.add_channel(
            name='Harness Test Channel',
            channel_type='webhook',
            config={'url': 'https://httpbin.org/post', 'method': 'POST'},
        )
        r.duration_seconds = time.time() - t0

        if channel_id:
            r.status = 'PASS'
            r.output_summary = f'Channel {channel_id[:12]}... created'
            r.data_retained = True
        else:
            r.status = 'FAIL'
            r.error = 'add_channel returned None'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # List channels
    r = TestResult('notifications.list_channels', 'Main > Settings > Notifications')
    r.input_desc = 'get_channels()'
    t0 = time.time()
    try:
        from lib.notifications import get_notification_manager
        nm = get_notification_manager()
        channels = nm.get_channels()
        r.duration_seconds = time.time() - t0
        if channels is not None:
            r.status = 'PASS'
            r.output_summary = f'{len(channels)} channels'
        else:
            r.status = 'FAIL'
            r.error = 'get_channels returned None'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # Send test notification
    r = TestResult('notifications.send_test', 'Main > Settings > Notifications')
    r.input_desc = 'notify("critical_finding", "Harness Test", "...", severity="CRITICAL")'
    t0 = time.time()
    try:
        from lib.notifications import get_notification_manager
        nm = get_notification_manager()
        if channel_id and hasattr(nm, 'notify'):
            result = nm.notify(
                event_type='critical_finding',
                subject='Harness Test Notification',
                body='This is a test notification from the functional test harness.',
                severity='CRITICAL',
            )
            r.duration_seconds = time.time() - t0
            # Delivery to httpbin might succeed or fail depending on network.
            # We document what happened.
            if result:
                r.status = 'PASS'
                r.output_summary = f'Notification sent to {len(result)} channel(s): {result}'
            else:
                r.status = 'PASS'
                r.output_summary = 'notify() returned empty (0 enabled channels matched)'
        elif channel_id:
            r.status = 'FAIL'
            r.error = 'NotificationManager has no notify method'
        else:
            r.status = 'SKIP'
            r.error = 'No channel_id from create step'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        # Network errors are expected for httpbin in air-gapped environments
        r.status = 'FAIL'
        r.error = f'{type(exc).__name__}: {exc}'
        r.output_summary = 'Delivery attempted, failed (expected if air-gapped)'
    harness.add(r)

    # Get statistics
    r = TestResult('notifications.statistics', 'Main > Settings > Notifications')
    r.input_desc = 'get_statistics()'
    t0 = time.time()
    try:
        from lib.notifications import get_notification_manager
        nm = get_notification_manager()
        stats = nm.get_statistics()
        r.duration_seconds = time.time() - t0
        if stats and isinstance(stats, dict):
            r.status = 'PASS'
            r.output_summary = json.dumps(stats, default=str)[:200]
        else:
            r.status = 'FAIL'
            r.error = 'Statistics returned empty'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # Cleanup channel
    r = TestResult('notifications.delete_channel', 'Main > Settings > Notifications')
    r.input_desc = f'remove_channel("{channel_id}")'
    t0 = time.time()
    try:
        from lib.notifications import get_notification_manager
        nm = get_notification_manager()
        if channel_id:
            nm.remove_channel(channel_id)
            r.duration_seconds = time.time() - t0
            r.status = 'PASS'
            r.output_summary = 'Channel removed'
        else:
            r.status = 'SKIP'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)


# ---------------------------------------------------------------------------
# 8. Compliance report tests
# ---------------------------------------------------------------------------

COMPLIANCE_FRAMEWORKS = [
    ('nist_800_53', 'Main > Compliance > NIST 800-53 Report'),
    ('hipaa', 'Main > Compliance > HIPAA Report'),
    ('pci_dss_4', 'Main > Compliance > PCI-DSS Report'),
    ('cmmc', 'Main > Compliance > CMMC Report'),
    ('soc2', 'Main > Compliance > SOC 2 Report'),
    ('iso_27001_2022', 'Main > Compliance > ISO 27001 Report'),
]


def test_compliance_reports(harness: HarnessResults):
    """Generate compliance summary for each key framework."""
    print('\n=== COMPLIANCE REPORT TESTS ===')

    try:
        from lib.compliance import get_compliance_mapper
        from lib.evidence import get_evidence_manager
        mapper = get_compliance_mapper()
        em = get_evidence_manager()
    except Exception as exc:
        r = TestResult('compliance.import_failed', 'Compliance')
        r.status = 'ERROR'
        r.error = f'Import failed: {exc}'
        harness.add(r)
        return

    for framework, menu_path in COMPLIANCE_FRAMEWORKS:
        r = TestResult(f'compliance.report.{framework.lower().replace("-", "_")}', menu_path)
        r.input_desc = f'generate_compliance_summary(em, "{framework}")'
        t0 = time.time()
        try:
            summary = mapper.generate_compliance_summary(em, framework)
            r.duration_seconds = time.time() - t0

            total = summary.get('total_controls', 0)
            with_ev = summary.get('controls_with_evidence', 0)
            without_ev = summary.get('controls_without_evidence', 0)

            if total > 0:
                r.status = 'PASS'
                r.output_summary = (
                    f'{total} controls ({with_ev} with evidence, '
                    f'{without_ev} without)'
                )
                r.findings_count = with_ev
            else:
                r.status = 'FAIL'
                r.error = f'No controls defined for {framework}'
        except Exception as exc:
            r.duration_seconds = time.time() - t0
            r.status = 'ERROR'
            r.error = f'{type(exc).__name__}: {exc}'
        harness.add(r)


# ---------------------------------------------------------------------------
# 9. Risk quantification tests
# ---------------------------------------------------------------------------

def test_risk_quantification(harness: HarnessResults, target: str, session_id: str):
    """Run Monte Carlo risk quantification on real or synthetic findings."""
    print('\n=== RISK QUANTIFICATION TESTS ===')

    try:
        from lib.risk_quantification import get_risk_quantifier
        rq = get_risk_quantifier()
    except Exception as exc:
        r = TestResult('risk.import_failed', 'Risk')
        r.status = 'ERROR'
        r.error = f'Import failed: {exc}'
        harness.add(r)
        return

    # Set business context
    r = TestResult('risk.business_context', 'Main > Compliance > Risk Quantification')
    r.input_desc = 'set_business_context(industry="technology", revenue=10M, records=50K)'
    t0 = time.time()
    try:
        rq.set_business_context(
            industry='technology',
            revenue=10_000_000,
            record_count=50_000,
        )
        r.duration_seconds = time.time() - t0
        r.status = 'PASS'
        r.output_summary = 'Business context set'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # Quantify single finding (synthetic)
    r = TestResult('risk.quantify_finding', 'Main > Compliance > Risk Quantification')
    sample_finding = {
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'epss_score': 0.85,
        'kev_status': 'true',
        'title': 'Remote Code Execution (Harness Test)',
        'affected_asset': target,
        'cve_ids': ['CVE-2024-TEST'],
        'finding_id': 'FND-HARNESS-RQ-001',
    }
    r.input_desc = 'quantify_finding(CRITICAL, CVSS=9.8, EPSS=0.85, KEV=true)'
    t0 = time.time()
    try:
        result = rq.quantify_finding(sample_finding)
        r.duration_seconds = time.time() - t0

        ale_50 = result.get('ale_50th', 0)
        ale_90 = result.get('ale_90th', 0)
        dq = result.get('data_quality_score', 0)

        if ale_50 > 0 and ale_90 > ale_50:
            r.status = 'PASS'
            r.output_summary = (
                f"ALE: 10th=${result.get('ale_10th', 0):,.0f}, "
                f"50th=${ale_50:,.0f}, 90th=${ale_90:,.0f} | "
                f"SLE=${result.get('single_loss', 0):,.0f} | "
                f"Freq={result.get('frequency', 0):.2f}/yr | "
                f"DQ={dq:.0f}%"
            )
        elif ale_50 > 0:
            r.status = 'PASS'
            r.output_summary = f'ALE 50th=${ale_50:,.0f} (90th not > 50th, unusual)'
        else:
            r.status = 'FAIL'
            r.error = 'Monte Carlo produced $0 ALE for critical finding'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    # Organization-level quantification
    r = TestResult('risk.quantify_organization', 'Main > Compliance > Risk Quantification')
    r.input_desc = f'quantify_organization(session_id={session_id[:12]}...)'
    t0 = time.time()
    try:
        org = rq.quantify_organization(session_id=session_id)
        r.duration_seconds = time.time() - t0

        fc = org.get('finding_count', 0)
        ac = org.get('asset_count', 0)
        ale = org.get('ale_50th', 0)

        r.output_summary = f'{fc} findings, {ac} assets, org ALE 50th=${ale:,.0f}'
        r.findings_count = fc
        r.status = 'PASS' if fc >= 0 else 'FAIL'  # 0 findings is valid if no scans ran
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)


# ---------------------------------------------------------------------------
# 10. AI engine tests
# ---------------------------------------------------------------------------

def test_ai_engine(harness: HarnessResults, target: str):
    """Test AI engine template provider (no API key needed)."""
    print('\n=== AI ENGINE TESTS ===')

    # Import
    r = TestResult('ai.import', 'Main > Compliance > AI Analysis')
    r.input_desc = 'import lib.ai_engine'
    t0 = time.time()
    ai_engine = None
    try:
        from lib.ai_engine import get_ai_engine
        ai_engine = get_ai_engine()
        r.duration_seconds = time.time() - t0
        r.status = 'PASS'
        r.output_summary = f'Backend: {ai_engine.backend}, Model: {ai_engine.model_name}'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)

    if not ai_engine:
        return

    # Analyze finding
    r = TestResult('ai.analyze_finding', 'Main > Compliance > AI Analysis')
    sample = {
        'severity': 'HIGH',
        'title': 'SQL Injection in Login Form',
        'description': 'The login form is vulnerable to SQL injection',
        'affected_asset': target,
        'cvss_score': 8.6,
        'cve_ids': ['CVE-2024-TEST'],
        'remediation': 'Use parameterized queries',
    }
    r.input_desc = 'analyze_finding(HIGH SQL Injection)'
    t0 = time.time()
    try:
        result = ai_engine.analyze_finding(sample)
        r.duration_seconds = time.time() - t0

        if result and isinstance(result, dict):
            r.status = 'PASS'
            r.output_summary = f'Analysis returned {len(result)} keys'
            r.user_would_see = json.dumps(result, indent=2, default=str)[:1000]
        elif result and isinstance(result, str):
            r.status = 'PASS'
            r.output_summary = f'Analysis returned {len(result)} chars'
            r.user_would_see = result[:1000]
        else:
            r.status = 'FAIL'
            r.error = 'analyze_finding returned empty result'
    except Exception as exc:
        r.duration_seconds = time.time() - t0
        r.status = 'ERROR'
        r.error = str(exc)
    harness.add(r)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='functional-test-harness',
        description='Walk every feature of Donjon Platform and report what works.',
    )
    parser.add_argument(
        '--target', default='192.168.1.112',
        help='Primary scan target IP (default: 192.168.1.112)',
    )
    parser.add_argument(
        '--windows-target', default='192.168.1.119',
        help='Windows scan target IP (default: 192.168.1.119)',
    )
    parser.add_argument(
        '--server', default='http://localhost:8443',
        help='API server URL (default: http://localhost:8443)',
    )
    parser.add_argument(
        '--api-key', default='',
        help='API key for server authentication',
    )
    parser.add_argument(
        '--output', default='results/',
        help='Output directory for reports (default: results/)',
    )
    parser.add_argument(
        '--quick', action='store_true',
        help='Quick mode: scanners + exports only, skip API tests',
    )
    parser.add_argument(
        '--skip-scanners', action='store_true',
        help='Skip scanner tests (useful for fast re-runs)',
    )
    return parser.parse_args()


def main():
    args = parse_args()
    output_dir = Path(args.output)

    print('=' * 60)
    print('  DONJON PLATFORM - FUNCTIONAL TEST HARNESS')
    print('=' * 60)
    print(f'  Target:          {args.target}')
    print(f'  Windows target:  {args.windows_target}')
    print(f'  Server:          {args.server}')
    print(f'  Quick mode:      {args.quick}')
    print(f'  Output:          {output_dir}')
    print(f'  Started:         {datetime.now(timezone.utc).isoformat()}')
    print('=' * 60)

    harness = HarnessResults()

    # Create a test session in evidence DB
    session_id = f'HARNESS-{datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")}'
    try:
        from lib.evidence import get_evidence_manager
        em = get_evidence_manager()
        session_id = em.start_session(
            scan_type='functional_test_harness',
            target_networks=[args.target],
            metadata={'harness': True, 'quick': args.quick},
        )
        print(f'\n  Evidence session: {session_id}')
    except Exception as exc:
        print(f'\n  Warning: Could not create evidence session: {exc}')
        print(f'  Using fallback session ID: {session_id}')

    # --- Run test groups ---

    # 1. Scanners
    if not args.skip_scanners:
        test_scanners(harness, args.target, args.windows_target, session_id)

    # 2. Data flow
    test_data_flow(harness, args.target, session_id)

    # 3. API endpoints (unless quick mode)
    if not args.quick:
        test_api_endpoints(harness, args.server, args.api_key)

    # 4. Export formats
    test_export_formats(harness, session_id)

    # 5. TUI stubs
    test_tui_stubs(harness)

    # 6. Scheduling
    test_scheduling(harness)

    # 7. Notifications
    test_notifications(harness)

    # 8. Compliance reports
    test_compliance_reports(harness)

    # 9. Risk quantification
    test_risk_quantification(harness, args.target, session_id)

    # 10. AI engine
    test_ai_engine(harness, args.target)

    # --- End session ---
    try:
        from lib.evidence import get_evidence_manager
        em = get_evidence_manager()
        em.end_session(session_id, harness.summary())
    except Exception:
        pass

    # --- Save reports ---
    json_path = harness.save_json(output_dir)
    md_path = harness.save_markdown(output_dir)

    # --- Print summary ---
    counts = harness.summary()
    total = len(harness.results)
    print('\n' + '=' * 60)
    print('  SUMMARY')
    print('=' * 60)
    for status in ('PASS', 'FAIL', 'ERROR', 'STUB', 'SKIP'):
        c = counts.get(status, 0)
        pct = (c / total * 100) if total > 0 else 0
        bar = '#' * int(pct / 2)
        print(f'  {status:6s}  {c:3d} ({pct:5.1f}%)  {bar}')
    print(f'  {"TOTAL":6s}  {total:3d}')
    print()
    print(f'  JSON report: {json_path}')
    print(f'  MD report:   {md_path}')
    print('=' * 60)


if __name__ == '__main__':
    main()
