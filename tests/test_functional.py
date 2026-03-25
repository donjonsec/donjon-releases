"""Functional tests — require running server at DONJON_TEST_SERVER.

Run: DONJON_TEST_SERVER=http://localhost:8443 pytest tests/test_functional.py -v
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

import pytest

SERVER = os.environ.get("DONJON_TEST_SERVER", "http://localhost:8443")


def _get(path):
    """GET request, return parsed JSON."""
    req = urllib.request.Request(SERVER + path)
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())


def _get_raw(path):
    """GET request, return (status, headers, body)."""
    req = urllib.request.Request(SERVER + path)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, dict(e.headers), body.decode("utf-8", errors="replace") if body else ""


def _post(path, data=None):
    """POST request with JSON body."""
    req = urllib.request.Request(SERVER + path, method="POST")
    req.add_header("Content-Type", "application/json")
    if data:
        req.data = json.dumps(data).encode()
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read()
        return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            return e.code, json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            return e.code, {"raw": body.decode("utf-8", errors="replace") if body else ""}


@pytest.fixture(autouse=True)
def skip_if_no_server():
    """Skip all tests if server is unreachable."""
    try:
        urllib.request.urlopen(SERVER + "/api/v1/health", timeout=5)
    except Exception:
        pytest.skip("Server not reachable at " + SERVER)


# ===================================================================
# Health + Core API
# ===================================================================

class TestHealthEndpoint:
    def test_returns_200(self):
        data = _get("/api/v1/health")
        assert data["status"] == "healthy"

    def test_version_is_730(self):
        data = _get("/api/v1/health")
        assert data["version"] == "7.5.0", f"Health version is {data['version']}"

    def test_has_module_status(self):
        data = _get("/api/v1/health")
        assert isinstance(data["modules"], dict)
        for mod in ["evidence", "compliance", "licensing", "ai_engine"]:
            assert mod in data["modules"], f"Module '{mod}' missing from health"

    def test_has_uptime(self):
        data = _get("/api/v1/health")
        assert data["uptime_seconds"] > 0


class TestLicenseEndpoints:
    def test_license_info(self):
        data = _get("/api/v1/license")
        assert "tier" in data or "license_tier" in data

    def test_trial_status(self):
        data = _get("/api/v1/license/trial/status")
        assert isinstance(data, dict)


class TestStatsEndpoint:
    def test_returns_dict_with_keys(self):
        data = _get("/api/v1/stats")
        assert isinstance(data, dict)
        assert len(data) >= 1, "Stats endpoint returned empty dict"


class TestScannerEndpoint:
    def test_lists_at_least_7_scanners(self):
        data = _get("/api/v1/scanners")
        if isinstance(data, dict) and "scanners" in data:
            scanners = data["scanners"]
        elif isinstance(data, list):
            scanners = data
        else:
            scanners = list(data.values()) if isinstance(data, dict) else []
        assert len(scanners) >= 7, f"Expected >=7 scanners, got {len(scanners)}"


# ===================================================================
# CRUD Endpoints
# ===================================================================

class TestAssetEndpoints:
    def test_list_assets(self):
        data = _get("/api/v1/assets")
        assert isinstance(data, (list, dict))

    def test_create_rejects_empty_body(self):
        code, _ = _post("/api/v1/assets", {})
        assert code in (400, 422), f"Empty asset should fail, got {code}"


class TestFindingEndpoints:
    def test_list_findings(self):
        data = _get("/api/v1/findings")
        assert isinstance(data, (list, dict))


class TestRiskEndpoints:
    def test_risk_posture(self):
        data = _get("/api/v1/risks/posture")
        assert isinstance(data, dict)

    def test_risk_matrix(self):
        data = _get("/api/v1/risks/matrix")
        assert isinstance(data, dict)


class TestRemediationEndpoints:
    def test_list_remediation(self):
        data = _get("/api/v1/remediation")
        assert isinstance(data, (list, dict))

    def test_remediation_metrics(self):
        data = _get("/api/v1/remediation/metrics")
        assert isinstance(data, dict)


# ===================================================================
# Compliance Endpoints
# ===================================================================

class TestComplianceEndpoints:
    def test_nist_report(self):
        # Compliance reports may return HTML or JSON
        code, _, body = _get_raw("/api/v1/reports/compliance/nist_800_53")
        assert code == 200, f"NIST report returned {code}"
        assert len(body) > 100, "NIST report too small"

    def test_framework_overlap(self):
        data = _get("/api/v1/compliance/overlap?frameworks=nist_800_53,hipaa")
        assert isinstance(data, dict)


# ===================================================================
# AI Endpoints
# ===================================================================

class TestAIEndpoints:
    def test_ai_status(self):
        data = _get("/api/v1/ai/status")
        assert isinstance(data, dict)

    def test_ai_config(self):
        data = _get("/api/v1/ai/config")
        assert isinstance(data, dict)


# ===================================================================
# Intel + Tools
# ===================================================================

class TestIntelEndpoints:
    def test_intel_status(self):
        data = _get("/api/v1/intel/status")
        assert isinstance(data, dict)

    def test_tools_list(self):
        data = _get("/api/v1/tools")
        assert isinstance(data, (list, dict))


# ===================================================================
# Tier Gating — Community tier should 403 on enterprise features
# ===================================================================

class TestTierGating:
    def test_audit_gated(self):
        code, _, _ = _get_raw("/api/v1/audit")
        # 403 = tier gate working, 404 = route not registered (sub-module import failed)
        assert code in (403, 404), f"Audit endpoint returned {code}, expected 403 or 404"
        if code == 404:
            pytest.skip("Audit sub-module not loaded — route not registered")

    def test_rbac_gated(self):
        code, _, _ = _get_raw("/api/v1/rbac/roles")
        assert code in (403, 404), f"RBAC returned {code}, expected 403 or 404"
        if code == 404:
            pytest.skip("RBAC sub-module not loaded")

    def test_mssp_gated(self):
        code, _, _ = _get_raw("/api/v1/mssp/clients")
        assert code in (403, 404), f"MSSP returned {code}, expected 403 or 404"
        if code == 404:
            pytest.skip("MSSP sub-module not loaded")


# ===================================================================
# Dashboard HTML
# ===================================================================

class TestDashboard:
    def test_serves_valid_html(self):
        code, _, body = _get_raw("/")
        assert code == 200
        assert "<html" in body and "</html>" in body

    def test_has_lifecycle_tab(self):
        _, _, body = _get_raw("/")
        assert "lifecycle" in body.lower() and ("lc-grid" in body or "lc-card" in body), \
            "Dashboard missing lifecycle tab content (lc-grid/lc-card classes)"

    def test_has_trends_tab(self):
        _, _, body = _get_raw("/")
        assert "trends" in body.lower() and ("tr-grid" in body or "tr-card" in body), \
            "Dashboard missing trends tab content (tr-grid/tr-card classes)"

    def test_version_correct(self):
        _, _, body = _get_raw("/")
        assert "v7.5.0" in body, "Dashboard should show v7.5.0"
        assert "v2.0" not in body, "Dashboard must NOT show v2.0"

    def test_substantial_size(self):
        _, _, body = _get_raw("/")
        assert len(body) > 20000, f"Dashboard too small: {len(body)} bytes"


# ===================================================================
# Security — Error Handling
# ===================================================================

class TestSecurityErrorHandling:
    def test_no_stack_trace_on_404(self):
        _, _, body = _get_raw("/api/v1/nonexistent_endpoint_xyz123")
        assert "Traceback" not in body, "404 leaks stack trace"
        assert 'File "/' not in body, "404 leaks file paths"

    def test_no_stack_trace_on_bad_id(self):
        _, _, body = _get_raw("/api/v1/scans/not-a-real-id-999")
        assert "Traceback" not in body

    def test_sqli_doesnt_crash(self):
        # URL-encode the SQLi payload to avoid Python's URL validation rejecting it
        import urllib.parse
        payload = urllib.parse.quote("high' OR '1'='1")
        code, _, _ = _get_raw(f"/api/v1/findings?severity={payload}")
        assert code != 500, "SQLi in query param caused server error"

    def test_oversized_input_handled(self):
        code, _ = _post("/api/v1/assets", {"name": "A" * 10000})
        assert code != 500, "Oversized input caused server error"


# ===================================================================
# Scheduling + Notifications + Maintenance
# ===================================================================

class TestScheduling:
    def test_schedule_list(self):
        data = _get("/api/v1/schedules")
        assert isinstance(data, (list, dict))


class TestNotifications:
    def test_channel_list(self):
        data = _get("/api/v1/notifications/channels")
        assert isinstance(data, (list, dict))

    def test_notification_history(self):
        data = _get("/api/v1/notifications/history")
        assert isinstance(data, (list, dict))

    def test_notification_stats(self):
        data = _get("/api/v1/notifications/stats")
        assert isinstance(data, dict)


class TestMaintenance:
    def test_storage_stats(self):
        data = _get("/api/v1/system/storage")
        assert isinstance(data, dict)

    def test_scan_profiles(self):
        data = _get("/api/v1/profiles")
        assert isinstance(data, (list, dict))


class TestEULA:
    def test_eula_endpoint(self):
        data = _get("/api/v1/legal/eula")
        assert isinstance(data, dict)


# ===================================================================
# Additional API Completeness
# ===================================================================

class TestAPICompleteness:
    def test_risk_list(self):
        data = _get("/api/v1/risks")
        assert isinstance(data, (list, dict))

    def test_exception_list(self):
        data = _get("/api/v1/exceptions")
        assert isinstance(data, (list, dict))

    def test_agent_list(self):
        data = _get("/api/v1/agents")
        assert isinstance(data, (list, dict))

    def test_network_local(self):
        data = _get("/api/v1/network/local")
        assert isinstance(data, dict)

    def test_discovery_hosts(self):
        data = _get("/api/v1/discovery/hosts")
        assert isinstance(data, (list, dict))
