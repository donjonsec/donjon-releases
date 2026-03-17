"""
Red Team Security Tests — Donjon Platform
Independent penetration test. Tests PASS if attacks are BLOCKED, FAIL if exploitable.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

BASE_URL = "http://localhost:8443"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _req(method, path, body=None, headers=None, expect_error=True):
    """Fire an HTTP request. Returns (status_code, response_body_dict_or_str)."""
    url = f"{BASE_URL}{path}"
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode() if e.fp else ""
        try:
            return e.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return e.code, raw
    except urllib.error.URLError as e:
        pytest.skip(f"Server not reachable: {e}")


def _forge_license_v1(payload: dict) -> str:
    """Forge a license using the leaked v1 HMAC key."""
    key = b"donjon-license-signing-key-v1"
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(key, body, hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(body).decode() + "." + sig
    return token


# ===========================================================================
# LICENSE FORGERY
# ===========================================================================

class TestLicenseForgery:
    """Attempt to forge / tamper with license tokens."""

    def test_forged_v1_hmac_rejected(self):
        """Forge a license with the known v1 HMAC key — must be rejected."""
        payload = {
            "version": 1,
            "tier": "enterprise",
            "org": "evil-corp",
            "exp": "2099-12-31",
            "features_override": {},
        }
        token = _forge_license_v1(payload)
        status, body = _req("POST", "/api/v1/license/activate", {"token": token})
        # Any 2xx acceptance means the forgery worked — that's bad
        assert status >= 400, (
            f"Forged v1 license was ACCEPTED (status {status}). "
            "The server should reject HMAC-SHA256 v1 signatures."
        )

    def test_version_field_omitted_rejected(self):
        """Omit version field to attempt downgrade — must be rejected."""
        payload = {
            "tier": "enterprise",
            "org": "downgrade-corp",
            "exp": "2099-12-31",
        }
        token = _forge_license_v1(payload)
        status, body = _req("POST", "/api/v1/license/activate", {"token": token})
        assert status >= 400, (
            f"License without version field was ACCEPTED (status {status}). "
            "Missing version should be rejected, not default to v1."
        )

    def test_features_override_boolean_escalation(self):
        """Try to override boolean features (sso, rbac) from False to True."""
        payload = {
            "version": 2,
            "tier": "community",
            "org": "escalation-corp",
            "exp": "2099-12-31",
            "features_override": {
                "sso": True,
                "rbac": True,
            },
        }
        token = _forge_license_v1(payload)
        status, body = _req("POST", "/api/v1/license/activate", {"token": token})
        # Either rejected outright, or accepted but overrides must be ignored
        if status < 400:
            # If accepted, check that the features were NOT escalated
            features = body.get("features", body.get("license", {}).get("features", {}))
            if isinstance(features, dict):
                assert features.get("sso") is not True, (
                    "features_override successfully escalated SSO to True"
                )
                assert features.get("rbac") is not True, (
                    "features_override successfully escalated RBAC to True"
                )

    def test_features_override_numeric_escalation(self):
        """Try to increase max_users above tier default via features_override."""
        payload = {
            "version": 2,
            "tier": "community",
            "org": "escalation-corp",
            "exp": "2099-12-31",
            "features_override": {
                "max_users": 999999,
            },
        }
        token = _forge_license_v1(payload)
        status, body = _req("POST", "/api/v1/license/activate", {"token": token})
        if status < 400:
            features = body.get("features", body.get("license", {}).get("features", {}))
            if isinstance(features, dict):
                max_users = features.get("max_users", 0)
                assert max_users < 999999, (
                    f"features_override escalated max_users to {max_users}"
                )


# ===========================================================================
# TIER BYPASS — Accessing gated endpoints on community tier
# ===========================================================================

class TestTierBypass:
    """Attempt to access enterprise/professional features on community tier."""

    @pytest.mark.parametrize("path", [
        "/api/v1/audit",
        "/api/v1/audit/trail",
        "/api/v1/rbac/roles",
        "/api/v1/sso/metadata",
        "/api/v1/tenants",
    ])
    def test_enterprise_endpoints_blocked(self, path):
        """Community tier must not access enterprise-gated endpoints."""
        status, _ = _req("GET", path)
        assert status in (401, 403, 404, 405), (
            f"Community tier accessed {path} with status {status} — tier gate bypassed"
        )

    @pytest.mark.parametrize("path", [
        "/api/v1/mssp/clients",
        "/api/v1/mssp/bulk-scan",
    ])
    def test_mssp_endpoints_blocked(self, path):
        """Community tier must not access MSSP endpoints."""
        status, _ = _req("GET", path)
        assert status in (401, 403, 404, 405), (
            f"Community tier accessed {path} with status {status} — MSSP gate bypassed"
        )

    def test_scheduled_scans_blocked(self):
        """Community tier should not be able to schedule scans."""
        status, _ = _req("POST", "/api/v1/scans/schedule", {
            "target": "192.168.1.1",
            "schedule": "daily",
        })
        assert status in (401, 403, 404, 405), (
            f"Scheduled scan accepted on community tier (status {status})"
        )

    def test_deep_scan_blocked(self):
        """Community tier should not be able to run deep scans."""
        status, _ = _req("POST", "/api/v1/scans", {
            "target": "192.168.1.1",
            "scan_type": "deep",
        })
        assert status in (401, 403, 404, 405), (
            f"Deep scan accepted on community tier (status {status})"
        )

    def test_pdf_export_blocked(self):
        """Community tier should not be able to export PDFs."""
        status, _ = _req("GET", "/api/v1/reports/export?format=pdf")
        assert status in (401, 403, 404, 405), (
            f"PDF export accepted on community tier (status {status})"
        )

    def test_ai_summarize_blocked(self):
        """Community tier should not access AI summarize."""
        status, _ = _req("POST", "/api/v1/ai/summarize", {"scan_id": "test"})
        assert status in (401, 403, 404, 405), (
            f"AI summarize accepted on community tier (status {status})"
        )

    def test_excess_targets_blocked(self):
        """Community tier should be limited to 16 targets."""
        targets = [f"192.168.1.{i}" for i in range(1, 20)]  # 19 targets
        status, body = _req("POST", "/api/v1/targets/bulk", {"targets": targets})
        if status < 400:
            # If accepted, check it was truncated
            accepted = body.get("accepted", body.get("targets", targets))
            if isinstance(accepted, list):
                assert len(accepted) <= 16, (
                    f"Community tier accepted {len(accepted)} targets (limit is 16)"
                )
            else:
                # Can't verify — pass conservatively
                pass
        # 4xx means blocked, which is correct


# ===========================================================================
# SSRF — Server-Side Request Forgery via discovery scan
# ===========================================================================

class TestSSRF:
    """Attempt SSRF through the network discovery/scan endpoints."""

    def test_cloud_metadata_cidr_blocked(self):
        """169.254.169.254/32 (AWS/cloud metadata) must be blocked."""
        status, body = _req("POST", "/api/v1/discovery", {
            "cidr": "169.254.169.254/32",
            "methods": ["tcp"],
        })
        assert status in (400, 403, 422), (
            f"Cloud metadata CIDR accepted (status {status}) — SSRF possible"
        )

    def test_public_ip_cidr_blocked(self):
        """8.8.8.0/24 (public IP range) must be blocked."""
        status, body = _req("POST", "/api/v1/discovery", {
            "cidr": "8.8.8.0/24",
            "methods": ["tcp"],
        })
        assert status in (400, 403, 422), (
            f"Public IP CIDR accepted (status {status}) — external scanning possible"
        )

    def test_invalid_scan_method_rejected(self):
        """Invalid discovery methods must be rejected."""
        status, body = _req("POST", "/api/v1/discovery", {
            "cidr": "192.168.1.0/24",
            "methods": ["../../etc/passwd"],
        })
        assert status in (400, 403, 422), (
            f"Invalid scan method accepted (status {status})"
        )

    def test_private_cidr_allowed(self):
        """Private RFC1918 CIDR should be accepted (baseline sanity check)."""
        status, body = _req("POST", "/api/v1/discovery", {
            "cidr": "192.168.1.0/24",
            "methods": ["arp"],
        })
        # Should NOT be blocked — 2xx or even 404 (endpoint exists but no scanner) is fine
        assert status not in (403,), (
            f"Private CIDR 192.168.1.0/24 was blocked (status {status}) — "
            "overly restrictive SSRF filter"
        )


# ===========================================================================
# AUTH BYPASS — Brute force / rate limiting
# ===========================================================================

class TestAuthBypass:
    """Attempt authentication bypass via brute force."""

    def test_health_endpoint_baseline(self):
        """Health endpoint should be accessible (sanity check)."""
        status, _ = _req("GET", "/api/v1/health")
        # Accept 200 or common health paths
        if status == 404:
            status, _ = _req("GET", "/health")
        assert status == 200, f"Health endpoint not reachable (status {status})"

    @pytest.mark.skipif(
        os.environ.get("DONJON_ALLOW_NO_AUTH") == "1",
        reason="Rate limiting requires auth to be enabled"
    )
    def test_brute_force_rate_limited(self):
        """15+ invalid API key attempts should trigger rate limiting."""
        rate_limited = False
        for i in range(20):
            status, _ = _req(
                "GET",
                "/api/v1/scans",
                headers={"X-API-Key": f"donjon_{'%048x' % i}"},
            )
            if status == 429:
                rate_limited = True
                break
        assert rate_limited, (
            "Sent 20 invalid API keys without hitting rate limiting (no 429 response)"
        )


# ===========================================================================
# INPUT VALIDATION
# ===========================================================================

class TestInputValidation:
    """Attempt to abuse input handling."""

    def test_limit_parameter_bounded(self):
        """?limit=99999999 should be clamped to a sane maximum."""
        status, body = _req("GET", "/api/v1/scans?limit=99999999")
        if status == 200 and isinstance(body, dict):
            items = body.get("items", body.get("results", body.get("data", [])))
            if isinstance(items, list):
                assert len(items) <= 1000, (
                    f"Unbounded limit returned {len(items)} items — DoS vector"
                )

    def test_invalid_json_body_rejected(self):
        """Malformed JSON body should return 400/422, not 500."""
        url = f"{BASE_URL}/api/v1/scans"
        req = urllib.request.Request(
            url,
            data=b"{this is not valid json!!!}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        except urllib.error.URLError:
            pytest.skip("Server not reachable")

        assert status != 500, (
            "Invalid JSON caused a 500 Internal Server Error — unhandled exception"
        )

    @pytest.mark.parametrize("malicious_id", [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%27%3B%20DROP%20TABLE%20scans%3B%20--",
        "<script>alert(1)</script>",
    ])
    def test_path_traversal_in_session_id(self, malicious_id):
        """Path traversal in session_id parameter must be rejected."""
        status, body = _req("GET", f"/api/v1/scans/{malicious_id}")
        assert status != 500, (
            f"Path traversal payload '{malicious_id}' caused a 500 error"
        )
        # Should get 400 (bad request) or 404 (not found), never 200 with file contents
        if status == 200 and isinstance(body, (str, dict)):
            body_str = json.dumps(body) if isinstance(body, dict) else body
            assert "root:" not in body_str, "Path traversal returned /etc/passwd contents"
            assert "SYSTEM" not in body_str, "Path traversal returned Windows system file"

    @pytest.mark.parametrize("malicious_id", [
        "../../etc/shadow",
        "..%2f..%2f..%2fetc%2fshadow",
    ])
    def test_path_traversal_in_asset_id(self, malicious_id):
        """Path traversal in asset_id parameter must be rejected."""
        status, body = _req("GET", f"/api/v1/assets/{malicious_id}")
        assert status != 500, (
            f"Path traversal payload '{malicious_id}' caused a 500 error"
        )
        if status == 200 and isinstance(body, (str, dict)):
            body_str = json.dumps(body) if isinstance(body, dict) else body
            assert "root:" not in body_str, "Path traversal returned /etc/shadow contents"


# ===========================================================================
# REVOCATION BYPASS — Corrupt revocation list
# ===========================================================================

class TestRevocationBypass:
    """Attempt to bypass license revocation by corrupting the revocation file."""

    def test_corrupt_revocation_file_fails_closed(self):
        """
        Write corrupt JSON to data/revoked.json.
        The system must fail CLOSED (treat as revoked), not fail OPEN.
        """
        revoked_path = Path("data/revoked.json")
        original_content = None

        # Save original if it exists
        if revoked_path.exists():
            original_content = revoked_path.read_text()

        try:
            revoked_path.parent.mkdir(parents=True, exist_ok=True)
            revoked_path.write_text("THIS IS NOT VALID JSON {{{{{")

            # Now try to validate a license — system should fail closed
            status, body = _req("GET", "/api/v1/license/status")
            if status == 200 and isinstance(body, dict):
                # If the license status says "valid" or "active" while revocation
                # list is corrupt, the system is failing OPEN
                lic_status = body.get("status", "").lower()
                assert lic_status not in ("valid", "active"), (
                    "License reported as valid/active with corrupt revocation file — "
                    "system fails OPEN instead of CLOSED"
                )
        finally:
            # Restore original state
            if original_content is not None:
                revoked_path.write_text(original_content)
            elif revoked_path.exists():
                revoked_path.unlink()


# ===========================================================================
# AIR-GAP MODE
# ===========================================================================

class TestAirGapMode:
    """Verify that DONJON_OFFLINE=1 blocks outbound network calls."""

    def test_intel_feed_blocked_in_offline_mode(self):
        """
        With DONJON_OFFLINE=1, intel/threat feed endpoints must refuse
        to make external network calls.
        """
        # We can't set env vars on a running server via HTTP.
        # Instead, test the endpoint behavior — if the server is running
        # with DONJON_OFFLINE=1, intel feeds should return an error.
        #
        # If the server is NOT in offline mode, we verify the endpoint
        # exists but skip the offline assertion.
        offline_mode = os.environ.get("DONJON_OFFLINE", "0") == "1"

        intel_paths = [
            "/api/v1/intel/feeds",
            "/api/v1/intel/update",
            "/api/v1/threat/feed",
            "/api/v1/intel/sync",
        ]

        if not offline_mode:
            pytest.skip(
                "Server not running with DONJON_OFFLINE=1 — "
                "restart server with DONJON_OFFLINE=1 to test air-gap mode"
            )

        for path in intel_paths:
            status, body = _req("GET", path)
            if status == 404:
                continue  # endpoint doesn't exist, not applicable
            assert status in (403, 503), (
                f"{path} returned {status} in offline mode — "
                "should refuse with 403/503 when DONJON_OFFLINE=1"
            )

    def test_offline_env_propagates(self):
        """If DONJON_OFFLINE=1 is set, verify the server acknowledges it."""
        offline_mode = os.environ.get("DONJON_OFFLINE", "0") == "1"
        if not offline_mode:
            pytest.skip("DONJON_OFFLINE not set — skipping air-gap verification")

        status, body = _req("GET", "/api/v1/health")
        if status == 404:
            status, body = _req("GET", "/health")
        if status == 200 and isinstance(body, dict):
            # Health endpoint should indicate offline mode
            mode = body.get("mode", body.get("offline", body.get("air_gap")))
            if mode is not None:
                assert mode in (True, "offline", "air-gap"), (
                    f"Server health reports mode={mode} despite DONJON_OFFLINE=1"
                )
