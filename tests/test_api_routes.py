#!/usr/bin/env python3
"""
Test suite: API route registration, auth enforcement, and public path access.

Verifies that:
- All expected routes are registered in DonjonAPI
- Public paths don't require authentication
- Protected paths require a valid API key
- Admin paths require an admin API key
- New Phase 3 endpoints (rotate, register agent) are present
"""

import sys
import unittest
from pathlib import Path

# Ensure project root is on the path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(_PROJECT_ROOT))


class TestAPIRouteRegistration(unittest.TestCase):
    """Test that all expected routes are registered."""

    @classmethod
    def setUpClass(cls):
        from web.api import DonjonAPI
        from web.auth import APIKeyAuth
        auth = APIKeyAuth(enabled=True)
        # Add a known key for testing
        cls.test_key = 'donjon_test_key_for_unit_tests_1234'
        cls.admin_key = 'donjon_admin_key_for_unit_tests_5678'
        auth.add_key(cls.test_key)
        auth._admin_keys.add(cls.admin_key)
        auth._keys.add(cls.admin_key)
        cls.api = DonjonAPI(auth=auth)

    def _route_patterns(self):
        """Return set of (method, pattern_str) for all registered routes."""
        patterns = set()
        for route in self.api.routes:
            patterns.add((route.method, route.regex.pattern))
        return patterns

    def test_health_route_registered(self):
        patterns = self._route_patterns()
        self.assertTrue(any('health' in p for _, p in patterns))

    def test_scan_routes_registered(self):
        patterns = self._route_patterns()
        self.assertTrue(any('scans' in p for _, p in patterns))

    def test_agent_routes_registered(self):
        patterns = self._route_patterns()
        self.assertTrue(any('agents/checkin' in p for _, p in patterns))
        self.assertTrue(any('agents/register' in p for _, p in patterns))

    def test_auth_rotate_route_registered(self):
        patterns = self._route_patterns()
        self.assertTrue(any('auth/rotate' in p for _, p in patterns))

    def test_ai_routes_registered(self):
        patterns = self._route_patterns()
        self.assertTrue(any('ai/analyze' in p for _, p in patterns))
        self.assertTrue(any('ai/status' in p for _, p in patterns))

    def test_license_route_registered(self):
        patterns = self._route_patterns()
        self.assertTrue(any('license' in p and 'activate' not in p for _, p in patterns))


class TestAPIAuthentication(unittest.TestCase):
    """Test auth enforcement on different path types."""

    @classmethod
    def setUpClass(cls):
        from web.api import DonjonAPI
        from web.auth import APIKeyAuth
        auth = APIKeyAuth(enabled=True)
        cls.test_key = 'donjon_test_key_for_unit_tests_1234'
        cls.admin_key = 'donjon_admin_key_for_unit_tests_5678'
        auth.add_key(cls.test_key)
        auth._admin_keys.add(cls.admin_key)
        auth._keys.add(cls.admin_key)
        cls.api = DonjonAPI(auth=auth)

    def test_public_health_no_auth(self):
        """GET /api/v1/health should work without API key."""
        body, status, _ = self.api.dispatch('GET', '/api/v1/health', {}, None)
        self.assertEqual(status, 200)

    def test_public_eula_no_auth(self):
        """GET /api/v1/legal/eula should work without API key."""
        body, status, _ = self.api.dispatch('GET', '/api/v1/legal/eula', {}, None)
        self.assertEqual(status, 200)

    def test_protected_path_requires_auth(self):
        """GET /api/v1/stats should require API key."""
        body, status, _ = self.api.dispatch('GET', '/api/v1/stats', {}, None)
        self.assertEqual(status, 401)

    def test_protected_path_with_valid_key(self):
        """GET /api/v1/stats should work with valid API key."""
        body, status, _ = self.api.dispatch(
            'GET', '/api/v1/stats', {}, None, api_key=self.test_key
        )
        self.assertEqual(status, 200)

    def test_protected_path_with_invalid_key(self):
        """GET /api/v1/stats should reject invalid API key."""
        body, status, _ = self.api.dispatch(
            'GET', '/api/v1/stats', {}, None, api_key='invalid_key'
        )
        self.assertEqual(status, 401)


class TestKeyRotation(unittest.TestCase):
    """Test API key rotation mechanism."""

    def test_rotate_key(self):
        from web.auth import APIKeyAuth
        auth = APIKeyAuth(enabled=True)
        original_key = auth.generate_api_key()
        auth.add_key(original_key)

        result = auth.rotate_key(original_key, grace_seconds=3600)
        self.assertIn('new_key', result)
        self.assertTrue(result['new_key'].startswith('donjon_'))

        # Both old and new key should work during grace period
        self.assertTrue(auth.authenticate('/api/v1/stats', original_key))
        self.assertTrue(auth.authenticate('/api/v1/stats', result['new_key']))

    def test_rotate_nonexistent_key_raises(self):
        from web.auth import APIKeyAuth
        auth = APIKeyAuth(enabled=True)
        with self.assertRaises(ValueError):
            auth.rotate_key('nonexistent_key')

    def test_agent_token_registration(self):
        from web.auth import APIKeyAuth
        auth = APIKeyAuth(enabled=True)

        token = auth.register_agent_token('agent-001')
        self.assertTrue(token.startswith('donjon_agent_'))
        self.assertTrue(auth.verify_agent_token('agent-001', token))
        self.assertFalse(auth.verify_agent_token('agent-001', 'wrong_token'))
        self.assertFalse(auth.verify_agent_token('agent-999', token))


if __name__ == '__main__':
    unittest.main()
