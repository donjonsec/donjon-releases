#!/usr/bin/env python3
"""
Donjon - API Authentication Module
Simple API key authentication for the REST API.
Keys can be configured via environment variable DONJON_API_KEYS
(comma-separated) or generated on the fly.
"""

import hashlib
import hmac
import os
import secrets
import sys
import time
from typing import Dict, List, Optional, Set

# -------------------------------------------------------------------------
# Public (unauthenticated) paths
# -------------------------------------------------------------------------
PUBLIC_PATHS: Set[str] = {
    '/',
    '/api/v1/health',
    '/api/v1/legal/eula',
}


class APIKeyAuth:
    """Manages API key validation for the Donjon REST API."""

    # Paths that require admin-level API key (destructive operations)
    ADMIN_PATHS: Set[str] = {
        '/api/v1/maintenance/purge-scans',
        '/api/v1/maintenance/purge-audit',
        '/api/v1/maintenance/purge-notifications',
        '/api/v1/maintenance/purge-all',
    }

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._keys: Set[str] = set()
        self._admin_keys: Set[str] = set()
        self._load_keys_from_env()

    # -----------------------------------------------------------------
    # Key management
    # -----------------------------------------------------------------

    def _load_keys_from_env(self):
        """Load API keys from DONJON_API_KEYS and DONJON_ADMIN_KEYS."""
        raw = os.environ.get('DONJON_API_KEYS', '')
        if raw:
            for key in raw.split(','):
                key = key.strip()
                if key:
                    self._keys.add(key)
        # Admin keys have full access including destructive operations
        raw_admin = os.environ.get('DONJON_ADMIN_KEYS', '')
        if raw_admin:
            for key in raw_admin.split(','):
                key = key.strip()
                if key:
                    self._admin_keys.add(key)
                    self._keys.add(key)  # Admin keys also work as regular keys

    def add_key(self, key: str):
        """Register an API key at runtime."""
        self._keys.add(key)

    def remove_key(self, key: str):
        """Revoke an API key."""
        self._keys.discard(key)

    def list_keys(self) -> List[str]:
        """Return all registered keys (masked for display)."""
        masked: List[str] = []
        for k in sorted(self._keys):
            if len(k) > 8:
                masked.append(k[:4] + '...' + k[-4:])
            else:
                masked.append('****')
        return masked

    @staticmethod
    def generate_api_key() -> str:
        """Generate a cryptographically secure API key.

        Format: ``donjon_<48 hex chars>`` (24 random bytes).
        """
        token = secrets.token_hex(24)
        return f"donjon_{token}"

    # -----------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------

    def is_public_path(self, path: str) -> bool:
        """Return True if *path* does not require authentication."""
        # Exact match
        if path in PUBLIC_PATHS:
            return True
        # Serve static assets without auth (if any)
        if path.startswith('/static/'):
            return True
        return False

    def is_admin_path(self, path: str) -> bool:
        """Return True if *path* requires admin-level authentication."""
        return path in self.ADMIN_PATHS

    def authenticate(self, path: str, api_key: Optional[str] = None) -> bool:
        """Check whether a request should be allowed.

        Args:
            path: The request URL path.
            api_key: The value of the ``X-API-Key`` header.

        Returns:
            True if the request is authenticated (or auth is disabled).
        """
        # Auth disabled globally
        if not self.enabled:
            return True

        # Public endpoints never need a key
        if self.is_public_path(path):
            return True

        # No keys registered -> generate one and require it
        if not self._keys:
            key = self.generate_api_key()
            self._keys.add(key)
            self._admin_keys.add(key)  # First auto-generated key is also admin
            sys.stderr.write(
                f"\n[Donjon] No API keys configured. Auto-generated key:\n"
                f"  {key}\n"
                f"  Set DONJON_API_KEYS={key} to persist.\n\n"
            )
            # Still require the key for this request
            if not api_key:
                return False
            return hmac.compare_digest(api_key, key)

        # Validate the key
        if not api_key:
            return False

        # Admin paths require admin key
        if self.is_admin_path(path):
            for registered in self._admin_keys:
                if hmac.compare_digest(api_key, registered):
                    return True
            return False

        # Constant-time comparison to prevent timing attacks
        for registered in self._keys:
            if hmac.compare_digest(api_key, registered):
                return True

        return False

    def get_auth_error_response(self, path: str = '') -> Dict:
        """Return a JSON-serialisable error body for 401/403 responses."""
        if self.is_admin_path(path):
            return {
                'error': 'forbidden',
                'message': 'This endpoint requires an admin API key. '
                           'Set DONJON_ADMIN_KEYS to authorize destructive operations.',
            }
        return {
            'error': 'unauthorized',
            'message': 'Missing or invalid API key. '
                       'Provide a valid key via the X-API-Key header.',
        }


# =========================================================================
# Module-level singleton
# =========================================================================
_auth: Optional[APIKeyAuth] = None


def get_auth(enabled: bool = True) -> APIKeyAuth:
    """Get or create the API key authenticator singleton."""
    global _auth
    if _auth is None:
        _auth = APIKeyAuth(enabled=enabled)
    return _auth


# =========================================================================
# CLI helper
# =========================================================================
if __name__ == '__main__':
    key = APIKeyAuth.generate_api_key()
    print(f"Generated API key: {key}")
    print(f"Set it via:  set DONJON_API_KEYS={key}")
    print("Or pass --generate-key to start-server.py")
