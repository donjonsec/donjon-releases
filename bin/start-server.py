#!/usr/bin/env python3
"""
Donjon GRC - Web Server Launcher
Start the REST API and Dashboard server.

Usage:
    python bin/start-server.py                    # Start on 0.0.0.0:8443
    python bin/start-server.py --port 9090        # Custom port
    python bin/start-server.py --host 127.0.0.1   # Localhost only
    python bin/start-server.py --no-auth          # Disable API key auth
    python bin/start-server.py --generate-key     # Generate a new API key
    python bin/start-server.py --stdlib           # Force stdlib mode (no Flask)
"""

import argparse
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / 'lib'))

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description='Donjon GRC - Start the web server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--host', default='127.0.0.1',
        help='Bind address (default: 127.0.0.1, use 0.0.0.0 for all interfaces)',
    )
    parser.add_argument(
        '--port', type=int, default=8443,
        help='Listen port (default: 8443)',
    )
    parser.add_argument(
        '--no-auth', action='store_true',
        help='Disable API key authentication',
    )
    parser.add_argument(
        '--generate-key', action='store_true',
        help='Generate a new API key and exit',
    )
    parser.add_argument(
        '--add-key', metavar='KEY',
        help='Register an API key at startup',
    )
    parser.add_argument(
        '--stdlib', action='store_true',
        help='Force stdlib http.server mode (skip Flask even if available)',
    )
    parser.add_argument(
        '--tls-cert', metavar='PATH',
        default=os.environ.get('DONJON_TLS_CERT'),
        help='Path to TLS certificate (PEM). Also reads DONJON_TLS_CERT env var.',
    )
    parser.add_argument(
        '--tls-key', metavar='PATH',
        default=os.environ.get('DONJON_TLS_KEY'),
        help='Path to TLS private key (PEM). Also reads DONJON_TLS_KEY env var.',
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # --generate-key: print a key and exit
    if args.generate_key:
        from web.auth import APIKeyAuth
        key = APIKeyAuth.generate_api_key()
        print(f"Generated API key:\n\n  {key}\n")
        print("Usage:")
        if sys.platform == 'win32':
            print(f"  set DONJON_API_KEYS={key}")
        else:
            print(f"  export DONJON_API_KEYS={key}")
        print(f"  python bin/start-server.py")
        print(f"\nOr pass it directly:")
        print(f"  python bin/start-server.py --add-key {key}")
        print(f"\nThen include in requests:")
        print(f"  curl -H \"X-API-Key: {key}\" http://localhost:8443/api/v1/stats")
        return

    # Ensure data directories exist
    try:
        from lib.paths import paths
        paths.ensure_directories()
    except Exception as e:
        print(f"Warning: Could not create directories: {e}", file=sys.stderr)

    # Set up auth
    from web.auth import get_auth
    if args.no_auth:
        if os.environ.get("DONJON_PRODUCTION") == "1":
            print(
                "\n  ERROR: --no-auth is not allowed when DONJON_PRODUCTION=1\n"
                "  Remove --no-auth or unset DONJON_PRODUCTION to proceed.\n",
                file=sys.stderr
            )
            sys.exit(1)
        if os.environ.get("DONJON_ALLOW_NO_AUTH") != "1":
            print(
                "\n  WARNING: --no-auth disables ALL authentication.\n"
                "  Every endpoint (including purge, license, MSSP) is wide open.\n"
                "  Set DONJON_ALLOW_NO_AUTH=1 to confirm this is intentional.\n",
                file=sys.stderr
            )
            sys.exit(1)
        import logging
        logging.getLogger('donjon').critical(
            "SECURITY: Server started with --no-auth. "
            "All API endpoints are unauthenticated."
        )
    auth = get_auth(enabled=not args.no_auth)
    if args.add_key:
        auth.add_key(args.add_key)
        print(f"[Donjon GRC] Registered API key: {args.add_key[:4]}...{args.add_key[-4:]}")

    # EULA acceptance check
    from lib.eula import prompt_eula_acceptance_server
    if not prompt_eula_acceptance_server():
        print()
        print("  ERROR: EULA not accepted.")
        print("  Accept via the TUI launcher first, or set:")
        print("    DONJON_ACCEPT_EULA=yes")
        print()
        sys.exit(1)

    # Security: check data directory permissions
    try:
        from lib.paths import paths
        data_dir = paths.data
        if data_dir.exists() and os.name == 'posix':
            import stat
            mode = data_dir.stat().st_mode
            if mode & stat.S_IROTH:
                print(
                    f"  WARNING: Data directory {data_dir} is world-readable.\n"
                    f"  Evidence and scan data may be exposed.\n"
                    f"  Fix: chmod 700 {data_dir}\n",
                    file=sys.stderr
                )
    except Exception:
        pass

    # Banner
    print()
    print("  ====================================")
    print("    Donjon GRC - Web Server")
    print("  ====================================")
    print()

    # Start server
    from web.api import start_server
    start_server(
        host=args.host,
        port=args.port,
        no_auth=args.no_auth,
        prefer_flask=not args.stdlib,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
    )


if __name__ == '__main__':
    main()
