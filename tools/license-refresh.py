#!/usr/bin/env python3
"""
Donjon Platform - Offline License Refresh Tool

For air-gap / government customers who cannot connect to the internet.
Validates a new license file using the embedded public keys and imports
it to data/license.json if valid.

Usage:
    python tools/license-refresh.py --license /path/to/new-license.json
    python tools/license-refresh.py --license E:/license.json   # USB drive

Exit codes:
    0 - License imported successfully
    1 - Validation failed (bad signatures, expired, wrong machine, revoked)
    2 - File not found or unreadable
    3 - Internal error
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "lib"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("donjon.license-refresh")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Donjon Platform - Offline License Refresh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python tools/license-refresh.py --license /mnt/usb/license.json\n"
            "  python tools/license-refresh.py --license E:\\license.json\n"
        ),
    )
    parser.add_argument(
        "--license",
        required=True,
        help="Path to the new license.json file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate without importing (check signatures only)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    license_path = Path(args.license).resolve()

    # ------------------------------------------------------------------
    # Step 1: Read the new license file
    # ------------------------------------------------------------------
    if not license_path.exists():
        logger.error("License file not found: %s", license_path)
        return 2

    try:
        raw = license_path.read_text("utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Could not read license file: %s", exc)
        return 2

    if not isinstance(data, dict):
        logger.error("License file root is not a JSON object")
        return 1

    # ------------------------------------------------------------------
    # Step 2: Validate using LicenseManager
    # ------------------------------------------------------------------
    try:
        from lib.licensing import LicenseManager
    except ImportError as exc:
        logger.error("Could not import licensing module: %s", exc)
        return 3

    lm = LicenseManager.get_instance()

    logger.info("Validating license from: %s", license_path)
    logger.info(
        "  Tier: %s | Organization: %s | Expires: %s | License ID: %s",
        data.get("tier", "unknown"),
        data.get("organization", "unknown"),
        data.get("expires", "perpetual"),
        data.get("license_id", "unknown"),
    )

    version = data.get("version", data.get("format_version", 2))
    logger.info("  Format version: %d", version)

    if not lm.validate_license(data):
        logger.error("VALIDATION FAILED. The license file is not valid.")
        logger.error(
            "Possible causes: invalid signatures, expired, wrong machine, "
            "revoked, or unsupported tier."
        )
        return 1

    logger.info("VALIDATION PASSED. All signature and integrity checks succeeded.")

    if args.dry_run:
        logger.info("Dry run -- license was NOT imported.")
        return 0

    # ------------------------------------------------------------------
    # Step 3: Back up existing license and import the new one
    # ------------------------------------------------------------------
    try:
        from lib.paths import paths
    except ImportError as exc:
        logger.error("Could not import paths module: %s", exc)
        return 3

    dest = paths.data / "license.json"
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Back up existing license if present
    if dest.exists():
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = dest.with_name(f"license.{timestamp}.bak.json")
        shutil.copy2(str(dest), str(backup))
        logger.info("Backed up existing license to: %s", backup)

    # Copy new license
    shutil.copy2(str(license_path), str(dest))
    logger.info("License imported to: %s", dest)

    # ------------------------------------------------------------------
    # Step 4: Reload and verify
    # ------------------------------------------------------------------
    lm.reload()
    new_tier = lm.get_tier()
    info = lm.get_license_info()

    logger.info("License reload complete.")
    logger.info("  Active tier: %s", new_tier)
    logger.info("  Organization: %s", info.get("organization", ""))
    logger.info("  Expires: %s", info.get("expires", "perpetual"))
    logger.info("  License ID: %s", info.get("license_id", ""))

    days = lm.days_until_expiry()
    if days is not None:
        if days < 0:
            logger.warning("  NOTE: This license is expired (%d days ago).", abs(days))
        elif days <= 30:
            logger.info("  NOTE: This license expires in %d day(s).", days)

    print()
    print(f"  License imported successfully.")
    print(f"  Tier: {new_tier}")
    print(f"  Organization: {info.get('organization', '')}")
    print(f"  Restart the server to apply changes.")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
