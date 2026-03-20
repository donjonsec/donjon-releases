#!/usr/bin/env python3
"""
Donjon Platform - EULA Acceptance Tracking

Implements click-wrap EULA acceptance for contract enforceability.
Stores acceptance state in data/eula_accepted.json.
"""

import json
import hashlib
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from .paths import paths
except ImportError:
    from paths import paths

# Must match the version in the LICENSE file header
EULA_VERSION = "1.5"

# Acceptance record file
_ACCEPTANCE_FILE = paths.data / "eula_accepted.json"


def _get_machine_id() -> str:
    """Generate a stable machine identifier for the acceptance record."""
    raw = f"{platform.node()}|{platform.machine()}|{platform.system()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def check_eula_accepted() -> bool:
    """Check if the current EULA version has been accepted on this machine."""
    if not _ACCEPTANCE_FILE.exists():
        return False
    try:
        data = json.loads(_ACCEPTANCE_FILE.read_text("utf-8"))
        return data.get("eula_version") == EULA_VERSION
    except (json.JSONDecodeError, OSError):
        return False


def get_acceptance_record() -> Optional[dict]:
    """Return the stored acceptance record, or None."""
    if not _ACCEPTANCE_FILE.exists():
        return None
    try:
        return json.loads(_ACCEPTANCE_FILE.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def record_acceptance() -> dict:
    """Record EULA acceptance with timestamp and machine ID."""
    record = {
        "eula_version": EULA_VERSION,
        "accepted_at": datetime.now(timezone.utc).isoformat(),
        "machine_id": _get_machine_id(),
        "platform": platform.system(),
        "python_version": platform.python_version(),
    }
    _ACCEPTANCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _ACCEPTANCE_FILE.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def get_eula_text() -> str:
    """Read and return the full EULA text from the LICENSE file."""
    license_file = paths.home / "LICENSE"
    if license_file.exists():
        return license_file.read_text(encoding="utf-8")
    return f"EULA v{EULA_VERSION} — LICENSE file not found."


def get_eula_summary() -> str:
    """Return a short summary for the click-wrap prompt."""
    return f"""
DONJON PLATFORM — END USER LICENSE AGREEMENT (v{EULA_VERSION})

By using this software you agree to be bound by the EULA terms including:

  - License is for business/professional use only (Section 2.6)
  - You must have written authorization before scanning any system (Section 5)
  - You may not use output to train AI/ML models (Section 4j)
  - Community Edition: 16 targets, 3 frameworks, 10 AI queries/day (Section 3)
  - DonjonSec is not liable for assessment damages (Section 9.3)
  - Disputes resolved by binding arbitration in Florida (Section 14.1)
  - You may opt out of arbitration within 30 days (Section 14.1d)

Full text: LICENSE file in the installation directory
Online: https://donjonsec.com/legal/eula
"""


def prompt_eula_acceptance_tui() -> bool:
    """
    Display EULA summary and prompt for acceptance in the TUI.
    Returns True if accepted, False if declined.
    """
    # Import here to avoid circular dependency
    from tui import tui, C, safe_input, is_non_interactive

    if is_non_interactive():
        # CI/CD mode — check env var for pre-acceptance
        if _env_accepted():
            record_acceptance()
            return True
        print(
            "ERROR: EULA not accepted. Set DONJON_ACCEPT_EULA=yes to accept "
            "in non-interactive mode.",
            file=sys.stderr,
        )
        return False

    print(get_eula_summary())
    print(f"  {C.DIM}Type 'view' to read the full EULA, or 'y' to accept.{C.RESET}")
    print()

    while True:
        response = safe_input(
            f"  {C.YELLOW}Do you accept the EULA? [y/N/view]: {C.RESET}"
        ).strip().lower()

        if response == "view":
            # Page through the full EULA
            text = get_eula_text()
            _page_text(text)
            print()
            continue
        elif response in ("y", "yes"):
            record_acceptance()
            tui.success(f"EULA v{EULA_VERSION} accepted.")
            return True
        elif response in ("n", "no"):
            return False
        elif response == "":
            print(f"  {C.DIM}Please type 'y' to accept or 'n' to decline.{C.RESET}")
            continue
        else:
            print(f"  {C.DIM}Please enter 'y', 'n', or 'view'.{C.RESET}")


def prompt_eula_acceptance_server() -> bool:
    """
    Check EULA acceptance for the web server entry point.
    In server mode, acceptance comes from: prior TUI acceptance, env var, or
    the stored acceptance file.
    """
    if check_eula_accepted():
        return True
    if _env_accepted():
        record_acceptance()
        return True
    return False


def _env_accepted() -> bool:
    """Check if EULA is accepted via environment variable."""
    import os
    return os.environ.get("DONJON_ACCEPT_EULA", "").lower() in ("yes", "1", "true")


def _page_text(text: str):
    """Simple pager for terminal output."""
    from tui import safe_input

    lines = text.splitlines()
    term_height = 30
    try:
        import shutil
        term_height = shutil.get_terminal_size().lines - 2
    except Exception:
        pass

    for i, line in enumerate(lines):
        print(line)
        if (i + 1) % term_height == 0 and i + 1 < len(lines):
            resp = safe_input("  -- Press Enter for more, 'q' to stop -- ").strip().lower()
            if resp == "q":
                break
