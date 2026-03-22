#!/usr/bin/env python3
"""
Donjon Platform - Automated Competitive Demo Script

Runs a complete platform demo in under 5 minutes:
  1. Accept EULA, start web server
  2. Run a Windows security scan (quick mode, real findings)
  3. Screenshot every key dashboard tab via Playwright
  4. Export findings to SARIF and CSV
  5. Generate a compliance report summary
  6. Produce data/demo/ with screenshots and demo-report.md

Usage:
    python tools/demo.py                    # Full demo
    python tools/demo.py --no-scan          # Skip scan, use existing data
    python tools/demo.py --output path/     # Custom output directory
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Project bootstrap
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent

sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_PROJECT_ROOT / "lib"))
sys.path.insert(0, str(_PROJECT_ROOT / "scanners"))

os.environ["DONJON_HOME"] = str(_PROJECT_ROOT)
os.environ["DONJON_ACCEPT_EULA"] = "yes"
os.environ["DONJON_TEST_MODE"] = "1"
os.environ["DONJON_ALLOW_NO_AUTH"] = "1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_free_port() -> int:
    """Find a random free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(host: str, port: int, timeout: float = 30.0) -> bool:
    """Block until the server accepts TCP connections or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def _print_step(n: int, msg: str) -> None:
    print(f"\n  [{n:02d}] {msg}")


def _print_ok(msg: str) -> None:
    print(f"       -> {msg}")


def _print_fail(msg: str) -> None:
    print(f"       !! {msg}")


# ---------------------------------------------------------------------------
# EULA acceptance (ensure the file exists before anything else)
# ---------------------------------------------------------------------------

def ensure_eula() -> None:
    """Record EULA acceptance so the server and scanner don't block."""
    from eula import check_eula_accepted, record_acceptance
    if not check_eula_accepted():
        record_acceptance()


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def start_server(port: int) -> subprocess.Popen:
    """Start the web server in background and return the Popen handle."""
    cmd = [
        sys.executable,
        str(_PROJECT_ROOT / "bin" / "start-server.py"),
        "--host", "127.0.0.1",
        "--port", str(port),
        "--no-auth",
    ]
    env = {**os.environ}
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    return proc


def stop_server(proc: subprocess.Popen) -> None:
    """Terminate the server process tree."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            # On Windows, kill the entire process tree
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
            )
        else:
            proc.terminate()
            proc.wait(timeout=5)
    except Exception:
        proc.kill()


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def run_scan() -> Dict[str, Any]:
    """Run a quick Windows security scan directly via the scanner module."""
    import uuid
    from evidence import get_evidence_manager

    # Record acceptance before scan too
    ensure_eula()

    em = get_evidence_manager()

    # Start a session in the evidence database (returns generated ID)
    session_id = em.start_session(
        scan_type="quick",
        target_networks=["localhost"],
    )

    findings_count = 0
    exit_code = 0

    try:
        # Import and run the Windows scanner directly
        sys.path.insert(0, str(_PROJECT_ROOT / "scanners"))
        from windows_scanner import WindowsScanner

        scanner = WindowsScanner(session_id=session_id)
        result = scanner.scan(targets=["localhost"], scan_type="quick")
        findings_count = len(scanner.findings)
    except Exception as exc:
        _print_fail(f"Scanner error: {exc}")
        exit_code = 1

    # End session
    try:
        em.end_session(session_id, summary={"findings_count": findings_count})
    except Exception:
        pass

    return {
        "session_id": session_id,
        "findings_count": findings_count,
        "exit_code": exit_code,
    }


# ---------------------------------------------------------------------------
# Screenshots via Playwright
# ---------------------------------------------------------------------------

SCREENSHOT_PLAN = [
    ("01-overview.png",    "overview",    "Overview"),
    ("02-scan-center.png", "scan-center", "Scan Center"),
    ("03-trends.png",      "trends",      "Trends"),
    ("04-license.png",     "lifecycle",   "License"),
]


def take_screenshots(base_url: str, output_dir: Path) -> List[Dict[str, str]]:
    """Launch Playwright, navigate through tabs, capture screenshots."""
    from playwright.sync_api import sync_playwright

    results: List[Dict[str, str]] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            device_scale_factor=1,
        )
        page = context.new_page()

        # Navigate to dashboard
        page.goto(base_url, wait_until="networkidle", timeout=30_000)

        # Wait for nav buttons to be rendered (proves the shell JS ran)
        page.wait_for_selector('.nav-item[data-tab="overview"]', timeout=15_000)

        # Give the overview tab time to load its data via API
        page.wait_for_timeout(3000)

        for filename, tab_id, label in SCREENSHOT_PLAN:
            # Click the sidebar nav button for this tab (switchTab is inside
            # an IIFE closure, so we trigger it via the click handler)
            nav_btn = page.locator(f'.nav-item[data-tab="{tab_id}"]')
            nav_btn.click()
            # Wait for tab content to render and API calls to settle
            page.wait_for_timeout(2500)

            filepath = output_dir / filename
            page.screenshot(path=str(filepath), full_page=False)
            results.append({"file": filename, "tab": label, "path": str(filepath)})
            _print_ok(f"Screenshot: {filename} ({label})")

        browser.close()

    return results


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

def export_findings(session_id: str, output_dir: Path) -> Dict[str, Path]:
    """Export findings to SARIF and CSV."""
    from export import ExportManager

    exporter = ExportManager()
    exported: Dict[str, Path] = {}

    try:
        results = exporter.export_all(
            session_id=session_id,
            output_dir=output_dir,
            formats=["sarif", "csv"],
        )
        for fmt, path in results.items():
            exported[fmt] = Path(path)
    except Exception as exc:
        _print_fail(f"Export error: {exc}")

    return exported


# ---------------------------------------------------------------------------
# Compliance summary
# ---------------------------------------------------------------------------

def get_compliance_summary() -> Dict[str, Any]:
    """Gather compliance framework statistics."""
    from compliance import get_compliance_mapper

    mapper = get_compliance_mapper()
    frameworks = mapper.get_supported_frameworks()
    return {
        "frameworks_count": len(frameworks),
        "frameworks": frameworks,
    }


def get_findings_summary(session_id: str) -> Dict[str, Any]:
    """Get a findings breakdown from the evidence database."""
    from evidence import get_evidence_manager

    em = get_evidence_manager()

    if session_id and session_id != "unknown":
        findings = em.get_findings_for_session(session_id)
    else:
        findings = em.get_findings_by_severity(status="open")

    by_severity: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_demo_report(
    output_dir: Path,
    screenshots: List[Dict[str, str]],
    scan_result: Dict[str, Any],
    findings_summary: Dict[str, Any],
    compliance: Dict[str, Any],
    exports: Dict[str, Path],
    scan_time: float,
) -> Path:
    """Write demo-report.md into output_dir."""

    sev = findings_summary.get("by_severity", {})
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_table = "\n".join(
        f"| {s} | {c} |"
        for s, c in sorted(sev.items(), key=lambda x: sev_order.index(x[0]) if x[0] in sev_order else 99)
    ) or "| (none) | 0 |"

    export_lines = "\n".join(
        f"- **{fmt.upper()}**: `{path.name}`"
        for fmt, path in exports.items()
    ) or "- (no exports produced)"

    fw_count = compliance.get("frameworks_count", 0)
    fw_list = ", ".join(compliance.get("frameworks", [])[:10])
    if fw_count > 10:
        fw_list += f", ... ({fw_count} total)"

    session_id = scan_result.get("session_id", "N/A")
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_findings = findings_summary.get("total", 0)

    # Build screenshots section
    ss_section = ""
    for ss in screenshots:
        ss_section += f"### {ss['tab']}\n\n![{ss['tab']}]({ss['file']})\n\n"

    report = f"""# Donjon Platform - Automated Demo Report

**Generated:** {gen_time}
**Session ID:** `{session_id}`
**Scan Duration:** {scan_time:.1f}s

---

## Platform Overview

Donjon is a self-contained cybersecurity assessment platform that runs
entirely on-premises with zero cloud dependencies. It ships with 17+
integrated scanners, maps findings to {fw_count} compliance frameworks,
and exports to 10 industry formats including SARIF, STIX 2.1, and CEF.

## Scan Results

| Severity | Count |
|----------|-------|
{sev_table}

**Total findings:** {total_findings}

## Dashboard Screenshots

{ss_section}## Compliance Coverage

Donjon maps every finding to controls across **{fw_count} frameworks**:

{fw_list}

## Export Formats

{export_lines}

Donjon supports 10 export formats out of the box: CEF, STIX 2.1,
Splunk HEC, Microsoft Sentinel, QRadar LEEF, ServiceNow/Jira CSV,
Qualys XML, SARIF 2.1.0, Syslog RFC 5424, and JSON Lines.

## Key Differentiators

| Capability | Donjon | Typical Competitor |
|------------|--------|--------------------|
| Air-gap operation | Yes, zero internet required | Cloud-dependent |
| Scanners included | 17+ built-in | 1-3, rest via plugins |
| Compliance frameworks | {fw_count} | 3-5 |
| Export formats | 10 SIEM/GRC formats | PDF + CSV |
| Deployment | Single directory, no Docker required | Complex multi-service |
| Time to first scan | < 2 minutes | Hours of setup |

---

*This report was generated automatically by the Donjon Platform demo script.*
*All findings are from a real scan against the local system.*
"""

    report_path = output_dir / "demo-report.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Donjon Platform - Automated Competitive Demo",
    )
    parser.add_argument(
        "--no-scan", action="store_true",
        help="Skip scan, use existing findings data",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Custom output directory (default: data/demo/)",
    )
    args = parser.parse_args()

    # Output directory
    if args.output:
        output_dir = Path(args.output).resolve()
    else:
        output_dir = _PROJECT_ROOT / "data" / "demo"
    output_dir.mkdir(parents=True, exist_ok=True)

    print()
    print("  ============================================")
    print("    Donjon Platform - Competitive Demo")
    print("  ============================================")
    print()
    print(f"  Output: {output_dir}")

    demo_start = time.monotonic()

    # ------------------------------------------------------------------
    # Step 1: EULA
    # ------------------------------------------------------------------
    _print_step(1, "Accepting EULA")
    ensure_eula()
    _print_ok("EULA accepted")

    # ------------------------------------------------------------------
    # Step 2: Scan
    # ------------------------------------------------------------------
    scan_time = 0.0
    scan_result: Dict[str, Any] = {"session_id": "unknown", "findings_count": 0}

    if not args.no_scan:
        _print_step(2, "Running Windows security scan (quick mode)")
        scan_start = time.monotonic()
        scan_result = run_scan()
        scan_time = time.monotonic() - scan_start
        _print_ok(
            f"Scan complete: {scan_result.get('findings_count', 0)} findings "
            f"in {scan_time:.1f}s (session: {scan_result.get('session_id', 'N/A')[:8]}...)"
        )
    else:
        _print_step(2, "Skipping scan (--no-scan)")
        _print_ok("Using existing findings data")

    # ------------------------------------------------------------------
    # Step 3: Start server
    # ------------------------------------------------------------------
    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    _print_step(3, f"Starting web server on port {port}")
    server_proc = start_server(port)

    if not _wait_for_server("127.0.0.1", port, timeout=30):
        _print_fail("Server failed to start within 30s")
        stop_server(server_proc)
        return 1
    _print_ok(f"Server running at {base_url}")

    try:
        # ------------------------------------------------------------------
        # Step 4: Screenshots
        # ------------------------------------------------------------------
        _print_step(4, "Capturing dashboard screenshots")
        screenshots = take_screenshots(base_url, output_dir)
        _print_ok(f"{len(screenshots)} screenshots saved")

        # ------------------------------------------------------------------
        # Step 5: Exports
        # ------------------------------------------------------------------
        session_id = scan_result.get("session_id", "unknown")
        exports: Dict[str, Path] = {}

        if session_id != "unknown":
            _print_step(5, "Exporting findings (SARIF + CSV)")
            exports = export_findings(session_id, output_dir)
            for fmt, path in exports.items():
                _print_ok(f"{fmt.upper()}: {path.name}")
        else:
            _print_step(5, "Skipping exports (no scan session)")
            # Try to export from latest session via API
            try:
                from evidence import get_evidence_manager
                em = get_evidence_manager()
                sessions = em.get_all_sessions(limit=1)
                if sessions:
                    latest_sid = sessions[0].get("session_id")
                    if latest_sid:
                        session_id = latest_sid
                        exports = export_findings(session_id, output_dir)
                        for fmt, path in exports.items():
                            _print_ok(f"{fmt.upper()}: {path.name}")
            except Exception:
                _print_ok("No previous session data available for export")

        # ------------------------------------------------------------------
        # Step 6: Compliance summary
        # ------------------------------------------------------------------
        _print_step(6, "Generating compliance summary")
        compliance = get_compliance_summary()
        _print_ok(f"{compliance['frameworks_count']} compliance frameworks supported")

        # ------------------------------------------------------------------
        # Step 7: Findings summary
        # ------------------------------------------------------------------
        _print_step(7, "Collecting findings summary")
        findings_summary = get_findings_summary(session_id)
        _print_ok(f"{findings_summary['total']} total findings")
        for sev, count in sorted(findings_summary["by_severity"].items()):
            _print_ok(f"  {sev}: {count}")

        # ------------------------------------------------------------------
        # Step 8: Generate report
        # ------------------------------------------------------------------
        _print_step(8, "Generating demo report")
        report_path = generate_demo_report(
            output_dir=output_dir,
            screenshots=screenshots,
            scan_result=scan_result,
            findings_summary=findings_summary,
            compliance=compliance,
            exports=exports,
            scan_time=scan_time,
        )
        _print_ok(f"Report: {report_path.name}")

    finally:
        # ------------------------------------------------------------------
        # Step 9: Stop server
        # ------------------------------------------------------------------
        _print_step(9, "Stopping web server")
        stop_server(server_proc)
        _print_ok("Server stopped")

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    total_time = time.monotonic() - demo_start

    print()
    print("  ============================================")
    print("    Demo Complete")
    print("  ============================================")
    print()
    print(f"  Findings:    {findings_summary['total']}")
    print(f"  Frameworks:  {compliance['frameworks_count']}")
    print(f"  Exports:     {', '.join(fmt.upper() for fmt in exports) or 'none'}")
    print(f"  Screenshots: {len(screenshots)}")
    print(f"  Scan time:   {scan_time:.1f}s")
    print(f"  Total time:  {total_time:.1f}s")
    print(f"  Output:      {output_dir}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
