#!/usr/bin/env python3
"""Performance Baseline Tracker.

Records scan execution times and alerts on regression.
Compares current run against stored baselines.

Usage:
    python tools/performance-baseline.py --record     # Run scans, save baselines
    python tools/performance-baseline.py --check      # Run scans, compare to baselines
    python tools/performance-baseline.py --show       # Show stored baselines
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ.setdefault("DONJON_ACCEPT_EULA", "yes")
os.environ.setdefault("DONJON_TEST_MODE", "1")

BASELINE_FILE = Path(__file__).parent.parent / "data" / "performance_baselines.json"


def load_baselines() -> dict:
    if BASELINE_FILE.exists():
        return json.loads(BASELINE_FILE.read_text())
    return {}


def save_baselines(baselines: dict) -> None:
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(baselines, indent=2))


def time_operation(name: str, func, *args, **kwargs) -> tuple[float, any]:
    """Time an operation. Returns (seconds, result)."""
    start = time.time()
    try:
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        return elapsed, result
    except Exception as e:
        elapsed = time.time() - start
        return elapsed, {"error": str(e)}


def run_benchmarks() -> dict:
    """Run all benchmarks and return timing results."""
    results = {}

    # 1. Config load time
    elapsed, _ = time_operation("config_load", lambda: __import__("lib.config", fromlist=["Config"]).Config())
    results["config_load"] = {"seconds": round(elapsed, 3), "threshold": 1.0}

    # 2. Compliance mapper load
    elapsed, mapper = time_operation(
        "compliance_load",
        lambda: __import__("lib.compliance", fromlist=["get_compliance_mapper"]).get_compliance_mapper()
    )
    results["compliance_load"] = {"seconds": round(elapsed, 3), "threshold": 2.0}

    # 3. Framework count
    if hasattr(mapper, "get_all_frameworks"):
        elapsed, fws = time_operation("framework_query", mapper.get_all_frameworks)
        results["framework_query"] = {
            "seconds": round(elapsed, 3),
            "threshold": 1.0,
            "count": len(fws) if isinstance(fws, list) else 0,
        }

    # 4. Evidence manager init
    elapsed, _ = time_operation(
        "evidence_init",
        lambda: __import__("lib.evidence", fromlist=["get_evidence_manager"]).get_evidence_manager()
    )
    results["evidence_init"] = {"seconds": round(elapsed, 3), "threshold": 1.0}

    # 5. Export manager — generate SARIF
    try:
        from lib.export import ExportManager
        import tempfile

        em = ExportManager()
        test_findings = [
            {"id": "PERF-001", "title": "Performance test", "severity": "high",
             "host": "10.0.0.1", "port": 443, "cve": "CVE-2024-0001", "cvss": 8.5,
             "scanner": "perf_test", "timestamp": "2026-01-01T00:00:00Z",
             "remediation": "Test", "description": "Test", "category": "test", "status": "open"}
        ] * 100  # 100 findings

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmp = Path(f.name)
        elapsed, _ = time_operation("sarif_export_100", em.export_sarif, test_findings, tmp)
        size = tmp.stat().st_size if tmp.exists() else 0
        tmp.unlink(missing_ok=True)
        results["sarif_export_100"] = {"seconds": round(elapsed, 3), "threshold": 5.0, "bytes": size}
    except Exception as e:
        results["sarif_export_100"] = {"seconds": 0, "error": str(e)}

    # 6. Windows scanner (if on Windows)
    if sys.platform == "win32":
        try:
            from scanners.windows_scanner import WindowsScanner
            scanner = WindowsScanner("PERF-BENCH")
            elapsed, result = time_operation("windows_scan_quick", scanner.scan, scan_type="quick")
            checks = result.get("checks_completed", 0) if isinstance(result, dict) else 0
            results["windows_scan_quick"] = {"seconds": round(elapsed, 3), "threshold": 30.0, "checks": checks}
        except Exception as e:
            results["windows_scan_quick"] = {"seconds": 0, "error": str(e)}

    # 7. Server startup time
    try:
        import subprocess
        start = time.time()
        proc = subprocess.Popen(
            [sys.executable, "bin/start-server.py", "--host", "127.0.0.1", "--port", "19877", "--no-auth", "--stdlib"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "DONJON_ACCEPT_EULA": "yes", "DONJON_ALLOW_NO_AUTH": "1"},
        )
        # Poll until health responds
        import urllib.request
        for _ in range(20):
            time.sleep(0.5)
            try:
                urllib.request.urlopen("http://127.0.0.1:19877/api/v1/health", timeout=2)
                elapsed = time.time() - start
                results["server_startup"] = {"seconds": round(elapsed, 3), "threshold": 10.0}
                break
            except Exception:
                continue
        else:
            results["server_startup"] = {"seconds": time.time() - start, "threshold": 10.0, "error": "timeout"}
        proc.terminate()
        proc.wait(timeout=5)
    except Exception as e:
        results["server_startup"] = {"seconds": 0, "error": str(e)}

    return results


def main():
    parser = argparse.ArgumentParser(description="Performance Baseline Tracker")
    parser.add_argument("--record", action="store_true", help="Run benchmarks and save as baseline")
    parser.add_argument("--check", action="store_true", help="Run benchmarks and compare to baseline")
    parser.add_argument("--show", action="store_true", help="Show stored baselines")
    parser.add_argument("--regression-threshold", type=float, default=2.0,
                        help="Alert if timing exceeds baseline by this multiplier (default: 2.0)")
    args = parser.parse_args()

    if args.show:
        baselines = load_baselines()
        if not baselines:
            print("No baselines stored. Run with --record first.")
            return
        print(f"Baselines recorded: {baselines.get('recorded_at', '?')}")
        print(f"Platform: {baselines.get('platform', '?')}")
        print()
        for name, data in baselines.get("benchmarks", {}).items():
            print(f"  {name:30s} {data['seconds']:8.3f}s  (threshold: {data.get('threshold', '?')}s)")
        return

    print("Running performance benchmarks...")
    results = run_benchmarks()

    if args.record:
        baselines = {
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "benchmarks": results,
        }
        save_baselines(baselines)
        print(f"\nBaselines saved to {BASELINE_FILE}")
        for name, data in results.items():
            status = "OK" if data["seconds"] < data.get("threshold", 999) else "SLOW"
            print(f"  [{status:4s}] {name:30s} {data['seconds']:8.3f}s")

    elif args.check:
        baselines = load_baselines()
        if not baselines:
            print("No baselines stored. Run with --record first.")
            return

        print(f"\nComparing to baseline from {baselines.get('recorded_at', '?')}")
        regressions = []
        for name, current in results.items():
            baseline = baselines.get("benchmarks", {}).get(name)
            if baseline is None:
                print(f"  [NEW ] {name:30s} {current['seconds']:8.3f}s (no baseline)")
                continue

            ratio = current["seconds"] / max(baseline["seconds"], 0.001)
            if ratio > args.regression_threshold:
                status = "REGR"
                regressions.append((name, baseline["seconds"], current["seconds"], ratio))
            elif current["seconds"] > current.get("threshold", 999):
                status = "SLOW"
            else:
                status = "OK"

            print(f"  [{status:4s}] {name:30s} {current['seconds']:8.3f}s  (was {baseline['seconds']:.3f}s, {ratio:.1f}x)")

        if regressions:
            print(f"\n  WARNING: {len(regressions)} regressions detected!")
            for name, old, new, ratio in regressions:
                print(f"    {name}: {old:.3f}s -> {new:.3f}s ({ratio:.1f}x slower)")
        else:
            print("\n  No regressions detected.")
    else:
        print("\nResults (use --record to save or --check to compare):")
        for name, data in results.items():
            print(f"  {name:30s} {data['seconds']:8.3f}s")


if __name__ == "__main__":
    main()
