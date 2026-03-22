from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("donjon-scan")

# Resolve project root so we can import internal packages regardless of cwd
_BIN_DIR = Path(__file__).resolve().parent
_ROOT = _BIN_DIR.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from lib.evidence import get_evidence_manager  # noqa: E402
from lib.export import ExportManager  # noqa: E402

# Scanner name to module/class mapping
SCANNER_MAP: dict[str, tuple[str, str]] = {
    "network": ("scanners.network_scanner", "NetworkScanner"),
    "vulnerability": ("scanners.vulnerability_scanner", "VulnerabilityScanner"),
    "web": ("scanners.web_scanner", "WebScanner"),
    "ssl": ("scanners.ssl_scanner", "SSLScanner"),
    "windows": ("scanners.windows_scanner", "WindowsScanner"),
    "linux": ("scanners.linux_scanner", "LinuxScanner"),
    "compliance": ("scanners.compliance_scanner", "ComplianceScanner"),
    "ad": ("scanners.ad_scanner", "ADScanner"),
    "cloud": ("scanners.cloud_scanner", "CloudScanner"),
    "container": ("scanners.container_scanner", "ContainerScanner"),
    "sbom": ("scanners.sbom_scanner", "SBOMScanner"),
    "credential": ("scanners.credential_scanner", "CredentialScanner"),
    "asm": ("scanners.asm_scanner", "ASMScanner"),
    "openvas": ("scanners.openvas_scanner", "OpenVASScanner"),
    "malware": ("scanners.malware_scanner", "MalwareScanner"),
    "shadow_ai": ("scanners.shadow_ai_scanner", "ShadowAIScanner"),
    "adversary": ("scanners.adversary_scanner", "AdversaryScanner"),
}


def _load_scanner(scanner_name: str, session_id: str):
    """Dynamically load a scanner class and return an instance."""
    import importlib
    if scanner_name not in SCANNER_MAP:
        raise ValueError(f"Unknown scanner: {scanner_name}. Available: {list(SCANNER_MAP.keys())}")
    mod_path, cls_name = SCANNER_MAP[scanner_name]
    mod = importlib.import_module(mod_path)
    cls = getattr(mod, cls_name)
    return cls(session_id)


def run_scan(
    targets: list[str],
    scanners: list[str],
) -> dict[str, Any]:
    """Execute a scan session and return a result envelope.

    Parameters
    ----------
    targets:
        Host IPs, CIDRs, or hostnames to scan.
    scanners:
        Scanner identifiers to enable (e.g. ``["network", "vulnerability"]``).

    Returns
    -------
    dict with keys ``session_id`` (str), ``findings_count`` (int),
    ``exit_code`` (int).
    """
    if not targets:
        raise ValueError("targets must not be empty")
    if not scanners:
        raise ValueError("scanners must not be empty")

    evidence_mgr = get_evidence_manager()
    session_id: str = evidence_mgr.start_session(
        scan_type="cli_scan",
        target_networks=targets,
    )
    logger.info("Starting scan session %s — targets=%s scanners=%s", session_id, targets, scanners)

    findings_count: int = 0
    exit_code: int = 0

    for scanner_name in scanners:
        logger.info("Loading scanner '%s'", scanner_name)
        try:
            scanner = _load_scanner(scanner_name, session_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load scanner '%s': %s", scanner_name, exc)
            exit_code = 1
            continue

        logger.info("Running scanner '%s' against %d target(s)", scanner_name, len(targets))
        try:
            result = scanner.scan(targets=targets, scan_type="standard")
            # Count findings from scanner result
            count = (
                result.get("findings_count", 0) or
                len(result.get("findings", [])) or
                len(result.get("vulnerabilities", [])) or
                len(result.get("hosts", [])) or
                result.get("results_count", 0) or
                result.get("summary", {}).get("findings_count", 0) or
                result.get("summary", {}).get("total_findings", 0) or
                result.get("summary", {}).get("total_ports", 0) or
                0
            )
            findings_count += count
            logger.info(
                "Scanner '%s': %d finding(s)",
                scanner_name,
                count,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Scanner '%s' failed: %s", scanner_name, exc)
            exit_code = 1

    evidence_mgr.end_session(session_id, status="completed" if exit_code == 0 else "partial")
    logger.info("Session %s complete — %d total findings", session_id, findings_count)

    result: dict[str, Any] = {
        "session_id": session_id,
        "findings_count": findings_count,
        "exit_code": exit_code,
    }
    logger.info("Scan complete: %s", result)
    return result


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="donjon-scan",
        description="Run one or more scanners against one or more targets.",
    )
    parser.add_argument(
        "--targets",
        required=True,
        nargs="+",
        metavar="TARGET",
        help="Host, IP, or CIDR range to scan (repeat or space-separated).",
    )
    parser.add_argument(
        "--scanners",
        required=True,
        nargs="+",
        metavar="SCANNER",
        help="Scanner identifier(s) to run.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Emit result as JSON on stdout.",
    )
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    result = run_scan(targets=args.targets, scanners=args.scanners)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Session : {result['session_id']}\nFindings: {result['findings_count']}\nExit    : {result['exit_code']}")

    sys.exit(result["exit_code"])


if __name__ == "__main__":
    main()
