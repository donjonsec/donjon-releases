from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
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


def run_scan(
    targets: list[str],
    scanners: list[str],
) -> dict[str, Any]:
    """Execute a scan session and return a result envelope.

    Parameters
    ----------
    targets:
    scanners:
        Scanner identifiers to enable for this session (e.g. ``["nmap", "trivy"]``).

    Returns
    dict with keys ``session_id`` (str), ``findings_count`` (int),
    ``exit_code`` (int).  ``exit_code`` is 0 on success, non-zero on
    partial or full failure.
    """
    if not targets:
        raise ValueError("targets must not be empty")
    if not scanners:
        raise ValueError("scanners must not be empty")

    session_id: str = str(uuid.uuid4())
    logger.info("Starting scan session %s — targets=%s scanners=%s", session_id, targets, scanners)

    evidence_client = get_evidence_manager()
    export_client = ExportManager()

    findings_count: int = 0
    exit_code: int = 0

    for target in targets:
        for scanner_name in scanners:
            logger.info("Running scanner '%s' against target '%s'", scanner_name, target)
            try:
                findings: list[dict[str, Any]] = evidence_client.collect(
                    session_id=session_id,
                    target=target,
                    scanner=scanner_name,
                )
                findings_count += len(findings)
                logger.info(
                    "Scanner '%s' / target '%s': %d finding(s)",
                    scanner_name,
                    target,
                    len(findings),
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Scanner '%s' failed for target '%s': %s",
                    scanner_name,
                    target,
                    exc,
                )
                exit_code = 1

    try:
        export_client.export_session(session_id=session_id)
        logger.info("Session %s exported successfully", session_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("Export failed for session %s: %s", session_id, exc)
        exit_code = 1

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
