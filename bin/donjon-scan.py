from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.config import get_config
from lib.evidence import get_evidence_manager
from lib.paths import get_paths

logger = logging.getLogger(__name__)


def run_scan(
    targets: list[str],
    scanners: list[str] | None,
    depth: str,
) -> dict[str, Any]:
    paths = get_paths()
    cfg = get_config()

    if not targets:
        raise ValueError("targets must be a non-empty list")

    valid_depths = {"shallow", "normal", "deep"}
    if depth not in valid_depths:
        raise ValueError(f"depth must be one of {valid_depths}, got {depth!r}")

    active_scanners: list[str] = scanners if scanners is not None else cfg.get("tools", {})

    em = get_evidence_manager()
    session_id = em.start_session(
        scan_type=depth,
        target_networks=targets,
        metadata={"scanners": active_scanners},
    )

    # TODO: actually invoke scanner modules here

    em.end_session(session_id, {"targets": targets, "scanners": active_scanners, "depth": depth})

    return {
        "session_id": session_id,
        "findings_count": 0,
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="Donjon security scanner")
    parser.add_argument("--targets", nargs="+", required=True, help="Scan targets")
    parser.add_argument("--scanners", nargs="*", default=None, help="Scanner modules to use")
    parser.add_argument("--depth", default="normal", choices=["shallow", "normal", "deep"], help="Scan depth")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    result = run_scan(
        targets=args.targets,
        scanners=args.scanners,
        depth=args.depth,
    )

    if args.output_json:
        print(json.dumps(result))
    else:
        print(f"Session ID : {result['session_id']}")
        print(f"Findings   : {result['findings_count']}")


if __name__ == "__main__":
    main()
