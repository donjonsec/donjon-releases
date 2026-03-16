from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from darkfactory.config import get_config  # config-v1
from darkfactory.evidence import record_evidence  # evidence-v1
from darkfactory.paths import get_paths  # paths-v1

logger = logging.getLogger(__name__)


def run_scan(
    targets: list[str],
    scanners: list[str] | None,
    depth: str,
) -> dict[str, Any]:
    paths = get_paths()
    config = get_config()

    if not targets:
        raise ValueError("targets must be a non-empty list")

    valid_depths = {"shallow", "normal", "deep"}
    if depth not in valid_depths:
        raise ValueError(f"depth must be one of {valid_depths}, got {depth!r}")

    active_scanners: list[str] = scanners if scanners is not None else config.get("default_scanners", [])

    session_id = record_evidence(
        paths=paths,
        config=config,
        targets=targets,
        scanners=active_scanners,
        depth=depth,
    )

    findings_count: int = session_id.get("findings_count", 0) if isinstance(session_id, dict) else 0
    resolved_session_id: str = session_id.get("session_id", "") if isinstance(session_id, dict) else str(session_id)

    return {
        "session_id": resolved_session_id,
        "findings_count": findings_count,
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
