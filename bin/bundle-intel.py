from __future__ import annotations

import json
import logging
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

VALID_MODES = {"full", "incremental", "minimal"}


def _collect_intel_records(mode: str, source_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    if not source_dir.exists():
        logger.warning("Source directory %s does not exist, returning empty records", source_dir)
        return records

    patterns: list[str]
    if mode == "full":
        patterns = ["*.json", "*.jsonl", "*.ndjson"]
    elif mode == "incremental":
        patterns = ["*.jsonl", "*.ndjson"]
    else:
        patterns = ["*.json"]

    for pattern in patterns:
        for filepath in sorted(source_dir.rglob(pattern)):
            try:
                content = filepath.read_text(encoding="utf-8")
                if filepath.suffix in {".jsonl", ".ndjson"}:
                    for line in content.splitlines():
                        line = line.strip()
                        if line:
                            records.append(json.loads(line))
                else:
                    data = json.loads(content)
                    if isinstance(data, list):
                        records.extend(data)
                    else:
                        records.append(data)
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to read %s: %s", filepath, exc)

    return records


def _write_bundle(records: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".jsonl",
        delete=False,
        encoding="utf-8",
    ) as tmp:
        tmp_path = Path(tmp.name)
        for record in records:
            tmp.write(json.dumps(record, separators=(",", ":")) + "\n")

    try:
        if output_path.suffix in {".gz", ".tgz"} or str(output_path).endswith(".tar.gz"):
            with tarfile.open(output_path, "w:gz") as tar:
                tar.add(tmp_path, arcname="intel.jsonl")
        else:
            import shutil

            shutil.move(str(tmp_path), str(output_path))
            tmp_path = Path("")
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def bundle_intel(mode: str, output_path: str) -> dict[str, Any]:
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode '{mode}'. Must be one of: {sorted(VALID_MODES)}")

    if not output_path:
        raise ValueError("output_path must not be empty")

    out = Path(output_path)

    intel_dir_env = os.environ.get("INTEL_SOURCE_DIR", "")
    if intel_dir_env:
        source_dir = Path(intel_dir_env)
    else:
        source_dir = Path(__file__).parent.parent / "data" / "intel"

    logger.info("Bundling intel: mode=%s source=%s output=%s", mode, source_dir, out)

    records = _collect_intel_records(mode, source_dir)
    record_count = len(records)

    _write_bundle(records, out)

    logger.info("Bundle complete: %d records -> %s", record_count, out)

    return {"bundle_path": str(out), "record_count": record_count}


def main() -> int:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <mode> <output_path>", file=sys.stderr)
        print(f"Modes: {', '.join(sorted(VALID_MODES))}", file=sys.stderr)
        return 1

    mode = sys.argv[1]
    output_path = sys.argv[2]

    try:
        result = bundle_intel(mode, output_path)
        print(json.dumps(result))
        return 0
    except ValueError as exc:
        logger.error("Invalid arguments: %s", exc)
        return 2
    except OSError as exc:
        logger.error("I/O error during bundling: %s", exc)
        return 3


if __name__ == "__main__":
    sys.exit(main())
