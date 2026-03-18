from __future__ import annotations

import csv
import json
import logging
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def import_results(file_path: str, format: str) -> dict[str, Any]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    fmt = format.lower().strip()
    if fmt not in ("json", "csv", "jsonl"):
        raise ValueError(f"Unsupported format: {format!r}. Expected one of: json, csv, jsonl")

    records: list[dict[str, Any]] = _parse_file(path, fmt)
    session_id = str(uuid.uuid4())

    _store_evidence(session_id, records)

    logger.info(
        "Imported %d records from %s (format=%s, session_id=%s)",
        len(records),
        file_path,
        format,
        session_id,
    )

    return {
        "imported_count": len(records),
        "session_id": session_id,
    }


def _parse_file(path: Path, fmt: str) -> list[dict[str, Any]]:
    if fmt == "json":
        return _parse_json(path)
    if fmt == "jsonl":
        return _parse_jsonl(path)
    if fmt == "csv":
        return _parse_csv(path)
    raise ValueError(f"Unsupported format: {fmt!r}")


def _parse_json(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if isinstance(data, list):
        records: list[dict[str, Any]] = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                raise ValueError(f"JSON array element {i} is not an object")
            records.append(item)
        return records
    if isinstance(data, dict):
        return [data]
    raise ValueError("JSON root must be an array or object")


def _parse_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        if not isinstance(parsed, dict):
            raise ValueError(f"JSONL line {lineno} is not an object")
        records.append(parsed)
    return records


def _parse_csv(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return records
        for row in reader:
            records.append(dict(row))
    return records


def _store_evidence(session_id: str, records: list[dict[str, Any]]) -> None:
    try:
        from lib.database import DatabaseManager
    except ImportError:
        logger.warning("lib.database not available; skipping evidence persistence")
        return

    _db = DatabaseManager()
    conn = _db.get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO evidence_sessions (session_id, record_count, records)
                VALUES (%s, %s, %s::jsonb)
                ON CONFLICT (session_id) DO NOTHING
                """,
                (session_id, len(records), json.dumps(records)),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("Failed to persist evidence session %s", session_id)
        raise
    finally:
        conn.close()
