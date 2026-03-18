from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

log = logging.getLogger(__name__)


def _fingerprint(finding: dict[str, Any]) -> str:
    """Stable fingerprint: hash of (plugin_id, target, check_id) or full dict if missing."""
    keys = ("plugin_id", "target", "check_id", "rule_id", "title")
    parts: list[str] = []
    for k in keys:
        if k in finding:
            parts.append(f"{k}={finding[k]}")
    if not parts:
        # Fall back to deterministic hash of sorted dict
        parts = [json.dumps(finding, sort_keys=True, default=str)]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_prior_fingerprints(session_id: str) -> dict[str, dict[str, Any]]:
    """Load historical findings for sessions preceding the given one via lib.database."""
    try:
        from lib.database import DatabaseManager
        _db = DatabaseManager()
        get_connection = _db.get_connection
    except ImportError:
        log.warning("evidence-v1 DB layer unavailable; treating all findings as new")
        return {}

    prior: dict[str, dict[str, Any]] = {}
    try:
        conn = get_connection()
        cur = conn.cursor()
        # evidence-v1 schema: evidence(session_id, fingerprint, payload jsonb)
        cur.execute(
            """
            SELECT fingerprint, payload
            FROM evidence
            WHERE session_id != %s
              AND session_id IN (
                  SELECT DISTINCT session_id FROM evidence
                  WHERE session_id < %s
              )
            """,
            (session_id, session_id),
        )
        for row in cur.fetchall():
            fp: str = row[0]
            payload: dict[str, Any] = row[1] if isinstance(row[1], dict) else json.loads(row[1])
            prior[fp] = payload
        cur.close()
        conn.close()
    except Exception:
        log.exception("Failed to load prior fingerprints from evidence-v1")
    return prior


def _store_fingerprints(session_id: str, findings: list[dict[str, Any]], fingerprints: list[str]) -> None:
    """Persist current session findings into evidence store."""
    try:
        from lib.database import DatabaseManager
        _db = DatabaseManager()
        get_connection = _db.get_connection
    except ImportError:
        return

    try:
        conn = get_connection()
        cur = conn.cursor()
        for finding, fp in zip(findings, fingerprints):
            cur.execute(
                """
                INSERT INTO evidence (session_id, fingerprint, payload)
                VALUES (%s, %s, %s)
                ON CONFLICT (session_id, fingerprint) DO NOTHING
                """,
                (session_id, fp, json.dumps(finding, default=str)),
            )
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        log.exception("Failed to persist fingerprints to evidence-v1")


def deduplicate(session_id: str, findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """

    Args:
        session_id: Identifier for the current scan session.
        findings:   List of finding dicts from the current scan.

    Returns:
        - new:       findings whose fingerprint was never seen before.
        - recurring: findings whose fingerprint appeared in a prior session.
        - fixed:     findings from prior sessions absent in the current scan.
    """
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string")
    if not isinstance(findings, list):
        raise TypeError(f"findings must be a list, got {type(findings).__name__}")

    prior: dict[str, dict[str, Any]] = _load_prior_fingerprints(session_id)

    current_fps: list[str] = [_fingerprint(f) for f in findings]
    current_fp_set: set[str] = set(current_fps)

    new: list[dict[str, Any]] = []
    recurring: list[dict[str, Any]] = []

    for finding, fp in zip(findings, current_fps):
        if fp in prior:
            recurring.append(finding)
        else:
            new.append(finding)

    fixed: list[dict[str, Any]] = [payload for fp, payload in prior.items() if fp not in current_fp_set]

    _store_fingerprints(session_id, findings, current_fps)

    log.info(
        "dedup session=%s new=%d recurring=%d fixed=%d",
        session_id,
        len(new),
        len(recurring),
        len(fixed),
    )

    return {"new": new, "recurring": recurring, "fixed": fixed}


def run(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Entry point matching the contract envelope: {session_id, findings} -> {new, recurring, fixed}."""
    try:
        session_id: str = payload["session_id"]
        findings: list[dict[str, Any]] = payload["findings"]
    except KeyError as exc:
        raise ValueError(f"Missing required field in payload: {exc}") from exc

    return deduplicate(session_id=session_id, findings=findings)
