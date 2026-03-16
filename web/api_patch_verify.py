from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _load_evidence(session_id: str) -> dict[str, Any]:
    from darkfactory.evidence import load_evidence  # evidence-v1

    return load_evidence(session_id)


def _resolve_paths(session_id: str) -> dict[str, Path]:
    from darkfactory.paths import resolve_paths  # paths-v1

    return resolve_paths(session_id)


def _build_patch_diff(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    baseline_keys = set(baseline.keys())
    current_keys = set(current.keys())
    added = {k: current[k] for k in current_keys - baseline_keys}
    removed = {k: baseline[k] for k in baseline_keys - current_keys}
    changed: dict[str, dict[str, Any]] = {}
    for k in baseline_keys & current_keys:
        if baseline[k] != current[k]:
            changed[k] = {"before": baseline[k], "after": current[k]}
    return {"added": added, "removed": removed, "changed": changed}


def _verify_paths(
    baseline_paths: dict[str, Path],
    current_paths: dict[str, Path],
) -> dict[str, Any]:
    missing: list[str] = []
    new_paths: list[str] = []
    for name, path in current_paths.items():
        if not path.exists():
            missing.append(name)
    for name in set(current_paths) - set(baseline_paths):
        new_paths.append(name)
    return {"missing_paths": missing, "new_paths": new_paths}


def patch_verify(baseline_session: str, current_session: str) -> Callable[..., Any]:
    if not baseline_session or not isinstance(baseline_session, str):
        raise ValueError("baseline_session must be a non-empty string")
    if not current_session or not isinstance(current_session, str):
        raise ValueError("current_session must be a non-empty string")

    baseline_evidence = _load_evidence(baseline_session)
    current_evidence = _load_evidence(current_session)

    baseline_paths = _resolve_paths(baseline_session)
    current_paths = _resolve_paths(current_session)

    diff = _build_patch_diff(baseline_evidence, current_evidence)
    path_status = _verify_paths(baseline_paths, current_paths)

    verified = len(path_status["missing_paths"]) == 0
    payload: dict[str, Any] = {
        "baseline_session": baseline_session,
        "current_session": current_session,
        "diff": diff,
        "path_status": path_status,
        "verified": verified,
    }

    logger.info(
        "patch_verify complete: baseline=%s current=%s verified=%s",
        baseline_session,
        current_session,
        verified,
    )

    def json_response(**kwargs: Any) -> dict[str, Any]:
        return payload

    return json_response


def create_endpoint() -> Callable[..., Any]:
    def endpoint(baseline_session: str, current_session: str) -> dict[str, Any]:
        json_response = patch_verify(baseline_session, current_session)
        return {"json_response": json_response}

    return endpoint
