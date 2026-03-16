from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run_wizard(interactive: bool) -> None:
    from lib.config import get_config
    from lib.paths import get_paths
    from lib.evidence import get_evidence_manager

    paths = get_paths()
    cfg = get_config()

    if interactive:
        logger.info("Starting first-run wizard (interactive mode)")
        print("Welcome to Donjon Platform. Let's configure your environment.")

        data_dir = paths.data
        print(f"Data directory: {data_dir}")

        api_url = input("Enter the API base URL [http://localhost:8000]: ").strip()
        if not api_url:
            api_url = "http://localhost:8000"

        workspace_input = input("Enter your workspace name [default]: ").strip()
        workspace = workspace_input if workspace_input else "default"

        cfg.set("api_url", api_url)
        cfg.set("workspace", workspace)
        cfg.set("first_run_complete", True)
        cfg.save()
    else:
        logger.info("Starting first-run wizard (non-interactive mode)")
        if cfg.get("api_url") is None:
            cfg.set("api_url", "http://localhost:8000")
        if cfg.get("workspace") is None:
            cfg.set("workspace", "default")
        cfg.set("first_run_complete", True)
        cfg.save()

    marker_path = _get_marker_path()
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.touch()

    em = get_evidence_manager()
    session_id = em.start_session("first_run", [])
    em.add_evidence(session_id, "config", "First-run wizard completed",
                    description=f"interactive={interactive}")
    em.end_session(session_id, {"interactive": interactive})
    logger.info("First-run wizard completed successfully")


def is_first_run() -> bool:
    marker_path = _get_marker_path()
    return not marker_path.exists()


def _get_marker_path() -> Path:
    from lib.paths import get_paths

    paths = get_paths()
    return paths.data / ".first_run_complete"


def get_run_wizard(interactive: bool) -> Callable[[], None]:
    def _run_wizard() -> None:
        run_wizard(interactive)

    return _run_wizard


def get_is_first_run() -> Callable[[], bool]:
    return is_first_run


def build(interactive: bool) -> dict[str, Any]:
    return {
        "run_wizard": get_run_wizard(interactive),
        "is_first_run": get_is_first_run(),
    }
