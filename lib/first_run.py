from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run_wizard(interactive: bool) -> None:
    from lib.config import get_config, set_config
    from lib.paths import get_paths
    from lib.evidence import record_evidence

    paths = get_paths()
    config = get_config()

    if interactive:
        logger.info("Starting first-run wizard (interactive mode)")
        print("Welcome to DarkFactory. Let's configure your environment.")

        data_dir = paths.get("data_dir")
        if data_dir is not None:
            print(f"Data directory: {data_dir}")

        api_url = input("Enter the API base URL [http://localhost:8000]: ").strip()
        if not api_url:
            api_url = "http://localhost:8000"

        workspace_input = input("Enter your workspace name [default]: ").strip()
        workspace = workspace_input if workspace_input else "default"

        set_config("api_url", api_url)
        set_config("workspace", workspace)
        set_config("first_run_complete", True)
    else:
        logger.info("Starting first-run wizard (non-interactive mode)")
        config_api_url = config.get("api_url")
        if config_api_url is None:
            set_config("api_url", "http://localhost:8000")
        config_workspace = config.get("workspace")
        if config_workspace is None:
            set_config("workspace", "default")
        set_config("first_run_complete", True)

    marker_path = _get_marker_path()
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.touch()

    record_evidence("first_run_wizard_completed", {"interactive": interactive})
    logger.info("First-run wizard completed successfully")


def is_first_run() -> bool:
    marker_path = _get_marker_path()
    return not marker_path.exists()


def _get_marker_path() -> Path:
    from lib.paths import get_paths

    paths = get_paths()
    data_dir = paths.get("data_dir")
    if data_dir is not None:
        base = Path(str(data_dir))
    else:
        base = Path.home() / ".darkfactory"
    return base / ".first_run_complete"


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
