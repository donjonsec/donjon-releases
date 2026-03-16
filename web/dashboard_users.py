from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_users(output_dir: Path | str = "output") -> None:
    from paths import get_paths  # type: ignore[import]

    out = Path(str(output_dir))
    out.mkdir(parents=True, exist_ok=True)

    path_config: dict[str, Any] = get_paths()

    users_data: list[dict[str, Any]] = [
        {
            "id": 1,
            "username": "admin",
            "role": "administrator",
            "email": "admin@darkfactory.local",
            "active": True,
        },
        {
            "id": 2,
            "username": "operator",
            "role": "operator",
            "email": "operator@darkfactory.local",
            "active": True,
        },
        {
            "id": 3,
            "username": "viewer",
            "role": "viewer",
            "email": "viewer@darkfactory.local",
            "active": True,
        },
    ]

    users_file = out / "users.json"
    users_file.write_text(json.dumps(users_data, indent=2))
    logger.info("Generated users file at %s (paths config: %s)", users_file, path_config)
