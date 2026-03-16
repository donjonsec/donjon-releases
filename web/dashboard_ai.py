from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


def generate_ai(paths: dict[str, Path]) -> Callable[..., Any]:
    """Return a callable that generates AI-assisted dashboard content using paths-v1."""

    def _generate(prompt: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        if not prompt or not isinstance(prompt, str):
            raise ValueError("prompt must be a non-empty string")

        ctx: dict[str, Any] = context or {}
        base_path: Path = paths.get("base", Path("."))
        data_path: Path = paths.get("data", base_path / "data")

        logger.debug("generate_ai called with prompt=%r, data_path=%s", prompt, data_path)

        result: dict[str, Any] = {
            "prompt": prompt,
            "context": ctx,
            "data_path": str(data_path),
            "response": None,
        }
        return result

    return _generate
