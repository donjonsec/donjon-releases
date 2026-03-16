from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


def generate_patch_verify(paths: dict[str, Any]) -> dict[str, Any]:
    """Verify that dashboard patch files exist and are valid."""
    results: dict[str, Any] = {
        "verified": [],
        "missing": [],
        "errors": [],
    }

    patch_dir_key = "dashboard_patches"
    patch_dir: Path | None = None

    if patch_dir_key in paths:
        raw = paths[patch_dir_key]
        patch_dir = Path(raw) if not isinstance(raw, Path) else raw
    else:
        # Fall back to a conventional relative location
        for candidate_key in ("base_dir", "root", "project_root"):
            if candidate_key in paths:
                patch_dir = Path(paths[candidate_key]) / "dashboard" / "patches"
                break

    if patch_dir is None:
        results["errors"].append("No dashboard patch directory could be resolved from paths")
        return results

    if not patch_dir.exists():
        results["errors"].append(f"Patch directory does not exist: {patch_dir}")
        return results

    if not patch_dir.is_dir():
        results["errors"].append(f"Patch path is not a directory: {patch_dir}")
        return results

    patch_extensions = {".json", ".yaml", ".yml", ".patch"}

    for entry in sorted(patch_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in patch_extensions:
            continue
        try:
            content = entry.read_text(encoding="utf-8")
            if not content.strip():
                results["errors"].append(f"Patch file is empty: {entry.name}")
            else:
                results["verified"].append(str(entry))
                logger.debug("Verified patch file: %s", entry)
        except OSError as exc:
            error_msg = f"Cannot read patch file {entry.name}: {exc}"
            results["errors"].append(error_msg)
            logger.warning(error_msg)

    logger.info(
        "Patch verification complete: %d verified, %d missing, %d errors",
        len(results["verified"]),
        len(results["missing"]),
        len(results["errors"]),
    )

    return results


def create_patch_verify_callable(paths: dict[str, Any]) -> Callable[[], dict[str, Any]]:
    """Return a zero-argument callable bound to the resolved paths."""

    def _verify() -> dict[str, Any]:
        return generate_patch_verify(paths)

    return _verify


# Contract export: {"generate_patch_verify": "callable"}
generate_patch_verify_callable: Callable[[dict[str, Any]], dict[str, Any]] = generate_patch_verify
