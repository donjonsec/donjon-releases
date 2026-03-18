from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run(config: dict[str, Any]) -> dict[str, Any]:
    """

    config keys:
      evidence_dir  (str | Path) – root directory of evidence-v1 storage
      max_age_days  (int)        – delete artifacts older than this many days
      dry_run       (bool)       – if True, count but do not delete (default False)
    """
    if not isinstance(config, dict):
        raise TypeError(f"config must be a dict, got {type(config).__name__}")

    evidence_dir: Path = Path(config["evidence_dir"])
    max_age_days: int = int(config["max_age_days"])
    dry_run: bool = bool(config.get("dry_run", False))

    if not evidence_dir.exists():
        raise FileNotFoundError(f"evidence_dir does not exist: {evidence_dir}")
    if not evidence_dir.is_dir():
        raise NotADirectoryError(f"evidence_dir is not a directory: {evidence_dir}")
    if max_age_days < 0:
        raise ValueError(f"max_age_days must be >= 0, got {max_age_days}")

    cutoff: float = time.time() - (max_age_days * 86400)
    deleted_count: int = 0
    freed_bytes: int = 0

    # Walk depth-first so we can prune empty directories after file deletion
    for root, dirs, files in os.walk(evidence_dir, topdown=False):
        root_path = Path(root)
        for filename in files:
            file_path = root_path / filename
            try:
                stat = file_path.stat()
            except OSError as exc:
                logger.warning("Cannot stat %s: %s", file_path, exc)
                continue

            if stat.st_mtime < cutoff:
                size = stat.st_size
                if dry_run:
                    logger.info("dry-run: would delete %s (%d bytes)", file_path, size)
                else:
                    try:
                        file_path.unlink()
                        logger.info("Deleted %s (%d bytes)", file_path, size)
                    except OSError as exc:
                        logger.error("Failed to delete %s: %s", file_path, exc)
                        continue
                deleted_count += 1
                freed_bytes += size

        # Remove empty subdirectories (skip the root evidence_dir itself)
        if root_path != evidence_dir and not dry_run:
            try:
                if not any(root_path.iterdir()):
                    root_path.rmdir()
                    logger.info("Removed empty directory %s", root_path)
            except OSError as exc:
                logger.warning("Cannot remove directory %s: %s", root_path, exc)

    return {"deleted_count": deleted_count, "freed_bytes": freed_bytes}
