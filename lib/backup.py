from __future__ import annotations

import logging
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> int:
    """Extract tar members, rejecting any that would escape dest."""
    dest_resolved = dest.resolve()
    count = 0
    for member in tf.getmembers():
        # Reject absolute paths and any path that would escape destination
        if Path(member.name).is_absolute():
            raise ValueError(f"Tar member has absolute path: {member.name!r}")
        candidate = (dest_resolved / member.name).resolve()
        if not str(candidate).startswith(str(dest_resolved) + "/") and candidate != dest_resolved:
            raise ValueError(f"Tar member would escape destination: {member.name!r}")
        # Skip device/special files
        if member.isdev() or member.issym() or member.islnk():
            logger.warning("Skipping non-regular tar member: %s", member.name)
            continue
        tf.extract(member, path=dest, set_attrs=False)
        count += 1
    return count


def run(input_data: dict[str, Any], evidence: Any, paths: Any) -> dict[str, Any]:
    """
    Execute backup or restore operation.

    Args:
        input_data: {"mode": "backup"|"restore", "path": source/target path string}
        evidence:   evidence-v1 client for recording artifacts
        paths:      paths-v1 client for resolving managed directories

    Returns:
        {"backup_path": str, "file_count": int}
    """
    mode: str = input_data["mode"]
    raw_path: str = input_data["path"]

    if mode not in ("backup", "restore"):
        raise ValueError(f"Invalid mode {mode!r}; expected 'backup' or 'restore'")

    source_path = Path(raw_path).resolve()

    if mode == "backup":
        if not source_path.exists():
            raise FileNotFoundError(f"Source path does not exist: {source_path}")

        backup_dir: Path = Path(paths.backup_dir()).resolve()
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_name = f"backup_{timestamp}.tar.gz"
        archive_path = backup_dir / archive_name

        file_count = 0
        with tarfile.open(archive_path, "w:gz") as tf:
            if source_path.is_dir():
                for file in source_path.rglob("*"):
                    if file.is_file():
                        tf.add(file, arcname=file.relative_to(source_path))
                        file_count += 1
            else:
                tf.add(source_path, arcname=source_path.name)
                file_count = 1

        evidence.record(
            event="backup_created",
            archive=str(archive_path),
            source=str(source_path),
            file_count=file_count,
        )

        logger.info("Backup created: %s (%d files)", archive_path, file_count)
        return {"backup_path": str(archive_path), "file_count": file_count}

    # mode == "restore"
    archive_path = source_path
    if not archive_path.exists():
        raise FileNotFoundError(f"Archive does not exist: {archive_path}")
    if not tarfile.is_tarfile(str(archive_path)):
        raise ValueError(f"Path is not a valid tar archive: {archive_path}")

    restore_dir: Path = Path(paths.restore_dir()).resolve()
    restore_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "r:*") as tf:
        file_count = _safe_extract(tf, restore_dir)

    evidence.record(
        event="backup_restored",
        archive=str(archive_path),
        destination=str(restore_dir),
        file_count=file_count,
    )

    logger.info("Restore complete: %s -> %s (%d files)", archive_path, restore_dir, file_count)
    return {"backup_path": str(restore_dir), "file_count": file_count}
