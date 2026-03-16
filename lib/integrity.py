from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import logging
from pathlib import Path
from typing import Any

from lib.paths import get_root

logger = logging.getLogger(__name__)


class IntegrityError(Exception):
    pass


def _module_path(module_name: str) -> Path:
    spec = importlib.util.find_spec(module_name)
    if spec is None or spec.origin is None:
        raise IntegrityError(f"Cannot locate module: {module_name!r}")
    return Path(spec.origin)


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_path() -> Path:
    return get_root() / "integrity_manifest.json"


def generate_manifest(modules: list[str]) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for mod in modules:
        path = _module_path(mod)
        manifest[mod] = _hash_file(path)
        logger.debug("Hashed module %r -> %s", mod, manifest[mod])
    dest = _manifest_path()
    dest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    logger.info("Manifest written to %s (%d entries)", dest, len(manifest))
    return manifest


def verify_integrity(modules: list[str]) -> dict[str, bool]:
    dest = _manifest_path()
    if not dest.exists():
        raise IntegrityError(f"Integrity manifest not found at {dest}")
    stored: dict[str, Any] = json.loads(dest.read_text(encoding="utf-8"))
    results: dict[str, bool] = {}
    failures: list[str] = []
    for mod in modules:
        if mod not in stored:
            raise IntegrityError(f"Module {mod!r} not found in manifest; regenerate manifest first")
        path = _module_path(mod)
        current_hash = _hash_file(path)
        expected_hash: str = stored[mod]
        ok = current_hash == expected_hash
        results[mod] = ok
        if not ok:
            failures.append(mod)
            logger.warning("Integrity FAIL: %r expected=%s actual=%s", mod, expected_hash, current_hash)
        else:
            logger.debug("Integrity OK: %r", mod)
    if failures:
        raise IntegrityError(f"Integrity check failed for modules: {failures}")
    return results
