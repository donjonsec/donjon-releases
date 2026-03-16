from __future__ import annotations

import hashlib
import json
import logging
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# --- paths-v1 dependency ---
try:
    from src.darkfactory.paths import get_paths  # type: ignore[import]
except ImportError:
    def get_paths() -> dict[str, Path]:  # type: ignore[misc]
        base = Path(__file__).parent.parent
        return {
            "data": base / "data",
            "feeds": base / "data" / "feeds",
            "bundles": base / "data" / "bundles",
        }


_MANIFEST_FILENAME = "manifest.json"
_BUNDLE_SUFFIX = ".tar.gz"
_FEED_DIR_NAME = "feeds"


def _bundles_dir() -> Path:
    paths = get_paths()
    bdir: Path = paths.get("bundles", Path(paths["data"]) / "bundles")
    bdir.mkdir(parents=True, exist_ok=True)
    return bdir


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_bundle(output_path: str, include_feeds: bool) -> dict[str, Any]:
    """
    Create an offline intel bundle.

    Parameters
    ----------
    output_path:
        Destination path for the bundle archive (*.tar.gz).
    include_feeds:

    Returns
    dict with keys: path (str), sha256 (str), created_at (str), feed_count (int)
    """
    dest = Path(output_path)
    if dest.suffix not in {".gz", ".tgz"} and not dest.name.endswith(".tar.gz"):
        dest = dest.with_suffix(_BUNDLE_SUFFIX)

    paths = get_paths()
    feeds_dir: Path = paths.get("feeds", Path(paths["data"]) / "feeds")

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        bundle_stage = tmp / "bundle"
        bundle_stage.mkdir()

        feed_count = 0
        if include_feeds and feeds_dir.exists():
            staged_feeds = bundle_stage / _FEED_DIR_NAME
            staged_feeds.mkdir()
            feed_files = list(feeds_dir.glob("**/*"))
            for ff in feed_files:
                if ff.is_file():
                    rel = ff.relative_to(feeds_dir)
                    target = staged_feeds / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ff, target)
                    feed_count += 1

        manifest: dict[str, Any] = {
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
            "include_feeds": include_feeds,
            "feed_count": feed_count,
            "version": "1",
        }
        (bundle_stage / _MANIFEST_FILENAME).write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        dest.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(bundle_stage, arcname="bundle")

    sha256 = _sha256_file(dest)
    created_at = manifest["created_at"]

    logger.info("Bundle created at %s (sha256=%s, feeds=%d)", dest, sha256, feed_count)
    return {
        "path": str(dest),
        "sha256": sha256,
        "created_at": created_at,
        "feed_count": feed_count,
    }


def import_bundle(output_path: str, include_feeds: bool) -> dict[str, Any]:
    """

    Parameters
    ----------
    output_path:
        Path to the bundle archive to import.
    include_feeds:

    Returns
    dict with keys: imported_from (str), feed_count (int), manifest (dict)
    """
    src = Path(output_path)
    if not src.exists():
        raise FileNotFoundError(f"Bundle not found: {src}")
    if not tarfile.is_tarfile(src):
        raise ValueError(f"Not a valid tar archive: {src}")

    paths = get_paths()
    feeds_dir: Path = paths.get("feeds", Path(paths["data"]) / "feeds")
    feeds_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        with tarfile.open(src, "r:gz") as tar:
            # Security: only extract safe members (no absolute paths, no ..)
            safe_members = [
                m for m in tar.getmembers()
                if not Path(m.name).is_absolute()
                and ".." not in Path(m.name).parts
            ]
            tar.extractall(tmp, members=safe_members)  # noqa: S202

        bundle_root = tmp / "bundle"
        manifest_path = bundle_root / _MANIFEST_FILENAME
        if not manifest_path.exists():
            raise ValueError("Bundle is missing manifest.json")

        manifest: dict[str, Any] = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )

        feed_count = 0
        if include_feeds:
            staged_feeds = bundle_root / _FEED_DIR_NAME
            if staged_feeds.exists():
                for ff in staged_feeds.glob("**/*"):
                    if ff.is_file():
                        rel = ff.relative_to(staged_feeds)
                        target = feeds_dir / rel
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(ff, target)
                        feed_count += 1

    logger.info("Bundle imported from %s (feeds=%d)", src, feed_count)
    return {
        "imported_from": str(src),
        "feed_count": feed_count,
        "manifest": manifest,
    }


def list_bundles(output_path: str, include_feeds: bool) -> dict[str, Any]:
    """
    List available offline intel bundles.

    Parameters
    ----------
    output_path:
        Directory to search for bundles, or use the default bundles directory
        when empty string is provided.
    include_feeds:

    Returns
    dict with key 'bundles': list of bundle info records
    """
    if output_path:
        search_dir = Path(output_path)
    else:
        search_dir = _bundles_dir()

    if not search_dir.exists():
        return {"bundles": []}

    results: list[dict[str, Any]] = []
    for candidate in sorted(search_dir.glob(f"*{_BUNDLE_SUFFIX}")):
        if not candidate.is_file():
            continue
        try:
            sha256 = _sha256_file(candidate)
            created_at: str | None = None
            feed_count_manifest: int | None = None
            if tarfile.is_tarfile(candidate):
                with tarfile.open(candidate, "r:gz") as tar:
                    try:
                        member = tar.getmember(f"bundle/{_MANIFEST_FILENAME}")
                        fobj = tar.extractfile(member)
                        if fobj is not None:
                            mdata: dict[str, Any] = json.loads(fobj.read().decode("utf-8"))
                            created_at = mdata.get("created_at")
                            feed_count_manifest = mdata.get("feed_count")
                    except KeyError:
                        pass
            results.append(
                {
                    "path": str(candidate),
                    "sha256": sha256,
                    "size_bytes": candidate.stat().st_size,
                    "created_at": created_at,
                    "feed_count": feed_count_manifest,
                }
            )
        except Exception as exc:
            logger.warning("Skipping bundle %s: %s", candidate, exc)

    return {"bundles": results}


if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Offline intel bundle management")
    sub = parser.add_subparsers(dest="command")

    create_p = sub.add_parser("create", help="Create a bundle")
    create_p.add_argument("output_path", help="Destination path for the bundle")
    create_p.add_argument(
        "--include-feeds", action="store_true", help="Include feed files"
    )

    import_p = sub.add_parser("import", help="Import a bundle")
    import_p.add_argument("output_path", help="Path to the bundle archive")
    import_p.add_argument(
        "--include-feeds", action="store_true", help="Also extract feed files"
    )

    list_p = sub.add_parser("list", help="List available bundles")
    list_p.add_argument(
        "output_path", nargs="?", default="", help="Directory to search"
    )

    args = parser.parse_args()

    if args.command == "create":
        result = create_bundle(args.output_path, args.include_feeds)
        print(json.dumps(result, indent=2))
    elif args.command == "import":
        result = import_bundle(args.output_path, args.include_feeds)
        print(json.dumps(result, indent=2))
    elif args.command == "list":
        result = list_bundles(args.output_path, False)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()
        sys.exit(1)
