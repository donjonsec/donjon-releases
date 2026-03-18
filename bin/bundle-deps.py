from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import TypedDict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


class BundleInput(TypedDict):
    requirements_path: str
    platform: str


class BundleOutput(TypedDict):
    bundle_path: str
    package_count: int


def _validate_platform(platform: str) -> None:
    if not platform or not platform.strip():
        raise ValueError("platform must be a non-empty string")
    # Rough sanity check — platform strings look like linux_x86_64, manylinux2014_aarch64, etc.
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
    if not all(c in allowed_chars for c in platform):
        raise ValueError(f"platform contains invalid characters: {platform!r}")


def _count_packages_in_dir(wheel_dir: Path) -> int:
    """Count distinct packages by counting wheel/sdist files downloaded."""
    count = 0
    for entry in wheel_dir.iterdir():
        if entry.is_file() and entry.suffix in {".whl", ".gz", ".zip", ".bz2"}:
            count += 1
    return count


def _build_bundle_path(requirements_path: Path, platform: str) -> Path:
    """Derive a deterministic bundle path next to the requirements file."""
    req_hash = hashlib.sha256(requirements_path.read_bytes()).hexdigest()[:8]
    safe_platform = platform.replace("/", "_").replace("\\", "_")
    bundle_name = f"deps-bundle-{safe_platform}-{req_hash}.zip"
    return requirements_path.parent / bundle_name


def _download_wheels(
    requirements_path: Path,
    platform: str,
    dest_dir: Path,
) -> None:
    """Run pip download to fetch wheels for the target platform."""
    python_version = f"{sys.version_info.major}{sys.version_info.minor}"
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--no-deps",  # avoid double-counting transitive deps already listed
        "--dest",
        str(dest_dir),
        "--platform",
        platform,
        "--python-version",
        python_version,
        "--only-binary=:all:",
        "-r",
        str(requirements_path),
    ]
    logger.info("Running pip download: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # First attempt with binary-only failed; retry allowing source distributions
        logger.warning(
            "Binary-only download failed (exit %d), retrying with sdists allowed",
            result.returncode,
        )
        cmd_with_sdist = [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--no-deps",
            "--dest",
            str(dest_dir),
            "--platform",
            platform,
            "--python-version",
            python_version,
            "-r",
            str(requirements_path),
        ]
        result2 = subprocess.run(
            cmd_with_sdist,
            capture_output=True,
            text=True,
        )
        if result2.returncode != 0:
            raise RuntimeError(f"pip download failed (exit {result2.returncode}):\nstdout: {result2.stdout}\nstderr: {result2.stderr}")


def _zip_directory(source_dir: Path, dest_zip: Path) -> None:
    """Compress all files in source_dir into dest_zip."""
    with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(source_dir.iterdir()):
            if file.is_file():
                zf.write(file, arcname=file.name)


def bundle_deps(input_data: BundleInput) -> BundleOutput:
    requirements_path_str: str = input_data["requirements_path"]
    platform: str = input_data["platform"]

    requirements_path = Path(requirements_path_str).resolve()

    if not requirements_path.exists():
        raise FileNotFoundError(f"requirements file not found: {requirements_path}")
    if not requirements_path.is_file():
        raise ValueError(f"requirements_path is not a file: {requirements_path}")

    _validate_platform(platform)

    bundle_path = _build_bundle_path(requirements_path, platform)

    with tempfile.TemporaryDirectory(prefix="dep-bundle-") as tmpdir:
        wheel_dir = Path(tmpdir) / "wheels"
        wheel_dir.mkdir()

        _download_wheels(requirements_path, platform, wheel_dir)

        package_count = _count_packages_in_dir(wheel_dir)
        if package_count == 0:
            logger.warning(
                "No packages were downloaded for requirements=%s platform=%s",
                requirements_path,
                platform,
            )

        _zip_directory(wheel_dir, bundle_path)

    logger.info("Bundle created: %s (%d packages)", bundle_path, package_count)

    return BundleOutput(
        bundle_path=str(bundle_path),
        package_count=package_count,
    )


def main() -> None:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Bundle Python dependencies for offline use.")
    parser.add_argument(
        "--requirements-path",
        required=True,
        help="Path to requirements.txt",
    )
    parser.add_argument(
        "--platform",
        required=True,
        help="Target platform string (e.g. linux_x86_64, manylinux2014_aarch64)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit JSON output to stdout",
    )

    args = parser.parse_args()

    input_data: BundleInput = {
        "requirements_path": args.requirements_path,
        "platform": args.platform,
    }

    result = bundle_deps(input_data)

    if args.json:
        print(json.dumps(result))
    else:
        print(f"bundle_path: {result['bundle_path']}")
        print(f"package_count: {result['package_count']}")


if __name__ == "__main__":
    main()
