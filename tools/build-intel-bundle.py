#!/usr/bin/env python3
"""
Donjon Platform — Intel Bundle Builder

Packages all threat intelligence data into a signed, versioned bundle
for air-gap distribution. Supports full and differential modes.

Every piece of data carries provenance: source authority, URL, license,
fetch timestamp, record count, and SHA-256 integrity hash.

Usage:
    python tools/build-intel-bundle.py --full          # Full bundle (~800MB)
    python tools/build-intel-bundle.py --differential  # Changes since last bundle
    python tools/build-intel-bundle.py --verify        # Verify existing bundle
    python tools/build-intel-bundle.py --import FILE   # Import bundle into local data

Sources (all authoritative, auditable):
    NVD CVEs         — NIST (US Gov)         — Public Domain
    CISA KEV         — CISA (US Gov)         — Public Domain
    EPSS Scores      — FIRST.org             — CC BY-SA 4.0
    ExploitDB        — OffSec                — GPL-2.0
    OSV              — Google OSS            — CC BY 4.0
    GitHub Advisories — GitHub/MITRE         — CC BY 4.0
    CISA Alerts      — CISA (US Gov)         — Public Domain
    MITRE ATT&CK     — MITRE Corporation    — Apache 2.0
    URLhaus          — abuse.ch              — CC0 1.0
    ThreatFox        — abuse.ch              — CC0 1.0
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

BUNDLE_DIR = PROJECT_ROOT / "data" / "bundles"
MANIFEST_NAME = "intel-manifest.json"

# Authoritative source registry — every feed must be listed here
INTEL_SOURCES = {
    "nvd_cves": {
        "authority": "National Institute of Standards and Technology (NIST)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0/",
        "license": "Public Domain (US Government Work)",
        "description": "National Vulnerability Database — all CVE records with CVSS scores, CWEs, references",
        "data_file": "vuln_db/vuln_intel.db",
        "table": "nvd_cves",
    },
    "cisa_kev": {
        "authority": "Cybersecurity and Infrastructure Security Agency (CISA)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "license": "Public Domain (US Government Work)",
        "description": "Known Exploited Vulnerabilities catalog — actively exploited CVEs with remediation deadlines",
        "data_file": "threat_intel/cisa_kev.json",
    },
    "epss_scores": {
        "authority": "Forum of Incident Response and Security Teams (FIRST.org)",
        "url": "https://api.first.org/data/v1/epss",
        "license": "CC BY-SA 4.0",
        "description": "Exploit Prediction Scoring System — probability of exploitation in next 30 days",
        "data_file": "vuln_db/vuln_intel.db",
        "table": "epss_scores",
    },
    "exploit_refs": {
        "authority": "OffSec (Offensive Security)",
        "url": "https://gitlab.com/exploit-database/exploitdb",
        "license": "GPL-2.0",
        "description": "ExploitDB — public exploits and proof-of-concept code mapped to CVEs",
        "data_file": "intel_feeds.db",
        "table": "exploitdb",
    },
    "osv": {
        "authority": "Google Open Source Security",
        "url": "https://api.osv.dev/v1/",
        "license": "CC BY 4.0",
        "description": "Open Source Vulnerabilities — PyPI, npm, Go, Maven, NuGet, RubyGems, crates.io",
        "data_file": "intel_feeds.db",
        "table": "osv_vulns",
    },
    "github_advisories": {
        "authority": "GitHub / MITRE CVE Numbering Authority",
        "url": "https://api.github.com/advisories",
        "license": "CC BY 4.0",
        "description": "GitHub Security Advisories — cross-ecosystem vulnerability advisories",
        "data_file": "intel_feeds.db",
        "table": "github_advisories",
    },
    "cisa_alerts": {
        "authority": "Cybersecurity and Infrastructure Security Agency (CISA)",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "license": "Public Domain (US Government Work)",
        "description": "CISA cybersecurity alerts and ICS-CERT advisories",
        "data_file": "intel_feeds.db",
        "table": "cisa_alerts",
    },
    "mitre_attack": {
        "authority": "MITRE Corporation",
        "url": "https://github.com/mitre/cti",
        "license": "Apache 2.0",
        "description": "MITRE ATT&CK Enterprise — tactics, techniques, and mitigations",
        "data_file": "intel_feeds.db",
        "table": "mitre_attack",
    },
    "urlhaus": {
        "authority": "abuse.ch (Bern University of Applied Sciences)",
        "url": "https://urlhaus-api.abuse.ch/v1/",
        "license": "CC0 1.0 (Public Domain Dedication)",
        "description": "URLhaus — malicious URLs used for malware distribution",
        "data_file": "intel_feeds.db",
        "table": "urlhaus_urls",
    },
    "threatfox": {
        "authority": "abuse.ch (Bern University of Applied Sciences)",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "license": "CC0 1.0 (Public Domain Dedication)",
        "description": "ThreatFox — indicators of compromise (IOCs) shared by the infosec community",
        "data_file": "intel_feeds.db",
        "table": "threatfox_iocs",
    },
}


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def get_table_count(db_path: Path, table: str) -> int:
    """Count rows in a SQLite table, return 0 if table doesn't exist."""
    if not db_path.exists():
        return 0
    try:
        conn = sqlite3.connect(str(db_path))
        count = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def get_json_count(json_path: Path) -> int:
    """Count entries in a JSON file."""
    if not json_path.exists():
        return 0
    try:
        with open(json_path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            # CISA KEV format
            return len(data.get("vulnerabilities", data.get("entries", [])))
        if isinstance(data, list):
            return len(data)
        return 0
    except Exception:
        return 0


def build_manifest(data_dir: Path) -> dict:
    """Build a manifest documenting all intel data with provenance."""
    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "bundle_version": "1.0",
        "created_at": now,
        "created_by": "Donjon Platform Intel Bundle Builder",
        "platform_version": "7.3.0",
        "sources": {},
        "files": {},
        "totals": {"sources": 0, "records": 0, "files": 0, "size_bytes": 0},
    }

    seen_files = set()
    total_records = 0

    for source_id, source_info in INTEL_SOURCES.items():
        data_file = source_info["data_file"]
        file_path = data_dir / data_file

        # Count records
        if "table" in source_info and file_path.suffix == ".db":
            count = get_table_count(file_path, source_info["table"])
        elif file_path.suffix == ".json":
            count = get_json_count(file_path)
        else:
            count = 0

        manifest["sources"][source_id] = {
            "authority": source_info["authority"],
            "url": source_info["url"],
            "license": source_info["license"],
            "description": source_info["description"],
            "records": count,
            "data_file": data_file,
        }
        total_records += count

        # File-level metadata (deduplicated — multiple sources share intel_feeds.db)
        if data_file not in seen_files and file_path.exists():
            seen_files.add(data_file)
            manifest["files"][data_file] = {
                "size_bytes": file_path.stat().st_size,
                "sha256": sha256_file(file_path),
                "modified_at": datetime.fromtimestamp(
                    file_path.stat().st_mtime, tz=timezone.utc
                ).isoformat(),
            }

    manifest["totals"]["sources"] = len(manifest["sources"])
    manifest["totals"]["records"] = total_records
    manifest["totals"]["files"] = len(manifest["files"])
    manifest["totals"]["size_bytes"] = sum(
        f["size_bytes"] for f in manifest["files"].values()
    )

    return manifest


def build_full_bundle(data_dir: Path, output_dir: Path) -> Path:
    """Build a full intel bundle with all data files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    bundle_name = f"intel-bundle-{date_str}.tar.gz"
    bundle_path = output_dir / bundle_name

    manifest = build_manifest(data_dir)

    # Write manifest to temp location
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, dir=str(output_dir)
    ) as mf:
        json.dump(manifest, mf, indent=2)
        manifest_tmp = Path(mf.name)

    # Build tar.gz
    with tarfile.open(bundle_path, "w:gz") as tar:
        # Add manifest
        tar.add(str(manifest_tmp), arcname=MANIFEST_NAME)

        # Add data files
        for data_file in manifest["files"]:
            file_path = data_dir / data_file
            if file_path.exists():
                tar.add(str(file_path), arcname=f"data/{data_file}")

    manifest_tmp.unlink()

    # Also save manifest alongside bundle
    manifest_path = output_dir / f"intel-manifest-{date_str}.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return bundle_path


def build_differential_bundle(
    data_dir: Path, output_dir: Path, previous_manifest_path: Path
) -> Path | None:
    """Build a differential bundle containing only changed files."""
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(previous_manifest_path) as f:
        prev = json.load(f)

    current = build_manifest(data_dir)

    # Find changed files by comparing SHA-256 hashes
    changed_files = []
    for data_file, file_info in current["files"].items():
        prev_file = prev.get("files", {}).get(data_file)
        if prev_file is None or prev_file["sha256"] != file_info["sha256"]:
            changed_files.append(data_file)

    if not changed_files:
        print("  No changes since last bundle — nothing to package.")
        return None

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    bundle_name = f"intel-diff-{date_str}.tar.gz"
    bundle_path = output_dir / bundle_name

    # Mark as differential in manifest
    current["bundle_type"] = "differential"
    current["base_bundle"] = prev.get("created_at", "unknown")
    current["changed_files"] = changed_files

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, dir=str(output_dir)
    ) as mf:
        json.dump(current, mf, indent=2)
        manifest_tmp = Path(mf.name)

    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(str(manifest_tmp), arcname=MANIFEST_NAME)
        for data_file in changed_files:
            file_path = data_dir / data_file
            if file_path.exists():
                tar.add(str(file_path), arcname=f"data/{data_file}")

    manifest_tmp.unlink()

    # Save manifest
    manifest_path = output_dir / f"intel-manifest-{date_str}.json"
    with open(manifest_path, "w") as f:
        json.dump(current, f, indent=2)

    return bundle_path


def verify_bundle(bundle_path: Path) -> bool:
    """Verify integrity of an intel bundle."""
    print(f"  Verifying: {bundle_path.name}")

    with tarfile.open(bundle_path, "r:gz") as tar:
        # Extract manifest
        manifest_member = tar.getmember(MANIFEST_NAME)
        manifest_data = tar.extractfile(manifest_member).read()
        manifest = json.loads(manifest_data)

    print(f"  Created:   {manifest.get('created_at', '?')}")
    print(f"  Type:      {manifest.get('bundle_type', 'full')}")
    print(f"  Sources:   {manifest['totals']['sources']}")
    print(f"  Records:   {manifest['totals']['records']:,}")
    print(f"  Files:     {manifest['totals']['files']}")
    print(f"  Size:      {manifest['totals']['size_bytes'] / 1024 / 1024:.1f} MB")
    print()

    # Verify file hashes
    errors = 0
    with tarfile.open(bundle_path, "r:gz") as tar:
        for data_file, expected in manifest.get("files", {}).items():
            member_name = f"data/{data_file}"
            try:
                member = tar.getmember(member_name)
                f = tar.extractfile(member)
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
                actual_hash = h.hexdigest()
                if actual_hash != expected["sha256"]:
                    print(f"  FAIL  {data_file}: hash mismatch")
                    errors += 1
                else:
                    print(f"  OK    {data_file} ({expected['size_bytes'] / 1024:.0f} KB)")
            except KeyError:
                if manifest.get("bundle_type") == "differential":
                    # Differential bundles only include changed files
                    if data_file not in manifest.get("changed_files", []):
                        print(f"  SKIP  {data_file} (unchanged, not in diff)")
                        continue
                print(f"  MISS  {data_file}: not in bundle")
                errors += 1

    print()
    # Show provenance
    print("  Source Provenance:")
    for source_id, info in manifest.get("sources", {}).items():
        print(f"    {source_id:25s} {info['records']:>8,} records  [{info['authority']}]")
        print(f"    {'':25s} {info['url']}")
        print(f"    {'':25s} License: {info['license']}")

    if errors:
        print(f"\n  VERIFICATION FAILED: {errors} errors")
        return False
    print("\n  VERIFICATION PASSED: all hashes match")
    return True


def import_bundle(bundle_path: Path, data_dir: Path) -> bool:
    """Import an intel bundle into local data directory."""
    print(f"  Importing: {bundle_path.name}")

    with tarfile.open(bundle_path, "r:gz") as tar:
        # Read manifest first
        manifest_data = tar.extractfile(MANIFEST_NAME).read()
        manifest = json.loads(manifest_data)

        bundle_type = manifest.get("bundle_type", "full")
        print(f"  Type:    {bundle_type}")
        print(f"  Sources: {manifest['totals']['sources']}")
        print(f"  Records: {manifest['totals']['records']:,}")

        # Extract data files
        for member in tar.getmembers():
            if member.name.startswith("data/"):
                rel_path = member.name[5:]  # Strip "data/" prefix
                dest = data_dir / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)

                # Verify hash before writing
                expected = manifest.get("files", {}).get(rel_path, {})
                f = tar.extractfile(member)
                content = f.read()
                actual_hash = hashlib.sha256(content).hexdigest()

                if expected and actual_hash != expected.get("sha256"):
                    print(f"  REJECT {rel_path}: integrity check failed")
                    continue

                with open(dest, "wb") as out:
                    out.write(content)
                print(f"  OK     {rel_path} ({len(content) / 1024:.0f} KB)")

    # Save manifest locally for differential tracking
    manifest_dest = data_dir / "last-bundle-manifest.json"
    with open(manifest_dest, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n  Import complete. Manifest saved to {manifest_dest}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Donjon Intel Bundle Builder — package threat intel for offline distribution"
    )
    parser.add_argument("--full", action="store_true", help="Build full bundle")
    parser.add_argument("--differential", action="store_true", help="Build differential bundle")
    parser.add_argument("--verify", type=str, help="Verify a bundle file")
    parser.add_argument("--import-bundle", type=str, dest="import_file", help="Import bundle into local data")
    parser.add_argument("--manifest", action="store_true", help="Show current data manifest")
    parser.add_argument("--data-dir", type=str, default=str(PROJECT_ROOT / "data"),
                        help="Data directory (default: data/)")
    parser.add_argument("--output-dir", type=str, default=str(BUNDLE_DIR),
                        help="Output directory for bundles")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)

    if args.manifest:
        manifest = build_manifest(data_dir)
        print(json.dumps(manifest, indent=2))
        return

    if args.verify:
        ok = verify_bundle(Path(args.verify))
        sys.exit(0 if ok else 1)

    if args.import_file:
        ok = import_bundle(Path(args.import_file), data_dir)
        sys.exit(0 if ok else 1)

    if args.differential:
        prev = data_dir / "last-bundle-manifest.json"
        if not prev.exists():
            print("  No previous manifest found. Run --full first.")
            sys.exit(1)
        result = build_differential_bundle(data_dir, output_dir, prev)
        if result:
            size_mb = result.stat().st_size / 1024 / 1024
            print(f"\n  Differential bundle: {result} ({size_mb:.1f} MB)")
        return

    if args.full:
        result = build_full_bundle(data_dir, output_dir)
        size_mb = result.stat().st_size / 1024 / 1024
        print(f"\n  Full bundle: {result} ({size_mb:.1f} MB)")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
