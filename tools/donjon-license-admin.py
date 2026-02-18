#!/usr/bin/env python3
"""
DONJON LICENSE ADMIN
Post-Quantum Secure (ML-DSA-65 + Ed25519)

Standalone CLI tool for generating and managing Donjon Platform licenses.
Uses ML-DSA-65 (NIST FIPS 204) + Ed25519 dual-signature scheme.

SECURITY WARNING
----------------
This tool performs private key operations (key generation, signing).
It must NEVER be distributed with the product binary, shipped in Docker
images, or committed to public repositories.  It is intended for use
only on an air-gapped or tightly controlled signing workstation.

Usage:
    python donjon-license-admin.py keygen [--force]
    python donjon-license-admin.py sign --tier <tier> --org <name> [options]
    python donjon-license-admin.py verify --license <path>
    python donjon-license-admin.py revoke --license-id <id>
    python donjon-license-admin.py fingerprint
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from dilithium_py.ml_dsa import ML_DSA_65


# ---------------------------------------------------------------------------
# Constants and configuration
# ---------------------------------------------------------------------------

BANNER = """
================================================
  DONJON LICENSE ADMIN
  Post-Quantum Secure (ML-DSA-65 + Ed25519)
================================================
  WARNING: This tool contains private key operations.
           Never distribute this tool with the product.
================================================
"""

# Key storage paths -- relative to this script's working directory.
# In production these should live on an encrypted, access-controlled volume.
KEYS_DIR = Path("keys")
CLASSICAL_PRIVATE_PATH = KEYS_DIR / "donjon-private-classical.pem"
CLASSICAL_PUBLIC_PATH = KEYS_DIR / "donjon-public-classical.pem"
PQC_PRIVATE_PATH = KEYS_DIR / "donjon-private-pqc.bin"
PQC_PUBLIC_PATH = KEYS_DIR / "donjon-public-pqc.bin"
REVOKED_PATH = KEYS_DIR / "revoked.json"

# Tiers must be an exact match -- never accept unknown strings as valid tiers
# because the product side uses these to gate feature access.
VALID_TIERS = ("community", "pro", "enterprise", "managed")

# License ID format: DON-<4-digit year>-<5 hex chars uppercase>
# This regex is used to validate IDs before writing them to the revocation list.
LICENSE_ID_PATTERN = re.compile(r"^DON-\d{4}-[A-F0-9]{5}$")

# Maximum size (bytes) for files read from disk, to prevent memory exhaustion
# if someone replaces a key file with a multi-gigabyte blob.
_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB


# ---------------------------------------------------------------------------
# Secure memory helpers
# ---------------------------------------------------------------------------

def _secure_zero(data: bytearray) -> None:
    """Overwrite a mutable buffer with zeros to erase sensitive key material.

    Why: Python's garbage collector does not guarantee timely deallocation of
    ``bytes`` objects, so secret key material can linger in memory.  Using a
    mutable ``bytearray`` and explicitly zeroing it reduces the window of
    exposure.  ``ctypes.memset`` writes directly to the buffer, bypassing
    potential Python-level optimisations that could elide the write.

    NOTE: This is a best-effort mitigation.  Python may still hold copies in
    internal buffers, CPU caches, or swap space.  For higher assurance, use
    a purpose-built HSM or a C-level secrets library.
    """
    if not isinstance(data, bytearray):
        return  # Can only zero mutable buffers
    ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Print the tool banner with security warning to stdout."""
    print(BANNER)


def generate_license_id() -> str:
    """Create a unique, human-readable license identifier.

    Format: DON-<year>-<5 random hex digits>
    The year prefix aids manual triage; the random suffix provides
    collision resistance (16^5 = 1,048,576 possible values per year).

    TODO: Consider adding a check-digit for fat-finger detection when
    operators type IDs manually on the command line.
    """
    year = datetime.now(timezone.utc).year
    suffix = uuid.uuid4().hex[:5].upper()
    return f"DON-{year}-{suffix}"


def canonical_payload(license_data: dict) -> bytes:
    """Build the canonical byte representation of a license for signing.

    Security notes:
    - The canonical form EXCLUDES the 'signatures' key so that the
      signature does not cover itself (which would be circular).
    - ``sort_keys=True`` ensures field-order-independent serialisation,
      preventing an attacker from producing a semantically identical
      license that has a different byte representation.
    - ``separators=(",", ":")`` removes all optional whitespace, ensuring
      that pretty-printing differences don't invalidate signatures.
    - ``ensure_ascii=True`` (the default) avoids encoding ambiguities
      with multibyte characters.

    WARNING: Any change to this function's serialisation logic will
    invalidate ALL previously signed licenses.
    """
    payload = {k: v for k, v in license_data.items() if k != "signatures"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_read_file(path: Path, max_size: int = _MAX_FILE_SIZE) -> bytes:
    """Read a file with size guard to prevent memory exhaustion attacks.

    Why: If an attacker replaces a key file with an oversized blob,
    unchecked reads could exhaust memory.  This caps reads at a
    reasonable maximum.
    """
    size = path.stat().st_size
    if size > max_size:
        raise ValueError(
            f"File {path} is {size} bytes, exceeding the "
            f"{max_size} byte safety limit"
        )
    return path.read_bytes()


def load_classical_private_key() -> Ed25519PrivateKey:
    """Load the Ed25519 private key from disk.

    SECURITY: The caller is responsible for limiting the lifetime of the
    returned key object.  Ideally, sign immediately and discard.
    """
    raw = _safe_read_file(CLASSICAL_PRIVATE_PATH)
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Expected an Ed25519 private key")
    return key


def load_classical_public_key() -> Ed25519PublicKey:
    """Load the Ed25519 public key from disk for verification."""
    raw = _safe_read_file(CLASSICAL_PUBLIC_PATH)
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Expected an Ed25519 public key")
    return key


def load_pqc_private_key() -> bytes:
    """Load the ML-DSA-65 private key (raw binary) from disk.

    SECURITY: The returned bytes contain secret key material.  The caller
    should zero the buffer (if mutable) as soon as signing is complete.
    """
    return _safe_read_file(PQC_PRIVATE_PATH)


def load_pqc_public_key() -> bytes:
    """Load the ML-DSA-65 public key (raw binary) from disk."""
    return _safe_read_file(PQC_PUBLIC_PATH)


def keys_exist() -> bool:
    """Return True if ANY key file already exists on disk.

    Uses OR logic so that partial keysets (e.g. interrupted keygen) are
    detected and the operator is warned before overwriting.
    """
    return (
        CLASSICAL_PRIVATE_PATH.exists()
        or CLASSICAL_PUBLIC_PATH.exists()
        or PQC_PRIVATE_PATH.exists()
        or PQC_PUBLIC_PATH.exists()
    )


# ---------------------------------------------------------------------------
# Subcommand: keygen -- generate a new ML-DSA-65 + Ed25519 keypair
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a new ML-DSA-65 + Ed25519 keypair and write to disk.

    Generates two independent keypairs:
    1. Ed25519 (classical) -- fast, widely deployed, quantum-vulnerable.
    2. ML-DSA-65 (post-quantum) -- NIST FIPS 204, lattice-based, larger.

    Both must verify for a license to be accepted (belt-and-suspenders).
    This protects against a future quantum break of Ed25519 while also
    guarding against undiscovered weaknesses in ML-DSA.
    """
    if keys_exist() and not args.force:
        print("[ERROR] Key files already exist. Use --force to overwrite.")
        return 1

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    # --- Ed25519 (classical) ---
    classical_private = Ed25519PrivateKey.generate()
    classical_public = classical_private.public_key()

    classical_private_pem = classical_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
        # TODO: Consider encrypting private keys at rest with a passphrase
        # using serialization.BestAvailableEncryption(passphrase) for
        # defence-in-depth if the signing workstation is ever compromised.
    )
    classical_public_pem = classical_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    CLASSICAL_PRIVATE_PATH.write_bytes(classical_private_pem)
    CLASSICAL_PUBLIC_PATH.write_bytes(classical_public_pem)

    # --- ML-DSA-65 (post-quantum) ---
    pqc_public, pqc_private = ML_DSA_65.keygen()

    PQC_PRIVATE_PATH.write_bytes(pqc_private)
    PQC_PUBLIC_PATH.write_bytes(pqc_public)

    # Restrict file permissions on private keys (best-effort on Windows).
    # Why: Limits accidental exposure if the keys directory is on a shared
    # filesystem or the operator's umask is too permissive.
    try:
        os.chmod(CLASSICAL_PRIVATE_PATH, 0o600)
        os.chmod(PQC_PRIVATE_PATH, 0o600)
    except OSError:
        # Windows may not support Unix permission bits; this is non-fatal.
        pass

    # --- Summary (public key material only -- safe to display) ---
    classical_public_raw = classical_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    classical_pub_b64 = base64.b64encode(classical_public_raw).decode("ascii")
    pqc_pub_b64 = base64.b64encode(pqc_public).decode("ascii")

    print("[OK] Keypair generated successfully.")
    print()
    print(f"  Classical private : {CLASSICAL_PRIVATE_PATH}")
    print(f"  Classical public  : {CLASSICAL_PUBLIC_PATH}")
    print(f"  PQC private       : {PQC_PRIVATE_PATH}")
    print(f"  PQC public        : {PQC_PUBLIC_PATH}")
    print()
    print("--- Public keys for embedding in product source ---")
    print()
    print(f'CLASSICAL_PUBLIC_B64 = "{classical_pub_b64}"')
    print()
    print(f'PQC_PUBLIC_B64 = "{pqc_pub_b64}"')
    print()
    print("[SECURITY] Keep private keys safe. Back them up securely.")
    print("           Never commit private keys to version control.")
    print("           Consider encrypting the keys directory at rest.")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: sign -- generate a signed license file
# ---------------------------------------------------------------------------

def cmd_sign(args: argparse.Namespace) -> int:
    """Generate a dual-signed license file.

    Workflow:
    1. Validate inputs (tier, dates, fingerprint format).
    2. Assemble the license payload JSON.
    3. Canonicalise the payload (deterministic JSON, sorted keys).
    4. Sign with Ed25519 and ML-DSA-65 independently.
    5. Attach both signatures and write the output file.

    The private keys are loaded, used, and then go out of scope.  For the
    PQC key we additionally zero the mutable buffer.
    """
    if not CLASSICAL_PRIVATE_PATH.exists() or not PQC_PRIVATE_PATH.exists():
        print("[ERROR] Private keys not found. Run 'keygen' first.")
        return 1

    # -- Validate tier --
    if args.tier not in VALID_TIERS:
        print(f"[ERROR] Invalid tier '{args.tier}'. Must be one of: {', '.join(VALID_TIERS)}")
        return 1

    # -- Parse and validate expiry date --
    expires_str: Optional[str] = None
    if args.expires:
        try:
            expires_dt = datetime.fromisoformat(args.expires)
            expires_str = expires_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            print(f"[ERROR] Invalid date format '{args.expires}'. Use ISO format (YYYY-MM-DD).")
            return 1

    # -- Validate fingerprint format if provided --
    # Why: Accepting arbitrary strings could let an operator accidentally
    # bind a license to a typo that will never match any machine.
    if args.fingerprint and not args.fingerprint.startswith("sha256:"):
        print("[ERROR] Fingerprint must start with 'sha256:'. Use the 'fingerprint' subcommand.")
        return 1
    if args.fingerprint and len(args.fingerprint) != 71:  # "sha256:" + 64 hex chars
        print("[ERROR] Fingerprint must be 'sha256:' followed by 64 hex characters.")
        return 1

    # -- Build features_override for managed tier overrides --
    features_override: dict = {}
    if args.max_users is not None:
        if args.max_users < 1:
            print("[ERROR] --max-users must be a positive integer.")
            return 1
        features_override["max_users"] = args.max_users
    if args.max_clients is not None:
        if args.max_clients < 1:
            print("[ERROR] --max-clients must be a positive integer.")
            return 1
        features_override["max_clients"] = args.max_clients

    # -- Assemble license payload --
    license_id = generate_license_id()
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    license_data: dict = {
        "version": 2,
        "license_id": license_id,
        "tier": args.tier,
        "organization": args.org,
        "issued_at": issued_at,
        "expires": expires_str,
        "machine_fingerprint": args.fingerprint,
        "features_override": features_override,
    }

    # -- Canonicalise payload for signing --
    payload = canonical_payload(license_data)

    # -- Sign with Ed25519 (classical) --
    classical_key = load_classical_private_key()
    classical_sig = classical_key.sign(payload)
    classical_sig_b64 = base64.b64encode(classical_sig).decode("ascii")
    # Ed25519PrivateKey is a C-backed object; we cannot zero it from Python,
    # but we drop the reference so the GC can reclaim it promptly.
    del classical_key

    # -- Sign with ML-DSA-65 (post-quantum) --
    # Use a bytearray so we can zero the private key material after signing.
    pqc_sk = bytearray(load_pqc_private_key())
    try:
        pqc_sig = ML_DSA_65.sign(bytes(pqc_sk), payload)
        pqc_sig_b64 = base64.b64encode(pqc_sig).decode("ascii")
    finally:
        # SECURITY: Zero the PQC private key buffer regardless of success/failure.
        _secure_zero(pqc_sk)
        del pqc_sk

    # -- Attach signatures to the license --
    license_data["signatures"] = {
        "classical": classical_sig_b64,
        "pqc": pqc_sig_b64,
        "algorithm_classical": "Ed25519",
        "algorithm_pqc": "ML-DSA-65-FIPS204",
    }

    # -- Write the signed license file --
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(license_data, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[OK] License signed and written to {output_path}")
    print()
    print(f"  License ID   : {license_id}")
    print(f"  Tier         : {args.tier}")
    print(f"  Organization : {args.org}")
    print(f"  Issued       : {issued_at}")
    print(f"  Expires      : {expires_str or 'never'}")
    print(f"  Fingerprint  : {args.fingerprint or 'none (floating license)'}")
    if features_override:
        print(f"  Overrides    : {features_override}")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: verify -- verify a license file's dual signatures
# ---------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a license file's dual signatures and check validity.

    This is the admin-side verifier that loads public keys from disk.
    The product-side verifier in lib/licensing.py uses embedded keys.
    """
    license_path = Path(args.license)
    if not license_path.exists():
        print(f"[ERROR] License file not found: {license_path}")
        return 1

    if not CLASSICAL_PUBLIC_PATH.exists() or not PQC_PUBLIC_PATH.exists():
        print("[ERROR] Public keys not found. Run 'keygen' first.")
        return 1

    try:
        raw_text = license_path.read_text(encoding="utf-8")
        # Guard against oversized files
        if len(raw_text) > _MAX_FILE_SIZE:
            print("[ERROR] License file exceeds maximum allowed size.")
            return 1
        license_data = json.loads(raw_text)
    except json.JSONDecodeError:
        # SECURITY: Don't echo the parse error -- it could leak file contents.
        print("[ERROR] License file contains invalid JSON.")
        return 1
    except OSError as exc:
        print(f"[ERROR] Failed to read license file: {exc}")
        return 1

    signatures = license_data.get("signatures")
    if not isinstance(signatures, dict):
        print("[FAIL] License file has no valid signatures block.")
        return 1

    payload = canonical_payload(license_data)

    # -- Verify Ed25519 signature --
    classical_valid = False
    try:
        classical_sig_b64 = signatures.get("classical", "")
        if not classical_sig_b64:
            print("  [FAIL] Missing classical signature field.")
        else:
            classical_sig = base64.b64decode(classical_sig_b64, validate=True)
            classical_pk = load_classical_public_key()
            classical_pk.verify(classical_sig, payload)
            classical_valid = True
    except Exception:
        # SECURITY: Don't log the exception details -- they could reveal
        # information about the expected signature format to an attacker.
        print("  [FAIL] Classical (Ed25519) signature invalid.")

    # -- Verify ML-DSA-65 signature --
    pqc_valid = False
    try:
        pqc_sig_b64 = signatures.get("pqc", "")
        if not pqc_sig_b64:
            print("  [FAIL] Missing PQC signature field.")
        else:
            pqc_sig = base64.b64decode(pqc_sig_b64, validate=True)
            pqc_pk = load_pqc_public_key()
            pqc_valid = ML_DSA_65.verify(pqc_pk, payload, pqc_sig)
    except Exception:
        # SECURITY: Same rationale as above -- suppress exception details.
        print("  [FAIL] PQC (ML-DSA-65) signature invalid.")

    # -- Report license metadata --
    print()
    print(f"  License ID   : {license_data.get('license_id', 'unknown')}")
    print(f"  Version      : {license_data.get('version', 'unknown')}")
    print(f"  Tier         : {license_data.get('tier', 'unknown')}")
    print(f"  Organization : {license_data.get('organization', 'unknown')}")
    print(f"  Issued       : {license_data.get('issued_at', 'unknown')}")
    print(f"  Expires      : {license_data.get('expires') or 'never'}")
    print(f"  Fingerprint  : {license_data.get('machine_fingerprint') or 'none (floating)'}")
    print()
    print(f"  Ed25519      : {'VALID' if classical_valid else 'INVALID'}")
    print(f"  ML-DSA-65    : {'VALID' if pqc_valid else 'INVALID'}")
    print()

    if classical_valid and pqc_valid:
        # -- Check expiry date --
        expires_raw = license_data.get("expires")
        if expires_raw:
            try:
                expires_dt = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                if expires_dt < now:
                    print("  [WARN] License has EXPIRED.")
                else:
                    days_left = (expires_dt - now).days
                    print(f"  [OK] License is valid. {days_left} day(s) remaining.")
            except ValueError:
                print("  [WARN] Could not parse expiry date.")
        else:
            print("  [OK] License is valid (no expiry).")

        # -- Check revocation list --
        if REVOKED_PATH.exists():
            try:
                revoked_text = REVOKED_PATH.read_text(encoding="utf-8")
                revoked = json.loads(revoked_text)
                lid = license_data.get("license_id")
                if lid and lid in [entry.get("license_id") for entry in revoked]:
                    print(f"  [WARN] License '{lid}' appears on the revocation list.")
            except (json.JSONDecodeError, OSError):
                # Silently skip if the revocation list is unreadable;
                # it may not exist yet in a fresh installation.
                pass

        return 0

    print("  [FAIL] License signature verification FAILED.")
    return 1


# ---------------------------------------------------------------------------
# Subcommand: revoke -- add a license ID to the revocation list
# ---------------------------------------------------------------------------

def cmd_revoke(args: argparse.Namespace) -> int:
    """Add a license ID to the local revocation list.

    The revocation list is a simple JSON array stored alongside the keys.
    It is consumed by the product-side verifier and can be distributed
    to the Cloudflare Worker for online revocation checks.

    Why a separate revocation mechanism:  Licenses are signed offline and
    may be distributed without network access.  Revocation allows the
    issuer to retroactively invalidate a compromised or refunded license.
    """
    # Validate the license ID format to prevent injection of garbage data.
    if not LICENSE_ID_PATTERN.match(args.license_id):
        print(f"[ERROR] Invalid license ID format: '{args.license_id}'.")
        print("        Expected format: DON-YYYY-XXXXX (e.g. DON-2026-A1B2C)")
        return 1

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    revoked: list = []
    if REVOKED_PATH.exists():
        try:
            revoked = json.loads(REVOKED_PATH.read_text(encoding="utf-8"))
            if not isinstance(revoked, list):
                print("[WARN] Existing revoked.json is not a list. Starting fresh.")
                revoked = []
        except (json.JSONDecodeError, OSError):
            print("[WARN] Existing revoked.json is malformed. Starting fresh.")
            revoked = []

    # Check for duplicate before appending.
    existing_ids = [entry.get("license_id") for entry in revoked if isinstance(entry, dict)]
    if args.license_id in existing_ids:
        print(f"[WARN] License '{args.license_id}' is already revoked.")
        return 0

    revoked.append({
        "license_id": args.license_id,
        "revoked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })

    REVOKED_PATH.write_text(
        json.dumps(revoked, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[OK] License '{args.license_id}' added to revocation list.")
    print(f"     Revocation list: {REVOKED_PATH} ({len(revoked)} entries)")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: fingerprint -- generate a machine fingerprint
# ---------------------------------------------------------------------------

def _get_disk_serial_windows() -> str:
    """Retrieve the boot-disk serial number on Windows via WMI.

    Why WMI: We need a hardware identifier that persists across reboots
    and OS updates.  The boot disk serial is a reasonable proxy, although
    it will change if the user replaces the boot drive.

    TODO: Consider also including the BIOS/UEFI serial and motherboard
    serial for more resilient fingerprinting.
    """
    try:
        result = subprocess.run(
            ["wmic", "diskdrive", "where", "Index=0", "get", "SerialNumber"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = [ln.strip() for ln in result.stdout.strip().splitlines() if ln.strip()]
        if len(lines) >= 2:
            return lines[1]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _get_machine_id_linux() -> str:
    """Read /etc/machine-id on Linux.

    This file is generated at install time by systemd and is stable
    across reboots.  It changes if the OS is reinstalled, which is
    acceptable for license-binding purposes.

    SECURITY NOTE: /etc/machine-id is world-readable and easily spoofed
    by a root user.  Fingerprinting is a deterrent, not a guarantee.
    """
    machine_id_path = Path("/etc/machine-id")
    if machine_id_path.exists():
        try:
            return machine_id_path.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return "unknown"


def cmd_fingerprint(args: argparse.Namespace) -> int:
    """Generate a machine fingerprint for the current host.

    Combines several hardware/OS identifiers into a single SHA-256 digest.
    The resulting fingerprint can be embedded in a license to bind it to
    a specific machine.

    SECURITY NOTE: Machine fingerprints are not cryptographically strong
    bindings.  A sufficiently motivated attacker with root/admin access
    can spoof all of the components.  The fingerprint serves as a
    commercial deterrent against casual sharing, not as DRM.
    """
    mac_addr = format(uuid.getnode(), "012x")
    hostname = platform.node()
    plat = platform.platform()
    processor = platform.processor() or "unknown"

    if sys.platform == "win32":
        disk_id = _get_disk_serial_windows()
    else:
        disk_id = _get_machine_id_linux()

    # Concatenate all components with a separator that cannot appear in
    # individual values (the pipe character).
    components = f"{mac_addr}|{hostname}|{plat}|{processor}|{disk_id}"
    digest = hashlib.sha256(components.encode("utf-8")).hexdigest()
    fingerprint = f"sha256:{digest}"

    print(f"  Fingerprint : {fingerprint}")
    print()
    print("  Components used:")
    print(f"    MAC        : {mac_addr}")
    print(f"    Hostname   : {hostname}")
    print(f"    Platform   : {plat}")
    print(f"    Processor  : {processor}")
    print(f"    Disk/ID    : {disk_id}")
    print()
    print("  SECURITY NOTE: Fingerprints are a deterrent, not strong DRM.")
    print("  A root/admin user can spoof these components.")
    return 0


# ---------------------------------------------------------------------------
# CLI entry point and argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with all subcommands.

    Each subcommand maps to a ``cmd_*`` function above.
    """
    parser = argparse.ArgumentParser(
        prog="donjon-license-admin",
        description="Donjon Platform license administration tool (ML-DSA-65 + Ed25519).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- keygen --
    kg = subparsers.add_parser("keygen", help="Generate a new ML-DSA-65 + Ed25519 keypair.")
    kg.add_argument("--force", action="store_true", help="Overwrite existing keys.")

    # -- sign --
    sg = subparsers.add_parser("sign", help="Generate a signed license file.")
    sg.add_argument("--tier", required=True, choices=VALID_TIERS, help="License tier.")
    sg.add_argument("--org", required=True, help="Organization name.")
    sg.add_argument("--expires", default=None, help="Expiry date in ISO format (YYYY-MM-DD).")
    sg.add_argument("--fingerprint", default=None, help="Machine fingerprint (sha256:...).")
    sg.add_argument("--output", default="license.json", help="Output file path.")
    sg.add_argument("--max-users", type=int, default=None, help="Max users override (managed tier).")
    sg.add_argument("--max-clients", type=int, default=None, help="Max clients override (managed tier).")

    # -- verify --
    vf = subparsers.add_parser("verify", help="Verify a license file.")
    vf.add_argument("--license", required=True, help="Path to the license JSON file.")

    # -- revoke --
    rv = subparsers.add_parser("revoke", help="Add a license to the revocation list.")
    rv.add_argument("--license-id", required=True, help="License ID to revoke (DON-YYYY-XXXXX).")

    # -- fingerprint --
    subparsers.add_parser("fingerprint", help="Generate machine fingerprint for this host.")

    return parser


def main() -> int:
    """Parse arguments and dispatch to the appropriate subcommand handler."""
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "keygen": cmd_keygen,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "revoke": cmd_revoke,
        "fingerprint": cmd_fingerprint,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
