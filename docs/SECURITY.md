# Donjon Platform v7.0 -- Security

This document describes the cryptographic design, license verification model, security architecture, and vulnerability reporting process for the Donjon Platform.

---

## Post-Quantum Cryptography

Donjon uses **NIST FIPS 204 ML-DSA-65** (Module-Lattice-Based Digital Signature Algorithm, security level 3) for license signing and verification. ML-DSA-65 is a lattice-based signature scheme standardized by NIST in August 2024 as part of the post-quantum cryptography standards. It is resistant to attacks by both classical and quantum computers.

### Why Post-Quantum Now?

- **Harvest now, decrypt later**: Adversaries collecting signed artifacts today could forge licenses once large-scale quantum computers exist
- **Long-lived licenses**: Enterprise licenses may span multiple years, overlapping with projected timelines for cryptographically relevant quantum computers
- **Compliance forward-looking**: NIST, NSA (CNSA 2.0), and EU (ENISA) all recommend beginning post-quantum migration now
- **No performance penalty**: ML-DSA-65 verification is fast (sub-millisecond on modern hardware); the larger signature size (~3,293 bytes) is irrelevant for license files

### Implementation

The platform uses the `dilithium-py` Python package, which provides a pure-Python implementation of ML-DSA-65. The license admin tool (`tools/donjon-license-admin.py`) generates keypairs and signs licenses. The product code (`lib/licensing.py`) contains only verification logic and public keys.

---

## Dual-Signature "Belt and Suspenders" Approach

Every license carries two independent signatures:

| Algorithm | Standard | Purpose | Library |
|---|---|---|---|
| **ML-DSA-65** | NIST FIPS 204 | Post-quantum resistance | `dilithium-py` |
| **Ed25519** | RFC 8032 | Classical trust anchor, widely audited | `cryptography` |

### Verification Rules

1. Both signatures are checked against their respective embedded public keys
2. Both must pass for the license to be accepted
3. If one cryptographic library is not installed, that check is skipped with a warning (graceful degradation)
4. At least one library must be installed; if neither is available, the license is rejected
5. A `False` result from either check (as opposed to `None` for "library unavailable") always rejects the license

This design ensures:
- If ML-DSA-65 is ever found to have a vulnerability, Ed25519 still protects
- If a quantum computer breaks Ed25519, ML-DSA-65 still protects
- Attackers must break both schemes simultaneously to forge a license

---

## Machine Fingerprinting

Licenses can optionally be bound to a specific machine via a SHA-256 fingerprint composed of:

| Component | Source |
|---|---|
| MAC address | First available network interface (`uuid.getnode()`) |
| Hostname | `platform.node()` |
| Platform string | `platform.system()` + `platform.machine()` (e.g., `Windows-AMD64`) |
| Processor | `platform.processor()` |
| Machine ID | Linux: `/etc/machine-id`; Windows: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |

The fingerprint is computed as:

```
sha256("mac:{mac}|host:{hostname}|platform:{os}-{arch}|cpu:{processor}|mid:{machine_id}")
```

Result format: `sha256:<hex_digest>`

Machine-bound licenses cannot be transferred to a different machine. Licenses without a `machine_fingerprint` field are portable and can be used on any machine.

---

## License Revocation

The platform supports offline license revocation via a JSON file:

- **Location:** `data/revoked.json`
- **Format:** JSON array of license IDs (strings) or objects with a `license_id` field

```json
["DJ-2026-0001", "DJ-2026-0042"]
```

or:

```json
[
  {"license_id": "DJ-2026-0001", "reason": "refund", "revoked_at": "2026-01-15T00:00:00Z"},
  {"license_id": "DJ-2026-0042", "reason": "abuse", "revoked_at": "2026-02-01T00:00:00Z"}
]
```

The revocation list is checked during license validation. In connected environments, the list can be updated from the Cloudflare Worker license server. In air-gapped environments, it is updated manually.

---

## Air-Gap Secure Activation

Donjon licenses can be activated in fully disconnected environments:

1. **Generate fingerprint:** Run the platform on the target machine; it computes the machine fingerprint automatically
2. **Create license offline:** Use the license admin tool on a connected machine to generate a machine-bound license
3. **Transfer via USB:** Copy `license.json` to `data/license.json` on the target machine
4. **Verification is local:** All cryptographic verification uses embedded public keys -- no network call required
5. **Revocation is manual:** Copy an updated `revoked.json` to the target machine if needed

No license server communication is required at any point. The platform defaults to Community tier if no license file is present, ensuring the platform is always functional.

---

## No Private Keys in Product Code

The Donjon Platform repository strictly separates signing and verification:

| Component | Contains | Location |
|---|---|---|
| **Product code** (`lib/licensing.py`) | Public keys (base64-encoded), verification logic only | Distributed with the platform |
| **License admin tool** (`tools/donjon-license-admin.py`) | Private key operations, license generation | Never distributed with the product |
| **Key files** (`keys/`) | Public and private key material | Private keys are for admin use only |

The `tools/donjon-license-admin.py` file header contains an explicit warning:

> WARNING: This tool contains private key operations. Never distribute this tool with the product.

Public keys are embedded directly in `lib/licensing.py` as base64-encoded constants, so the product code never needs to read key files from disk.

---

## Cloudflare Worker License Server

The `infrastructure/cloudflare-worker/` directory contains a Cloudflare Worker that serves as an optional online license management endpoint. It provides:

- License validation as a service (for connected environments)
- Revocation list distribution
- Usage telemetry (anonymous, opt-in)
- License activation flow for online scenarios

The worker is entirely optional. The platform functions fully without it.

---

## Data Protection

### Credential Storage

- Credentials for external services (cloud providers, Jira, ServiceNow, etc.) are encrypted using **Fernet symmetric encryption** (`lib/credential_manager.py`)
- Encryption keys are derived per-installation
- In USB portable mode, cloud credentials are never stored

### Evidence Database

- The evidence database (`data/evidence.db`) contains scan results, findings, and remediation records
- This data is sensitive and should be protected with appropriate filesystem permissions
- The database is not encrypted at rest by default; full-disk encryption is recommended for production deployments

### LLM Data Sanitization

- When using external AI providers (Anthropic, OpenAI, Gemini, StepFun), the platform strips IP addresses and hostnames from finding data before sending API requests
- Controlled by the `ai.sanitize_external` configuration flag (default: `true`)
- Local providers (Ollama, template) never send data externally
- All AI-generated output is tagged with a disclaimer: `"AI-Generated - Verify Before Acting"`

### API Authentication

- REST API authentication via `X-API-Key` header or `?api_key=` query parameter
- API keys configured via `DONJON_API_KEYS` environment variable (comma-separated)
- Keys can be generated via `python bin/start-server.py --generate-key`
- Public endpoints (health check, dashboard) are accessible without authentication
- Authentication can be disabled for development with `--no-auth`

---

## Scan Authorization

- All active scanning requires explicit operator authorization
- The platform does not scan targets automatically unless configured via schedules (Pro tier and above)
- Cloud scanners use read-only API calls exclusively
- Container scanners use read-only operations (no `exec` or `attach`)
- The `human_behavior.py` module implements realistic timing delays to avoid detection during authorized penetration tests
- Scan stealth level is configurable (`scanning.stealth_level` in config.yaml)

---

## Security Reporting

To report a security vulnerability in the Donjon Platform:

1. **Do not open a public issue.** Security vulnerabilities should be reported privately.
2. **Contact:** security@donjon.dev (or the repository maintainer directly)
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact assessment
4. **Response time:** We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

We follow responsible disclosure practices and will credit reporters (with permission) in release notes.
