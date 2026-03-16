# Changelog

All notable changes to Donjon Platform are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

---

## [7.1.0] - 2026-03-15

### Security
- **3-layer licensing enforcement** — Added `lib/license_guard.py` with `@require_tier()` decorator, scanner base class tier gate, and API-level filtering. Replaces single API-only check.
- **File integrity verification** — Added `lib/integrity.py` with SHA-256 manifest of critical modules (licensing, license_guard, base scanner). Tampering detected = Community fallback.
- **Legacy HMAC v1 removed** — Eliminated embedded `donjon-license-signing-key-v1` shared key. Only v2 (ML-DSA-65 + Ed25519) licenses accepted.
- **Fail-closed revocation** — Revocation list deletion no longer bypasses check. Embedded hash of last-known list enforced.
- **AI quota integrity** — HMAC-signed quota file prevents deletion/reset to bypass daily query limits.
- **Scanner list filtered by tier** — Community users see only 7 permitted scanners in API responses. Pro+ scanners shown as locked with upgrade prompt.

### Added
- **Enterprise: SSO/SAML** (`lib/sso.py`) — SAML 2.0 Service Provider with IdP metadata parsing, assertion validation, air-gap XML file support
- **Enterprise: RBAC** (`lib/rbac.py`) — Role-based access control with admin/analyst/auditor/viewer roles, custom role creation, fine-grained permissions
- **Enterprise: Multi-tenant** (`lib/multi_tenant.py`) — Tenant isolation via per-tenant SQLite databases, thread-local tenant context, cross-tenant query prevention
- **Enterprise: Zero-retention** (`lib/zero_retention.py`) — Ephemeral scan sessions with cryptographic erasure and purge certificates
- **Enterprise: Audit trail** (`lib/audit_trail.py`) — Immutable append-only event log with SHA-256 hash chain, SIEM-compatible export
- **MSSP: Management plane** (`mssp/`) — 10 modules: client provisioning, data isolation, bulk scan orchestration, scan templates, client dashboards, rollup reporting, cross-client analytics, usage metering, license sub-allocation, white-label branding
- **6 compliance frameworks** — HITRUST CSF v11, SOX IT controls, NERC CIP v7, GLBA Safeguards Rule, FERPA, CIS Controls v8.1 (total: 30 frameworks)
- **Intel bundler** (`bin/bundle-intel.py`) — Offline vulnerability database packaging for USB/air-gap transfer with SHA-256 checksums
- **Intel status** — `update-intel.py --status` shows data source freshness with stale/critical warnings

### Removed
- Internal development docs (DARK_FACTORY_BUILD_LOG.md, SESSION_HANDOFF.md, ERRORS_AND_FIXES.md) removed from public repository

---

## [7.0.1] - 2026-02-20

### Security
- **WinRM password no longer visible in process listings** — `credential_scanner.py` now pipes passwords via stdin instead of interpolating into PowerShell command strings
- **Cloudflare Worker CORS restricted** — Changed from wildcard `*` to `https://donjonsec.com` with configurable `CORS_ALLOW_ORIGIN` env var in `wrangler.toml`
- **Rate limiting on license validation** — Added KV-based sliding window rate limiter (30 req/min per IP) on `/api/v1/validate` endpoint
- **API key rotation mechanism** — Added `rotate_key()` with configurable grace period and `cleanup_expired_keys()` to `web/auth.py`
- **Per-agent authentication tokens** — Added `register_agent_token()`, `verify_agent_token()`, `revoke_agent_token()` to `web/auth.py`; `_agent_checkin` now verifies per-agent tokens via `hmac.compare_digest()`

### Fixed
- **EULA empty-input decline** — Empty Enter no longer silently declines the EULA; now re-prompts with helpful message (`lib/eula.py`)
- **EULA bare input() crash in CI** — Replaced bare `input()` with `safe_input()` in `_page_text()` to prevent crashes in non-interactive/piped environments
- **EULA bypass via CLI commands** — CLI commands (`quick`, `standard`, `deep`, etc.) now check EULA acceptance before dispatching (`bin/donjon-launcher`)
- **EULA API endpoint crash** — `_legal_eula()` called nonexistent `self._json_ok()` / `self._json_error()`; fixed to use module-level `json_response()` / `error_response()`

### Added
- **CI/CD pipeline** — GitHub Actions CI with lint (flake8) → test matrix (Ubuntu + Windows, Python 3.10-3.12) → SAST (bandit)
- **Release automation** — GitHub Actions release pipeline with changelog validation, full test suite, and auto-tagging
- **Dependabot** — Weekly dependency updates for pip and GitHub Actions
- **Pre-commit hooks** — Trailing whitespace, YAML/JSON validation, private key detection, flake8, bandit, custom bare-input and secrets guards
- **PR template** — Standardized pull request template with summary, changes, test plan, and checklist
- **API key rotation endpoint** — `POST /api/v1/auth/rotate` (admin-only) for key rotation with grace period
- **Agent registration endpoint** — `POST /api/v1/agents/register` (admin-only) for per-agent token management
- **Scanner test suite** — 34 tests covering import and instantiation of all 18 scanner modules
- **EULA test suite** — 6 tests covering acceptance flow, empty-input fix, and safe_input usage
- **API route test suite** — 15 tests covering route registration, auth enforcement, key rotation, and agent tokens

---

## [7.0.0] - 2026-02-16

### Added
- 18 security scanners (network, web, SSL, cloud, container, compliance, malware, shadow AI, adversary emulation, and more)
- 24 compliance frameworks (NIST 800-53, HIPAA, PCI-DSS, SOC 2, ISO 27001, CIS, and more)
- Post-quantum licensing with ML-DSA-65 + Ed25519 dual signatures
- 4-tier gating: Community (free), Pro, Enterprise, Managed (MSSP)
- FAIR risk quantification with Monte Carlo simulation (10,000 iterations)
- AI-powered analysis engine with 3 backends (template, Ollama, OpenAI-compatible)
- SBOM generation in CycloneDX 1.4 and SPDX 2.3 formats
- CI/CD integration with SARIF output for GitHub/GitLab/Jenkins
- Container security scanner (Docker/Podman) with read-only inspection
- Cloud security scanner (AWS/Azure/GCP) with SDK + CLI fallback
- Attack surface management (CT logs, DNS enumeration, Shodan integration)
- Adversary emulation with 35 threat actor profiles across 10 categories
- Executive dashboard (terminal + HTML export)
- Web dashboard (self-contained SPA, 2,203 lines)
- REST API (50+ endpoints, API key auth, TLS support)
- Python TUI (full interactive menu system)
- Bash CLI (interactive menu + direct commands)
- 3 deployment modes: portable (USB/air-gap), installed, CI/CD
- Fernet-encrypted credential storage
- SHA-256 evidence chain of custody
- Enterprise Linux support (RHEL/SUSE/Arch with CIS benchmarks)
- Docker multi-stage build with 3 targets (api, worker, scanner)
- Cloudflare Worker for license validation + telemetry
- 14 documentation files (5,470+ lines)

### Fixed (pre-release)
- 6 bugs from Linux (Kali) cross-platform testing
- 4 bugs from architecture audit
- 5 bash launcher fragility issues
- Shadow AI scanner Windows/Linux path separation

---

For detailed v7.0 release notes, see [docs/CHANGELOG-v7.md](docs/CHANGELOG-v7.md).
For v6.0 history, see [docs/CHANGELOG-v6.md](docs/CHANGELOG-v6.md).
