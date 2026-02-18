# Donjon Platform v7.0 -- Architecture

This document describes the internal architecture of the Donjon Platform: module layout, data flow, database design, AI engine, license verification, and deployment models.

---

## Directory Layout

```
donjon-platform/
  START.bat                     # Windows one-click launcher
  docker-compose.yml            # Production Docker stack
  Dockerfile                    # Multi-stage build (api, worker, scanner)
  requirements.txt              # Python dependencies
  config/active/config.yaml     # Active platform configuration

  bin/                          # Launchers, setup scripts, CLI tools
    donjon-launcher             # Main Python TUI launcher (cross-platform)
    donjon-launcher.bat         # Windows batch wrapper
    donjon-launcher.ps1         # PowerShell wrapper
    donjon                      # CLI entry point (Linux)
    donjon.bat                  # CLI entry point (Windows)
    start-server.py             # Web API server launcher
    run-worker.py               # Background scheduler worker
    scheduler.py                # Cron-like scheduler process
    setup.sh                    # Linux/macOS environment setup
    setup-windows.bat           # Windows environment setup
    install.sh                  # Full Linux install script
    install-windows.bat         # Full Windows install script
    setup-ai.py                 # Interactive AI backend configuration
    update-intel.py             # 7-source vulnerability intelligence downloader
    update-frameworks.py        # Compliance framework data updater
    migrate-db.py               # SQLite-to-PostgreSQL migration tool
    bundle-tools.py             # Bundle external tools for air-gap deployment

  lib/                          # Core library modules (37 modules)
    # -- Foundation --
    paths.py                    # Portable path resolution (auto-detects USB/installed/CI)
    config.py                   # YAML configuration management
    platform_detect.py          # OS + deployment mode detection
    logger.py                   # Structured logging
    database.py                 # Dual-backend DB abstraction (SQLite/PostgreSQL)
    exceptions.py               # Exception/risk-acceptance management

    # -- Security Core --
    licensing.py                # License verification (ML-DSA-65 + Ed25519, tier enforcement)
    credential_manager.py       # Encrypted credential storage (Fernet)
    evidence.py                 # SQLite evidence database (sessions, findings, evidence)

    # -- Intelligence --
    vuln_database.py            # 7-source vulnerability intelligence (NVD/EPSS/SSVC/exploits)
    threat_intel.py             # CISA KEV + EPSS enrichment
    intel_feeds.py              # External threat intelligence feeds
    tool_discovery.py           # Security tool auto-detection (nmap, nuclei, etc.)

    # -- AI --
    ai_engine.py                # 6-provider AI backend (Ollama/StepFun/Anthropic/Gemini/OpenAI/template)
    ai_analyzer.py              # Legacy AI analysis interface
    ai_prompts.py               # System prompts and prompt templates

    # -- Risk & Compliance --
    risk_quantification.py      # FAIR Monte Carlo risk engine
    risk_register.py            # Risk register with scoring matrix
    compliance.py               # 30-framework compliance mapper
    cis_benchmarks.py           # CIS benchmark checks
    audit.py                    # Audit trail logging

    # -- Assets & Scanning --
    asset_inventory.py          # Asset inventory with business context
    asset_manager.py            # Asset lifecycle management
    discovery.py                # Network auto-discovery engine
    network.py                  # Network utility functions
    qod.py                      # Quality of Detection scoring
    scan_diff.py                # Scan delta comparison
    scheduler.py                # Scan scheduling engine

    # -- Reporting & Export --
    executive_report.py         # Executive summary and compliance report generation
    export.py                   # Multi-format export manager
    notifications.py            # Email, Slack, Teams, SMS, webhook notifications
    remediation.py              # Remediation tracking and SLA management
    sbom_generator.py           # CycloneDX + SPDX SBOM generation

    # -- Specialized --
    human_behavior.py           # Human behavior simulation for stealth scanning
    agent_deployer.py           # Remote agent deployment
    tui.py                      # Terminal UI components (rich/curses)

  scanners/                     # Security scanners (17 scanners)
    base.py                     # Abstract base scanner class
    network_scanner.py          # TCP/UDP port scanning, service detection, OS fingerprinting
    vulnerability_scanner.py    # CVE-based vulnerability detection (Nuclei, Nmap NSE)
    web_scanner.py              # Web application scanning (OWASP Top 10, Nikto)
    ssl_scanner.py              # SSL/TLS certificate and cipher assessment
    windows_scanner.py          # Windows configuration, GPO, patch audit
    linux_scanner.py            # Linux hardening, SSH, file permissions
    ad_scanner.py               # Active Directory security assessment
    cloud_scanner.py            # AWS/Azure/GCP misconfiguration detection
    container_scanner.py        # Docker/Podman/K8s security
    sbom_scanner.py             # SBOM generation and dependency analysis
    compliance_scanner.py       # Multi-framework compliance checks
    credential_scanner.py       # Password policy, leaked credentials, default creds
    asm_scanner.py              # Attack surface management (CT logs, DNS, Shodan)
    openvas_scanner.py          # OpenVAS/GVM integration
    malware_scanner.py          # YARA rule matching + ClamAV
    shadow_ai_scanner.py        # Unauthorized AI detection (LLMs, browser extensions, API keys)

  web/                          # Web API and dashboard
    api.py                      # REST API server (stdlib http.server + optional Flask)
    auth.py                     # API key authentication
    dashboard.py                # HTML dashboard generator

  utilities/                    # Reporting and orchestration
    orchestrator.py             # Full assessment orchestration
    reporter.py                 # HTML/JSON/CSV report generation
    executive_dashboard.py      # Terminal + HTML executive dashboards
    delta_report.py             # Trend analysis + delta reports
    exporter.py                 # SARIF, Jira, ServiceNow, Slack, Teams export
    audit_report.py             # Audit evidence and compliance reports

  agents/                       # Distributed scanning agents
    scanner_agent.py            # Remote scanner agent (checks in via API)

  tools/                        # Bundled external tools (air-gap deployment)
    donjon-license-admin.py     # License generation CLI (private keys -- never distribute)
    nmap/                       # Portable nmap binaries
    nuclei.exe                  # Portable nuclei binary
    testssl/                    # Portable testssl.sh
    amass/                      # Portable amass binary
    gobuster/                   # Portable gobuster binary
    sysinternals/               # Windows Sysinternals tools
    wordlists/                  # Password and directory wordlists
    yara/                       # YARA rules for malware scanning

  infrastructure/               # Deployment infrastructure
    cloudflare-worker/          # Cloudflare Worker license server

  keys/                         # Cryptographic key material
    donjon-public-classical.pem # Ed25519 public key (verification only)
    donjon-public-pqc.bin       # ML-DSA-65 public key (verification only)
    donjon-private-*.pem/.bin   # Private keys (admin use only, never distribute)

  data/                         # Runtime data (mostly gitignored)
    threat_intel/               # KEV + EPSS cache (tracked in git for offline use)
    vuln_db/                    # Full intel DB (~732 MB, generated by update-intel.py)
    evidence/                   # SQLite evidence database
    reports/                    # Generated reports
    logs/                       # Scan logs
    license.json                # License file (placed here for activation)
    revoked.json                # License revocation list
    ai_config.json              # Persisted AI backend configuration
    ai_quota.json               # AI daily usage counter

  tests/                        # Test suite
  docs/                         # Documentation
```

---

## Core Library Modules (37 Modules)

All core library modules in `lib/` follow a **singleton pattern** with a module-level factory function:

```python
# Every module exposes a get_<name>() singleton accessor
_instance: Optional[SomeManager] = None

def get_some_manager() -> SomeManager:
    global _instance
    if _instance is None:
        _instance = SomeManager()
    return _instance
```

This ensures:
- Exactly one instance per module across the entire application
- Lazy initialization (resources only allocated when first needed)
- Consistent API: every module is accessed via `get_<module>()` from any call site
- The web API imports all singletons at startup and checks availability with `if get_<module> is not None`

### Module Dependency Graph (Simplified)

```
paths.py  <--  config.py  <--  platform_detect.py
    ^               ^
    |               |
    +-- database.py |
    +-- evidence.py-+
    +-- licensing.py
    +-- ai_engine.py --> ai_prompts.py
    +-- all scanners --> base.py
    +-- web/api.py --> web/auth.py, web/dashboard.py
```

`paths.py` is the foundational module. It auto-detects the deployment mode (USB portable, fixed installation, or CI/CD) and resolves all filesystem paths accordingly.

---

## Dual Database Backend

The `database.py` module provides a unified abstraction layer over SQLite and PostgreSQL.

### Configuration

```bash
# SQLite (default -- zero configuration, portable)
# Databases stored as .db files in data/

# PostgreSQL (production, Docker)
export DONJON_DB_BACKEND=postgres
export DONJON_DB_URL=postgresql://donjon:password@localhost:5432/donjon
```

### Design

- **`DatabaseManager`** class wraps connection management, query execution, and schema initialization
- Automatic SQL translation between SQLite (`?` placeholders, `AUTOINCREMENT`) and PostgreSQL (`%s` placeholders, `SERIAL`)
- Schema migration via `migrate-db.py` copies all SQLite tables to PostgreSQL
- Singleton registry: `get_database(db_name)` returns the same instance for each logical database name

### Logical Databases

Each domain module creates its own logical database:

| Module | Database Name | Purpose |
|---|---|---|
| `evidence.py` | evidence | Scan sessions, findings, evidence artifacts |
| `audit.py` | audit | Audit trail entries |
| `remediation.py` | remediation | Remediation items, SLA tracking |
| `risk_register.py` | risk_register | Risk entries, scoring matrix |
| `asset_inventory.py` | asset_inventory | Asset records, business context |
| `notifications.py` | notifications | Notification channels, delivery history |
| `scheduler.py` | scheduler | Scan schedules, run history |
| `exceptions.py` | exceptions | Risk acceptance and exception records |
| `discovery.py` | discovery | Discovered hosts, network mapping |

In SQLite mode, each becomes a separate `.db` file in `data/`. In PostgreSQL mode, all share the same database with separate tables.

---

## AI Engine (6-Provider Fallback Chain)

The `ai_engine.py` module implements a unified AI backend with automatic provider detection.

### Detection Order

1. **Ollama** (local) -- probe `http://localhost:11434/api/tags` for running models. Best for air-gapped and privacy-sensitive deployments. Preferred model order: `step-3.5-flash`, `donjon-security`, `llama3.2`, `mistral`, `mixtral`, `phi3`, etc.
2. **StepFun Step 3.5 Flash** -- `STEPFUN_API_KEY` env var. 196B MoE, 11B active, fast agentic model. Also available via OpenRouter.
3. **Anthropic Claude** -- `ANTHROPIC_API_KEY` env var.
4. **Google Gemini** -- `GEMINI_API_KEY` env var. Fast, generous free tier.
5. **OpenAI GPT-4** -- `OPENAI_API_KEY` env var. Also supports any OpenAI-compatible endpoint.
6. **Template fallback** -- pure Python, always available. No LLM needed. Produces structured output using rule-based logic (severity validation, CVSS/EPSS scoring, SLA mapping).

### Configuration

AI backend can be configured three ways:
- **Auto-detection** (default): probes providers in order at startup
- **Config file** (`data/ai_config.json`): persisted backend selection
- **API endpoint** (`POST /api/v1/ai/config`): hot-reload at runtime

### Analysis Methods

| Method | Description |
|---|---|
| `analyze_finding()` | Validate severity, assess exploit likelihood, map MITRE techniques |
| `triage_findings()` | Prioritize a batch of findings by urgency |
| `generate_remediation()` | Step-by-step remediation instructions |
| `summarize_scan()` | Executive-friendly scan session summary |
| `query()` | Natural-language Q&A with optional scan context |

All LLM output is tagged with `"AI-Generated - Verify Before Acting"`. Data sanitization strips IP addresses and hostnames before sending to external providers.

---

## License Verification Flow

License verification is **product-side only** -- no private keys exist in the product code.

### Signature Scheme

Donjon uses a **dual-signature "belt and suspenders"** approach:

1. **ML-DSA-65** (NIST FIPS 204) -- post-quantum lattice-based signature. Resistant to quantum computer attacks.
2. **Ed25519** -- classical elliptic curve signature. Fast, widely trusted, audited.

Both signatures must pass verification for a license to be accepted. If only one cryptographic library is installed, the other check is skipped with a warning, but at least one must be available.

### Verification Steps

```
License file (data/license.json)
       |
       v
  1. Parse JSON, determine format version (v1 legacy / v2 current)
       |
       v
  2. Verify ML-DSA-65 signature against embedded public key
       |
       v
  3. Verify Ed25519 signature against embedded public key
       |
       v
  4. Check expiry date (ISO 8601 timestamp)
       |
       v
  5. Check machine fingerprint (SHA-256 of MAC + hostname + platform + CPU + machine-id)
       |
       v
  6. Check revocation list (data/revoked.json)
       |
       v
  7. Map tier string to TIERS dict, apply limits
```

### Tier Enforcement

The `LicenseManager` singleton enforces tier limits at two levels:
- **Library level:** `check_limit()`, `check_feature_item()`, `check_scan_depth()`, `check_ai_quota()`
- **API level:** `DonjonAPI._check_tier_limit()` intercepts requests and returns 403 with upgrade messages

### License Format (v2)

```json
{
  "format_version": 2,
  "license_id": "DJ-2026-XXXX",
  "tier": "pro",
  "organization": "Acme Corp",
  "expires": "2027-01-15T00:00:00Z",
  "machine_fingerprint": "sha256:abc123...",
  "signatures": {
    "classical": "<base64 Ed25519 signature>",
    "pqc": "<base64 ML-DSA-65 signature>"
  }
}
```

---

## Web API + TUI Dual Interface

Donjon offers two primary interfaces:

### TUI Launcher (`bin/donjon-launcher`)

- Interactive terminal UI using `rich` library (falls back to `curses`)
- Menu-driven: select scanner, configure targets, view results
- Supports headless mode for CI/CD (`--non-interactive`, `quick` command)

### REST API (`web/api.py`)

- Framework-agnostic `DonjonAPI` class with route registry
- Two transport modes:
  - **stdlib** `http.server` -- zero dependencies, always available
  - **Flask** -- auto-detected when installed, used for production
- CORS enabled for browser-based dashboard access
- API key authentication via `X-API-Key` header or `?api_key=` query parameter
- Dashboard HTML served at `GET /`

---

## Air-Gap Deployment Model

Donjon is designed for fully disconnected operation:

1. **No network required at runtime** -- all vulnerability intelligence is stored locally in SQLite
2. **Bundled tools** -- `tools/` directory contains portable binaries (nmap, nuclei, testssl, amass, gobuster, YARA rules, wordlists)
3. **Template AI** -- always-available fallback that works without any LLM or API key
4. **Local Ollama** -- for AI in air-gapped environments, install Ollama with a downloaded model
5. **USB detection** -- `paths.py` and `platform_detect.py` auto-detect removable media and adjust features (disable cloud scanning, template-only AI)
6. **License activation** -- licenses carry machine fingerprints and can be verified offline; the revocation list (`data/revoked.json`) is a simple JSON file updated manually or via the Cloudflare Worker license server when connectivity is available
7. **Pre-populated intel** -- `threat_intel/` directory is tracked in git, providing KEV + EPSS data for offline use

---

## Docker Architecture

The `docker-compose.yml` defines a three-service stack:

| Service | Image Target | Purpose | Port |
|---|---|---|---|
| `postgres` | `postgres:16-alpine` | PostgreSQL 16 database | 5432 |
| `api` | `Dockerfile` target `api` | REST API + dashboard | 8443 |
| `scheduler` | `Dockerfile` target `worker` | Background scan scheduler | -- |

The Dockerfile uses multi-stage builds with a shared `base` stage that includes Python 3.11, nmap, and all project dependencies. Three final stages (`api`, `worker`, `scanner`) extend the base for different runtime roles.
