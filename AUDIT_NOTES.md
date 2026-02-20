# Donjon Platform — Architecture Audit & Dark Factory Migration Notes

**Date:** 2026-02-19
**Branch:** develop
**Purpose:** Comprehensive analysis to identify fragile vs engineered modules,
protocol entry points, auth flows, and community/commercial code discrepancies.
Informs the migration path toward a dark factory development model.

---

## 1. Directory Tree-Map

**Total Size:** 287 MB | **Python Files:** 84 | **YAML Configs:** 43 | **Docs:** 50

```
C:\Donjonsec\
│
├── bin/                          # Entry points (290K)
│   ├── donjon-launcher           # Main CLI launcher (primary entry point)
│   ├── donjon / donjon.bat       # Cross-platform launcher wrappers
│   ├── start-server.py           # REST API + Dashboard server
│   ├── run-worker.py             # Background worker process
│   ├── scheduler.py              # Scheduled scanning daemon
│   ├── bundle-tools.py           # Tool bundling utility
│   ├── migrate-db.py             # Database migration tool
│   ├── setup-ai.py               # AI system initialization
│   ├── update-frameworks.py      # Compliance framework updater
│   ├── update-intel.py           # Intel feed updater
│   ├── install.sh / install-windows.bat
│   └── setup.sh / setup-windows.bat
│
├── lib/                          # Core library (1.2M, 39 modules)
│   ├── ai_engine.py              # Core AI engine
│   ├── ai_analyzer.py            # Analysis engine
│   ├── ai_prompts.py             # Prompt management
│   ├── risk_quantification.py    # FAIR risk calculation
│   ├── risk_register.py          # Risk tracking
│   ├── compliance.py             # Compliance checking
│   ├── cis_benchmarks.py         # CIS benchmark mapping
│   ├── vulnerability_database.py # Vuln database interface
│   ├── threat_intel.py           # Threat intelligence feeds
│   ├── intel_feeds.py            # Intel feed management
│   ├── credential_manager.py     # Credential handling
│   ├── asset_inventory.py        # Asset database
│   ├── asset_manager.py          # Asset management
│   ├── discovery.py              # Asset discovery
│   ├── tool_discovery.py         # Tool discovery
│   ├── network.py                # Network utilities
│   ├── database.py               # Database layer
│   ├── agent_deployer.py         # Agent deployment
│   ├── cicd_integration.py       # CI/CD pipeline integration
│   ├── notifications.py          # Alert/notification system
│   ├── scheduler.py              # Job scheduler
│   ├── sbom_generator.py         # Software Bill of Materials
│   ├── executive_report.py       # Executive summaries
│   ├── export.py                 # Data export
│   ├── scan_diff.py              # Scan comparison/deltas
│   ├── evidence.py               # Evidence collection
│   ├── config.py                 # Configuration management
│   ├── paths.py                  # Path resolution
│   ├── platform_detect.py        # OS/platform detection
│   ├── logger.py                 # Logging system
│   ├── exceptions.py             # Exception definitions
│   ├── eula.py                   # EULA management
│   ├── licensing.py              # License management
│   ├── human_behavior.py         # Behavioral analysis
│   ├── tui.py                    # Terminal UI components
│   ├── qod.py                    # Quality of Detection
│   └── audit.py                  # Audit logging
│
├── scanners/                     # Scanning modules (748K, 18 modules)
│   ├── base.py                   # Base scanner class
│   ├── network_scanner.py        # Network scanning
│   ├── vulnerability_scanner.py  # Vulnerability scanning
│   ├── web_scanner.py            # Web application scanning
│   ├── ssl_scanner.py            # SSL/TLS scanning
│   ├── cloud_scanner.py          # Cloud infrastructure
│   ├── container_scanner.py      # Container/Docker
│   ├── compliance_scanner.py     # Compliance/standards
│   ├── credential_scanner.py     # Credential exposure
│   ├── malware_scanner.py        # Malware detection
│   ├── shadow_ai_scanner.py      # Unauthorized AI detection
│   ├── adversary_scanner.py      # Adversary/threat actor
│   ├── asm_scanner.py            # Attack Surface Management
│   ├── ad_scanner.py             # Active Directory
│   ├── windows_scanner.py        # Windows system
│   ├── linux_scanner.py          # Linux system
│   ├── sbom_scanner.py           # SBOM vulnerability
│   └── openvas_scanner.py        # OpenVAS integration
│
├── utilities/                    # Orchestration (149K, 7 modules)
│   ├── orchestrator.py           # Scan orchestration engine
│   ├── reporter.py               # Report generation
│   ├── audit_report.py           # Audit report builder
│   ├── delta_report.py           # Differential reporting
│   ├── executive_dashboard.py    # Dashboard aggregation
│   └── exporter.py               # Multi-format export
│
├── web/                          # Web interface (205K, 4 modules)
│   ├── api.py                    # REST API endpoints
│   ├── dashboard.py              # Web dashboard UI
│   └── auth.py                   # Authentication/authorization
│
├── agents/                       # Agent deployment (40K)
│   └── scanner_agent.py          # Remote scanner agent
│
├── config/                       # Configuration (556K)
│   ├── active/config.yaml        # Active system config
│   ├── frameworks/               # 34 compliance frameworks (YAML)
│   │   ├── nist_800_53.yaml, nist_csf_2.0.yaml, iso_27001_2022.yaml
│   │   ├── pci_dss_4.yaml, hipaa.yaml, gdpr.yaml, soc2.yaml
│   │   ├── fedramp.yaml, cmmc.yaml, dora.yaml, nis2.yaml
│   │   └── eu_ai_act.yaml, ccpa.yaml, sec_cyber.yaml, ...
│   ├── adversary_profiles/       # 11 threat actor profiles
│   │   ├── apt28.yaml, apt29.yaml, lazarus.yaml, lockbit.yaml
│   │   └── volt_typhoon.yaml, sandworm.yaml, scattered_spider.yaml, ...
│   └── templates/config.yaml.example
│
├── infrastructure/               # Deployment (42K)
│   └── cloudflare-worker/
│       ├── src/worker.py         # License server Worker
│       └── wrangler.toml         # Wrangler config
│
├── tools/                        # Bundled binaries (204M)
│   ├── nmap/                     # Network mapper + NSE scripts
│   ├── amass/                    # Subdomain enumeration
│   ├── gobuster/                 # Directory brute-forcing
│   ├── testssl/                  # SSL/TLS analysis
│   ├── yara/                     # Malware pattern matching
│   ├── sysinternals/             # Windows utilities
│   ├── wordlists/                # Fuzzing wordlists
│   └── donjon-license-admin.py   # License admin CLI
│
├── docker/                       # Container orchestration (28K)
│   ├── Makefile
│   └── init-db.sql               # DB initialization
│
├── docs/                         # Documentation (396K)
│   ├── ARCHITECTURE.md, API.md, CLI-REFERENCE.md, SECURITY.md
│   ├── QUICKSTART.md, TROUBLESHOOTING.md, WINDOWS-GUIDE.md
│   ├── CHANGELOG-v6.md, CHANGELOG-v7.md, FEATURES-v7.md
│   └── kb/                       # HTML Knowledge Base
│       ├── index.html, user-guide.html, admin-guide.html
│       └── api-reference.html, security-guide.html, training.html
│
├── tests/                        # Tests (28K)
│   └── test_production_ready.py
│
├── ERRORS_AND_FIXES.md           # Bug findings from cross-platform testing
├── pyproject.toml                # Project metadata
├── requirements.txt              # Dependencies
├── Dockerfile / docker-compose.yml
├── START.bat                     # Windows quick-start
└── LICENSE                       # Proprietary EULA
```

---

## 2. Protocol Entry Points & Authentication Flows

### 2.1 HTTP / API (Primary Entry Point)

| Component | Detail |
|-----------|--------|
| **Server** | `web/api.py:1721` — stdlib `HTTPServer` or Flask |
| **Default Bind** | `127.0.0.1:8443` (localhost only — safe default) |
| **TLS** | Optional, via `DONJON_TLS_CERT` / `DONJON_TLS_KEY` env vars |
| **Auth Method** | API Key in `X-API-Key` header |
| **Key Format** | `donjon_<48 hex chars>` — constant-time `hmac.compare_digest()` |
| **Key Source** | `DONJON_API_KEYS` / `DONJON_ADMIN_KEYS` env vars |
| **Public Paths** | `/`, `/api/v1/health`, `/api/v1/legal/eula` |
| **Admin Paths** | `/api/v1/maintenance/purge-*` (require admin key) |
| **Dashboard** | GET `/` serves HTML (no auth by default) |
| **`--no-auth` flag** | Disables auth entirely (bin/start-server.py) |

### 2.2 SSH

| Component | Detail |
|-----------|--------|
| **Library** | Paramiko (`lib/credential_manager.py:256-296`) |
| **Auth Methods** | Password (`client.connect(password=)`) or key-based (`key_filename=`) |
| **Host Key Policy** | `AutoAddPolicy()` — accepts all (intended for scanner use) |
| **Timeout** | 10 seconds |
| **Remote Exec** | `scanners/credential_scanner.py:135-157` — `exec_command(cmd, timeout=30)` |
| **Credential Storage** | `config/active/credentials.yaml` (sensitive fields Fernet-encrypted) |

### 2.3 WinRM (Windows Remote Management)

| Component | Detail |
|-----------|--------|
| **Method** | PowerShell `Invoke-Command` via subprocess (`scanners/credential_scanner.py:159-182`) |
| **Ports** | 5985 (HTTP) / 5986 (HTTPS) |
| **Guard** | Windows-only (`sys.platform == 'win32'`) |
| **Issue** | Password passed as `-AsPlainText -Force` in PowerShell string |

### 2.4 RDP

- **Detection only** — port 3389 identified in `lib/discovery.py:269-271`
- No RDP client code — used for OS fingerprinting (Windows indicator)

### 2.5 Database

| Component | Detail |
|-----------|--------|
| **Default** | SQLite — file-based in `data/*.db` (no credentials) |
| **Optional** | PostgreSQL via `DONJON_DB_URL` env var |
| **Migration** | `lib/database.py:459-614` — SQLite → PostgreSQL |
| **Tables** | evidence, findings, sessions, audit_log, assets, discovered_hosts, etc. |
| **Connection Masking** | `re.sub(r':([^@]+)@', ':***@', url)` — masks password in logs |

### 2.6 Cloudflare Worker (License Server)

| Component | Detail |
|-----------|--------|
| **File** | `infrastructure/cloudflare-worker/src/worker.py` |
| **Public** | `/api/v1/validate`, `/api/v1/public-keys`, `/api/v1/revoked` |
| **Admin** | `/api/v1/generate`, `/api/v1/revoke`, `/api/v1/stats` |
| **Auth** | `X-Admin-Key` header, key stored in KV |
| **Limits** | 512 KiB max body, 10K max revocation entries |

### 2.7 Agent Communication

| Component | Detail |
|-----------|--------|
| **Check-in** | POST `/api/v1/agents/checkin` (`web/api.py:897-934`) |
| **Body** | JSON: agent_id, hostname, ip_address, results |
| **Auth** | Server-level API key only — no per-agent token |

### 2.8 Environment Variables (Credential Surface)

| Env Var | Risk |
|---------|------|
| `DONJON_API_KEYS` / `DONJON_ADMIN_KEYS` | API keys in env — exposed if env leaked |
| `DONJON_DB_URL` | PostgreSQL URL contains plaintext password |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` | AI provider keys |
| `NVD_API_KEY` / `GITHUB_TOKEN` | External service tokens |
| `DONJON_TLS_CERT` / `DONJON_TLS_KEY` | Paths only (not secret) |

### 2.9 Credential Encryption

- **Library:** `cryptography.fernet.Fernet` (`lib/credential_manager.py:69-89`)
- **Key file:** `config/active/.cred_key` (chmod 0o600 on Unix)
- **Encrypted fields:** password, key_passphrase, community_string, secret
- **No plaintext fallback** — raises error if cryptography unavailable

### 2.10 Entry Point Summary Table

| Protocol | Endpoint | Auth | Weakness | File |
|----------|----------|------|----------|------|
| HTTP | `0.0.0.0:8443` | API Key (X-API-Key) | Key in env var, no rotation | `web/api.py:1721` |
| SSH | Paramiko client | Password / Key | Host key verification disabled | `lib/credential_manager.py:260` |
| WinRM | PowerShell subprocess | Username / Password | Plaintext password in script | `scanners/credential_scanner.py:171` |
| PostgreSQL | TCP:5432 | URL with password | Password in plaintext URL | `lib/database.py:49` |
| CF Worker | HTTPS (Cloudflare) | X-Admin-Key header | Key in KV, no rotation | `worker.py:79` |
| Agent | POST `/api/v1/agents/checkin` | Server-level API key | No per-agent auth | `web/api.py:897` |

---

## 3. Community vs Commercial Code Discrepancies

**Status:** Local tree is fully synced with `origin/develop` — no code drift.

### 3.1 Architecture: Three-Layer Separation

| Layer | What | Committed? | Notes |
|-------|------|------------|-------|
| **Community Code** | Core scanners, compliance, audit, TUI | YES | Open, functional at community tier |
| **Commercial Code** | Licensing, feature gates, admin tools, CF Worker | YES | Gated by tier checks at runtime |
| **Secrets** | Private keys, credentials, API keys, DB state | NO (.gitignored) | Never touches the repo |

### 3.2 Tier-Gated Feature Matrix

| Feature | Community | Pro | Enterprise | Managed |
|---------|-----------|-----|------------|---------|
| Scanners | 7 (core) | ALL 17 | ALL 17 | ALL 17 |
| Scan depth | quick, standard | ALL | ALL | ALL |
| Max targets | 16 | Unlimited | Unlimited | Unlimited |
| History retention | 30 days | Unlimited | Unlimited | Unlimited |
| Throttle | 500ms delay | None | None | None |
| Export formats | CSV, JSON | ALL | ALL | ALL |
| Compliance frameworks | 3 | Unlimited | Unlimited | Unlimited |
| AI queries | 10/day | Unlimited | Unlimited | Unlimited |
| Users | 1 | 25 | Unlimited | Unlimited |
| Scheduled scans | NO | YES | YES | YES |
| Alert routing | NO | YES | YES | YES |
| SSO / RBAC | NO | NO | YES | YES |
| Custom branding | NO | NO | YES | YES |
| Multi-tenant | NO | NO | YES | YES |
| MSSP features | NO | NO | NO | YES |

### 3.3 Commercial Components (Committed — Repository Must Stay Private)

- [ ] **`tools/donjon-license-admin.py`** — Post-quantum key generation & license signing CLI.
  Explicitly marked "NEVER distribute with product binary." Present in repo.
- [ ] **`lib/licensing.py`** — Tier definitions, feature gates, dual-signature verification
  (ML-DSA-65 + Ed25519). Public keys embedded (safe); private keys gitignored.
- [ ] **`infrastructure/cloudflare-worker/`** — License distribution/validation at
  `license.donjonsec.com`. KV credentials provisioned at deploy time.

### 3.4 Correctly Gitignored (Secrets & State)

- [x] `keys/` — License admin private keys (4 files)
- [x] `config/active/.cred_key` — Fernet encryption key
- [x] `config/active/credentials.yaml` — Encrypted credentials
- [x] `data/*.db` — SQLite databases (runtime)
- [x] `data/license.json` — Customer license file
- [x] `data/ai_quota.json` — AI query counter
- [x] `data/revoked.json` — Local revocation cache
- [x] `.env*` — Environment-specific secrets

### 3.5 Risk Flag

> **`tools/donjon-license-admin.py` is committed to the remote.** Its own docstring says
> "NEVER distribute with product binary, shipped in Docker images, or committed to public
> repositories." This is safe **only** if the repository remains private. If any community/
> open-source release is planned, this file must be excluded or moved to a separate
> private repo.

---

## 4. Module Classification: Fragile vs Engineered

### 4.1 Summary

| Rating | Count | Modules |
|--------|-------|---------|
| **Engineered** | 19 | All Python modules across lib/, scanners/, utilities/, web/, infrastructure/ |
| **Fragile** | 1 | `bin/donjon` (the bash launcher) |

### 4.2 FRAGILE: `bin/donjon` (Bash Launcher)

**Confidence: HIGH** — 5 distinct fragility patterns:

- [ ] **Bare `read` without CI guard (L241, 376, 399)** — No TTY/stdin check.
  Python launcher uses `safe_input()` but bash has no equivalent. Breaks in CI/Docker/piped mode.
- [ ] **Broken prerequisite check (L222)** — `-o` operator inside `[ ]` has wrong precedence.
  Mis-classifies `testssl.sh` as missing even when bundled copy exists.
- [ ] **`set -e` kills shell on scan failure (L7)** — Python scanner returns `{'error': ...}`
  but non-zero exit code terminates the bash launcher entirely. No graceful "scan failed" message.
- [ ] **No path quoting for `DONJON_HOME` (L144)** — If path contains spaces,
  inline Python `-c` string produces syntax error. No quoting defense.
- [ ] **`run_scanner()` has no file existence check (L152)** — Missing scanner file
  produces raw Python traceback instead of user-friendly error.

### 4.3 ENGINEERED: Python Modules (All Pass)

**Consistent patterns observed across the codebase:**

- [x] `try/except ImportError` fallback on every relative import
- [x] `safe_input()` for all interactive prompts (Python side)
- [x] Platform-aware tool detection (`sys.platform` / `platform.system()`)
- [x] No hardcoded credentials — env vars + encrypted credential store
- [x] `None`-check conventions on all subprocess helpers
- [x] Base scanner wraps evidence/QoD/threat-intel enrichment in exception handlers
- [x] `subprocess.run` with explicit `timeout` on all external commands
- [x] `json.dump(default=str)` for non-serializable types
- [x] `hmac.compare_digest()` / `secrets.compare_digest()` for constant-time auth

**Standout modules:**
- `infrastructure/cloudflare-worker/src/worker.py` — Most hardened module. Size limits,
  input sanitization, constant-time comparison, no error detail leakage, strict ID validation.
- `lib/tui.py` — `safe_input()` implementation is correct and complete.
- `scanners/base.py` — Solid base class; all 18 scanners inherit reliable patterns.

### 4.4 Additional Bugs Found (Not in Original 6)

#### Bug 7: `cloud_scanner.py:329` — Timezone-naive/aware datetime mix

```python
# CURRENT (crashes on AWS keys older than 90 days):
rotated = datetime.strptime(last_rotated[:10], '%Y-%m-%d')          # naive
age_days = (datetime.now(timezone.utc) - rotated).days               # TypeError

# FIX:
rotated = datetime.strptime(last_rotated[:10], '%Y-%m-%d').replace(tzinfo=timezone.utc)
age_days = (datetime.now(timezone.utc) - rotated).days
```

**Severity: HIGH** — Guaranteed crash when scanning AWS environments with old access keys.

#### Bug 8: `tool_discovery.py:454` — String/Path division TypeError

```python
# CURRENT (str / Path raises TypeError):
for name in ('yara' / Path('yara64.exe'), 'yara' / Path('yara.exe')):

# FIX:
for name in (Path('yara') / 'yara64.exe', Path('yara') / 'yara.exe'):
```

**Severity: MEDIUM** — Only reachable on Windows (inside `if is_windows:` guard), but will crash
YARA tool discovery on any Windows machine.

#### Bug 9: `utilities/reporter.py:695` — Wrong version string

```python
# CURRENT:
"Generated by Donjon v6.0"

# FIX:
"Generated by Donjon v7.0"
```

**Severity: LOW** — Cosmetic, but visible in all generated trend reports.

#### Bug 10: `utilities/orchestrator.py:282` — Overly strict Linux check

```python
# CURRENT (misses 'linux2' on some systems):
if LinuxScanner is not None and sys.platform == 'linux':

# FIX:
if LinuxScanner is not None and sys.platform.startswith('linux'):
```

**Severity: LOW** — Only affects legacy Python 2 containers (rare in 2026).

---

## 5. Dark Factory Migration Roadmap

### 5.1 Idea Map

```
                    DARK FACTORY MODEL
                          |
          +---------------+---------------+
          |               |               |
     AUTOMATION      QUALITY GATE     IDENTITY
          |               |               |
    +-----+-----+    +---+---+      +----+----+
    |     |     |    |       |      |         |
   CI/CD  Auto  Pre  Tests  Lint  Single    No AI
   Pipeline Fix  commit       |   Author   Traces
    |     |     Hook   +-----+    (donjonsec)
    |     |     |      |     |
   GitHub Dark  Guard  Unit  SAST
   Actions Factory Rail  Tests Scanner
          Bot
```

### 5.2 Phase 1 — Foundation (Immediate)

**Goal:** Fix remaining bugs, establish quality baseline.

- [ ] Fix Bug 7: `cloud_scanner.py:329` timezone crash
- [ ] Fix Bug 8: `tool_discovery.py:454` YARA Path TypeError
- [ ] Fix Bug 9: `reporter.py:695` version string v6.0 → v7.0
- [ ] Fix Bug 10: `orchestrator.py:282` Linux platform check
- [ ] Harden `bin/donjon` bash launcher (5 issues from Section 4.2)
- [ ] Commit and push as `donjonsec <dev@donjonsec.com>`

### 5.3 Phase 2 — Quality Gates (Short-term)

**Goal:** Prevent regressions, enforce standards automatically.

- [ ] Add pre-commit hooks (lint, import check, bare `input()` detection)
- [ ] Expand `tests/test_production_ready.py` with import tests for all 18 scanners
- [ ] Add platform-specific test matrix (Windows + Linux)
- [ ] Add `.github/workflows/ci.yml` for automated testing on push
- [ ] Enforce `safe_input()` pattern via grep-based pre-commit check
- [ ] Add SAST scanning (bandit/semgrep) to CI pipeline

### 5.4 Phase 3 — Dark Factory Pipeline (Medium-term)

**Goal:** Fully automated build-test-release cycle under donjonsec identity.

- [ ] GitHub Actions workflow: test → lint → build → tag → release
- [ ] Automated changelog generation from conventional commits
- [ ] Docker image build and push (automated)
- [ ] Cloudflare Worker deployment via `wrangler` in CI
- [ ] All commits authored as `donjonsec <dev@donjonsec.com>` (enforced)
- [ ] No AI attribution in any commit, PR, or release note
- [ ] Branch protection rules on `main` (require passing CI)

### 5.5 Phase 4 — Commercial Separation (When Ready)

**Goal:** Clean split between community and commercial artifacts.

- [ ] Move `tools/donjon-license-admin.py` to a separate private repo
- [ ] Evaluate whether `lib/licensing.py` tier definitions need obfuscation
- [ ] Create `community` branch stripped of commercial components (if open-sourcing)
- [ ] Implement API key rotation mechanism
- [ ] Add per-agent authentication tokens
- [ ] Restrict Cloudflare Worker CORS (`_CORS_ALLOW_ORIGIN`)
- [ ] Add rate limiting on `/api/v1/validate`

### 5.6 Security Hardening Checklist

- [ ] Enable TLS by default (require cert/key files)
- [ ] Implement API key rotation and expiration
- [ ] Sanitize SSH command execution in `credential_scanner.py`
- [ ] Fix WinRM plaintext password handling
- [ ] Add per-agent auth tokens (not just server-level API key)
- [ ] Rotate Cloudflare Worker admin keys on schedule
- [ ] Move secrets from env vars to a secrets manager (Vault, 1Password CLI, etc.)

---
