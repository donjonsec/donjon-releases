# Donjon Platform — Product Roadmap

**Last Updated:** 2026-02-20
**Current Version:** v7.0.0
**Branch:** develop

---

## Current State: What's Built

### Platform Core — Complete
- 84 Python modules across lib/ (39), scanners/ (18), utilities/ (7), web/ (4), bin/ (16)
- 18 security scanners (network, web, SSL, cloud, container, compliance, malware, shadow AI, etc.)
- 34 compliance frameworks (NIST, HIPAA, PCI-DSS, SOC 2, ISO 27001, etc.)
- Post-quantum licensing (ML-DSA-65 + Ed25519 dual signatures)
- 4-tier gating: Community (free), Pro, Enterprise, Managed (MSSP)
- AI engine with 6 provider backends (Ollama, StepFun, Anthropic, Gemini, OpenAI, template fallback)
- FAIR risk quantification with dollar-quantified ALE

### User Interfaces — Complete
| Interface | Technology | Lines | Status |
|-----------|-----------|-------|--------|
| Web Dashboard | Self-contained SPA (inline HTML/CSS/JS) | 2,203 | Production-ready |
| REST API | Python stdlib HTTP + Flask option | 1,844 | 50+ endpoints, API key auth, TLS |
| Python TUI | Custom terminal UI (bin/donjon-launcher) | 2,066 | Full interactive menu system |
| TUI Library | ANSI + Unicode/ASCII components | 451 | Reusable component library |
| Bash CLI | Interactive menu + direct commands | 436 | Recently hardened (5 fixes) |
| Server Launcher | Python with TLS support | 141 | HTTP/HTTPS, configurable |

### Distribution — Complete
| Method | Files | Status |
|--------|-------|--------|
| Docker | Dockerfile (multi-stage), docker-compose.yml | 3 targets: api, worker, scanner |
| Tool Bundler | bin/bundle-tools.py | Air-gap portable tool download |
| Intel Updater | bin/update-intel.py | NVD + KEV + EPSS + 7 feed sources |
| Framework Sync | bin/update-frameworks.py | GitHub-based YAML sync |
| Windows Install | bin/install-windows.bat, bin/setup-windows.bat | Full installer + setup |
| Linux Install | bin/install.sh, bin/setup.sh | Full installer + setup |
| USB/Portable | Auto-detected by paths.py + platform_detect.py | Air-gap ready |

### Documentation — Complete (14 files, 5,470 lines)
| Document | Lines | Coverage |
|----------|-------|----------|
| ARCHITECTURE.md | 386 | Full system design, data flow, deployment models |
| API.md | 823 | All 50+ endpoints with examples |
| CONFIGURATION.md | 460 | Complete config reference |
| QUICKSTART.md | 305 | 5-minute start guide for all platforms |
| CLI-REFERENCE.md | 320 | Full CLI command reference |
| DEPLOYMENT.md | 387 | Production deployment guide |
| DEPLOYMENT-MODES.md | 271 | Portable, installed, CI/CD modes |
| FEATURES-v7.md | 819 | Complete v7 feature documentation |
| WINDOWS-GUIDE.md | 366 | Windows-specific instructions |
| SECURITY.md | 196 | Security model and vulnerability reporting |
| TROUBLESHOOTING.md | 411 | Common issues and solutions |
| API-KEYS.md | 106 | API key management guide |
| CHANGELOG-v7.md | 408 | Version 7 changelog |
| CHANGELOG-v6.md | 212 | Version 6 changelog |

### Quality — Recent Fixes
- 10 bugs fixed (6 from Linux testing + 4 from architecture audit)
- Bash launcher hardened (5 fragility issues resolved)
- Cross-platform shadow AI scanner path fix
- 5 security fixes: WinRM credential exposure, CORS wildcard, rate limiting, EULA bypass, EULA empty-input
- API key rotation mechanism with grace period
- Per-agent authentication tokens with HMAC verification
- CI/CD pipeline (GitHub Actions: lint → test matrix → SAST)
- Pre-commit hooks (lint, secrets, bare-input detection)
- Test suite expanded: 137 tests (82 production + 34 scanner + 6 EULA + 15 API)
- All commits as donjonsec identity (clean contributor history)

---

## Roadmap: What's Next

### Phase 2: One-Click GUI Launcher
**Priority:** HIGH | **Effort:** Small (1-2 sessions)

**Goal:** User double-clicks a file → dashboard opens in browser. No terminal commands.

| Task | Platform | File |
|------|----------|------|
| Enhance donjon.bat to start server + open browser | Windows | bin/donjon.bat |
| Create donjon-gui script for Linux | Linux | bin/donjon-gui (new) |
| Add --gui flag to Python launcher | Both | bin/donjon-launcher |
| Create .desktop file for Linux | Linux | donjon.desktop (new) |

**How it works:**
1. Detect Python (venv or system)
2. Start `start-server.py` in background
3. Poll `/api/v1/health` until ready
4. Open `http://localhost:8443` in default browser
5. Console shows "Server running. Press Ctrl+C to stop"

---

### Phase 3: Offline Update Pack System
**Priority:** HIGH | **Effort:** Medium (1-2 sessions)

**Goal:** Build a transferable archive on a connected machine, apply on air-gapped target.

| Task | File |
|------|------|
| Build update pack (connected machine) | bin/build-update-pack.py (new) |
| Apply update pack (air-gapped machine) | bin/apply-update-pack.py (new) |

**Pack contents:**
- NVD CVE data (full or incremental)
- CISA KEV catalog + EPSS scores
- Threat intel feeds (ExploitDB, OSV, etc.)
- Compliance framework YAMLs
- Portable tool binaries
- Version manifest with SHA-256 checksums

**Commands:**
```bash
# On connected machine
python bin/build-update-pack.py --output donjon-update-2026-02-20.tar.gz

# Transfer to air-gapped machine (USB, SCP, etc.)

# On air-gapped machine
python bin/apply-update-pack.py donjon-update-2026-02-20.tar.gz
```

---

### Phase 4: Single Binary Distribution (PyInstaller)
**Priority:** MEDIUM | **Effort:** Medium (2-3 sessions)

**Goal:** Download one file, run it, everything works. No Python install required.

| Task | Platform | File |
|------|----------|------|
| PyInstaller spec | Both | build/donjon.spec (new) |
| Windows build script | Windows | build/build-windows.bat (new) |
| Linux build script | Linux | build/build-linux.sh (new) |
| AppImage recipe | Linux | build/appimage/ (new) |

**Deliverables:**
- `donjon-platform.exe` — Windows portable (single file, ~50-80MB)
- `donjon-platform.AppImage` — Linux portable (single file)
- Both include Python runtime, all deps, dashboard, tools

---

### Phase 5: Dashboard Enhancement
**Priority:** LOW | **Effort:** Medium

**Non-blocking polish:**
- Lightweight chart library (Chart.js ~60KB, embedded inline)
- WebSocket for real-time scan progress (replace 30s polling)
- Print-friendly report view (CSS @media print)
- Keyboard shortcuts for power users
- Mobile-optimized responsive layout

---

### Known Open Issues

| Issue | Priority | Status |
|-------|----------|--------|
| ~~EULA acceptance kicks user out, requires relaunch~~ | ~~MEDIUM~~ | **Fixed** (v7.0.1) |
| Cloudflare MCP OAuth needs re-auth after session restart | LOW | External dependency |
| `tools/donjon-license-admin.py` in repo — repo must stay private | HIGH | By design (private repo) |
| v1 legacy HMAC key in licensing.py needs removal | LOW | After migration complete |
| ~~No API key rotation mechanism~~ | ~~HIGH~~ | **Fixed** (v7.0.1) |
| ~~No per-agent authentication tokens~~ | ~~HIGH~~ | **Fixed** (v7.0.1) |
| ~~WinRM plaintext password in PowerShell string~~ | ~~CRITICAL~~ | **Fixed** (v7.0.1) |
| ~~Cloudflare Worker CORS is `*`~~ | ~~HIGH~~ | **Fixed** (v7.0.1) |
| ~~No rate limiting on `/api/v1/validate`~~ | ~~HIGH~~ | **Fixed** (v7.0.1) |

---

### CI/CD Infrastructure — Complete

| Asset | Status |
|-------|--------|
| `.github/workflows/ci.yml` | Lint → test matrix (6 combos) → SAST |
| `.github/workflows/release.yml` | Changelog validation → full test → GitHub Release |
| `.github/dependabot.yml` | Weekly pip + Actions updates |
| `.pre-commit-config.yaml` | 8 hooks (lint, secrets, bare-input, large files) |
| `.github/pull_request_template.md` | Standardized PR template |

---

## Dark Factory Integration

This product is built and maintained using the Dark Factory framework at `C:\Darkfactory`.
All changes follow the standards, playbooks, and pipelines defined there.

| Dark Factory File | Applied To |
|-------------------|-----------|
| standards/IDENTITY_RULES.md | All commits as donjonsec identity |
| standards/COMMIT_CONVENTIONS.md | Conventional commit format |
| standards/CODE_STYLE.md | Python/Bash style enforcement |
| playbooks/BUG_TRIAGE.md | 10 bugs found, classified, fixed, verified |
| templates/VALIDATION_CONTROL.md | Verification scripts for each fix batch |
| pipelines/github-actions-ci.yml | Instantiated as `.github/workflows/ci.yml` |
| pipelines/github-actions-release.yml | Instantiated as `.github/workflows/release.yml` |
| pipelines/pre-commit-config.yml | Instantiated as `.pre-commit-config.yaml` |
| pipelines/dependabot.yml | Instantiated as `.github/dependabot.yml` |

---
