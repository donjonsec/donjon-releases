# Dark Factory Build Log

> A transparent, granular record of building an AI-driven software factory from scratch.
> Every decision, every error, every dollar — documented for public scrutiny.

## Project Identity

| Field | Value |
|-------|-------|
| **Project** | DonjonSec Dark Factory |
| **Goal** | Autonomous AI software development platform (Dan Shapiro Level 5) |
| **Start Date** | 2026-02-24, 00:30 EST |
| **Operator** | Cris (DonjonSec) |
| **AI Architect** | Claude Opus 4.6 (Anthropic, Claude Max subscription) |
| **AI Coder** | Qwen 2.5 Coder 32B (local, Ollama, CPU-only) |
| **Philosophy** | Two-brain model — frontier AI architects, local AI codes 24/7 |

---

## Phase 0: Infrastructure Stand-Up

### Hardware

**Server: Dell PowerEdge R630 (1U Rackmount)**
| Component | Specification |
|-----------|--------------|
| CPU | 2x Intel Xeon E5-2667 v4 @ 3.20 GHz (16 cores / 32 threads total) |
| RAM | 378 GB DDR4 ECC |
| Storage | 5 TB LVM thin pool + 94 GB local |
| GPU | NVIDIA Quadro P400 (2 GB GDDR5, 256 CUDA cores) — not yet utilized |
| NIC | Broadcom BCM57800 (10 GbE) |
| Hypervisor | Proxmox VE 9.0.11 |

**Desktop (Operator Workstation)**
| Component | Specification |
|-----------|--------------|
| NIC | Intel X540-AT2 (10 GbE) |
| OS | Windows 11 Pro |
| AI Tools | Claude Code CLI (Claude Max), Git Bash |

### Network Performance (Desktop ↔ R630)

| Test | Result |
|------|--------|
| Ping | < 1 ms |
| iperf3 upload (Desktop → R630, 4 streams) | **9.49 Gbps** |
| iperf3 download (R630 → Desktop, 4 streams) | **7.44 Gbps** |
| SSH upload (encryption-limited) | 1.09 Gbps |
| SSH download (encryption-limited) | 0.61 Gbps |

### Containers Deployed

All containers run on Proxmox LXC (privileged mode for full device access).

| CT ID | Hostname | Purpose | OS | CPU | RAM | Disk | IP(s) |
|-------|----------|---------|-----|-----|-----|------|-------|
| 100 | factory-core | Ollama + Factory Control Panel | Debian 12 | 16 cores | 128 GB | 200 GB | 192.168.1.110 |
| 101 | scanner-node | DonjonSec scanner host | Debian 12 | 4 cores | 4 GB | 20 GB | 192.168.1.111 / 10.10.10.10 |
| 102 | target-debian | Cyber range target | Debian 12 | 1 core | 2 GB | 10 GB | 10.10.10.20 |
| 103 | target-ubuntu | Cyber range target | Ubuntu 22.04 | 1 core | 2 GB | 10 GB | 10.10.10.21 |
| 104 | target-rocky | Cyber range target | Rocky Linux 9 | 1 core | 2 GB | 10 GB | 10.10.10.22 |

**Total resource allocation**: 23 cores, 138 GB RAM, 250 GB disk
**Remaining capacity**: 9 cores, 240 GB RAM, ~4.8 TB disk

### Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PRODUCTION NETWORK (vmbr0)                │
│                    192.168.1.0/24                            │
│                                                              │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ Desktop  │  │ factory-core │  │ scanner-node │           │
│  │ .101     │  │ .110         │  │ .111         │           │
│  │ 10GbE    │  │ Ollama API   │  │ Python/nmap  │           │
│  └──────────┘  └──────────────┘  └──────┬───────┘           │
│                                          │                   │
│  ┌───────────┐                          │                   │
│  │ Proxmox   │                          │                   │
│  │ .100      │◄── NAT (MASQUERADE) ─────┤                   │
│  └───────────┘                          │                   │
│                                          │                   │
├──────────────────────────────────────────┼───────────────────┤
│                    CYBER RANGE (vmbr1)   │                   │
│                    10.10.10.0/24         │ (isolated bridge) │
│                                          │                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──┴───────────┐      │
│  │ target-debian│  │ target-ubuntu│  │ scanner-node │      │
│  │ .20          │  │ .21          │  │ .10 (dual)   │      │
│  │ SSH, Apache  │  │ SSH,Apache,  │  │              │      │
│  │              │  │ MySQL        │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌──────────────┐                                           │
│  │ target-rocky │                                           │
│  │ .22          │                                           │
│  │ SSH, httpd   │                                           │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### Ollama / Local LLM

| Field | Value |
|-------|-------|
| Engine | Ollama (systemd service on CT 100) |
| Model (primary) | qwen2.5-coder:32b (Q4_K_M, 19 GB) |
| Model (fast) | qwen2.5-coder:14b (downloading) |
| API | http://192.168.1.110:11434 |
| Compute | CPU-only (32 threads Xeon E5-2667 v4) |
| Inference speed | ~0.9 tok/s (32B on CPU) |
| Cost | $0/month (runs on owned hardware) |

### Services on Scan Targets

| Target | Services Running |
|--------|-----------------|
| target-debian (10.10.10.20) | SSH (22), Apache2 (80) |
| target-ubuntu (10.10.10.21) | SSH (22), Apache2 (80), MySQL (3306) |
| target-rocky (10.10.10.22) | SSH (22), httpd (80) |

---

## Issues Encountered & Resolved

Every problem hit during the build, in chronological order. This is the real work — not the plan, but the debugging.

### Issue 1: UCG Refuses DNS
- **Symptom**: `apt-get update` fails on Proxmox, `server can't find deb.debian.org: REFUSED`
- **Root cause**: UCG gateway (192.168.1.1) was primary nameserver but actively refuses DNS queries
- **Fix**: Added `nameserver 8.8.8.8` as primary in `/etc/resolv.conf`
- **Time to diagnose**: ~3 minutes

### Issue 2: SSH Key Auth Failure (Windows → Proxmox)
- **Symptom**: Key offered and accepted (PK_OK), but authentication fails silently
- **Root cause**: Windows OpenSSH uses `publickey-hostbound-v00@openssh.com` signature method, Proxmox's OpenSSH 10.0p2 rejects it. Additionally, Proxmox stores `authorized_keys` on a cluster filesystem symlink (`/etc/pve/priv/authorized_keys`)
- **Things tried**: chmod 600 (doesn't work on Windows), forcing `PubkeyAcceptedAlgorithms=ssh-ed25519`, breaking the symlink, server-side DEBUG3 logging
- **Fix**: Generated fresh Ed25519 key pair ON the Proxmox server, SCP'd private key to desktop
- **Time to diagnose**: ~45 minutes (longest single issue)
- **Lesson**: When SSH key auth fails between different OpenSSH implementations, generate the key ON the server

### Issue 3: Windows CRLF in PEM Files
- **Symptom**: `error in libcrypto` when using SSH key written by Claude's Write tool
- **Root cause**: Write tool outputs Windows line endings (CRLF). OpenSSH private keys must use Unix line endings (LF only)
- **Fix**: Used `scp` binary transfer instead of the Write tool for PEM files
- **Time to diagnose**: ~5 minutes
- **Lesson**: Never write SSH private keys with Windows tools — always transfer binary

### Issue 4: Windows File Permissions for SSH Keys
- **Symptom**: `WARNING: UNPROTECTED PRIVATE KEY FILE!` — Git Bash `chmod 600` is silently ignored on Windows
- **Root cause**: Windows NTFS permissions don't respond to POSIX chmod in Git Bash
- **Fix**: `icacls ~/.ssh/id_pve /inheritance:r /grant:r 'Cris:(R)'`
- **Time to diagnose**: ~5 minutes

### Issue 5: Range Containers No Internet
- **Symptom**: Containers on vmbr1 (isolated bridge, no physical NIC) can't resolve DNS or reach package repos
- **Root cause**: vmbr1 has no upstream route — it's an isolated bridge by design. But we need internet temporarily for package installation
- **Fix**: Added iptables MASQUERADE NAT on Proxmox host + ip_forward + default gateway on each container
- **Persistence**: post-up hook in `/etc/network/interfaces`, sysctl.d config, gateway in LXC conf
- **Time to diagnose**: ~10 minutes

### Issue 6: Ollama Install Requires zstd
- **Symptom**: `This version requires zstd for extraction`
- **Root cause**: Ollama switched to zstd-compressed tarballs, not installed on minimal Debian
- **Fix**: `apt-get install zstd` before running install script
- **Time to diagnose**: ~2 minutes

### Issue 7: Scanner-Node SSH Connection Reset
- **Symptom**: `ssh scanner-node` returns "Connection reset by peer" despite container running
- **Root cause**: Desktop SSH key not in scanner-node's authorized_keys (only root password auth was configured)
- **Fix**: Used `pct exec 101` via Proxmox to push desktop's public key into container
- **Time to diagnose**: ~5 minutes

### Issue 8: Git Clone Hangs on Scanner-Node
- **Symptom**: `git clone https://github.com/DonjonSec/DonjonSec.git` hangs indefinitely
- **Root cause**: Repository is private, git prompts for credentials but terminal is non-interactive
- **Fix**: Used `scp -r /c/DonjonSec scanner-node:/opt/DonjonSec` instead
- **Time to diagnose**: ~3 minutes

### Issue 9: Python Externally Managed on Debian 13
- **Symptom**: `pip install` refuses with "externally managed environment" on factory-core
- **Root cause**: Debian 13 (Trixie) with Python 3.13 enforces PEP 668, blocking system-wide pip installs
- **Fix**: Created venv: `python3 -m venv /opt/factory-venv`
- **Time to diagnose**: ~5 minutes
- **Lesson**: Always use venv on Debian 13+

### Issue 10: FastAPI StaticFiles Empty Directory
- **Symptom**: App crashes on startup with StaticFiles mount error
- **Root cause**: `StaticFiles(directory=...)` requires at least one file in the directory
- **Fix**: Created minimal `style.css` placeholder in `/opt/dark-factory/app/static/`
- **Time to diagnose**: ~2 minutes

### Issue 11: Jinja2 Unquoted String Comparisons
- **Symptom**: Project status badges always show gray (default) regardless of actual status
- **Root cause**: Template used `{% if project.status == active %}` without quotes — `active` is treated as an undefined variable, comparison always false
- **Fix**: Changed to `{% if project.status == 'active' %}` (quoted string literal)
- **Time to diagnose**: ~1 minute (caught during code review before user noticed)
- **Lesson**: Always quote string literals in Jinja2 comparisons

### Issue 12: SSH Heredoc Escaping Failure
- **Symptom**: `ssh factory-core 'cat > file << EOF...'` fails with "Permission denied" errors
- **Root cause**: Shell quoting nests poorly when writing multi-line content over SSH — escaping single quotes inside single-quoted heredocs is unreliable
- **Fix**: Write files locally, then `scp` to remote host
- **Time to diagnose**: ~3 minutes
- **Lesson**: Never use heredocs over SSH for complex content. Write locally + SCP.

---

## Architecture Decisions

| Decision | Rationale | Alternative Considered |
|----------|-----------|----------------------|
| **Two-brain model** (Claude + Qwen) | Claude Max has session limits; Qwen on local hardware is unlimited 24/7 | Single model (Claude only) — too expensive for continuous operation |
| **LXC over VMs** | Near-native performance, shared kernel, lower overhead. 128 GB RAM for Ollama wouldn't work well in a VM with overhead | KVM VMs — heavier, slower to provision |
| **Privileged containers** | Ollama needs `/dev` access; nmap needs raw sockets | Unprivileged with device passthrough — more complex, fragile |
| **Isolated cyber range** (vmbr1) | Scan targets must not be routable from production network. NAT provides controlled internet access | Flat network — dangerous for active scanning |
| **CPU-only inference** (for now) | Quadro P400 has only 2 GB VRAM, insufficient for 32B model. CPU at 0.9 tok/s is slow but functional | GPU offload — would need $100-150 Tesla P40 for meaningful speedup |
| **32B + 14B dual model** | 32B for high-quality architecture/review, 14B for faster bulk coding tasks | Single model — suboptimal for different task types |
| **Server-generated SSH keys** | Avoids cross-platform key format issues between Windows OpenSSH and Linux OpenSSH | Client-generated — failed due to signature method mismatch |
| **Build all 10 agents at once** | Factory is its own first customer; need full roster to test adversarial review, cross-model review | Incremental — would slow down the feedback loop |

---

## Factory Architecture (Designed)

### Agent Roster (10 Agents)

| Agent | Role | Model | Purpose |
|-------|------|-------|---------|
| Lead | Orchestrator | Claude Opus | Project management, task decomposition, decision-making |
| Coder-1 | Primary developer | Qwen 32B | Feature implementation, bug fixes |
| Coder-2 | Secondary developer | Qwen 14B | Bulk coding, templates, boilerplate |
| Doc-1 | Documentation | Qwen 14B | API docs, user guides, changelogs |
| Reviewer-1 | Code review | Claude Opus | Adversarial review, quality gates |
| Security-1 | Security audit | Claude Opus | Vulnerability scanning, crypto review |
| Tester-1 | Test engineer | Qwen 32B | Test generation, coverage analysis |
| Scout-1 | Discovery (frameworks) | Claude Haiku | Language/framework trend monitoring |
| Scout-2 | Discovery (CVEs) | Claude Haiku | CVE monitoring, dependency auditing |
| Scout-3 | Discovery (standards) | Claude Haiku | Standards/compliance monitoring |

### Pipeline (4-Phase Loop)

```
IMPLEMENT → VALIDATE → ADVERSARIAL REVIEW → COMMIT
     ↑                                         │
     └─────────── (on failure) ────────────────┘
```

- **IMPLEMENT**: Coder agents write code against spec
- **VALIDATE**: Tester agent runs test suite, coverage check
- **ADVERSARIAL REVIEW**: Fresh reviewer instance (never the author), binary PASS/FAIL
- **COMMIT**: Only on PASS — atomic commit with full provenance

### Key Design Principles (from competitive analysis)

| Principle | Source | Our Implementation |
|-----------|--------|-------------------|
| Fresh reviewer rule | Metaswarm | New reviewer instance per review, never the author |
| Cross-model review | Original | Writer reviewed by different model (Claude writes → Qwen reviews) |
| Spec-driven DoD | StrongDM Attractor | 3 spec files define "done" — PRODUCT_SPEC, ARCHITECTURE_SPEC, QUALITY_SPEC |
| Progressive autonomy | Original | HITL → Guided → Supervised → Autonomous (trust earned per-product) |
| Self-improvement loop | Metaswarm | After each project, factory reviews its own process and proposes improvements |
| Structured knowledge base | Metaswarm BEADS | JSONL task tracking with selective context priming |

---

## Cost Analysis

### Hardware (One-Time)

| Item | Cost | Status |
|------|------|--------|
| Dell R630 (dual Xeon, 378 GB, 5 TB) | ~$400-600 (used) | Owned |
| Intel X540-AT2 10 GbE NIC (desktop) | ~$30-50 (used) | Owned |
| 10 GbE SFP+ cables + DAC | ~$15-30 | Owned |
| Quadro P400 | ~$30-50 (used) | Installed, not utilized |
| **Total hardware** | **~$475-730** | |

### Ongoing

| Item | Monthly Cost |
|------|-------------|
| Electricity (R630 idle ~200W) | ~$15-25 |
| Claude Max subscription | ~$100-200 |
| Internet (existing) | $0 (sunk cost) |
| Ollama / Qwen inference | $0 (local) |
| **Total monthly** | **~$115-225** |

### Comparison to Cloud AI Development

| Approach | Monthly Cost | Inference Limit |
|----------|-------------|-----------------|
| **Our approach** (local Ollama + Claude Max) | ~$115-225 | Unlimited local, session-limited Claude |
| OpenAI API (GPT-4 equivalent throughput) | $500-2,000+ | Pay per token |
| AWS Bedrock (Claude equivalent) | $300-1,500+ | Pay per token |
| GitHub Copilot Enterprise (per-seat) | $39/seat | Limited to completions |

---

## Timeline

| Time (EST) | Activity | Duration |
|------------|----------|----------|
| 00:30 | Session start, R630 hardware discovery via Proxmox API | 10 min |
| 00:40 | Network speed testing (ping, SSH, iperf3) | 20 min |
| 01:00 | DNS debugging (UCG refuses queries) | 5 min |
| 01:05 | Container planning and template downloads | 15 min |
| 01:20 | Create vmbr1 isolated bridge | 5 min |
| 01:25 | Create all 5 LXC containers in parallel | 10 min |
| 01:35 | SSH key auth debugging (Windows ↔ Proxmox) | 45 min |
| 02:20 | SSH config and passwordless access | 10 min |
| 02:30 | Range container internet access (NAT setup) | 15 min |
| 02:45 | Install services on scan targets (Apache, MySQL, httpd) | 15 min |
| 03:00 | Ollama installation (zstd dependency, download) | 20 min |
| 03:20 | Qwen 2.5 Coder 32B model pull (19 GB) | 10 min (117 MB/s) |
| 03:30 | Competitive analysis (StrongDM Attractor, Metaswarm) | 30 min |
| 04:00 | Dark Factory architecture design session | 45 min |
| 04:45 | First Qwen inference test (0.9 tok/s on CPU) | 5 min |
| 04:50 | Make infrastructure persistent (NAT, gateways, sysctl) | 10 min |
| 05:00 | Scanner-node setup (Python, git, nmap, connectivity) | 10 min |
| 05:10 | GPU assessment (Quadro P400, 2 GB — insufficient for 32B) | 5 min |
| 05:15 | 14B model pull initiated + build log documentation | ongoing |
| 05:20 | NVIDIA driver 550.163.01 install on PVE host | 15 min |
| 05:35 | GPU passthrough to factory-core (cgroup + bind mounts) | 10 min |
| 05:45 | Ollama GPU detection, inference: 0.9 → 1.1 tok/s | 5 min |
| 05:50 | 14B model pull complete, benchmark: 2.3 tok/s | 5 min |
| 05:55 | DonjonSec cloned to scanner-node via SCP | 5 min |
| 06:00 | Tech stack decision (FastAPI + HTMX + SQLite) | 5 min |
| 06:05 | Cloudflare Tunnel setup (factory.donjonsec.com) | 15 min |
| 06:20 | Factory Control Panel — backend code (6 routers, auth, DB) | 30 min |
| 06:50 | Factory Control Panel — templates (6 HTMX pages) | 15 min |
| 07:05 | Agent roster design (10 agents, concurrent background task) | 20 min |
| 07:25 | Seed agents into SQLite, deploy real app, systemd service | 10 min |
| 07:35 | Fix Jinja2 template bugs, verify end-to-end through tunnel | 5 min |

**Total active time**: ~7 hours
**Infrastructure from zero to operational**: ~3 hours (including 45 min SSH debugging)
**Factory Control Panel from zero to live**: ~1.5 hours

---

## Factory Control Panel (Deployed)

| Field | Value |
|-------|-------|
| **URL** | https://factory.donjonsec.com |
| **Tech Stack** | FastAPI 0.132.0 + HTMX 2.0.4 + Jinja2 + Tailwind CSS (CDN) + SQLite WAL |
| **Auth** | Session cookies (admin), API keys for agents (dfk_ prefix) |
| **Tunnel** | Cloudflare Tunnel (ID: 78738886-f0cb-43ed-8da5-21ba52e92190) |
| **Services** | `dark-factory.service` + `cloudflared.service` (both enabled at boot) |
| **Code** | `/opt/dark-factory/` on factory-core |
| **Venv** | `/opt/factory-venv/` (Python 3.13, Debian Trixie) |
| **Database** | `/opt/dark-factory/data/factory.db` |

### Dashboard Features
- Login page (terminal aesthetic, green-on-black)
- Stats grid: agents online, projects, tasks done, tokens used
- Agent roster cards with color-coded names, status dots, task counts
- Active projects with task progress bars
- Activity feed (audit log) with auto-refresh every 10s via HTMX
- Agent detail page with capability badges
- API endpoints for agent checkin, task management, LLM proxy

### Agent Roster (10 Agents, Seeded)

| # | ID | Name | Role | Model | Tier |
|---|-----|------|------|-------|------|
| 1 | lead | **Wraith** | Factory Orchestrator | Claude Opus | Frontier |
| 2 | coder-1 | **Cipher** | Primary Developer | Qwen 32B | Quality |
| 3 | coder-2 | **Jackal** | Secondary Developer | Qwen 14B | Speed |
| 4 | doc-1 | **Scribe** | Documentation Engineer | Qwen 14B | Speed |
| 5 | reviewer-1 | **Specter** | Adversarial Code Reviewer | Claude Opus | Frontier |
| 6 | security-1 | **Phantom** | Security Auditor | Claude Opus | Frontier |
| 7 | tester-1 | **Glitch** | Test Engineer | Qwen 32B | Quality |
| 8 | scout-1 | **Hawk** | Framework Scout | Claude Haiku | Lightweight |
| 9 | scout-2 | **Raven** | CVE Scout | Claude Haiku | Lightweight |
| 10 | scout-3 | **Oracle** | Standards Scout | Claude Haiku | Lightweight |

**Model Distribution**: 3 Claude Opus (architect/review/security), 2 Qwen 32B (complex coding/testing), 2 Qwen 14B (bulk coding/docs), 3 Claude Haiku (scouting/monitoring)

---

## What's Next

1. ~~**GPU Decision**~~: DONE — NVIDIA driver installed, GPU passthrough working, Quadro P400 gives 22% speedup
2. ~~**14B Model**~~: DONE — 2.3 tok/s, 2.1x faster than 32B
3. ~~**Clone DonjonSec to scanner-node**~~: DONE via SCP
4. ~~**Factory Control Panel**~~: DONE — live at factory.donjonsec.com
5. ~~**Build all 10 agents**~~: DONE — Wraith, Cipher, Jackal, Scribe, Specter, Phantom, Glitch, Hawk, Raven, Oracle
6. ~~**Phase 0 Product Validation**~~: DONE — see below
7. **Factory eats itself**: Submit the factory itself as the first project through the pipeline
8. **Business model**: DonjonAI — dark factory as a service, consulting on spec quality
9. **GPU upgrade**: Tesla T4 (16 GB, 70W, single-slot, $150-250) — fits R630 perfectly

---

## Phase 0: DonjonSec Product Validation (2026-02-24)

> Prerequisite gate: Before any project runs through the factory, the core product must be proven end-to-end.

### 0a. Test Suite — Linux (scanner-node, Debian 12, Python 3.11.2)

| Metric | Result |
|--------|--------|
| Tests collected | 137 |
| Tests passed | **137 (100%)** |
| Tests failed | 0 |
| Duration | 1.72s |
| Venv | `/opt/DonjonSec/venv` (created for PEP 668 compliance) |

```
tests/test_api_routes.py     — 14 passed (route registration, auth, key rotation)
tests/test_eula.py           —  6 passed (acceptance flow, empty-input, safe_input)
tests/test_production_ready.py — 82 passed (imports, paths, config, evidence, compliance)
tests/test_scanners.py       — 34 passed (17 import + 17 instantiation)
```

### 0a'. Test Suite — Windows (desktop, Windows 11, Python 3.13.5)

| Metric | Result |
|--------|--------|
| Tests collected | 137 |
| Tests passed | **137 (100%)** |
| Tests failed | 0 |
| Duration | 4.55s |

### 0b. Scanner Operations — Cyber Range

| Scanner | Target(s) | Type | Result |
|---------|-----------|------|--------|
| NetworkScanner | 10.10.10.20 (target-debian) | quick | 1 host, 22 ports discovered |
| NetworkScanner | 10.10.10.21 (target-ubuntu) | quick | 1 host, 22 ports discovered |
| NetworkScanner | 10.10.10.22 (target-rocky) | quick | 1 host, 22 ports discovered |
| ComplianceScanner | NIST-800-53 | full | 21 controls assessed, 8 recommendations |
| WebScanner | 10.10.10.20 | quick | Graceful error: `{"error": "Nikto not installed"}` |
| SSLScanner | 10.10.10.20 | quick | Graceful error: `{"error": "testssl.sh not installed"}` |

**Missing tools on scanner-node**: nikto, testssl.sh, nuclei (nmap only installed)
**Verdict**: Scanners that have dependencies correctly report errors without crashing. Network + compliance scanners fully functional.

### 0c. Web Dashboard & API

| Test | Method | Path | Result |
|------|--------|------|--------|
| Health (public) | GET | /api/v1/health | 200 — status: healthy, 14 modules active |
| EULA (public) | GET | /api/v1/legal/eula | 200 — version 1.5, 30,272 chars |
| Stats (protected, no key) | GET | /api/v1/stats | 401 — correctly rejected |
| Stats (protected, bad key) | GET | /api/v1/stats | 401 — correctly rejected |
| Stats (protected, valid key) | GET | /api/v1/stats | 200 — full stats returned |
| Scanners list | GET | /api/v1/scanners | 200 — 17 scanner types |
| License/tier | GET | /api/v1/license | 200 — community tier, limits shown |
| AI status | GET | /api/v1/ai/status | 200 — template backend ready |
| Network local | GET | /api/v1/network/local | 200 — hostname + 2 interfaces |
| Agent register (admin) | POST | /api/v1/agents/register | 201 — token generated |
| Agent checkin (correct token) | POST | /api/v1/agents/checkin | 200 — acknowledged |
| Agent checkin (wrong token) | POST | /api/v1/agents/checkin | 403 — correctly rejected |
| Key rotation | POST | /api/v1/auth/rotate | 200 — new key + 60s grace |
| Old key during grace | GET | /api/v1/stats | 200 — still accepted |

**Server**: Flask 3.1.3 on 0.0.0.0:8443, auth enabled

### 0d. Cross-Platform Verification

| Test | Platform | Result |
|------|----------|--------|
| `python bin/donjon-launcher --help` | Windows 11 | PASS — all 14 commands shown |
| `bash bin/donjon --help` | Windows 11 (Git Bash) | PASS (after fix) — all 6 commands shown |
| `python -m pytest tests/ -v` | Windows 11, Python 3.13.5 | PASS — 137/137 |

### Issues Found During Phase 0

#### Issue 13: Bash Launcher Uses Unix-Only Venv Paths on Windows

- **Symptom**: `bash bin/donjon --help` prints `[ERROR] /c/DonjonSec/venv/bin/pip: No such file or directory` on Windows Git Bash, then continues
- **Root cause**: Bootstrap section hardcodes `venv/bin/python3` and `venv/bin/pip` — Windows venvs use `venv/Scripts/python.exe` and `venv/Scripts/pip.exe`
- **Fix**: Added platform detection (`uname -s` check for MINGW/MSYS/CYGWIN) with `VENV_BIN`, `VENV_PYTHON`, `VENV_PIP` variables that resolve to correct paths per platform
- **Lines changed**: `bin/donjon:24-46`, `bin/donjon:49-88`
- **Verified**: `bash bin/donjon --help` now correctly uses `Scripts/python.exe` on Windows

#### Design Note: Agent Checkin Auth Model

- `/api/v1/agents/checkin` is NOT in PUBLIC_PATHS — requires API key + agent token
- This is intentional for factory architecture: the factory worker daemon has the API key and passes it with all agent submissions
- Remote agents without the API key cannot check in directly (they go through the factory API)

### Phase 0 Verdict: **PASS**

- 137/137 tests pass on both Linux and Windows
- Network scanner functional against all 3 cyber range targets
- Compliance scanner functional (21 controls, 8 recommendations)
- Web/SSL scanners degrade gracefully when dependencies missing
- API authentication enforced correctly (public/protected/admin paths)
- Agent registration + token verification working
- Key rotation with grace period working
- 1 bug found and fixed (bash launcher Windows paths)
- Proceeding to Phase 1: Factory Runtime

---

## Phase 1-5: Factory Runtime Build (2026-02-24)

### Phase 1: Ollama Worker Daemon

| File | Location | Lines |
|------|----------|-------|
| `worker.py` | factory-core `/opt/dark-factory/` | 231 |
| `dark-factory-worker.service` | factory-core `/etc/systemd/system/` | 18 |

**Architecture**: Single-threaded daemon polling DB every 5s for Ollama-agent tasks.
- Picks up tasks where `status='assigned'` and agent model is Ollama-based
- Calls Ollama `/api/generate` with agent system prompt + task description
- 600s timeout per task, graceful SIGTERM handling
- Updates task status, agent stats, audit log, and LLM request tracking
- Running as enabled systemd service: `dark-factory-worker.service`

**Bug found & fixed**: `sqlite3.Row` doesn't support `.get()` — must convert to `dict()` first.

**Live test**: Worker picked up task #1, called Ollama qwen2.5-coder:32b. Model loaded (22.5 GB Q4_K_M), actively generating at ~1.1 tok/s on CPU.

### Phase 2: Pipeline Manager

| File | Location | Lines |
|------|----------|-------|
| `pipeline.py` | factory-core `/opt/dark-factory/` | 280 |

**6-phase pipeline**: `planning` → `implement` → `validate` → `review` → `commit` → `done`

**DB migration**: Added 3 columns:
- `tasks.phase` (TEXT, default 'implement')
- `tasks.retry_count` (INTEGER, default 0)
- `projects.pipeline_phase` (TEXT, default 'planning')

**Verified flows**:
- Full pipeline: implement → validate → review(PASS) → commit → done ✓
- Review FAIL: Creates remediation tasks, loops back to implement ✓
- Escalation: After MAX_TASK_RETRIES (3), marks project as failed ✓
- Auto-advance: Skips empty phases, advances when all tasks complete ✓

### Phase 3: Pipeline API

| File | Location | Lines |
|------|----------|-------|
| `app/routers/pipeline.py` | factory-core `/opt/dark-factory/` | 92 |

**Endpoints**:
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/pipeline/{id}/decompose` | Submit Wraith's task list |
| GET | `/api/v1/pipeline/{id}/status` | Full pipeline status |
| POST | `/api/v1/pipeline/{id}/review` | Submit PASS/FAIL verdict |
| POST | `/api/v1/pipeline/{id}/advance` | Manual phase advancement |
| GET | `/api/v1/pipeline/pending-reviews` | Tasks waiting for Claude agents |

### Phase 4: Claude Agent Workspaces

| File | Location | Purpose |
|------|----------|---------|
| `workspaces/wraith/CLAUDE.md` | `C:\Darkfactory\` | Orchestrator: decomposition + git integration |
| `workspaces/specter/CLAUDE.md` | `C:\Darkfactory\` | Adversarial reviewer: binary PASS/FAIL |
| `workspaces/phantom/CLAUDE.md` | `C:\Darkfactory\` | Security auditor: CWE-referenced findings |

Each workspace defines: mission, rules, output format, API submission endpoints.

### Phase 5: Dashboard Updates

| File | Location | Changes |
|------|----------|---------|
| `app/templates/dashboard.html` | factory-core | Agent launch buttons, pipeline phase badges, pending tasks, "Needs Attention" |
| `app/templates/pipeline.html` | factory-core | New — visual pipeline with phase dots, task lists, expandable results |
| `app/routers/dashboard.py` | factory-core | Project detail page, HTMX activity feed, advance endpoint |
| `app/main.py` | factory-core | Pipeline router registration, auto-migration on startup |

### Issue 14: sqlite3.Row Doesn't Support .get()

- **Symptom**: Worker crashes with `'sqlite3.Row' object has no attribute 'get'`
- **Root cause**: `sqlite3.Row` supports `row["key"]` but not `row.get("key", default)`. Query results from `row_factory = sqlite3.Row` must be converted to dict for `.get()` support.
- **Fix**: Added `task = dict(task)` after fetching the row in `worker.py:poll_and_execute()`
- **Time to diagnose**: ~1 minute

### Services Running (2 + existing)

| Service | Status | Purpose |
|---------|--------|---------|
| `dark-factory.service` | active (enabled) | FastAPI control panel on :8000 |
| `dark-factory-worker.service` | active (enabled) | Ollama task execution daemon |
| `cloudflared.service` | active (enabled) | Tunnel to factory.donjonsec.com |
| `ollama.service` | active | Local LLM inference |

### Files Created/Modified This Session

| # | File | Action | Location |
|---|------|--------|----------|
| 1 | `worker.py` | CREATE | factory-core `/opt/dark-factory/` |
| 2 | `pipeline.py` | CREATE | factory-core `/opt/dark-factory/` |
| 3 | `app/routers/pipeline.py` | CREATE | factory-core `/opt/dark-factory/` |
| 4 | `app/main.py` | MODIFY | factory-core `/opt/dark-factory/` |
| 5 | `app/routers/dashboard.py` | MODIFY | factory-core `/opt/dark-factory/` |
| 6 | `app/templates/dashboard.html` | MODIFY | factory-core `/opt/dark-factory/` |
| 7 | `app/templates/pipeline.html` | CREATE | factory-core `/opt/dark-factory/` |
| 8 | `dark-factory-worker.service` | CREATE | factory-core `/etc/systemd/system/` |
| 9 | `workspaces/wraith/CLAUDE.md` | CREATE | desktop `C:\Darkfactory\` |
| 10 | `workspaces/specter/CLAUDE.md` | CREATE | desktop `C:\Darkfactory\` |
| 11 | `workspaces/phantom/CLAUDE.md` | CREATE | desktop `C:\Darkfactory\` |
| 12 | `bin/donjon` | MODIFY | desktop `C:\DonjonSec\` |

---

*This document is updated in real-time during the build process. Every claim is backed by actual command output, not aspirational planning.*
