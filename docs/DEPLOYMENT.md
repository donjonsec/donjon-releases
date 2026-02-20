# Donjon Platform v7.0 -- Deployment Guide

This document covers all deployment methods: Windows, Linux/macOS, Docker, and air-gapped USB.

---

## Deployment Modes

The platform automatically detects its deployment context and adjusts features:

| Mode | Detection | Cloud Scanning | AI | TUI | SARIF |
|---|---|---|---|---|---|
| **Portable (USB)** | Removable media detected | Disabled | Template only | Full | Yes |
| **Installed (Fixed)** | Default (no USB, no CI env) | All providers | All backends | Full | Yes |
| **CI/CD** | `GITHUB_ACTIONS`, `GITLAB_CI`, or similar env vars | All providers | All backends | Headless | Yes |
| **Docker** | Container environment | All providers (PostgreSQL backend) | All backends | API only | Yes |

---

## Windows Deployment

### One-Click Start (Recommended)

Double-click `START.bat` in the project root. It calls `bin\donjon-launcher.bat`, which:

1. Checks for Python 3.10+
2. Creates a virtual environment (`venv/`) if it does not exist
3. Installs dependencies from `requirements.txt`
4. Launches the TUI launcher

```cmd
REM From the project directory
.\START.bat

REM Or directly
.\bin\donjon-launcher.bat
```

### PowerShell Launcher

```powershell
.\bin\donjon-launcher.ps1
```

The PowerShell launcher provides the same functionality with better terminal handling on Windows Terminal.

### Manual Setup

```cmd
REM 1. Create virtual environment
python -m venv venv
.\venv\Scripts\activate

REM 2. Install dependencies
pip install -r requirements.txt

REM 3. (Optional) Populate vulnerability intelligence
python bin\update-intel.py --quick

REM 4. Launch TUI
python bin\donjon-launcher

REM Or launch web API server
python bin\start-server.py
```

### Windows Setup Script

```cmd
.\bin\setup-windows.bat
```

This script automates the manual steps above: creates the virtual environment, installs dependencies, and verifies the installation.

### Web Server on Windows

```cmd
REM Start the REST API + dashboard
python bin\start-server.py

REM Custom port and no authentication (development)
python bin\start-server.py --port 9090 --no-auth

REM Generate an API key
python bin\start-server.py --generate-key
```

The server binds to `0.0.0.0:8443` by default. Access the dashboard at `http://localhost:8443/`.

---

## Linux / macOS Deployment

### Setup Script

```bash
# Full setup: creates venv, installs deps, creates data dirs
./bin/setup.sh

# Then launch
python3 bin/donjon-launcher
```

### Manual Setup

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Populate vulnerability intelligence
python3 bin/update-intel.py --quick

# 4. Launch TUI
python3 bin/donjon-launcher

# Or launch web API server
python3 bin/start-server.py
```

### CLI Entry Point

```bash
# Direct CLI access
./bin/donjon

# Or via the donjon launcher
./bin/donjon-launcher
```

### Install Script (System-Wide)

```bash
# Install to /opt/donjon with systemd service
sudo ./bin/install.sh
```

### Web Server as a Service

```bash
# Start the API server
python3 bin/start-server.py --host 0.0.0.0 --port 8443

# With API key authentication
export DONJON_API_KEYS=your-generated-key
python3 bin/start-server.py

# Force stdlib mode (skip Flask even if installed)
python3 bin/start-server.py --stdlib
```

### Background Scheduler

```bash
# Run the background scan scheduler
python3 bin/run-worker.py

# Or use the cron-like scheduler
python3 bin/scheduler.py
```

---

## Docker Deployment

### Production Stack (docker-compose)

The `docker-compose.yml` defines three services:

| Service | Purpose | Port |
|---|---|---|
| `postgres` | PostgreSQL 16 database | 5432 |
| `api` | REST API + web dashboard | 8443 |
| `scheduler` | Background scan scheduler | -- |

```bash
# Start the full stack
docker compose up -d

# View logs
docker compose logs -f api

# Stop
docker compose down
```

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required
POSTGRES_PASSWORD=your_secure_password

# Optional
DONJON_API_KEYS=your-api-key-1,your-api-key-2
NVD_API_KEY=your-nvd-api-key

# AI provider keys (pick one or more)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIza...
STEPFUN_API_KEY=...
```

### Docker Build Targets

The multi-stage Dockerfile provides three build targets:

```bash
# API server only
docker build --target api -t donjon-api .

# Background worker only
docker build --target worker -t donjon-worker .

# Scanner (interactive or non-interactive)
docker build --target scanner -t donjon-scanner .

# Run a one-off scan in a container
docker run --rm donjon-scanner python /app/bin/donjon-launcher --non-interactive
```

### Volumes

| Mount | Container Path | Purpose |
|---|---|---|
| `./data` | `/app/data` | Scan data, evidence, reports, intelligence DB |
| `./tools` | `/app/tools` | External scanning tools |
| `./config` | `/app/config` | Configuration files |
| `pgdata` (Docker volume) | `/var/lib/postgresql/data` | PostgreSQL data |

### Health Check

The API container includes a health check:

```bash
curl -f http://localhost:8443/api/v1/health
```

Returns `200 OK` with module availability when healthy.

---

## Air-Gapped USB Deployment

Donjon is designed to run from a USB drive with zero network connectivity.

### Preparation (Connected Machine)

1. **Clone or download** the repository to a USB drive
2. **Create the virtual environment** on the target platform:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```
3. **Pre-populate intelligence** (optional but recommended):
   ```bash
   python3 bin/update-intel.py --quick
   ```
4. **Bundle external tools** (optional):
   ```bash
   python3 bin/bundle-tools.py
   ```
   This copies nmap, nuclei, testssl, and other tools into `tools/` for portable use.

### Usage on Target Machine

```bash
# Linux/macOS
python3 /media/USB_DRIVE/donjon-platform/bin/donjon-launcher

# Windows (double-click START.bat on the USB drive)
E:\donjon-platform\START.bat
```

### Air-Gap Behavior

When USB/portable mode is detected:
- Cloud scanning is disabled (no cloud credentials on removable media)
- AI defaults to template backend (no external API calls)
- All data stored locally on the USB drive
- Path resolution adjusts to use the USB mount point as the project root
- Vulnerability intelligence uses pre-populated local data

### License Activation (Air-Gapped)

1. Run the platform once to generate the machine fingerprint (displayed in the TUI or via `GET /api/v1/license`)
2. On a connected machine, use the license admin tool to create a machine-bound license:
   ```bash
   python3 tools/donjon-license-admin.py generate \
     --tier pro \
     --org "Acme Corp" \
     --fingerprint "sha256:abc123..."
   ```
3. Copy the generated `license.json` to `data/license.json` on the USB drive
4. The platform will verify the license offline on next launch

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DONJON_DB_BACKEND` | `sqlite` | Database backend: `sqlite` or `postgres` |
| `DONJON_DB_URL` | -- | PostgreSQL connection URL (required when backend is `postgres`) |
| `DONJON_API_KEYS` | -- | Comma-separated API keys for authentication |
| `DONJON_HOME` | auto-detected | Override the project root directory |
| `NVD_API_KEY` | -- | NIST NVD API key for faster intelligence downloads |
| `ANTHROPIC_API_KEY` | -- | Anthropic Claude API key |
| `OPENAI_API_KEY` | -- | OpenAI API key |
| `GEMINI_API_KEY` | -- | Google Gemini API key |
| `STEPFUN_API_KEY` | -- | StepFun Step 3.5 Flash API key |
| `OPENROUTER_API_KEY` | -- | OpenRouter API key (StepFun fallback) |
| `ABUSECH_API_KEY` | -- | abuse.ch URLhaus + ThreatFox API key (free: https://auth.abuse.ch/) |

---

## Configuration Files

| File | Location | Purpose |
|---|---|---|
| `config/active/config.yaml` | Main config | Platform settings: scanning, compliance, AI, risk, cloud, etc. |
| `data/ai_config.json` | Auto-created | Persisted AI backend selection |
| `data/license.json` | Manual | License file for paid tiers |
| `data/revoked.json` | Manual/auto | License revocation list |
| `data/ai_quota.json` | Auto-created | Daily AI query usage counter |
| `.env` | Project root | Docker Compose environment variables |

See [CONFIGURATION.md](CONFIGURATION.md) for the complete `config.yaml` reference.

---

## First-Run Auto-Setup Behavior

On first launch, the platform automatically:

1. **Creates directory structure**: `data/`, `data/evidence/`, `data/results/`, `data/logs/`, `data/reports/`, `data/archives/`
2. **Initializes databases**: SQLite `.db` files created in `data/` with proper schema
3. **Detects deployment mode**: USB portable, fixed installation, CI/CD, or Docker
4. **Detects available tools**: Scans PATH and `tools/` for nmap, nuclei, nikto, testssl, trivy, amass, docker/podman, cloud CLIs
5. **Probes AI backends**: Checks for local Ollama, then API keys in environment variables
6. **Loads license**: Reads `data/license.json` if present; defaults to Community tier if not
7. **Generates API key**: If no `DONJON_API_KEYS` is set, generates and displays a key on first web server start

No manual configuration is required for basic operation. The platform is functional immediately after `pip install -r requirements.txt`.

---

## Upgrade Path

### From v6.x

1. Back up the `data/` directory
2. Pull or copy the v7.0 code
3. Re-run `pip install -r requirements.txt` (new dependencies for AI, PQC, etc.)
4. The existing SQLite databases are compatible; no migration needed
5. New features (AI, risk quantification, container/cloud scanning) activate automatically

### SQLite to PostgreSQL Migration

```bash
# Set up PostgreSQL target
export DONJON_DB_URL=postgresql://donjon:password@localhost:5432/donjon

# Run the migration tool
python3 bin/migrate-db.py

# Switch the platform to PostgreSQL
export DONJON_DB_BACKEND=postgres
```

The migration tool reads all `.db` files from `data/` and copies tables and rows to PostgreSQL.

---

## Port Reference

| Service | Default Port | Configurable Via |
|---|---|---|
| Web API + Dashboard | 8443 | `--port` flag or Docker mapping |
| PostgreSQL | 5432 | `docker-compose.yml` |
| Ollama | 11434 | Ollama configuration |
