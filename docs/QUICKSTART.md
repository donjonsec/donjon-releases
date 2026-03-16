# Donjon Platform v7.0 - Quick Start

Four deployment modes, one platform. Pick the one that fits your environment.

---

## Prerequisites (All Modes)

- **Python 3.10+** (3.11+ recommended)
- **4 GB RAM**, 1 GB disk
- **nmap** (recommended for network scanning)

---

## Mode 1: USB / Portable

No installation. No network. Plug in and scan.

**Step 1.** Copy the `donjon-platform/` directory to a USB drive (or receive a pre-loaded one).

**Step 2.** Plug the USB into the target machine.

**Step 3.** Launch the platform:

```bash
# Windows
E:\donjon-platform\START.bat

# Linux / macOS
python3 /media/USB_DRIVE/donjon-platform/bin/donjon-launcher
```

**Step 4.** Select option `4` (Quick Scan) from the interactive menu. The platform auto-detects local network ranges.

**Step 5.** View results in the terminal dashboard or `data/reports/`.

**Expected output:**

```
DONJON PLATFORM v7.0
Systems Thinking Security Assessment | Portable Mode

[*] Auto-detected network: 192.168.1.0/24
[*] Phase 1: Network Discovery    ... 12 hosts
[*] Phase 2: Vulnerability Scan   ... 47 ports checked
[*] Phase 3: Compliance Mapping   ... 10 frameworks
[+] Scan complete! Session: SESSION-20260316-143022
    CRITICAL: 1  HIGH: 4  MEDIUM: 8  LOW: 6  INFO: 4
```

> Portable mode automatically disables cloud scanning, defaults AI to the offline template backend, and stores all data in local SQLite.

---

## Mode 2: Docker

Production-ready stack with PostgreSQL, API server, and scheduler.

**Step 1.** Create a `.env` file in the project root:

```bash
POSTGRES_PASSWORD=your_secure_password_here
DONJON_API_KEYS=donjon_your_api_key_here
NVD_API_KEY=your_nvd_key          # optional, speeds up intel downloads
```

**Step 2.** Start the stack:

```bash
docker compose up -d
```

**Step 3.** Open the dashboard:

```
http://localhost:8443/
```

**Step 4.** Run a scan via API:

```bash
# Windows (PowerShell)
Invoke-RestMethod -Uri http://localhost:8443/api/v1/scans -Method POST `
  -Headers @{"X-API-Key"="donjon_your_api_key_here"; "Content-Type"="application/json"} `
  -Body '{"scan_type":"quick","targets":["192.168.1.0/24"]}'

# Linux / macOS
curl -X POST http://localhost:8443/api/v1/scans \
  -H "X-API-Key: donjon_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"quick","targets":["192.168.1.0/24"]}'
```

**Step 5.** Check scan status:

```bash
curl -H "X-API-Key: donjon_your_api_key_here" \
  http://localhost:8443/api/v1/scans
```

**Expected output:**

```json
{
  "count": 1,
  "sessions": [
    {
      "session_id": "SESSION-20260316-143022",
      "scan_type": "quick",
      "status": "running"
    }
  ]
}
```

> The Docker stack includes three containers: `donjon-postgres` (PostgreSQL 16), `donjon-api` (REST API on port 8443), and `donjon-scheduler` (background scan worker).

---

## Mode 3: Installed (pip)

Install into a Python virtual environment for command-line scanning.

**Step 1.** Clone or download the project:

```bash
git clone https://github.com/DonjonSec/donjon-platform.git
cd donjon-platform
```

**Step 2.** Create a virtual environment and install dependencies:

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Windows
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

**Step 3.** (Optional) Download threat intelligence data:

```bash
# Quick mode (~2 min): KEV + EPSS + 14-day NVD
python bin/update-intel.py --quick

# Full mode (~30 min with API key): all 7 sources
NVD_API_KEY=your-key python bin/update-intel.py --all
```

**Step 4.** Run a scan:

```bash
# Interactive menu
python bin/donjon-launcher

# Quick scan (headless)
python bin/donjon-launcher quick

# Standard assessment
python bin/donjon-launcher standard
```

**Step 5.** View results:

```bash
# Terminal dashboard
python bin/donjon-launcher dashboard

# Start the web dashboard + API
python bin/start-server.py
# Open http://localhost:8443/
```

---

## Mode 4: CI/CD Pipeline

Integrate Donjon into GitHub Actions, GitLab CI, or Jenkins.

**Step 1.** Add the platform to your repository:

```bash
git clone https://github.com/DonjonSec/donjon-platform.git .donjon
```

**Step 2.** Create `.github/workflows/security-scan.yml`:

```yaml
name: Donjon Security Scan
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Donjon
        run: |
          pip install -r .donjon/requirements.txt
          sudo apt-get install -y nmap

      - name: Run Security Scan
        run: |
          python .donjon/bin/donjon-launcher quick --output sarif
        env:
          DONJON_HEADLESS: "true"

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: data/reports/donjon-results.sarif

      - name: Security Gate
        run: |
          python .donjon/bin/donjon-launcher gate \
            --fail-on critical \
            --max-high 5
```

**Step 3.** Configure environment variables in your CI provider:

| Variable | Required | Purpose |
|---|---|---|
| `DONJON_HEADLESS` | Yes | Disables interactive prompts |
| `NVD_API_KEY` | No | Faster intel downloads |
| `DONJON_API_KEYS` | No | API authentication |

**Step 4.** Push and monitor the workflow.

**Step 5.** SARIF results appear in the GitHub Security tab under Code Scanning Alerts.

**Expected CI output:**

```
[Donjon] Headless mode: quick scan
[*] Scanning 3 targets...
[+] Scan complete: 7 findings (0 critical, 2 high, 3 medium, 2 low)
[+] SARIF report: data/reports/donjon-results.sarif
[+] Security gate: PASS (0 critical, 2 high <= 5 max)
```

---

## What to Do Next

| Task | Command |
|---|---|
| Configure your environment | Edit `config/active/config.yaml` |
| Download vulnerability intel | `python bin/update-intel.py --all` |
| Set up scheduled scans | API: `POST /api/v1/schedules` (Pro+) |
| Generate compliance reports | `python bin/donjon-launcher` > Compliance & Reports |
| View FAIR risk quantification | `python bin/donjon-launcher risk` |
| Compare scan sessions | `python bin/donjon-launcher delta` |

---

## Getting Help

```bash
python bin/donjon-launcher help          # CLI help
```

| Document | What It Covers |
|---|---|
| [SCANNER-GUIDE.md](SCANNER-GUIDE.md) | All 17 scanners with config and examples |
| [COMPLIANCE-GUIDE.md](COMPLIANCE-GUIDE.md) | 30 compliance frameworks |
| [API-REFERENCE.md](API-REFERENCE.md) | Complete REST API reference |
| [AIRGAP-DEPLOYMENT.md](AIRGAP-DEPLOYMENT.md) | Air-gapped / classified network deployment |
| [CONFIGURATION.md](CONFIGURATION.md) | Full config.yaml reference |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions |
