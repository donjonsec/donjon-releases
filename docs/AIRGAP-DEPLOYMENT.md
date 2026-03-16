# Donjon Platform v7.0 - Air-Gap Deployment Guide

Deploy Donjon on classified networks, SCIF environments, OT/ICS systems, and any network without internet connectivity. The platform is designed to operate fully offline with no degradation in scanning, compliance mapping, or reporting capabilities.

---

## Overview

Air-gapped deployment follows a three-phase process:

1. **Prepare** on a connected machine (download intel, create bundles)
2. **Transfer** via USB drive or data diode
3. **Deploy** on the air-gapped target

```
Connected Machine          Transfer Media          Air-Gapped Network
+------------------+       +-----------+       +--------------------+
| update-intel.py  | ----> |           | ----> | bundle-intel.py    |
| bundle-intel.py  |       | USB Drive |       |   import           |
|                  |       | or Diode  |       | donjon-launcher    |
+------------------+       +-----------+       +--------------------+
```

---

## Phase 1: Pre-Deployment (Connected Machine)

Perform these steps on a machine with internet access. This only needs to happen once for initial deployment, then periodically for intel updates.

### Step 1: Install the Platform

```bash
# Linux
git clone https://github.com/DonjonSec/donjon-platform.git
cd donjon-platform
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Windows
git clone https://github.com/DonjonSec/donjon-platform.git
cd donjon-platform
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Download Threat Intelligence

Download all 7 intelligence sources (803,000+ entries):

```bash
# Full download with NVD API key (recommended, ~30-60 minutes)
NVD_API_KEY=your-key python3 bin/update-intel.py --full

# Or without API key (~2-4 hours)
python3 bin/update-intel.py --full
```

This populates:

| Database | Contents | Typical Size |
|---|---|---|
| `data/vuln_intel.db` | 318,000+ NVD CVEs with CVSS scores | ~500 MB |
| `data/kev_catalog.json` | 1,500+ CISA Known Exploited Vulnerabilities | ~2 MB |
| `data/epss_cache.db` | 314,000+ EPSS exploit probability scores | ~50 MB |
| `data/intel_feeds.db` | ExploitDB, OSV, GitHub Advisories, MITRE ATT&CK, abuse.ch | ~200 MB |

### Step 3: Verify Intel Completeness

```bash
python3 bin/update-intel.py --status
```

Expected output:

```
  CISA KEV:
    Entries: 1,513
    Stale: False

  EPSS:
    Cached scores: 314,949
    Stale: False

  NVD (vuln_intel.db):
    CVEs cached: 318,225
    DB size: 487.3 MB

  Intel Feeds (intel_feeds.db):
    exploitdb: 30,215
    osv_vulns: 45,000+
    github_advisories: 12,000+
    cisa_alerts: 850+
    mitre_attack: 1,200+
    threat_indicators: 41,000+
```

### Step 4: Create the Intel Bundle

Package all intelligence data into a portable archive:

```bash
# Create bundle with all feed data
python3 bin/bundle-intel.py create /path/to/donjon-intel-bundle.tar.gz --include-feeds
```

Output:

```json
{
  "path": "/path/to/donjon-intel-bundle.tar.gz",
  "sha256": "a1b2c3d4e5f6...",
  "created_at": "2026-03-16T14:30:00+00:00",
  "feed_count": 47
}
```

**Record the SHA-256 hash.** You will use it to verify integrity after transfer.

### Step 5: Prepare the USB Drive

```bash
# Linux
DEST=/media/USB_DRIVE/donjon
mkdir -p $DEST
cp -r donjon-platform/ $DEST/donjon-platform/
cp /path/to/donjon-intel-bundle.tar.gz $DEST/

# Windows
set DEST=E:\donjon
mkdir %DEST%
xcopy /E /I donjon-platform\ %DEST%\donjon-platform\
copy donjon-intel-bundle.tar.gz %DEST%\
```

USB drive contents:

```
USB_DRIVE/
  donjon/
    donjon-platform/          # Full platform (code, config, tools)
    donjon-intel-bundle.tar.gz  # Intel bundle
```

---

## Phase 2: Transfer

### Standard USB Transfer

1. Physically transport the USB drive to the air-gapped environment
2. Follow your organization's media sanitization and import procedures
3. Scan the USB with the air-gapped network's malware scanning tools per policy

### Data Diode Transfer

For one-way data diode environments:

1. Place the `donjon-intel-bundle.tar.gz` and `donjon-platform/` directory in the diode's outbound queue
2. Verify transfer completion on the receiving side
3. The platform directory can be transferred as a tar archive for easier handling:

```bash
# On connected side
tar czf donjon-platform-full.tar.gz donjon-platform/

# On air-gapped side after transfer
tar xzf donjon-platform-full.tar.gz
```

---

## Phase 3: Deploy on Air-Gapped Target

### Step 1: Verify Transfer Integrity

```bash
# Linux
sha256sum /media/USB_DRIVE/donjon/donjon-intel-bundle.tar.gz

# Windows (PowerShell)
Get-FileHash E:\donjon\donjon-intel-bundle.tar.gz -Algorithm SHA256
```

Compare the output hash against the hash recorded during Phase 1 Step 4. If they do not match, do not proceed -- the bundle may be corrupted or tampered with.

### Step 2: Copy to Target System

```bash
# Linux
cp -r /media/USB_DRIVE/donjon/donjon-platform/ /opt/donjon/
cp /media/USB_DRIVE/donjon/donjon-intel-bundle.tar.gz /opt/donjon/

# Windows
xcopy /E /I E:\donjon\donjon-platform\ C:\donjon\donjon-platform\
copy E:\donjon\donjon-intel-bundle.tar.gz C:\donjon\
```

### Step 3: Install Python Dependencies (Offline)

If the air-gapped system does not have pip packages pre-installed, include them on the USB:

**On the connected machine (preparation):**

```bash
# Download wheels for offline install
pip download -r requirements.txt -d /media/USB_DRIVE/donjon/wheels/
```

**On the air-gapped system:**

```bash
# Linux
cd /opt/donjon/donjon-platform
python3 -m venv venv
source venv/bin/activate
pip install --no-index --find-links=/media/USB_DRIVE/donjon/wheels/ -r requirements.txt

# Windows
cd C:\donjon\donjon-platform
python -m venv venv
.\venv\Scripts\activate
pip install --no-index --find-links=E:\donjon\wheels\ -r requirements.txt
```

### Step 4: Import the Intel Bundle

```bash
# Linux
python3 bin/bundle-intel.py import /opt/donjon/donjon-intel-bundle.tar.gz --include-feeds

# Windows
python bin\bundle-intel.py import C:\donjon\donjon-intel-bundle.tar.gz --include-feeds
```

Verify the import:

```bash
python3 bin/update-intel.py --status
```

### Step 5: Run Your First Scan

```bash
# Linux
python3 bin/donjon-launcher quick

# Windows
python bin\donjon-launcher quick
```

The platform automatically detects air-gap mode (no internet connectivity) and:

- Disables cloud scanning (AWS/Azure/GCP)
- Defaults AI to the template backend (works offline, no LLM required)
- Uses local SQLite for all data storage
- Relies on the imported intel bundle for CVE/KEV/EPSS data

---

## Updating Intel Periodically

Threat intelligence goes stale. Establish a regular update cadence:

| Frequency | Use Case |
|---|---|
| Weekly | High-security environments, active threat hunting |
| Monthly | Standard compliance environments |
| Quarterly | Stable environments with low change rate |

### Update Procedure

**On the connected machine:**

```bash
# Incremental update (only new data since last run)
python3 bin/update-intel.py --all

# Create a fresh bundle
python3 bin/bundle-intel.py create /path/to/donjon-intel-$(date +%Y%m%d).tar.gz --include-feeds
```

**Transfer and import on the air-gapped system** following the same USB/diode transfer process. The import is additive -- new data merges with existing data without losing historical records.

### Checking Freshness

Run this on the air-gapped system to check if intel needs updating:

```bash
python3 bin/update-intel.py --check
```

Exit code 0 means all data is fresh. Exit code 1 means at least one source is stale. Thresholds: NVD >24h, KEV >48h, feeds >72h.

---

## Security Considerations

### Transfer Media

- Use dedicated, encrypted USB drives for Donjon transfers
- Sanitize USB drives before and after each transfer per your organization's policy
- Label drives clearly with classification level and contents
- Maintain a chain-of-custody log for media entering classified environments

### Platform Security

- The platform stores scan results and evidence in `data/evidence/evidence.db` -- this database contains sensitive vulnerability information about your network. Protect it accordingly
- In portable/USB mode, no credentials are written to the drive (cloud credentials, API keys are held in memory only)
- The license file (`data/license.json`) is cryptographically signed with dual ML-DSA-65 (post-quantum) + Ed25519 signatures. Tampering with the license file causes validation failure
- All scanning requires explicit user initiation -- there are no automatic outbound connections

### Data Classification

Consider the classification level of scan results. Donjon findings reveal:

- Network topology and open services
- Software versions and known vulnerabilities
- Configuration weaknesses
- Compliance posture gaps

Treat exported reports at the same classification level as the network being scanned.

### Integrity Verification

Verify platform integrity after transfer:

```bash
# Generate integrity manifest (first run on trusted copy)
python3 -c "from lib.integrity import generate_manifest; generate_manifest(['lib.licensing', 'lib.compliance', 'lib.evidence', 'scanners.base'])"

# Verify on air-gapped system (compares module hashes against manifest)
python3 -c "from lib.integrity import verify_manifest; verify_manifest()"
```

### AI Backend in Air-Gap Mode

The default `template` AI backend works fully offline using Python-based analysis templates. No LLM is required. If you need LLM-powered analysis in an air-gapped environment:

1. Install Ollama on the air-gapped system
2. Transfer model weights via USB (GGUF files, typically 4-30 GB)
3. Configure Donjon to use the local Ollama instance:

```yaml
# config/active/config.yaml
ai:
  provider: 'ollama'
  ollama_url: 'http://localhost:11434'
  model: 'qwen2.5-coder:14b'
  sanitize_external: false     # not needed for local LLM
```

---

## Quick Reference

| Task | Command |
|---|---|
| Download all intel | `python3 bin/update-intel.py --full` |
| Create intel bundle | `python3 bin/bundle-intel.py create OUTPUT.tar.gz --include-feeds` |
| Import intel bundle | `python3 bin/bundle-intel.py import BUNDLE.tar.gz --include-feeds` |
| List available bundles | `python3 bin/bundle-intel.py list` |
| Check intel freshness | `python3 bin/update-intel.py --check` |
| Show intel status | `python3 bin/update-intel.py --status` |
| Quick scan | `python3 bin/donjon-launcher quick` |
| Start web dashboard | `python3 bin/start-server.py` |
| Export results | `python3 bin/donjon-launcher` > Compliance & Reports > Export |

---

## Troubleshooting

**"NVD cache is empty" after import:**
The intel bundle contains feed data but NVD CVE data is stored in `data/vuln_intel.db`. Ensure this file was included on the USB drive alongside the bundle. The NVD database is a separate SQLite file, not part of the tar.gz bundle.

**"Module not found" errors:**
Python dependencies were not installed. Follow Step 3 in Phase 3 to install from offline wheels.

**Scan finds no hosts:**
Ensure nmap is installed on the air-gapped system. Without nmap, the platform uses TCP connect scanning which may miss hosts behind firewalls. Install nmap from your organization's approved software repository.

**Low vulnerability detection count:**
Import the intel bundle with `--include-feeds` flag. Without feeds, the platform has CVE data but lacks exploit cross-references from ExploitDB, Nuclei, and Metasploit.
