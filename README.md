<p align="center">
  <img src="https://img.shields.io/badge/version-7.3.0-blue?style=for-the-badge" alt="Version 7.3.0">
  <img src="https://img.shields.io/badge/tests-168%20passing-brightgreen?style=for-the-badge" alt="168 Tests Passing">
  <img src="https://img.shields.io/badge/security-red%20team%20validated-darkgreen?style=for-the-badge" alt="Red Team Validated">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-Proprietary%20EULA-lightgrey?style=for-the-badge" alt="License">
</p>

# Donjon Platform

**Enterprise security assessment, compliance mapping, risk quantification, and AI-powered analysis — in a single platform.**

Donjon replaces $110K+/yr in commercial tooling (Tenable, Qualys, RiskLens, Drata) with 17 security scanners, 30 compliance frameworks, FAIR risk quantification, and post-quantum secure licensing. Deployable from a USB drive, Docker, pip install, or CI/CD pipeline. Air-gap ready. Government contractor tested.

> **License:** Proprietary EULA. See [LICENSE](LICENSE) for terms.

---

## Why Donjon

| What You Get | The Alternative |
|---|---|
| 19 scanners in one platform | Tenable ($65K) + Qualys ($30K) + Rapid7 ($25K) |
| 30 compliance frameworks | Drata ($10K) + manual mapping |
| FAIR risk quantification with Monte Carlo | RiskLens ($50K/yr) |
| AI-powered analysis (6 providers) | Manual analyst hours |
| USB-portable, air-gap ready | Cloud-only SaaS with no offline mode |
| Post-quantum secure licensing | Standard license keys |
| **One platform, one price** | **$110K+/yr in subscriptions** |

---

## Quick Start

```bash
# Option 1: One-click launch
./bin/donjon-launcher          # Linux/macOS
START.bat                      # Windows

# Option 2: Docker
docker compose up -d
# Dashboard: http://localhost:8443

# Option 3: pip install + scan
pip install -e .
donjon-scan 192.168.1.0/24

# Option 4: CI/CD
python3 bin/donjon-launcher quick --output sarif
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for detailed setup across all 4 deployment modes.

---

## Capabilities

### 17 Security Scanners

| Scanner | What It Does | Tier |
|---|---|---|
| Network | TCP/UDP port scanning, service detection, OS fingerprinting | Community |
| Vulnerability | CVE-based detection with CVSS/EPSS/KEV correlation | Community |
| Web Application | OWASP Top 10, XSS, SQLi, CSRF, header analysis | Community |
| SSL/TLS | Certificate validation, cipher suite analysis, protocol checks | Community |
| Windows | Registry, services, firewall, BitLocker, patch compliance | Community |
| Linux | SSH config, file permissions, kernel params, PAM, services | Community |
| Compliance | Framework-specific control validation | Community |
| Active Directory | GPO, Kerberos, delegation, privileged groups, trusts | Pro |
| Cloud (AWS/Azure/GCP) | IAM, S3/Blob, security groups, logging, encryption | Pro |
| Container | Docker/K8s config, image vulnerabilities, runtime security | Pro |
| SBOM | Software bill of materials with vulnerability correlation | Pro |
| Credential | Leaked credential detection across services | Pro |
| ASM | Attack surface mapping, subdomain discovery, exposed services | Pro |
| OpenVAS | Integration with OpenVAS/GVM vulnerability scanner | Pro |
| Malware | Signature + heuristic + YARA rule malware detection | Pro |
| Shadow AI | Unauthorized LLMs, AI browser extensions, API keys, model files | Pro |
| Adversary Simulation | MITRE ATT&CK-aligned purple team exercises | Pro |

### 30 Compliance Frameworks

NIST 800-53 Rev 5, NIST CSF 2.0, HIPAA, PCI-DSS v4.0, ISO 27001:2022, SOC 1 Type II, SOC 2 Type II, CMMC Level 1-3, FedRAMP (Low/Moderate/High), CIS Controls v8, GDPR, CCPA, SOX, HITRUST CSF, DORA, NIS2, ISO 27701, NIST 800-171, NIST AI RMF, EU AI Act, CSA CCM, FFIEC, GLBA, NERC CIP, IEC 62443, SWIFT CSCF, COBIT 2019, ITIL 4, FISMA, and Essential Eight.

### AI-Powered Analysis

6-provider fallback chain with automatic failover:

1. **Ollama** (local, private) — run your own LLM, zero data leaves the network
2. **StepFun** — Step 3.5 Flash for fast analysis
3. **Anthropic** — Claude for deep reasoning
4. **Google** — Gemini for broad analysis
5. **OpenAI** — GPT-4 for comprehensive reports
6. **Template** (always available) — structured analysis with no LLM needed

Infrastructure details are automatically sanitized before external API calls.

### Risk Quantification

FAIR taxonomy with Monte Carlo simulation (10,000 iterations), dollar-quantified Annual Loss Expectancy (ALE), EPSS/KEV/CVSS correlation, and industry benchmarks from IBM/Ponemon.

---

## Licensing

| Feature | Community | Pro | Enterprise | Managed (MSSP) |
|---|:---:|:---:|:---:|:---:|
| Core scanners (7) | Yes | Yes | Yes | Yes |
| Advanced scanners (10) | — | Yes | Yes | Yes |
| Scan depths | Quick, Standard | All | All | All |
| Targets per scan | 16 | Unlimited | Unlimited | Unlimited |
| Export formats | CSV, JSON | + HTML, PDF, SARIF, XML | All | All |
| Compliance frameworks | 3 | 30 | 30 | 30 |
| AI queries/day | 10 | Unlimited | Unlimited | Unlimited |
| Scheduled scans | — | Yes | Yes | Yes |
| Users | 1 | 25 | Unlimited | Unlimited |
| SSO / RBAC | — | — | Yes | Yes |
| Multi-tenant | — | — | Yes | Yes |
| MSSP client management | — | — | — | Yes |
| Bulk scan orchestration | — | — | — | Yes |
| Cross-client reporting | — | — | — | Yes |

Community tier works with no license file. Paid tiers activate via a signed `data/license.json` using dual ML-DSA-65 + Ed25519 post-quantum signatures.

---

## Security Posture

Donjon is a security product held to security-product standards.

**v7.2.0 was validated by a blind red team penetration test** — an isolated agent with no knowledge of the codebase attempted to exploit 31 attack vectors including license forgery, tier bypass, SSRF, auth brute force, path traversal, SQL injection, and revocation bypass. **Zero exploits succeeded.**

| Area | Protection |
|---|---|
| License verification | Dual ML-DSA-65 (NIST FIPS 204) + Ed25519 signatures |
| API authentication | HMAC-based key comparison, rate limiting (429 after 10 failures) |
| SSRF prevention | CIDR validation (RFC-1918 only), link-local/metadata endpoint blocked |
| TLS integrity | Never silently downgrades — explicit opt-in required for skip |
| Tier enforcement | Defense-in-depth: dispatch-level + handler-level + scanner-level |
| Evidence storage | Recommended encryption at rest, permission checks at startup |
| Air-gap mode | `DONJON_OFFLINE=1` blocks all outbound network calls |
| Credential handling | Fernet symmetric encryption, never stored in USB portable mode |
| LLM data safety | Infrastructure details stripped before external API calls |

To report a vulnerability: [docs/SECURITY.md](docs/SECURITY.md)

---

## Vulnerability Intelligence

7 sources aggregated into a local database for offline use:

| Source | What It Provides |
|---|---|
| NVD (NIST) | 327,000+ CVEs with CVSS scores, CWE mappings, affected products |
| EPSS (FIRST.org) | Exploit probability predictions for every CVE |
| CISA KEV | Known actively exploited vulnerabilities |
| CISA Vulnrichment | SSVC triage decisions (Act / Attend / Track) |
| Exploit-DB | CVE-to-public-exploit cross-references |
| Nuclei Templates | CVE-to-detection-template mappings |
| Metasploit | CVE-to-Metasploit-module mappings |

```bash
# Quick update (~2 min)
python3 bin/update-intel.py --quick

# Full update (~2 hrs with API key)
NVD_API_KEY=your-key python3 bin/update-intel.py --full

# Check status
python3 bin/update-intel.py --status
```

Free NVD API key: [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

---

## Platform Requirements

| Requirement | Details |
|---|---|
| Python | 3.10+ (3.12+ recommended) |
| RAM | 4 GB minimum |
| Disk | 1 GB (100 MB base + up to 800 MB for vulnerability DB) |
| OS | Windows 11, Linux (any modern distro), macOS |

### Optional External Tools

All scanners gracefully degrade when external tools are unavailable.

| Tool | Purpose | Tool | Purpose |
|---|---|---|---|
| nmap | Network scanning | trivy | Container/SBOM |
| nikto | Web scanning | amass | DNS enumeration |
| nuclei | Vuln scanning | docker/podman | Container scanning |
| testssl.sh | SSL assessment | aws/az/gcloud | Cloud scanning |

---

## Documentation

| Guide | Description |
|---|---|
| **[QUICKSTART](docs/QUICKSTART.md)** | 4 deployment modes in 5 minutes each |
| **[SCANNER-GUIDE](docs/SCANNER-GUIDE.md)** | All 17 scanners with config and examples |
| **[COMPLIANCE-GUIDE](docs/COMPLIANCE-GUIDE.md)** | 30 frameworks with mapping details |
| **[API-REFERENCE](docs/API-REFERENCE.md)** | 50+ REST endpoints with curl examples |
| **[AIRGAP-DEPLOYMENT](docs/AIRGAP-DEPLOYMENT.md)** | Classified network deployment guide |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Platform architecture and data flow |
| [SECURITY](docs/SECURITY.md) | Cryptographic design and security model |
| [CONFIGURATION](docs/CONFIGURATION.md) | Complete config.yaml reference |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | Windows, Linux, Docker, air-gap setup |
| [CLI-REFERENCE](docs/CLI-REFERENCE.md) | Command-line interface reference |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) | Common issues and solutions |

---

## Configuration

```yaml
# config/active/config.yaml
ai:
  provider: 'template'           # template | ollama | openai | anthropic | gemini | stepfun
  sanitize_external: true        # Strip IPs/hostnames for external LLMs

risk:
  industry: 'technology'         # Maps to IBM/Ponemon benchmarks
  monte_carlo_iterations: 10000

compliance:
  frameworks:
    - 'NIST-800-53'
    - 'HIPAA'
    - 'PCI-DSS-v4'

cicd:
  security_gate:
    fail_on_critical: true
    max_high: 5
```

---

<p align="center">
  <strong>Donjon Platform v7.3.0</strong> — DonjonSec
  <br>
  <a href="https://donjonsec.com">donjonsec.com</a>
</p>
