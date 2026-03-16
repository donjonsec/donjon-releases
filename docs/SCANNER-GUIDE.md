# Donjon Platform v7.0 - Scanner Guide

17 built-in scanners covering network infrastructure, applications, cloud, compliance, and emerging threats. Each scanner maps findings to compliance frameworks, enriches with threat intelligence (CISA KEV, EPSS), and assigns Quality of Detection (QoD) scores.

---

## Scanner Tier Requirements

| Scanner | ID | Tier | External Tool |
|---|---|---|---|
| Network Scanner | `network` | Community | nmap (recommended) |
| Vulnerability Scanner | `vulnerability` | Community | nuclei (optional) |
| Web Application Scanner | `web` | Community | nikto (optional) |
| SSL/TLS Scanner | `ssl` | Community | testssl.sh (optional) |
| Windows Security Scanner | `windows` | Community | -- |
| Linux Security Scanner | `linux` | Community | -- |
| Compliance Scanner | `compliance` | Community | -- |
| Active Directory Scanner | `ad` | Pro | -- |
| Cloud Security Scanner | `cloud` | Pro | aws/az/gcloud CLI |
| Container Scanner | `container` | Pro | docker/podman, trivy |
| SBOM Scanner | `sbom` | Pro | -- |
| Attack Surface Scanner | `asm` | Pro | amass (optional) |
| Credential Scanner | `credential` | Pro | -- |
| OpenVAS Integration | `openvas` | Pro | OpenVAS/GVM |
| Malware Scanner | `malware` | Pro | ClamAV (optional) |
| Shadow AI Scanner | `shadow_ai` | Pro | -- |
| Full Scan Suite | `full` | Community* | All of the above |

*Full Scan Suite runs all scanners available at your tier.

**Scan depths** (all scanners): `quick` (fastest, top ports/checks only), `standard` (balanced), `deep` (exhaustive, Pro+ only).

---

## 1. Network Scanner

**What it does.** Discovers hosts on the network via ARP/ICMP/TCP probes, then performs TCP/UDP port scanning with service detection and OS fingerprinting. Identifies open ports, running services, and potential network-level exposures.

**Prerequisites.** nmap recommended (gracefully degrades without it). No special privileges required for basic TCP scanning; root/admin needed for SYN scans and OS detection.

**Config options (`config/active/config.yaml`):**

```yaml
scanners:
  network:
    ports_quick: "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5432,5900,8080,8443"
    ports_standard: "--top-ports 1000"
    ports_deep: "1-65535"
    scan_delay: [1.0, 3.0]      # human-paced delay range (seconds)
    os_detection: true
    service_version: true
```

**Example command:**

```bash
# Windows
python bin\donjon-launcher quick --scanner network --targets 192.168.1.0/24

# Linux
python3 bin/donjon-launcher quick --scanner network --targets 192.168.1.0/24
```

**Framework mappings:** NIST 800-53 (CM-7, SC-7), PCI-DSS v4 (1.1, 6.2), ISO 27001 (A.13.1), HIPAA (164.312(e)(1)), CIS Benchmarks

---

## 2. Vulnerability Scanner

**What it does.** Detects known vulnerabilities (CVEs) on discovered services using banner analysis, version matching, and optional Nuclei template scanning. Correlates findings with NVD CVSS scores, CISA KEV status, and EPSS exploit probability.

**Prerequisites.** Nuclei templates optional but recommended for deeper detection. NVD data downloaded via `update-intel.py` enables offline CVE lookup.

**Config options:**

```yaml
scanners:
  vulnerability:
    use_nuclei: true
    severity_threshold: "medium"    # minimum severity to report
    max_cves_per_host: 100
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner vulnerability --targets 10.0.0.5
```

**Framework mappings:** NIST 800-53 (RA-5, SI-2), PCI-DSS v4 (6.3, 11.3), ISO 27001 (A.12.6), HIPAA (164.308(a)(1)), SOC2 (CC7.1)

---

## 3. Web Application Scanner

**What it does.** Tests web applications for OWASP Top 10 vulnerabilities including SQL injection, XSS, directory traversal, insecure headers, and exposed sensitive files. Analyzes HTTP security headers (CSP, HSTS, X-Frame-Options).

**Prerequisites.** nikto optional for extended checks. Target must be an HTTP/HTTPS endpoint.

**Config options:**

```yaml
scanners:
  web:
    check_headers: true
    check_directories: true
    check_sqli: true
    check_xss: true
    user_agent: "Donjon/7.0 Security Scanner"
    max_urls: 500
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner web --targets https://app.example.com
```

**Framework mappings:** NIST 800-53 (SI-10, SC-8), PCI-DSS v4 (6.2, 6.4), OWASP Top 10, ISO 27001 (A.14.2), HIPAA (164.312(e)(1))

---

## 4. SSL/TLS Scanner

**What it does.** Validates SSL/TLS certificates (expiry, chain, SANs), analyzes cipher suite strength, checks protocol versions (SSLv3 through TLS 1.3), and detects known weaknesses (BEAST, POODLE, Heartbleed exposure indicators).

**Prerequisites.** testssl.sh optional (Linux/macOS only) for comprehensive assessment. Built-in Python SSL checks work on all platforms.

**Config options:**

```yaml
scanners:
  ssl:
    check_cert_expiry_days: 30     # warn if cert expires within N days
    require_tls_1_2: true
    reject_weak_ciphers: true
```

**Example command:**

```bash
python3 bin/donjon-launcher quick --scanner ssl --targets example.com:443
```

**Framework mappings:** NIST 800-53 (SC-8, SC-12, SC-13), PCI-DSS v4 (2.2.7, 4.1), ISO 27001 (A.10.1), HIPAA (164.312(e)(1))

---

## 5. Windows Security Scanner

**What it does.** Audits Windows system configuration including patch levels, local user/group enumeration, password policy, firewall status, antivirus state, Windows Defender settings, and Group Policy hardening. Runs locally on the Windows host being assessed.

**Prerequisites.** Must run on a Windows system. Some checks require Administrator privileges.

**Config options:**

```yaml
scanners:
  windows:
    check_updates: true
    check_firewall: true
    check_defender: true
    check_users: true
    check_shares: true
```

**Example command:**

```bash
# Run on the Windows machine being assessed
python bin\donjon-launcher standard --scanner windows
```

**Framework mappings:** NIST 800-53 (CM-6, SI-2, AC-2), CIS Windows Benchmarks, PCI-DSS v4 (2.2, 6.3), ISO 27001 (A.12.1, A.12.6), CMMC (CM.2.064)

---

## 6. Linux Security Scanner

**What it does.** Audits Linux system hardening including SSH configuration, file permissions on sensitive files, running services, kernel parameters, user accounts, sudo configuration, and package update status. Checks against CIS Linux Benchmarks.

**Prerequisites.** Must run on a Linux system. Root access recommended for full checks.

**Config options:**

```yaml
scanners:
  linux:
    check_ssh_config: true
    check_file_permissions: true
    check_services: true
    check_kernel_params: true
    check_users: true
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner linux
```

**Framework mappings:** NIST 800-53 (CM-6, AC-6, AU-2), CIS Linux Benchmarks, PCI-DSS v4 (2.2), ISO 27001 (A.12.1), HIPAA (164.312(a)(1))

---

## 7. Compliance Scanner

**What it does.** Evaluates systems against specific compliance framework controls and generates evidence artifacts. Unlike the automatic compliance mapping that all scanners perform, this scanner runs targeted checks designed to satisfy specific audit requirements.

**Prerequisites.** None. Works offline.

**Config options:**

```yaml
scanners:
  compliance:
    frameworks:
      - "NIST-800-53"
      - "HIPAA"
      - "PCI-DSS-v4"
      - "ISO27001-2022"
    evidence_retention_days: 365
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner compliance --targets localhost
```

**Framework mappings:** All 30 supported frameworks (see [COMPLIANCE-GUIDE.md](COMPLIANCE-GUIDE.md))

---

## 8. Active Directory Scanner (Pro)

**What it does.** Assesses Active Directory security posture including Kerberos configuration (Kerberoasting exposure), LDAP signing, trust relationships, privileged group membership, password policy, GPO security, and stale/inactive accounts.

**Prerequisites.** Network access to a domain controller. Domain credentials for authenticated scanning. LDAP (389) or LDAPS (636) connectivity.

**Config options:**

```yaml
scanners:
  ad:
    domain_controller: "dc01.corp.local"
    check_kerberos: true
    check_trusts: true
    check_privileged_groups: true
    check_stale_accounts: true
    stale_days: 90
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner ad --targets dc01.corp.local
```

**Framework mappings:** NIST 800-53 (AC-2, AC-6, IA-2, IA-5), CMMC (AC.1.001, IA.1.076), PCI-DSS v4 (7.1, 8.3), ISO 27001 (A.9.2)

---

## 9. Cloud Security Scanner (Pro)

**What it does.** Audits cloud provider configurations across AWS, Azure, and GCP. Checks IAM policies, storage bucket permissions, network security groups, encryption settings, logging configuration, and publicly exposed resources. Auto-detects which cloud CLIs are available.

**Prerequisites.** AWS CLI (`aws`), Azure CLI (`az`), or Google Cloud CLI (`gcloud`) installed and configured with read-only credentials. Disabled in USB/portable mode.

**Config options:**

```yaml
scanners:
  cloud:
    providers: ["aws", "azure", "gcp"]    # auto-detect if empty
    check_iam: true
    check_storage: true
    check_networking: true
    check_encryption: true
    check_logging: true
    aws_regions: ["us-east-1", "us-west-2"]
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner cloud
```

**Framework mappings:** NIST 800-53 (AC-3, SC-7, AU-2), CIS Cloud Benchmarks (AWS/Azure/GCP), SOC2 (CC6.1, CC6.6), ISO 27001 (A.13.1), FedRAMP

---

## 10. Container Scanner (Pro)

**What it does.** Scans Docker and Kubernetes environments for security misconfigurations. Audits container images for known vulnerabilities (via Trivy integration), checks runtime configuration (privileged containers, capability drops, read-only root), and validates Kubernetes RBAC and network policies.

**Prerequisites.** Docker or Podman installed. Trivy optional for image vulnerability scanning. `kubectl` for Kubernetes environments.

**Config options:**

```yaml
scanners:
  container:
    scan_images: true
    scan_runtime: true
    use_trivy: true
    check_privileged: true
    check_capabilities: true
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner container
```

**Framework mappings:** NIST 800-53 (CM-7, SI-3), CIS Docker Benchmark, CIS Kubernetes Benchmark, PCI-DSS v4 (6.3), SOC2 (CC7.1)

---

## 11. SBOM Scanner (Pro)

**What it does.** Generates a Software Bill of Materials (SBOM) by analyzing installed packages, dependencies, and libraries. Identifies components with known vulnerabilities, checks license compliance, and detects outdated dependencies. Outputs CycloneDX or SPDX-compatible SBOMs.

**Prerequisites.** Access to the system or project directory being analyzed. Package managers (pip, npm, gem, etc.) for dependency resolution.

**Config options:**

```yaml
scanners:
  sbom:
    output_format: "cyclonedx"    # cyclonedx or spdx
    check_licenses: true
    check_vulnerabilities: true
    scan_paths:
      - "/app"
      - "/opt/project"
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner sbom --targets /path/to/project
```

**Framework mappings:** NIST 800-53 (CM-8, SA-11), PCI-DSS v4 (6.3), ISO 27001 (A.14.2), Executive Order 14028 (SBOM mandate), CMMC (CM.2.062)

---

## 12. Attack Surface Scanner (Pro)

**What it does.** Maps the external attack surface by enumerating DNS records, discovering subdomains (via amass integration), identifying exposed services, and checking for dangling DNS entries. Provides an outside-in view of what attackers can see.

**Prerequisites.** amass optional for active DNS enumeration. DNS resolution required. Best results with internet connectivity.

**Config options:**

```yaml
scanners:
  asm:
    enumerate_subdomains: true
    check_dangling_dns: true
    check_exposed_services: true
    use_amass: true
    max_subdomains: 1000
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner asm --targets example.com
```

**Framework mappings:** NIST 800-53 (RA-5, CM-8), NIST CSF (ID.AM-4), PCI-DSS v4 (11.3), ISO 27001 (A.8.1), CMMC (RM.2.142)

---

## 13. Credential Scanner (Pro)

**What it does.** Audits password policies, detects default credentials on discovered services, checks for leaked credentials against known breach databases (offline), and identifies weak authentication configurations. Checks common service defaults (SSH, databases, admin panels).

**Prerequisites.** None for policy checks. Network access to target services for default credential testing.

**Config options:**

```yaml
scanners:
  credential:
    check_password_policy: true
    check_default_creds: true
    check_leaked: true
    common_services: ["ssh", "mysql", "postgres", "redis", "mongodb"]
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner credential --targets 192.168.1.0/24
```

**Framework mappings:** NIST 800-53 (IA-5, AC-7), PCI-DSS v4 (8.3, 8.6), ISO 27001 (A.9.4), HIPAA (164.312(d)), CMMC (IA.2.078)

---

## 14. OpenVAS Integration (Pro)

**What it does.** Integrates with an existing OpenVAS/GVM (Greenbone Vulnerability Management) installation to leverage its extensive vulnerability test library (80,000+ NVTs). Ingests OpenVAS results into the Donjon evidence database with full compliance mapping and threat intelligence enrichment.

**Prerequisites.** OpenVAS/GVM installed and running. GVM API access (host, port, credentials).

**Config options:**

```yaml
scanners:
  openvas:
    host: "127.0.0.1"
    port: 9390
    username: "admin"
    # password from credential manager or environment variable
    scan_config: "Full and fast"
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner openvas --targets 10.0.0.0/24
```

**Framework mappings:** NIST 800-53 (RA-5, SI-2), PCI-DSS v4 (11.3), ISO 27001 (A.12.6), SOC2 (CC7.1), HIPAA (164.308(a)(8))

---

## 15. Malware Scanner (Pro)

**What it does.** Scans filesystems for malware using YARA rule matching and ClamAV antivirus integration. Detects known malware signatures, suspicious file patterns, webshells, cryptocurrency miners, and backdoors. Checks file hashes against known threat indicators.

**Prerequisites.** ClamAV optional for antivirus scanning. YARA rules loaded from `data/yara/` directory.

**Config options:**

```yaml
scanners:
  malware:
    use_clamav: true
    use_yara: true
    scan_paths:
      - "/var/www"
      - "/tmp"
      - "/home"
    max_file_size_mb: 100
    skip_extensions: [".iso", ".vmdk"]
```

**Example command:**

```bash
python3 bin/donjon-launcher standard --scanner malware --targets /var/www/html
```

**Framework mappings:** NIST 800-53 (SI-3, SI-4), PCI-DSS v4 (5.2, 5.3), ISO 27001 (A.12.2), HIPAA (164.308(a)(5)(ii)(B)), CMMC (SI.2.216)

---

## 16. Shadow AI Scanner (Pro)

**What it does.** Detects unauthorized AI usage across the environment: local LLM installations (Ollama, llama.cpp), browser-based AI tools, AI browser extensions, exposed API keys for OpenAI/Anthropic/Google, large model files (GGUF, safetensors), and AI-related network traffic patterns.

**Prerequisites.** None. Runs system-level checks. Admin/root recommended for comprehensive results.

**Config options:**

```yaml
scanners:
  shadow_ai:
    check_local_llms: true
    check_browser_extensions: true
    check_api_keys: true
    check_model_files: true
    check_network: true
    scan_paths:
      - "/home"
      - "/opt"
      - "C:\\Users"
```

**Example command:**

```bash
# Windows
python bin\donjon-launcher standard --scanner shadow_ai

# Linux
python3 bin/donjon-launcher standard --scanner shadow_ai
```

**Framework mappings:** NIST 800-53 (CM-7, CM-11), EU AI Act, NIST AI RMF, ISO 27001 (A.12.5), SOC2 (CC6.8)

---

## 17. Full Scan Suite

**What it does.** Orchestrates all applicable scanners against the specified targets. Automatically determines which scanners can run based on the target type (IP, hostname, URL, local system), available external tools, and your license tier. Produces a unified report across all scanner results.

**Prerequisites.** Varies by scanner. The orchestrator gracefully skips scanners whose prerequisites are not met.

**Config options:**

```yaml
scanners:
  full:
    skip_scanners: []             # scanners to exclude
    parallel: false               # run scanners in parallel (experimental)
    scan_type: "standard"         # quick, standard, deep
```

**Example command:**

```bash
# Run everything against a target
python3 bin/donjon-launcher standard --targets 192.168.1.0/24

# Deep audit with all scanners
python3 bin/donjon-launcher deep --targets 10.0.0.0/24
```

**Framework mappings:** All frameworks, aggregated from individual scanner results.

---

## Running Scans via API

All scanners are accessible through the REST API:

```bash
# List available scanners
curl -H "X-API-Key: YOUR_KEY" http://localhost:8443/api/v1/scanners

# Start a scan with a specific scanner
curl -X POST http://localhost:8443/api/v1/scans \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "standard",
    "targets": ["192.168.1.0/24"],
    "metadata": {
      "scanner": "network",
      "depth": "standard"
    }
  }'

# Get scan findings
curl -H "X-API-Key: YOUR_KEY" \
  http://localhost:8443/api/v1/scans/SESSION_ID/findings
```

---

## Scan Output

All scanners produce findings in a consistent format:

```json
{
  "severity": "HIGH",
  "title": "Outdated OpenSSH with known CVEs",
  "description": "OpenSSH 7.4 has 12 known CVEs...",
  "affected_asset": "192.168.1.10",
  "cvss_score": 8.1,
  "cve_ids": ["CVE-2023-38408"],
  "remediation": "Upgrade OpenSSH to 9.x",
  "kev_status": true,
  "epss_score": 0.42,
  "quality_of_detection": 85,
  "compliance_controls": {
    "NIST-800-53": ["SI-2", "RA-5"],
    "PCI-DSS-v4": ["6.3"]
  }
}
```

Findings are stored in the evidence database (`data/evidence/evidence.db`) and can be exported in JSON, CSV, HTML, PDF, SARIF, and XML formats.
