# Donjon Platform v7.0 - Compliance Guide

30 compliance frameworks with automated control mapping, evidence collection, and audit-ready report generation. Donjon maps every security finding to relevant controls across all active frameworks simultaneously.

---

## Supported Frameworks

| # | Framework | ID | Tier | Sector |
|---|---|---|---|---|
| 1 | NIST 800-53 Rev 5 | `NIST-800-53` | Community | Government / Universal |
| 2 | NIST CSF 2.0 | `nist_csf_2.0` | Community | Universal |
| 3 | NIST CSF (1.1) | `NIST-CSF` | Community | Universal |
| 4 | NIST 800-171 | `nist_800_171` | Pro | Defense Industrial Base |
| 5 | HIPAA Security Rule | `HIPAA` | Community | Healthcare |
| 6 | PCI-DSS v4.0 | `PCI-DSS-v4` | Pro | Payment Card |
| 7 | PCI-DSS 4 (alternate) | `pci_dss_4` | Pro | Payment Card |
| 8 | ISO 27001:2022 | `ISO27001-2022` | Pro | Universal |
| 9 | SOC 1 Type II | `SOC1-Type2` | Pro | Financial Services |
| 10 | SOC 2 Type II | `SOC2-Type2` | Pro | Technology / SaaS |
| 11 | SOC 2 | `soc2` | Pro | Technology / SaaS |
| 12 | CMMC | `CMMC` | Pro | Defense Contractors |
| 13 | FedRAMP | `FedRAMP` | Pro | Federal Cloud Providers |
| 14 | GDPR | `GDPR` | Pro | EU Data Privacy |
| 15 | SOX (Sarbanes-Oxley) | `SOX` | Pro | Public Companies |
| 16 | HITRUST CSF | `HITRUST` | Pro | Healthcare |
| 17 | CIS Controls | `CIS` | Community | Universal |
| 18 | CIS Benchmarks | `cis_benchmarks` | Pro | Universal |
| 19 | DORA | `dora` | Pro | EU Financial Services |
| 20 | NIS2 | `nis2` | Pro | EU Critical Infrastructure |
| 21 | EU AI Act | `eu_ai_act` | Pro | AI Systems (EU) |
| 22 | CCPA/CPRA | `ccpa` | Pro | California Privacy |
| 23 | APRA CPS 234 | `apra_cps234` | Pro | Australian Financial |
| 24 | SEC Cyber Rules | `sec_cyber` | Pro | US Public Companies |
| 25 | NY SHIELD Act | `ny_shield` | Pro | New York Privacy |
| 26 | Virginia CDPA | `virginia_cdpa` | Pro | Virginia Privacy |
| 27 | Colorado Privacy Act | `colorado_privacy` | Pro | Colorado Privacy |
| 28 | Connecticut DPA | `connecticut_cdpa` | Pro | Connecticut Privacy |
| 29 | Texas DPSA | `texas_dpsa` | Pro | Texas Privacy |
| 30 | UK FCA Resilience | `uk_fca_resilience` | Pro | UK Financial Services |

Community tier includes 3 frameworks (NIST 800-53, NIST CSF 2.0, CIS Controls). Pro and above: unlimited.

---

## How Compliance Mapping Works

1. **Scanners run** and produce findings (vulnerabilities, misconfigurations, exposures).
2. **Each finding type** has a pre-defined mapping to controls across all 30 frameworks.
3. **Controls are scored** based on finding severity and whether they pass or fail the check.
4. **Evidence artifacts** are automatically collected and linked to the relevant controls.
5. **Compliance reports** show per-framework control status with pass/fail/partial scores.

Configure active frameworks in `config/active/config.yaml`:

```yaml
compliance:
  frameworks:
    - "NIST-800-53"
    - "HIPAA"
    - "PCI-DSS-v4"
    - "ISO27001-2022"
    - "SOC2-Type2"
```

---

## Top 10 Framework Details

### 1. NIST 800-53 Rev 5

**What it covers.** The most comprehensive US federal security control catalog. 20 control families covering access control, audit, configuration management, identification, incident response, risk assessment, system protection, and more. Used as the basis for FedRAMP and many other frameworks.

**Key control families:** AC (Access Control), AU (Audit), CM (Configuration Management), IA (Identification and Authentication), RA (Risk Assessment), SC (System and Communications Protection), SI (System Integrity)

**Which scanners to run:**
- Network Scanner -- CM-7 (Least Functionality), SC-7 (Boundary Protection)
- Vulnerability Scanner -- RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation)
- SSL/TLS Scanner -- SC-8 (Transmission Confidentiality), SC-12/SC-13 (Cryptography)
- Windows/Linux Scanner -- CM-6 (Configuration Settings), AC-2 (Account Management)
- Compliance Scanner -- All control families

**Generate compliance report:**

```bash
# CLI
python3 bin/donjon-launcher   # select Compliance & Reports > NIST 800-53

# API
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/NIST-800-53
```

**Evidence export:**

```bash
curl -X POST http://localhost:8443/api/v1/export \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"session_id":"SESSION_ID","formats":["json","csv","html"]}'
```

---

### 2. NIST CSF 2.0

**What it covers.** The Cybersecurity Framework v2.0 organizes security around six core functions: Govern, Identify, Protect, Detect, Respond, and Recover. Designed as a risk-based framework applicable to organizations of any size or sector.

**Key functions:** GV (Govern), ID (Identify), PR (Protect), DE (Detect), RS (Respond), RC (Recover)

**Which scanners to run:**
- Network Scanner -- ID.AM (Asset Management)
- Vulnerability Scanner -- ID.RA (Risk Assessment)
- ASM Scanner -- ID.AM-4 (External Information Systems)
- SSL/TLS Scanner -- PR.DS (Data Security)
- Compliance Scanner -- All functions

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/nist_csf_2.0
```

---

### 3. HIPAA Security Rule

**What it covers.** The Health Insurance Portability and Accountability Act Security Rule. Three safeguard categories: Administrative (risk analysis, workforce security, incident response), Physical (facility access, workstation security), and Technical (access control, audit controls, transmission security, integrity).

**Key controls:** 164.308 (Administrative Safeguards), 164.310 (Physical Safeguards), 164.312 (Technical Safeguards)

**Which scanners to run:**
- Network Scanner -- 164.312(e)(1) (Transmission Security)
- Vulnerability Scanner -- 164.308(a)(1) (Security Management)
- SSL/TLS Scanner -- 164.312(e)(1) (Transmission Security)
- Windows/Linux Scanner -- 164.312(a)(1) (Access Control)
- Credential Scanner -- 164.312(d) (Person Authentication)
- Compliance Scanner -- All safeguard categories

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/HIPAA
```

---

### 4. PCI-DSS v4.0

**What it covers.** Payment Card Industry Data Security Standard v4.0. 12 requirement areas covering network security, cardholder data protection, vulnerability management, access control, monitoring, and security policy. Mandatory for organizations that store, process, or transmit cardholder data.

**Key requirements:** Req 1 (Network Security), Req 2 (Secure Config), Req 4 (Cryptography), Req 5 (Malware), Req 6 (Secure Development), Req 7 (Access Control), Req 8 (Authentication), Req 11 (Security Testing)

**Which scanners to run:**
- Network Scanner -- Req 1.1, 1.2 (network segmentation, firewall)
- Vulnerability Scanner -- Req 6.3, 11.3 (vulnerability management)
- Web Scanner -- Req 6.2, 6.4 (application security)
- SSL/TLS Scanner -- Req 2.2.7, 4.1 (encryption in transit)
- Credential Scanner -- Req 8.3, 8.6 (authentication strength)
- Malware Scanner -- Req 5.2, 5.3 (anti-malware)

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/PCI-DSS-v4
```

---

### 5. ISO 27001:2022

**What it covers.** International standard for information security management systems (ISMS). Annex A contains 93 controls organized into four themes: Organizational (37), People (8), Physical (14), and Technological (34). Covers risk assessment, access control, cryptography, operations security, and supplier relationships.

**Key Annex A themes:** A.5-A.8 (Organizational), A.6 (People), A.7 (Physical), A.8 (Technological)

**Which scanners to run:**
- Network Scanner -- A.13.1 (Network Security Management)
- Vulnerability Scanner -- A.12.6 (Technical Vulnerability Management)
- SSL/TLS Scanner -- A.10.1 (Cryptographic Controls)
- Cloud Scanner -- A.15.1 (Supplier Security)
- SBOM Scanner -- A.14.2 (Development Security)
- Container Scanner -- A.12.1 (Operational Procedures)

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/ISO27001-2022
```

---

### 6. SOC 2 Type II

**What it covers.** Service Organization Control 2 report based on the AICPA Trust Services Criteria. Five categories: Security (CC), Availability (A), Processing Integrity (PI), Confidentiality (C), and Privacy (P). Required by many enterprise SaaS customers as vendor due diligence.

**Key criteria:** CC6 (Logical and Physical Access), CC7 (System Operations), CC8 (Change Management), CC9 (Risk Mitigation)

**Which scanners to run:**
- Network Scanner -- CC6.1 (Access Control)
- Vulnerability Scanner -- CC7.1 (System Monitoring)
- SSL/TLS Scanner -- CC6.7 (Encryption)
- Container Scanner -- CC8.1 (Change Management)
- Cloud Scanner -- CC6.6 (External Services)

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/SOC2-Type2
```

---

### 7. CMMC (Cybersecurity Maturity Model Certification)

**What it covers.** Department of Defense cybersecurity standard for defense contractors. Three maturity levels: Level 1 (Foundational, 17 practices), Level 2 (Advanced, 110 practices aligned to NIST 800-171), Level 3 (Expert, 134 practices). Required for DoD contract eligibility.

**Key domains:** AC (Access Control), IA (Identification and Authentication), CM (Configuration Management), SC (System and Communications Protection), SI (System Integrity)

**Which scanners to run:**
- All Community scanners for Level 1
- AD Scanner -- AC.1.001 (Authorized Access)
- Credential Scanner -- IA.2.078 (Password Complexity)
- SBOM Scanner -- CM.2.062 (Software Inventory)
- Malware Scanner -- SI.2.216 (Malware Protection)

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/CMMC
```

---

### 8. FedRAMP

**What it covers.** Federal Risk and Authorization Management Program. Based on NIST 800-53 with additional requirements for cloud service providers serving US federal agencies. Three impact levels: Low (125 controls), Moderate (325 controls), High (421 controls).

**Key additions beyond NIST 800-53:** Continuous monitoring requirements, penetration testing, incident response timelines, POA&M tracking, and ConMon reporting.

**Which scanners to run:**
- All scanners applicable to NIST 800-53
- Cloud Scanner -- cloud-specific controls
- ASM Scanner -- external boundary monitoring
- Vulnerability Scanner -- monthly vulnerability scanning requirement

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/FedRAMP
```

---

### 9. GDPR (General Data Protection Regulation)

**What it covers.** EU data protection regulation. Article 32 mandates appropriate technical and organizational security measures. Article 35 requires data protection impact assessments for high-risk processing. Covers data encryption, pseudonymization, access controls, and breach notification.

**Key articles:** Art. 5 (Data Processing Principles), Art. 25 (Data Protection by Design), Art. 32 (Security of Processing), Art. 33-34 (Breach Notification)

**Which scanners to run:**
- SSL/TLS Scanner -- Art. 32 (Encryption in transit)
- Credential Scanner -- Art. 32 (Access controls)
- Web Scanner -- Art. 25 (Data protection by design)
- Cloud Scanner -- Art. 28 (Processor security)

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/GDPR
```

---

### 10. SOX (Sarbanes-Oxley)

**What it covers.** Financial reporting integrity controls (Section 302/404). IT General Controls (ITGCs) that support financial reporting systems: access management, change management, computer operations, and program development. Applies to public companies and their auditors.

**Key ITGC areas:** Access to Programs and Data, Program Changes, Computer Operations, Program Development

**Which scanners to run:**
- Network Scanner -- access to programs and data
- Vulnerability Scanner -- system integrity
- AD Scanner -- access control and authorization
- Windows/Linux Scanner -- configuration management

**Generate compliance report:**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/SOX
```

---

## Air-Gap Compliance Workflow

For networks without internet connectivity (classified, SCIF, OT/ICS):

**Step 1.** On a connected machine, update intel and prepare the platform:

```bash
python3 bin/update-intel.py --all
python3 bin/bundle-intel.py create /path/to/donjon-intel-bundle.tar.gz --include-feeds
```

**Step 2.** Copy the platform and intel bundle to transfer media (USB, data diode).

**Step 3.** On the air-gapped system, import the intel bundle:

```bash
python3 bin/bundle-intel.py import /media/USB/donjon-intel-bundle.tar.gz --include-feeds
```

**Step 4.** Run scans. All compliance mapping works offline:

```bash
python3 bin/donjon-launcher standard
```

**Step 5.** Export compliance evidence:

```bash
# CLI
python3 bin/donjon-launcher   # Compliance & Reports > Export Evidence

# Copy data/reports/ and data/evidence/ to transfer media for external review
```

All compliance frameworks, control mappings, and report generation work fully offline. The only features unavailable in air-gapped mode are cloud scanning and external AI providers.

---

## Government-Specific Guidance

### NIST 800-53 / CSF Compliance

For agencies following NIST Risk Management Framework (RMF):

1. **Categorize** your system (Low/Moderate/High) per FIPS 199
2. **Configure** frameworks in `config/active/config.yaml`:
   ```yaml
   compliance:
     frameworks: ["NIST-800-53", "nist_csf_2.0"]
   ```
3. **Run a deep scan** covering all applicable control families
4. **Generate the compliance report** -- maps findings to specific NIST controls
5. **Export evidence artifacts** for inclusion in your System Security Plan (SSP)
6. **Track POA&Ms** using the remediation API or dashboard

### CMMC Assessment Preparation

For defense contractors preparing for CMMC Level 2 assessment:

1. **Enable NIST 800-171 and CMMC frameworks:**
   ```yaml
   compliance:
     frameworks: ["CMMC", "nist_800_171", "NIST-800-53"]
   ```
2. **Run all Pro-tier scanners** (AD, credential, SBOM cover key CMMC practices)
3. **Review the CMMC compliance report** for practice-level pass/fail
4. **Generate evidence packages** for each practice domain
5. **Use the remediation tracker** to close gaps before assessment

### FedRAMP Continuous Monitoring

For cloud service providers maintaining FedRAMP authorization:

1. **Schedule monthly vulnerability scans:**
   ```bash
   curl -X POST http://localhost:8443/api/v1/schedules \
     -H "X-API-Key: KEY" -H "Content-Type: application/json" \
     -d '{
       "name": "FedRAMP Monthly Scan",
       "scanner_type": "full",
       "cron_expression": "0 2 1 * *",
       "targets": ["10.0.0.0/16"],
       "scan_type": "standard"
     }'
   ```
2. **Generate ConMon deliverables** from compliance reports
3. **Track POA&M items** via remediation API
4. **Export SARIF/JSON** for integration with GRC platforms

---

## Compliance Report Formats

Reports are available in multiple formats:

| Format | Use Case | Tier |
|---|---|---|
| JSON | Machine processing, API integration | Community |
| CSV | Spreadsheet analysis, import to GRC tools | Community |
| HTML | Browser viewing, stakeholder distribution | Pro |
| PDF | Formal audit deliverable | Pro |
| SARIF | CI/CD integration, GitHub Code Scanning | Pro |
| XML | Legacy GRC tool import | Pro |

Export via API:

```bash
curl -X POST http://localhost:8443/api/v1/export \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"session_id":"SESSION_ID","formats":["json","csv","html","pdf"]}'
```

---

## Framework Freshness

Compliance framework definitions receive periodic updates as standards are revised. Check freshness:

```bash
python3 bin/update-intel.py --status
```

The status output includes a "Compliance Frameworks" section showing which frameworks have stale definitions. Update framework data:

```bash
python3 bin/update-frameworks.py
```
