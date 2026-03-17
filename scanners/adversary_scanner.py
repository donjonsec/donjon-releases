#!/usr/bin/env python3
"""
Donjon v7.0 - Adversary Emulation Scanner
Purple team defense validation inspired by Permiso's Rufio concept.
Simulates known adversary group tactics and scores defensive coverage.

Safe simulation only — checks DEFENSES, never exploits.

35 adversary profiles covering:
  - 8 ransomware groups (Scattered Spider, LockBit, Akira, ALPHV, Cl0p, Play, Rhysida, Qilin)
  - 4 China nation-state (Volt Typhoon, Salt Typhoon, APT40, APT41)
  - 4 Russia nation-state (APT29, APT28, Sandworm, Turla)
  - 3 Iran nation-state (APT33, APT34, CyberAv3ngers)
  - 2 North Korea (Lazarus, Kimsuky)
  - 3 ICS/OT-specific (XENOTIME, CHERNOVITE, ICS general)
  - 1 financial crime (FIN7)
  - 1 hacktivist (Pro-Russia)
  - 4 AI/LLM attack profiles (prompt injection, Copilot, agent hijack, supply chain)
  - 5 technique-specific (Golden SAML, Kerberoast, container escape, supply chain, LOLBins)
"""

import os
import shlex
import sys
import re
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


# =========================================================================== #
#  Adversary Profiles                                                         #
# =========================================================================== #

ADVERSARY_PROFILES: Dict[str, Dict] = {
    # --- Ransomware Groups (7) ---
    'scattered_spider': {
        'name': 'Scattered Spider (LUCR-3)',
        'aliases': ['UNC3944', 'LUCR-3', 'Muddled Libra'],
        'attribution': 'Western cybercriminals',
        'motivation': 'financial',
        'target_sectors': ['telecom', 'technology', 'hospitality'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'MFA Phishing / SIM Swap', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Persistence', 'technique': 'Account Creation', 'id': 'T1136', 'check': '_sim_check_account_policies'},
            {'tactic': 'Privilege Escalation', 'technique': 'Admin Policy Manipulation', 'id': 'T1098', 'check': '_sim_check_account_policies'},
            {'tactic': 'Defense Evasion', 'technique': 'Valid Accounts (Cloud)', 'id': 'T1078', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Execution', 'technique': 'PowerShell/CLI Abuse', 'id': 'T1059', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Lateral Movement', 'technique': 'Remote Desktop Abuse', 'id': 'T1021', 'check': '_sim_check_ssh_hardening'},
            {'tactic': 'Exfiltration', 'technique': 'Exfil Over Cloud Service', 'id': 'T1567', 'check': '_sim_check_firewall_egress'},
        ],
    },
    'lockbit': {
        'name': 'LockBit 3.0',
        'aliases': ['Bitwise Spider', 'LockBit Black'],
        'attribution': 'Russia-linked RaaS',
        'motivation': 'financial',
        'target_sectors': ['manufacturing', 'healthcare', 'education'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'RDP Brute Force', 'id': 'T1133', 'check': '_sim_check_ssh_hardening'},
            {'tactic': 'Initial Access', 'technique': 'Brute Force', 'id': 'T1110', 'check': '_sim_check_account_policies'},
            {'tactic': 'Impact', 'technique': 'Data Encrypted for Impact', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Impact', 'technique': 'Inhibit System Recovery', 'id': 'T1490', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Impact', 'technique': 'Service Stop', 'id': 'T1489', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Lateral Movement', 'technique': 'RDP/SMB Lateral Movement', 'id': 'T1021', 'check': '_sim_check_firewall_egress'},
            {'tactic': 'Exfiltration', 'technique': 'Double Extortion Exfil', 'id': 'T1567', 'check': '_sim_check_firewall_egress'},
        ],
    },
    'akira': {
        'name': 'Akira (GOLD SAHARA)',
        'aliases': ['GOLD SAHARA', 'Storm-1567'],
        'attribution': 'Eastern European',
        'motivation': 'financial',
        'target_sectors': ['manufacturing', 'construction', 'healthcare'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'VPN Credential Exploitation', 'id': 'T1133', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Credential Access', 'technique': 'LSASS Memory Dump', 'id': 'T1003.001', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Execution', 'technique': 'PowerShell Abuse', 'id': 'T1059', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Impact', 'technique': 'Data Encrypted', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Exfiltration', 'technique': 'Double Extortion', 'id': 'T1567', 'check': '_sim_check_firewall_egress'},
            {'tactic': 'Lateral Movement', 'technique': 'RDP Lateral Movement', 'id': 'T1021', 'check': '_sim_check_ssh_hardening'},
            {'tactic': 'Defense Evasion', 'technique': 'Disable/Modify AV', 'id': 'T1562', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Defense Evasion', 'technique': 'Indicator Removal', 'id': 'T1070', 'check': '_sim_check_logging_coverage'},
        ],
    },
    'alphv': {
        'name': 'BlackCat/ALPHV',
        'aliases': ['BlackCat', 'Sphynx'],
        'attribution': 'Russia-linked RaaS',
        'motivation': 'financial',
        'target_sectors': ['healthcare', 'critical_infrastructure'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Exploit Public-Facing App', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Execution', 'technique': 'Rust-based Ransomware', 'id': 'T1059', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Impact', 'technique': 'Data Encrypted', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Exfiltration', 'technique': 'Data Exfiltration', 'id': 'T1567', 'check': '_sim_check_firewall_egress'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Lateral Movement', 'technique': 'Remote Services', 'id': 'T1021', 'check': '_sim_check_ssh_hardening'},
        ],
    },
    'clop': {
        'name': 'Cl0p (FIN11)',
        'aliases': ['FIN11', 'TA505', 'Lace Tempest'],
        'attribution': 'Russia-linked',
        'motivation': 'financial',
        'target_sectors': ['supply_chain', 'financial', 'government'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Mass File Transfer Exploits', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Collection', 'technique': 'Automated Data Collection', 'id': 'T1119', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Exfiltration', 'technique': 'Mass Data Exfiltration', 'id': 'T1567', 'check': '_sim_check_firewall_egress'},
            {'tactic': 'Impact', 'technique': 'Data Encrypted', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Defense Evasion', 'technique': 'Supply Chain Compromise', 'id': 'T1195', 'check': '_sim_check_supply_chain_integrity'},
        ],
    },
    'play': {
        'name': 'Play Ransomware',
        'aliases': ['PlayCrypt', 'Balloonfly'],
        'attribution': 'Unknown',
        'motivation': 'financial',
        'target_sectors': ['manufacturing', 'government'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'ProxyNotShell Exploitation', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Execution', 'technique': 'SystemBC RAT', 'id': 'T1059', 'check': '_sim_check_ids_rules'},
            {'tactic': 'Defense Evasion', 'technique': 'AV Evasion', 'id': 'T1562', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Impact', 'technique': 'Data Encrypted', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
        ],
    },
    'rhysida': {
        'name': 'Rhysida',
        'aliases': [],
        'attribution': 'Unknown',
        'motivation': 'financial',
        'target_sectors': ['healthcare', 'government', 'education'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'PrintNightmare Exploitation', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Command and Control', 'technique': 'Cobalt Strike', 'id': 'T1071', 'check': '_sim_check_ids_rules'},
            {'tactic': 'Impact', 'technique': 'Data Encrypted', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Exfiltration', 'technique': 'Data Exfil', 'id': 'T1567', 'check': '_sim_check_firewall_egress'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
        ],
    },
    'qilin': {
        'name': 'Qilin',
        'aliases': ['Agenda'],
        'attribution': 'Russia-linked',
        'motivation': 'financial',
        'target_sectors': ['manufacturing', 'telecom'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Spearphishing', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Execution', 'technique': 'ESXi Targeting', 'id': 'T1059', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Impact', 'technique': 'Cross-Platform Encryption', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Lateral Movement', 'technique': 'Remote Services', 'id': 'T1021', 'check': '_sim_check_ssh_hardening'},
        ],
    },

    # --- China Nation-State (4) ---
    'volt_typhoon': {
        'name': 'Volt Typhoon',
        'aliases': ['Bronze Silhouette', 'Vanguard Panda'],
        'attribution': 'China (PLA)',
        'motivation': 'espionage + pre-positioning',
        'target_sectors': ['critical_infrastructure', 'utilities', 'communications'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'SOHO Router Exploitation', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Execution', 'technique': 'LOLBins (Living Off The Land)', 'id': 'T1218', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Defense Evasion', 'technique': 'Masquerading', 'id': 'T1036', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Discovery', 'technique': 'System Information Discovery', 'id': 'T1082', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Lateral Movement', 'technique': 'Valid Accounts', 'id': 'T1078', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Command and Control', 'technique': 'Proxy via SOHO Devices', 'id': 'T1071', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Defense Evasion', 'technique': 'Indicator Removal', 'id': 'T1070', 'check': '_sim_check_logging_coverage'},
        ],
    },
    'salt_typhoon': {
        'name': 'Salt Typhoon',
        'aliases': ['GhostEmperor', 'FamousSparrow'],
        'attribution': 'China (MSS)',
        'motivation': 'espionage',
        'target_sectors': ['telecom', 'government_wiretapping'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Telecom Infrastructure Exploit', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Collection', 'technique': 'Lawful Intercept System Access', 'id': 'T1119', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Persistence', 'technique': 'Rootkit Installation', 'id': 'T1547', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Defense Evasion', 'technique': 'Kernel-level Evasion', 'id': 'T1014', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Exfiltration', 'technique': 'Data Exfiltration', 'id': 'T1041', 'check': '_sim_check_firewall_egress'},
        ],
    },
    'apt40': {
        'name': 'APT40 (Leviathan)',
        'aliases': ['Leviathan', 'TEMP.Periscope', 'Bronze Mohawk'],
        'attribution': 'China (MSS Hainan)',
        'motivation': 'espionage',
        'target_sectors': ['maritime', 'defense', 'aviation'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Rapid CVE Exploitation', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Initial Access', 'technique': 'Spearphishing Attachment', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Persistence', 'technique': 'Web Shell', 'id': 'T1505', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Exfiltration', 'technique': 'Data Exfil', 'id': 'T1041', 'check': '_sim_check_firewall_egress'},
        ],
    },
    'apt41': {
        'name': 'APT41 (Winnti)',
        'aliases': ['Winnti', 'Double Dragon', 'Barium'],
        'attribution': 'China',
        'motivation': 'espionage + financial',
        'target_sectors': ['technology', 'healthcare', 'supply_chain'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Supply Chain Compromise', 'id': 'T1195', 'check': '_sim_check_supply_chain_integrity'},
            {'tactic': 'Execution', 'technique': 'Signed Binary Abuse', 'id': 'T1218', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Persistence', 'technique': 'Boot/Logon Autostart', 'id': 'T1547', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Lateral Movement', 'technique': 'Remote Services', 'id': 'T1021', 'check': '_sim_check_ssh_hardening'},
            {'tactic': 'Exfiltration', 'technique': 'C2 Channel Exfil', 'id': 'T1041', 'check': '_sim_check_firewall_egress'},
        ],
    },

    # --- Russia Nation-State (4) ---
    'apt29': {
        'name': 'APT29 (Cozy Bear)',
        'aliases': ['Cozy Bear', 'Midnight Blizzard', 'Nobelium'],
        'attribution': 'Russia (SVR)',
        'motivation': 'espionage',
        'target_sectors': ['government', 'diplomatic', 'technology'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Supply Chain (SolarWinds)', 'id': 'T1195', 'check': '_sim_check_supply_chain_integrity'},
            {'tactic': 'Persistence', 'technique': 'OAuth Token Abuse', 'id': 'T1550', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Defense Evasion', 'technique': 'Valid Accounts (Cloud)', 'id': 'T1078', 'check': '_sim_check_account_policies'},
            {'tactic': 'Command and Control', 'technique': 'Web Protocols C2', 'id': 'T1071', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files', 'id': 'T1027', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Collection', 'technique': 'Email Collection', 'id': 'T1114', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Credential Access', 'technique': 'OS Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Command and Control', 'technique': 'Multi-hop Proxy', 'id': 'T1090', 'check': '_sim_check_firewall_egress'},
        ],
    },
    'apt28': {
        'name': 'APT28 (Fancy Bear)',
        'aliases': ['Fancy Bear', 'Forest Blizzard', 'Sofacy'],
        'attribution': 'Russia (GRU)',
        'motivation': 'espionage',
        'target_sectors': ['government', 'military', 'media'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Spearphishing', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Initial Access', 'technique': 'Exploit Public-Facing App', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Credential Access', 'technique': 'Credential Harvesting', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Execution', 'technique': 'Command & Scripting', 'id': 'T1059', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Command and Control', 'technique': 'Application Layer Protocol', 'id': 'T1071', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Credential Access', 'technique': 'Brute Force', 'id': 'T1110', 'check': '_sim_check_account_policies'},
        ],
    },
    'sandworm': {
        'name': 'Sandworm (APT44)',
        'aliases': ['APT44', 'Seashell Blizzard', 'Voodoo Bear'],
        'attribution': 'Russia (GRU Unit 74455)',
        'motivation': 'destruction',
        'target_sectors': ['power_grid', 'water', 'ics_ot'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Exploit Public-Facing', 'id': 'T1190', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Execution', 'technique': 'Command & Scripting', 'id': 'T1059', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Impact', 'technique': 'Data Destruction (Wipers)', 'id': 'T1485', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Impact', 'technique': 'Service Stop (ICS)', 'id': 'T1489', 'check': '_sim_check_ics_network_segmentation'},
            {'tactic': 'Defense Evasion', 'technique': 'Impair Defenses', 'id': 'T1562', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Lateral Movement', 'technique': 'Remote Services', 'id': 'T1021', 'check': '_sim_check_ssh_hardening'},
        ],
    },
    'turla': {
        'name': 'Turla (Snake)',
        'aliases': ['Snake', 'Venomous Bear', 'Krypton'],
        'attribution': 'Russia (FSB)',
        'motivation': 'espionage',
        'target_sectors': ['government', 'embassies', 'defense'],
        'ttps': [
            {'tactic': 'Command and Control', 'technique': 'Satellite C2', 'id': 'T1090', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Persistence', 'technique': 'Rootkit Installation', 'id': 'T1547', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Defense Evasion', 'technique': 'Kernel Rootkit', 'id': 'T1014', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Collection', 'technique': 'Data from Local System', 'id': 'T1005', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Exfiltration', 'technique': 'Exfil Over C2', 'id': 'T1041', 'check': '_sim_check_firewall_egress'},
        ],
    },

    # --- Iran Nation-State (3) ---
    'apt33': {
        'name': 'APT33 (Elfin)',
        'aliases': ['Elfin', 'Holmium', 'Magnallium'],
        'attribution': 'Iran (IRGC)',
        'motivation': 'espionage + destruction',
        'target_sectors': ['aviation', 'energy', 'military'],
        'ttps': [
            {'tactic': 'Impact', 'technique': 'Shamoon Wiper', 'id': 'T1485', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Initial Access', 'technique': 'Spearphishing', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Credential Access', 'technique': 'Password Spraying', 'id': 'T1110', 'check': '_sim_check_account_policies'},
            {'tactic': 'Execution', 'technique': 'PowerShell', 'id': 'T1059', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Persistence', 'technique': 'Scheduled Task', 'id': 'T1053', 'check': '_sim_check_logging_coverage'},
        ],
    },
    'apt34': {
        'name': 'APT34 (OilRig)',
        'aliases': ['OilRig', 'Helix Kitten', 'Hazel Sandstorm'],
        'attribution': 'Iran (MOIS)',
        'motivation': 'espionage',
        'target_sectors': ['government', 'financial', 'telecom'],
        'ttps': [
            {'tactic': 'Command and Control', 'technique': 'DNS Tunneling C2', 'id': 'T1071', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Credential Access', 'technique': 'Credential Theft', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Initial Access', 'technique': 'Watering Hole', 'id': 'T1189', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Persistence', 'technique': 'Web Shell', 'id': 'T1505', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Exfiltration', 'technique': 'DNS Exfil', 'id': 'T1048', 'check': '_sim_check_dns_monitoring'},
        ],
    },
    'cyberav3ngers': {
        'name': 'CyberAv3ngers (IRGC)',
        'aliases': ['CyberAv3ngers'],
        'attribution': 'Iran (IRGC-CEC)',
        'motivation': 'destruction',
        'target_sectors': ['water_wastewater', 'ics'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Unitronics PLC Exploitation', 'id': 'T1190', 'check': '_sim_check_plc_access_controls'},
            {'tactic': 'Impact', 'technique': 'Manipulation of Control', 'id': 'T0831', 'check': '_sim_check_safety_systems'},
            {'tactic': 'Lateral Movement', 'technique': 'Default Credentials', 'id': 'T1078', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Discovery', 'technique': 'HMI/SCADA Reconnaissance', 'id': 'T0846', 'check': '_sim_check_scada_exposure'},
        ],
    },

    # --- North Korea (2) ---
    'lazarus': {
        'name': 'Lazarus Group',
        'aliases': ['Hidden Cobra', 'Diamond Sleet', 'ZINC'],
        'attribution': 'North Korea (RGB)',
        'motivation': 'financial + espionage',
        'target_sectors': ['financial', 'cryptocurrency', 'defense'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Watering Hole', 'id': 'T1189', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Initial Access', 'technique': 'Spearphishing', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Execution', 'technique': 'Custom Malware', 'id': 'T1059', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Exfiltration', 'technique': 'Exfil Over Web Service', 'id': 'T1567', 'check': '_sim_check_firewall_egress'},
            {'tactic': 'Impact', 'technique': 'Data Encrypted for Impact', 'id': 'T1486', 'check': '_sim_check_backup_integrity'},
            {'tactic': 'Persistence', 'technique': 'Boot/Logon Autostart', 'id': 'T1547', 'check': '_sim_check_file_integrity'},
        ],
    },
    'kimsuky': {
        'name': 'Kimsuky (Velvet Chollima)',
        'aliases': ['Velvet Chollima', 'Emerald Sleet', 'Thallium'],
        'attribution': 'North Korea (RGB)',
        'motivation': 'espionage',
        'target_sectors': ['government', 'think_tanks', 'academia'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Spearphishing', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Credential Access', 'technique': 'Credential Harvesting', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
            {'tactic': 'Collection', 'technique': 'Data from Local System', 'id': 'T1005', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Command and Control', 'technique': 'Web C2', 'id': 'T1071', 'check': '_sim_check_dns_monitoring'},
            {'tactic': 'Exfiltration', 'technique': 'Data Exfil', 'id': 'T1041', 'check': '_sim_check_firewall_egress'},
        ],
    },

    # --- ICS/OT-Specific (3) ---
    'xenotime': {
        'name': 'XENOTIME (Triton/TRISIS)',
        'aliases': ['TEMP.Veles'],
        'attribution': 'Russia (TsNIIKhM)',
        'motivation': 'destruction',
        'target_sectors': ['oil_gas', 'petrochemical'],
        'ttps': [
            {'tactic': 'Impact', 'technique': 'SIS Attack (Triton)', 'id': 'T0880', 'check': '_sim_check_safety_systems'},
            {'tactic': 'Lateral Movement', 'technique': 'IT to OT Pivot', 'id': 'T0886', 'check': '_sim_check_ics_network_segmentation'},
            {'tactic': 'Execution', 'technique': 'Controller Manipulation', 'id': 'T0821', 'check': '_sim_check_plc_access_controls'},
            {'tactic': 'Discovery', 'technique': 'Network Service Scanning', 'id': 'T0841', 'check': '_sim_check_scada_exposure'},
        ],
    },
    'chernovite': {
        'name': 'CHERNOVITE (COSMICENERGY)',
        'aliases': ['COSMICENERGY'],
        'attribution': 'Russia',
        'motivation': 'destruction',
        'target_sectors': ['electric_utilities'],
        'ttps': [
            {'tactic': 'Impact', 'technique': 'IEC-104 Protocol Abuse', 'id': 'T0855', 'check': '_sim_check_ics_network_segmentation'},
            {'tactic': 'Execution', 'technique': 'Power Grid Manipulation', 'id': 'T0821', 'check': '_sim_check_plc_access_controls'},
            {'tactic': 'Lateral Movement', 'technique': 'IT-OT Bridge', 'id': 'T0886', 'check': '_sim_check_ics_network_segmentation'},
            {'tactic': 'Discovery', 'technique': 'RTU Discovery', 'id': 'T0846', 'check': '_sim_check_scada_exposure'},
        ],
    },
    'ics_general': {
        'name': 'ICS/SCADA General Threat',
        'aliases': [],
        'attribution': 'multiple',
        'motivation': 'destruction + espionage',
        'target_sectors': ['manufacturing', 'energy', 'water'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'HMI Exposure', 'id': 'T0855', 'check': '_sim_check_scada_exposure'},
            {'tactic': 'Initial Access', 'technique': 'VNC/Remote Access', 'id': 'T0866', 'check': '_sim_check_scada_exposure'},
            {'tactic': 'Execution', 'technique': 'PLC Manipulation', 'id': 'T0889', 'check': '_sim_check_plc_access_controls'},
            {'tactic': 'Impact', 'technique': 'Denial of Control', 'id': 'T0813', 'check': '_sim_check_safety_systems'},
            {'tactic': 'Lateral Movement', 'technique': 'Remote Services (OT)', 'id': 'T0886', 'check': '_sim_check_ics_network_segmentation'},
            {'tactic': 'Collection', 'technique': 'Theft of Op Information', 'id': 'T0882', 'check': '_sim_check_logging_coverage'},
        ],
    },

    # --- Financial Crime (1) ---
    'fin7': {
        'name': 'FIN7 (Carbanak)',
        'aliases': ['Carbanak', 'Carbon Spider'],
        'attribution': 'Eastern European',
        'motivation': 'financial',
        'target_sectors': ['retail', 'hospitality', 'financial'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Spearphishing', 'id': 'T1566', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Execution', 'technique': 'Social Engineering via Phone', 'id': 'T1059', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Persistence', 'technique': 'Scheduled Task/Job', 'id': 'T1053', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Collection', 'technique': 'POS Malware', 'id': 'T1005', 'check': '_sim_check_file_integrity'},
            {'tactic': 'Credential Access', 'technique': 'Credential Dumping', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
        ],
    },

    # --- Hacktivist (1) ---
    'pro_russia_hacktivist': {
        'name': 'Z-Pentest/NoName057(16)',
        'aliases': ['Z-Pentest', 'NoName057(16)', 'CyberArmyofRussia'],
        'attribution': 'Pro-Russia hacktivists',
        'motivation': 'hacktivism',
        'target_sectors': ['critical_infrastructure', 'government'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'HMI Tampering via VNC', 'id': 'T0866', 'check': '_sim_check_scada_exposure'},
            {'tactic': 'Impact', 'technique': 'DDoS', 'id': 'T1499', 'check': '_sim_check_firewall_egress'},
            {'tactic': 'Impact', 'technique': 'ICS Control Manipulation', 'id': 'T0831', 'check': '_sim_check_plc_access_controls'},
            {'tactic': 'Discovery', 'technique': 'Internet-Exposed ICS', 'id': 'T0846', 'check': '_sim_check_scada_exposure'},
        ],
    },

    # --- AI/LLM Attack Profiles (4) ---
    'ai_prompt_injection': {
        'name': 'LLM Prompt Injection',
        'aliases': [],
        'attribution': 'technique_based',
        'motivation': 'data_exfiltration',
        'target_sectors': ['any_llm_deployment'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Direct Prompt Injection', 'id': 'AML.T0051.000', 'check': '_sim_check_llm_input_validation'},
            {'tactic': 'Initial Access', 'technique': 'Indirect Prompt Injection', 'id': 'AML.T0051.001', 'check': '_sim_check_llm_input_validation'},
            {'tactic': 'Defense Evasion', 'technique': 'LLM Jailbreak', 'id': 'AML.T0054', 'check': '_sim_check_llm_output_filtering'},
            {'tactic': 'Exfiltration', 'technique': 'Data Leakage via LLM', 'id': 'AML.T0057', 'check': '_sim_check_llm_output_filtering'},
            {'tactic': 'Credential Access', 'technique': 'Sensitive Data Extraction', 'id': 'AML.T0057', 'check': '_sim_check_ai_access_controls'},
        ],
    },
    'ai_copilot_attack': {
        'name': 'Microsoft Copilot Compromise',
        'aliases': ['EchoLeak', 'Reprompt Attack'],
        'attribution': 'technique_based',
        'motivation': 'data_exfiltration',
        'target_sectors': ['any_m365_organization'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Indirect Prompt Injection via Docs', 'id': 'AML.T0051.001', 'check': '_sim_check_copilot_security'},
            {'tactic': 'Exfiltration', 'technique': 'EchoLeak Data Leakage', 'id': 'AML.T0057', 'check': '_sim_check_copilot_security'},
            {'tactic': 'Execution', 'technique': 'Plugin/Connector Compromise', 'id': 'AML.T0053', 'check': '_sim_check_copilot_security'},
            {'tactic': 'Collection', 'technique': 'Email via Copilot', 'id': 'T1114', 'check': '_sim_check_ai_access_controls'},
            {'tactic': 'Defense Evasion', 'technique': 'Jailbreak Content Filter', 'id': 'AML.T0054', 'check': '_sim_check_llm_output_filtering'},
        ],
    },
    'ai_agent_hijack': {
        'name': 'AI Agent Manipulation',
        'aliases': [],
        'attribution': 'technique_based',
        'motivation': 'control + exfiltration',
        'target_sectors': ['any_ai_agent_deployment'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Prompt Injection for Tool Abuse', 'id': 'AML.T0051', 'check': '_sim_check_agent_guardrails'},
            {'tactic': 'Execution', 'technique': 'Unauthorized Tool Invocation', 'id': 'AML.T0053', 'check': '_sim_check_agent_guardrails'},
            {'tactic': 'Persistence', 'technique': 'Memory Manipulation', 'id': 'AML.T0051', 'check': '_sim_check_agent_guardrails'},
            {'tactic': 'Impact', 'technique': 'Self-Replication', 'id': 'AML.T0061', 'check': '_sim_check_agent_guardrails'},
            {'tactic': 'Exfiltration', 'technique': 'Data via Agent Actions', 'id': 'AML.T0057', 'check': '_sim_check_ai_access_controls'},
        ],
    },
    'ai_supply_chain': {
        'name': 'AI/ML Supply Chain Attack',
        'aliases': [],
        'attribution': 'technique_based',
        'motivation': 'compromise',
        'target_sectors': ['any_ml_deployment'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Poisoned Model Upload', 'id': 'AML.T0058', 'check': '_sim_check_model_integrity'},
            {'tactic': 'Execution', 'technique': 'Malicious Package Install', 'id': 'AML.T0010.003', 'check': '_sim_check_supply_chain_integrity'},
            {'tactic': 'Defense Evasion', 'technique': 'Hallucinated Package Names', 'id': 'AML.T0060', 'check': '_sim_check_model_integrity'},
            {'tactic': 'Persistence', 'technique': 'Backdoored Model Weights', 'id': 'AML.T0058', 'check': '_sim_check_model_integrity'},
        ],
    },

    # --- Technique-Specific (5) ---
    'golden_saml': {
        'name': 'Golden SAML / Identity Federation Abuse',
        'aliases': [],
        'attribution': 'technique_based',
        'motivation': 'persistence',
        'target_sectors': ['any'],
        'ttps': [
            {'tactic': 'Credential Access', 'technique': 'SAML Token Forging', 'id': 'T1606', 'check': '_sim_check_mfa_enforcement'},
            {'tactic': 'Persistence', 'technique': 'Federation Trust Manipulation', 'id': 'T1484', 'check': '_sim_check_account_policies'},
            {'tactic': 'Lateral Movement', 'technique': 'Cloud Service Access', 'id': 'T1550', 'check': '_sim_check_mfa_enforcement'},
        ],
    },
    'kerberoast': {
        'name': 'Kerberoasting / Service Ticket Cracking',
        'aliases': [],
        'attribution': 'technique_based',
        'motivation': 'credential_access',
        'target_sectors': ['any_active_directory'],
        'ttps': [
            {'tactic': 'Credential Access', 'technique': 'Kerberoasting', 'id': 'T1558.003', 'check': '_sim_check_account_policies'},
            {'tactic': 'Credential Access', 'technique': 'AS-REP Roasting', 'id': 'T1558.004', 'check': '_sim_check_account_policies'},
            {'tactic': 'Lateral Movement', 'technique': 'Pass the Ticket', 'id': 'T1550', 'check': '_sim_check_credential_hygiene'},
        ],
    },
    'container_escape': {
        'name': 'Container Breakout',
        'aliases': [],
        'attribution': 'technique_based',
        'motivation': 'privilege_escalation',
        'target_sectors': ['any_containerized'],
        'ttps': [
            {'tactic': 'Privilege Escalation', 'technique': 'Container Escape', 'id': 'T1611', 'check': '_sim_check_service_exposure'},
            {'tactic': 'Execution', 'technique': 'Privileged Container Abuse', 'id': 'T1610', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Persistence', 'technique': 'Writable Host Mount', 'id': 'T1611', 'check': '_sim_check_file_integrity'},
        ],
    },
    'supply_chain': {
        'name': 'Dependency Confusion / Supply Chain',
        'aliases': [],
        'attribution': 'technique_based',
        'motivation': 'compromise',
        'target_sectors': ['software_development'],
        'ttps': [
            {'tactic': 'Initial Access', 'technique': 'Dependency Confusion', 'id': 'T1195.001', 'check': '_sim_check_supply_chain_integrity'},
            {'tactic': 'Execution', 'technique': 'Typosquatting Packages', 'id': 'T1195.002', 'check': '_sim_check_supply_chain_integrity'},
            {'tactic': 'Persistence', 'technique': 'Compromised CI/CD', 'id': 'T1195', 'check': '_sim_check_supply_chain_integrity'},
        ],
    },
    'lolbins': {
        'name': 'Living Off The Land Binaries',
        'aliases': ['LOLBins', 'LOLBAS'],
        'attribution': 'technique_based',
        'motivation': 'defense_evasion',
        'target_sectors': ['any'],
        'ttps': [
            {'tactic': 'Execution', 'technique': 'Signed Binary Proxy Execution', 'id': 'T1218', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Defense Evasion', 'technique': 'Trusted Developer Utils', 'id': 'T1127', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Discovery', 'technique': 'System Binary Abuse', 'id': 'T1082', 'check': '_sim_check_logging_coverage'},
            {'tactic': 'Credential Access', 'technique': 'Credential Access via LOLBin', 'id': 'T1003', 'check': '_sim_check_credential_hygiene'},
        ],
    },
}


# =========================================================================== #
#  Detection Status                                                           #
# =========================================================================== #

DETECTED = 'DETECTED'
PARTIAL = 'PARTIAL'
NOT_DETECTED = 'NOT_DETECTED'

# Map YAML-friendly simulation_check names to actual method names.
# YAML profiles use human-readable names; this resolves them to _sim_* methods.
YAML_CHECK_MAP: Dict[str, str] = {
    # MFA / identity
    'check_mfa_bypass_resilience': '_sim_check_mfa_enforcement',
    'check_phishing_resilience': '_sim_check_mfa_enforcement',
    'check_vpn_credential_abuse': '_sim_check_mfa_enforcement',
    'check_oauth_token_anomalies': '_sim_check_mfa_enforcement',
    'check_account_usage_anomalies': '_sim_check_mfa_enforcement',
    # Account policies
    'check_new_account_creation': '_sim_check_account_policies',
    'check_admin_policy_changes': '_sim_check_account_policies',
    'check_cloud_account_anomalies': '_sim_check_account_policies',
    'check_brute_force_indicators': '_sim_check_account_policies',
    # SSH / remote access
    'check_external_rdp_exposure': '_sim_check_ssh_hardening',
    'check_rdp_lateral_movement': '_sim_check_ssh_hardening',
    'check_remote_access_anomalies': '_sim_check_ssh_hardening',
    'check_lateral_movement_rdp_smb': '_sim_check_ssh_hardening',
    'check_lateral_movement_indicators': '_sim_check_ssh_hardening',
    # Firewall / egress / exfil
    'check_cloud_exfil_channels': '_sim_check_firewall_egress',
    'check_data_exfil_volume': '_sim_check_firewall_egress',
    'check_proxy_chain_indicators': '_sim_check_firewall_egress',
    'check_dos_indicators': '_sim_check_firewall_egress',
    # Logging / execution
    'check_scripting_execution': '_sim_check_logging_coverage',
    'check_powershell_abuse': '_sim_check_logging_coverage',
    'check_service_tampering': '_sim_check_logging_coverage',
    'check_log_clearing': '_sim_check_logging_coverage',
    'check_lolbin_usage': '_sim_check_logging_coverage',
    'check_native_tool_abuse': '_sim_check_logging_coverage',
    'check_email_access_anomalies': '_sim_check_logging_coverage',
    'check_local_data_staging': '_sim_check_logging_coverage',
    'check_ot_data_collection': '_sim_check_logging_coverage',
    # IDS / C2
    'check_c2_web_traffic': '_sim_check_dns_monitoring',
    'check_soho_proxy_c2': '_sim_check_dns_monitoring',
    'check_watering_hole_indicators': '_sim_check_dns_monitoring',
    # Credential hygiene
    'check_credential_dump_artifacts': '_sim_check_credential_hygiene',
    'check_lsass_access': '_sim_check_credential_hygiene',
    # Backup / ransomware
    'check_ransomware_indicators': '_sim_check_backup_integrity',
    'check_backup_integrity': '_sim_check_backup_integrity',
    'check_wiper_indicators': '_sim_check_backup_integrity',
    # File integrity / evasion
    'check_security_tool_tampering': '_sim_check_file_integrity',
    'check_obfuscation_indicators': '_sim_check_file_integrity',
    'check_masquerading_indicators': '_sim_check_file_integrity',
    'check_custom_malware_execution': '_sim_check_file_integrity',
    'check_autostart_persistence': '_sim_check_file_integrity',
    'check_defense_impairment': '_sim_check_file_integrity',
    'check_keylogger_artifacts': '_sim_check_file_integrity',
    # Service exposure
    'check_public_app_vulns': '_sim_check_service_exposure',
    'check_soho_router_compromise': '_sim_check_service_exposure',
    # Supply chain
    'check_supply_chain_integrity': '_sim_check_supply_chain_integrity',
    'check_ics_supply_chain': '_sim_check_supply_chain_integrity',
    # ICS / OT
    'check_ics_service_disruption': '_sim_check_ics_network_segmentation',
    'check_ics_lateral_movement': '_sim_check_ics_network_segmentation',
    'check_plc_program_integrity': '_sim_check_plc_access_controls',
    'check_controller_task_changes': '_sim_check_plc_access_controls',
    'check_hmi_exposure': '_sim_check_scada_exposure',
    'check_ics_remote_access': '_sim_check_scada_exposure',
    'check_control_denial': '_sim_check_safety_systems',
    # AI / LLM
    'check_prompt_injection_docs': '_sim_check_llm_input_validation',
    'check_llm_data_leakage': '_sim_check_llm_output_filtering',
    'check_jailbreak_attempts': '_sim_check_llm_output_filtering',
    'check_copilot_plugin_security': '_sim_check_copilot_security',
    'check_copilot_email_access': '_sim_check_ai_access_controls',
    'check_copilot_repo_access': '_sim_check_ai_access_controls',
}


# =========================================================================== #
#  AdversaryScanner                                                           #
# =========================================================================== #

class AdversaryScanner(BaseScanner):
    """Purple team adversary emulation and defense validation scanner."""

    SCANNER_NAME = "adversary"
    SCANNER_DESCRIPTION = "Adversary emulation and defense validation"
    ADVERSARY_PROFILES = ADVERSARY_PROFILES  # expose module-level dict as class attr

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self._profiles = dict(ADVERSARY_PROFILES)
        self._load_yaml_overrides()

    # -------------------------------------------------------------------
    # YAML override loading
    # -------------------------------------------------------------------

    def _load_yaml_overrides(self) -> None:
        """Load YAML profile overrides from config/adversary_profiles/."""
        profiles_dir = Path(__file__).parent.parent / 'config' / 'adversary_profiles'
        if not profiles_dir.is_dir():
            return

        try:
            import yaml
        except ImportError:
            self.scan_logger.debug("PyYAML not available; skipping profile overrides")
            return

        for yaml_file in profiles_dir.glob('*.yaml'):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding='utf-8'))
                if not data or 'profile' not in data:
                    continue
                profile = data['profile']
                pid = profile.get('id')
                if not pid:
                    continue

                if pid in self._profiles:
                    # Merge: YAML overrides embedded values
                    existing = self._profiles[pid]
                    if 'name' in profile:
                        existing['name'] = profile['name']
                    if 'ttps' in profile:
                        yaml_ttps = []
                        for ttp in profile['ttps']:
                            raw_check = ttp.get('simulation_check', '_sim_generic_check')
                            check = YAML_CHECK_MAP.get(raw_check, raw_check)
                            yaml_ttps.append({
                                'tactic': ttp.get('tactic', ''),
                                'technique': ttp.get('technique', ''),
                                'id': ttp.get('technique_id', ''),
                                'check': check,
                                'description': ttp.get('description', ''),
                            })
                        existing['ttps'] = yaml_ttps
                    if 'target_sectors' in profile:
                        existing['target_sectors'] = profile['target_sectors']
                else:
                    # New profile from YAML
                    ttps = []
                    for ttp in profile.get('ttps', []):
                        raw_check = ttp.get('simulation_check', '_sim_generic_check')
                        check = YAML_CHECK_MAP.get(raw_check, raw_check)
                        ttps.append({
                            'tactic': ttp.get('tactic', ''),
                            'technique': ttp.get('technique', ''),
                            'id': ttp.get('technique_id', ''),
                            'check': check,
                        })
                    self._profiles[pid] = {
                        'name': profile.get('name', pid),
                        'aliases': profile.get('aliases', []),
                        'attribution': profile.get('attribution', 'unknown'),
                        'motivation': profile.get('motivation', 'unknown'),
                        'target_sectors': profile.get('target_sectors', []),
                        'ttps': ttps,
                    }
                self.scan_logger.debug("Loaded profile override: %s", pid)
            except Exception as exc:
                self.scan_logger.warning("Failed to load %s: %s", yaml_file.name, exc)

    # -------------------------------------------------------------------
    # Core helpers
    # -------------------------------------------------------------------

    def _run_cmd(self, cmd: str, timeout: int = 30) -> Optional[str]:
        """Execute a command, return stdout or None."""
        try:
            proc = subprocess.run(
                shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode != 0:
                return None
            return (proc.stdout or '').strip() or None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return None

    def _run_cmd_lines(self, cmd: str, timeout: int = 30) -> List[str]:
        raw = self._run_cmd(cmd, timeout=timeout)
        if raw is None:
            return []
        return [line for line in raw.splitlines() if line.strip()]

    # -------------------------------------------------------------------
    # scan()
    # -------------------------------------------------------------------

    def scan(self, targets=None, scan_type: str = 'standard',
             profile: str = 'all', **kwargs) -> Dict:
        """Run adversary emulation defense validation.

        Parameters
        ----------
        profile : str
            Profile ID, comma-separated list, or ``'all'``.
        scan_type : str
            ``'quick'`` runs first 5 profiles, ``'standard'`` top 15,
            ``'deep'`` runs all profiles.
        """
        self.start_time = datetime.now(timezone.utc)

        # Determine which profiles to run
        if profile == 'all':
            if scan_type == 'quick':
                selected = list(self._profiles.keys())[:5]
            elif scan_type == 'standard':
                selected = list(self._profiles.keys())[:15]
            else:
                selected = list(self._profiles.keys())
        else:
            selected = [p.strip() for p in profile.split(',') if p.strip() in self._profiles]
            if not selected:
                self.scan_logger.warning("No matching profiles found for: %s", profile)
                selected = list(self._profiles.keys())[:5]

        self.scan_logger.info(
            "Adversary emulation: %d profiles, scan_type=%s", len(selected), scan_type
        )

        results: Dict[str, Any] = {
            'scanner': self.SCANNER_NAME,
            'scan_type': scan_type,
            'profiles_tested': len(selected),
            'scorecards': [],
        }

        for pid in selected:
            try:
                scorecard = self._run_profile(pid)
                results['scorecards'].append(scorecard)
            except Exception as exc:
                self.scan_logger.warning("Profile %s failed: %s", pid, exc)

        # Overall summary
        total_techniques = 0
        total_detected = 0
        total_partial = 0
        total_not_detected = 0

        for sc in results['scorecards']:
            for t in sc.get('techniques', []):
                total_techniques += 1
                if t['status'] == DETECTED:
                    total_detected += 1
                elif t['status'] == PARTIAL:
                    total_partial += 1
                else:
                    total_not_detected += 1

        detection_rate = (
            (total_detected + 0.5 * total_partial) / total_techniques * 100
            if total_techniques > 0 else 0
        )
        results['overall'] = {
            'total_techniques': total_techniques,
            'detected': total_detected,
            'partial': total_partial,
            'not_detected': total_not_detected,
            'detection_rate': round(detection_rate, 1),
            'grade': self._grade(detection_rate),
        }

        self.end_time = datetime.now(timezone.utc)
        results['summary'] = self.get_summary()
        self.save_results()
        return results

    # -------------------------------------------------------------------
    # Profile execution
    # -------------------------------------------------------------------

    def _run_profile(self, profile_id: str) -> Dict:
        """Run all TTP checks for a single adversary profile."""
        profile = self._profiles[profile_id]
        hostname = self._run_cmd('hostname') or 'localhost'
        techniques = []

        for ttp in profile['ttps']:
            check_method = ttp.get('check', '_sim_generic_check')
            method = getattr(self, check_method, self._sim_generic_check)

            try:
                status = method(ttp)
            except Exception:
                status = NOT_DETECTED

            techniques.append({
                'tactic': ttp['tactic'],
                'technique': ttp['technique'],
                'attack_id': ttp['id'],
                'check': check_method,
                'status': status,
            })

            # Create finding for gaps
            if status == NOT_DETECTED:
                self.add_finding(
                    severity='HIGH',
                    title='Defense Gap: {} - {}'.format(profile['name'], ttp['technique']),
                    description=(
                        'Adversary emulation for {} found no defense coverage for '
                        'technique {} ({}, {}). An attacker using this technique '
                        'would likely go undetected.'.format(
                            profile['name'], ttp['technique'],
                            ttp['id'], ttp['tactic'],
                        )
                    ),
                    affected_asset=hostname,
                    finding_type='detection_gap',
                    cvss_score=7.5,
                    remediation='Implement detection for {} ({}).'.format(
                        ttp['technique'], ttp['id']
                    ),
                    detection_method='adversary_emulation',
                )
            elif status == PARTIAL:
                self.add_finding(
                    severity='MEDIUM',
                    title='Partial Coverage: {} - {}'.format(profile['name'], ttp['technique']),
                    description=(
                        'Adversary emulation for {} found partial defense coverage '
                        'for technique {} ({}, {}). Some defensive controls exist '
                        'but gaps remain.'.format(
                            profile['name'], ttp['technique'],
                            ttp['id'], ttp['tactic'],
                        )
                    ),
                    affected_asset=hostname,
                    finding_type='detection_gap',
                    cvss_score=5.0,
                    remediation='Strengthen detection for {} ({}).'.format(
                        ttp['technique'], ttp['id']
                    ),
                    detection_method='adversary_emulation',
                )

        # Compute scorecard
        detected_count = sum(1 for t in techniques if t['status'] == DETECTED)
        partial_count = sum(1 for t in techniques if t['status'] == PARTIAL)
        total = len(techniques)
        rate = (detected_count + 0.5 * partial_count) / total * 100 if total > 0 else 0
        gaps = sum(1 for t in techniques if t['status'] == NOT_DETECTED)

        scorecard = {
            'profile_id': profile_id,
            'name': profile['name'],
            'attribution': profile.get('attribution', ''),
            'motivation': profile.get('motivation', ''),
            'techniques': techniques,
            'detection_rate': round(rate, 1),
            'grade': self._grade(rate),
            'critical_gaps': gaps,
        }

        # Log scorecard to INFO finding
        self.add_finding(
            severity='INFO',
            title='Adversary Scorecard: {} | Grade: {} | Detection: {}%'.format(
                profile['name'], scorecard['grade'], scorecard['detection_rate']
            ),
            description='Tested {} techniques. Detected: {}, Partial: {}, Not Detected: {}'.format(
                total, detected_count, partial_count, gaps
            ),
            affected_asset=hostname,
            finding_type='adversary_scorecard',
            detection_method='adversary_emulation',
        )

        return scorecard

    @staticmethod
    def _grade(rate: float) -> str:
        """Letter grade from detection rate percentage."""
        if rate >= 90:
            return 'A'
        elif rate >= 80:
            return 'B'
        elif rate >= 70:
            return 'C'
        elif rate >= 60:
            return 'D'
        return 'F'

    # ===================================================================== #
    #  Safe Simulation Checks — Infrastructure & Network                    #
    # ===================================================================== #

    def _sim_check_mfa_enforcement(self, ttp: Dict) -> str:
        """Check MFA and authentication hardening."""
        score = 0

        # PAM 2FA module?
        pam_2fa = self._run_cmd(
            'grep -rl "pam_google_authenticator\\|pam_duo\\|pam_u2f\\|pam_yubico" '
            '/etc/pam.d/ 2>/dev/null'
        )
        if pam_2fa:
            score += 2

        # SSH key-only auth?
        sshd = self._run_cmd('cat /etc/ssh/sshd_config 2>/dev/null')
        if sshd:
            if re.search(r'^\s*PasswordAuthentication\s+no', sshd, re.MULTILINE | re.IGNORECASE):
                score += 2
            if re.search(r'^\s*PubkeyAuthentication\s+yes', sshd, re.MULTILINE | re.IGNORECASE):
                score += 1

        # Account lockout configured?
        faillock = self._run_cmd(
            'grep -r "pam_faillock\\|pam_tally2" /etc/pam.d/ 2>/dev/null'
        )
        if faillock:
            score += 1

        if score >= 4:
            return DETECTED
        elif score >= 2:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_account_policies(self, ttp: Dict) -> str:
        """Check password/account policies."""
        score = 0

        login_defs = self._run_cmd('cat /etc/login.defs 2>/dev/null')
        if login_defs:
            m = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
            if m and int(m.group(1)) <= 365:
                score += 1
            m = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
            if m and int(m.group(1)) >= 1:
                score += 1
            m = re.search(r'^PASS_MIN_LEN\s+(\d+)', login_defs, re.MULTILINE)
            if m and int(m.group(1)) >= 14:
                score += 1

        # Inactive account cleanup
        useradd_defaults = self._run_cmd('useradd -D 2>/dev/null')
        if useradd_defaults and 'INACTIVE' in useradd_defaults:
            m = re.search(r'INACTIVE=(\d+)', useradd_defaults)
            if m and 0 < int(m.group(1)) <= 90:
                score += 1

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_ssh_hardening(self, ttp: Dict) -> str:
        """Check SSH server hardening."""
        sshd = self._run_cmd('cat /etc/ssh/sshd_config 2>/dev/null')
        if not sshd:
            return NOT_DETECTED

        dropin = self._run_cmd('cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null')
        full = sshd + '\n' + (dropin or '')
        score = 0

        checks = [
            (r'^\s*PermitRootLogin\s+(no|prohibit-password)', 1),
            (r'^\s*MaxAuthTries\s+([1-4])\b', 1),
            (r'^\s*X11Forwarding\s+no', 1),
            (r'^\s*PasswordAuthentication\s+no', 1),
            (r'^\s*PermitEmptyPasswords\s+no', 1),
            (r'^\s*ClientAliveInterval\s+(\d+)', 1),
        ]
        for pattern, points in checks:
            if re.search(pattern, full, re.MULTILINE | re.IGNORECASE):
                score += points

        if score >= 4:
            return DETECTED
        elif score >= 2:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_firewall_egress(self, ttp: Dict) -> str:
        """Check outbound firewall filtering."""
        score = 0

        # iptables OUTPUT chain
        ipt = self._run_cmd('iptables -L OUTPUT -n 2>/dev/null')
        if ipt and 'DROP' in ipt:
            score += 2
        elif ipt and 'REJECT' in ipt:
            score += 2

        # nftables
        nft = self._run_cmd('nft list ruleset 2>/dev/null')
        if nft and 'output' in nft.lower() and ('drop' in nft.lower() or 'reject' in nft.lower()):
            score += 2

        # firewalld
        fwd = self._run_cmd('firewall-cmd --list-rich-rules 2>/dev/null')
        if fwd and 'reject' in fwd.lower():
            score += 1

        # ufw
        ufw = self._run_cmd('ufw status 2>/dev/null')
        if ufw and 'Status: active' in ufw:
            if 'Default: deny (outgoing)' in ufw:
                score += 2
            else:
                score += 1

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_logging_coverage(self, ttp: Dict) -> str:
        """Check logging coverage for technique data sources."""
        score = 0

        # auditd running?
        auditd = self._run_cmd('systemctl is-active auditd 2>/dev/null')
        if auditd and 'active' in auditd:
            score += 1

            # Check for audit rules
            rules = self._run_cmd('auditctl -l 2>/dev/null')
            if rules and 'No rules' not in rules:
                rule_count = len([l for l in rules.splitlines() if l.strip()])
                if rule_count >= 10:
                    score += 2
                elif rule_count >= 1:
                    score += 1

        # syslog / journald
        journald = self._run_cmd('systemctl is-active systemd-journald 2>/dev/null')
        if journald and 'active' in journald:
            score += 1

        # Remote log forwarding?
        rsyslog = self._run_cmd(
            'grep -r "@@\\|@" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | '
            'grep -v "^#"'
        )
        if rsyslog:
            score += 1

        if score >= 4:
            return DETECTED
        elif score >= 2:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_ids_rules(self, ttp: Dict) -> str:
        """Check for IDS/IPS rules (suricata, zeek, snort)."""
        score = 0

        for ids_tool in ['suricata', 'zeek', 'snort']:
            if shutil.which(ids_tool):
                score += 2
                break

        svc = self._run_cmd(
            'systemctl is-active suricata 2>/dev/null || '
            'systemctl is-active zeek 2>/dev/null || '
            'systemctl is-active snort 2>/dev/null'
        )
        if svc and 'active' in svc:
            score += 2

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_credential_hygiene(self, ttp: Dict) -> str:
        """Check credential storage and rotation hygiene."""
        score = 0

        # Check for credential files in common locations
        cred_files = self._run_cmd(
            'find /home /root /etc -maxdepth 3 -name "*.pem" -o -name "id_rsa" '
            '-o -name ".pgpass" -o -name ".my.cnf" -o -name ".netrc" '
            '2>/dev/null | wc -l'
        )
        if cred_files:
            try:
                count = int(cred_files.strip())
                if count == 0:
                    score += 2
                elif count <= 3:
                    score += 1
            except ValueError:
                pass

        # SSH key has passphrase? (check if agent is running)
        ssh_agent = self._run_cmd('pgrep -x ssh-agent 2>/dev/null')
        if ssh_agent:
            score += 1

        # Check shadow permissions
        shadow_perms = self._run_cmd('stat -c "%a" /etc/shadow 2>/dev/null')
        if shadow_perms and shadow_perms.strip() in ('600', '640'):
            score += 1

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_backup_integrity(self, ttp: Dict) -> str:
        """Check backup configuration and immutable storage."""
        score = 0

        # Check for backup tools
        for tool in ['restic', 'borg', 'borgbackup', 'duplicity', 'rdiff-backup']:
            if shutil.which(tool):
                score += 1
                break

        # Systemd backup timers
        timers = self._run_cmd(
            'systemctl list-timers --all 2>/dev/null | grep -i backup'
        )
        if timers:
            score += 1

        # Cron backup jobs
        cron_backup = self._run_cmd(
            'grep -rl "backup\\|rsync\\|borg\\|restic" /etc/cron* 2>/dev/null'
        )
        if cron_backup:
            score += 1

        # Immutable flag on critical files
        immutable = self._run_cmd(
            'lsattr /etc/passwd /etc/shadow 2>/dev/null | grep -c "i"'
        )
        if immutable:
            try:
                if int(immutable.strip()) > 0:
                    score += 1
            except ValueError:
                pass

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_file_integrity(self, ttp: Dict) -> str:
        """Check file integrity monitoring (AIDE, OSSEC, etc.)."""
        score = 0

        for fim_tool in ['aide', 'ossec', 'wazuh-agent', 'tripwire', 'samhain']:
            if shutil.which(fim_tool):
                score += 2
                break

        # AIDE DB exists?
        aide_db = self._run_cmd(
            'test -f /var/lib/aide/aide.db -o -f /var/lib/aide/aide.db.gz && echo yes'
        )
        if aide_db:
            score += 1

        # OSSEC / Wazuh agent running?
        fim_svc = self._run_cmd(
            'systemctl is-active wazuh-agent 2>/dev/null || '
            'systemctl is-active ossec 2>/dev/null'
        )
        if fim_svc and 'active' in fim_svc:
            score += 2

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_dns_monitoring(self, ttp: Dict) -> str:
        """Check DNS logging and tunneling detection."""
        score = 0

        # DNS logging in systemd-resolved or dnsmasq
        resolved = self._run_cmd(
            'resolvectl status 2>/dev/null | grep -i "DNS"'
        )
        if resolved:
            score += 1

        # Check for DNS-specific logging rules in auditd
        audit_dns = self._run_cmd(
            'auditctl -l 2>/dev/null | grep -i "53\\|dns"'
        )
        if audit_dns:
            score += 1

        # Suricata/zeek DNS rules
        dns_rules = self._run_cmd(
            'grep -rl "dns" /etc/suricata/rules/ 2>/dev/null || '
            'test -d /opt/zeek/share/zeek/policy/protocols/dns && echo yes'
        )
        if dns_rules:
            score += 2

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_service_exposure(self, ttp: Dict) -> str:
        """Check for unnecessary exposed services and public ports."""
        score = 0

        # Count all-interface listeners
        ss_output = self._run_cmd('ss -tlnp 2>/dev/null')
        if ss_output:
            all_iface_count = 0
            for line in ss_output.splitlines():
                if re.search(r'(0\.0\.0\.0|::|\*):(\d+)', line):
                    all_iface_count += 1
            if all_iface_count <= 5:
                score += 2
            elif all_iface_count <= 10:
                score += 1

        # Firewall active?
        fw = self._run_cmd(
            'ufw status 2>/dev/null | grep -c "Status: active" || '
            'systemctl is-active firewalld 2>/dev/null'
        )
        if fw and ('active' in fw or '1' in fw):
            score += 2

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_supply_chain_integrity(self, ttp: Dict) -> str:
        """Check dependency signing and lock files."""
        score = 0

        # Package manager GPG verification
        apt_verify = self._run_cmd(
            'apt-config dump 2>/dev/null | grep -i "AllowUnauthenticated"'
        )
        if apt_verify and 'false' in apt_verify.lower():
            score += 1
        elif apt_verify is None:
            # Default is to verify, so if config doesn't exist, it's OK
            rpm_gpg = self._run_cmd('rpm -q gpg-pubkey 2>/dev/null | wc -l')
            if rpm_gpg:
                try:
                    if int(rpm_gpg.strip()) > 0:
                        score += 1
                except ValueError:
                    pass

        # Lock files in project directories
        lock_files = self._run_cmd(
            'find /home /opt /srv -maxdepth 4 '
            '\\( -name "package-lock.json" -o -name "yarn.lock" '
            '-o -name "Pipfile.lock" -o -name "poetry.lock" '
            '-o -name "Cargo.lock" -o -name "go.sum" \\) '
            '-type f 2>/dev/null | head -5'
        )
        if lock_files:
            score += 1

        # .gitignore doesn't include lock files (checking one level)
        gitignore_ok = self._run_cmd(
            'find /home /opt /srv -maxdepth 3 -name ".gitignore" -exec '
            'grep -l "package-lock\\|yarn.lock\\|Pipfile.lock" {} \\; '
            '2>/dev/null | wc -l'
        )
        if gitignore_ok:
            try:
                if int(gitignore_ok.strip()) == 0:
                    score += 1  # Good: lock files are NOT gitignored
            except ValueError:
                pass

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    # ===================================================================== #
    #  Safe Simulation Checks — ICS/OT-Specific                            #
    # ===================================================================== #

    def _sim_check_ics_network_segmentation(self, ttp: Dict) -> str:
        """Check IT/OT network boundary and segmentation."""
        score = 0

        # Multiple network interfaces (potential IT/OT boundary)
        interfaces = self._run_cmd(
            'ip -o link show 2>/dev/null | grep -c "state UP"'
        )
        if interfaces:
            try:
                if int(interfaces.strip()) >= 2:
                    score += 1  # Multiple interfaces suggests segmentation
            except ValueError:
                pass

        # VLANs configured?
        vlans = self._run_cmd('ip -d link show 2>/dev/null | grep -c "vlan"')
        if vlans:
            try:
                if int(vlans.strip()) > 0:
                    score += 1
            except ValueError:
                pass

        # Firewall rules between zones
        fw_zones = self._run_cmd('firewall-cmd --get-zones 2>/dev/null')
        if fw_zones and len(fw_zones.split()) >= 3:
            score += 2

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_plc_access_controls(self, ttp: Dict) -> str:
        """Check PLC authentication and firmware integrity controls."""
        score = 0

        # Check if common ICS ports are exposed
        ics_ports = [502, 102, 44818, 47808, 20000, 2222]
        ss_output = self._run_cmd('ss -tlnp 2>/dev/null')
        if ss_output:
            exposed = 0
            for port in ics_ports:
                if ':{}'.format(port) in ss_output:
                    exposed += 1
            if exposed == 0:
                score += 2  # No ICS ports exposed = good
            elif exposed <= 2:
                score += 1

        # Check for OPC UA security
        opcua = self._run_cmd(
            'grep -r "SecurityPolicy\\|SecurityMode" /etc/ 2>/dev/null | '
            'grep -iv "none"'
        )
        if opcua:
            score += 1

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_scada_exposure(self, ttp: Dict) -> str:
        """Check HMI/SCADA internet exposure."""
        score = 0

        # VNC not exposed on all interfaces
        vnc_exposed = self._run_cmd(
            'ss -tlnp 2>/dev/null | grep ":590[0-9]" | grep "0.0.0.0\\|::\\|\\*"'
        )
        if not vnc_exposed:
            score += 2

        # No HMI web interface on all interfaces
        hmi_ports = [8080, 8443, 80, 443]
        ss_output = self._run_cmd('ss -tlnp 2>/dev/null')
        if ss_output:
            hmi_exposed = 0
            for port in hmi_ports:
                pattern = '(0\\.0\\.0\\.0|::|\\*):{}\\b'.format(port)
                if re.search(pattern, ss_output):
                    hmi_exposed += 1
            if hmi_exposed == 0:
                score += 1

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_safety_systems(self, ttp: Dict) -> str:
        """Check SIS independence and physical interlocks."""
        # Safety systems are typically not detectable from a standard Linux host.
        # We check for network isolation indicators.
        score = 0

        # Separate safety network (check for multiple subnets)
        routes = self._run_cmd('ip route show 2>/dev/null')
        if routes:
            subnets = len([l for l in routes.splitlines() if l.strip() and 'dev' in l])
            if subnets >= 3:
                score += 1  # Multiple subnets suggest safety segmentation

        # ICS-specific firewall rules
        fw = self._run_cmd(
            'iptables -L -n 2>/dev/null | grep -i "502\\|44818\\|102"'
        )
        if fw:
            score += 1

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    # ===================================================================== #
    #  Safe Simulation Checks — AI/LLM-Specific                            #
    # ===================================================================== #

    def _sim_check_llm_input_validation(self, ttp: Dict) -> str:
        """Check for LLM prompt sanitization and injection detection."""
        score = 0

        # Check for content filtering libraries
        pip_output = self._run_cmd(
            'pip3 list 2>/dev/null | grep -i '
            '"guardrails\\|nemo-guardrails\\|rebuff\\|prompt-guard\\|lakera"'
        )
        if pip_output:
            score += 2

        # WAF rules for prompt injection
        waf_rules = self._run_cmd(
            'grep -rl "prompt.*inject\\|llm.*filter" /etc/nginx/ /etc/apache2/ '
            '/etc/httpd/ /etc/modsecurity/ 2>/dev/null'
        )
        if waf_rules:
            score += 2

        # Input validation in application configs
        app_config = self._run_cmd(
            'grep -rl "content_filter\\|input_sanitiz\\|prompt_guard" '
            '/opt/ /srv/ /home/ 2>/dev/null | head -3'
        )
        if app_config:
            score += 1

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_llm_output_filtering(self, ttp: Dict) -> str:
        """Check LLM output guardrails and PII detection."""
        score = 0

        # PII detection libraries
        pip_output = self._run_cmd(
            'pip3 list 2>/dev/null | grep -i '
            '"presidio\\|pii.*detect\\|scrubadub\\|spacy"'
        )
        if pip_output:
            score += 2

        # Output filtering configuration
        output_filter = self._run_cmd(
            'grep -rl "output_filter\\|content_policy\\|response_guard" '
            '/opt/ /srv/ /home/ 2>/dev/null | head -3'
        )
        if output_filter:
            score += 1

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_ai_access_controls(self, ttp: Dict) -> str:
        """Check AI model API authentication and rate limiting."""
        score = 0

        # Ollama bound to localhost only?
        ollama_listen = self._run_cmd(
            'ss -tlnp 2>/dev/null | grep ":11434" | grep "127.0.0.1"'
        )
        if ollama_listen:
            score += 2
        else:
            # Check if Ollama is bound to all interfaces (bad)
            ollama_all = self._run_cmd(
                'ss -tlnp 2>/dev/null | grep ":11434" | grep "0.0.0.0\\|::"'
            )
            if ollama_all:
                score -= 1  # Penalty

        # API auth in reverse proxy
        proxy_auth = self._run_cmd(
            'grep -rl "auth_basic\\|auth_request\\|api_key" '
            '/etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null | head -3'
        )
        if proxy_auth:
            score += 1

        # Rate limiting
        rate_limit = self._run_cmd(
            'grep -rl "limit_req\\|rate.*limit" '
            '/etc/nginx/ /etc/apache2/ 2>/dev/null | head -3'
        )
        if rate_limit:
            score += 1

        if score >= 3:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_copilot_security(self, ttp: Dict) -> str:
        """Check M365 Copilot DLP policies and sensitivity labels."""
        # M365 Copilot controls are cloud-side; check for local indicators
        score = 0

        # DLP policy enforcement (check for Microsoft Purview agent)
        purview = self._run_cmd(
            'systemctl is-active mdatp 2>/dev/null || '
            'pgrep -x MsSenseS 2>/dev/null'
        )
        if purview:
            score += 1

        # Information protection client
        aip_client = self._run_cmd(
            'pip3 list 2>/dev/null | grep -i "mip\\|msip\\|azure.*information"'
        )
        if aip_client:
            score += 1

        # Conditional access (Azure AD/Entra joined)
        aad_join = self._run_cmd(
            'dsregcmd /status 2>/dev/null | grep -i "AzureAdJoined" || '
            'test -f /etc/aad.conf && echo yes'
        )
        if aad_join:
            score += 1

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_agent_guardrails(self, ttp: Dict) -> str:
        """Check AI agent tool invocation approval and memory isolation."""
        score = 0

        # Check for agent framework guardrail configs
        guardrails = self._run_cmd(
            'find /opt /srv /home -maxdepth 4 '
            '-name "guardrails.yaml" -o -name "guardrails.yml" '
            '-o -name "tool_permissions.yaml" -o -name "agent_policy.yaml" '
            '2>/dev/null | head -3'
        )
        if guardrails:
            score += 2

        # Sandboxed execution environment
        sandbox = self._run_cmd(
            'grep -rl "sandbox\\|isolated.*exec\\|tool_confirm" '
            '/opt/ /srv/ 2>/dev/null | head -3'
        )
        if sandbox:
            score += 1

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    def _sim_check_model_integrity(self, ttp: Dict) -> str:
        """Check model checksum verification and registry signing."""
        score = 0

        # Model checksum files present
        checksums = self._run_cmd(
            'find /home /opt -maxdepth 4 '
            '-name "*.sha256" -o -name "model_checksums.json" '
            '-o -name "model_manifest.json" '
            '2>/dev/null | head -3'
        )
        if checksums:
            score += 2

        # Container image signing (cosign/notation)
        for tool in ['cosign', 'notation']:
            if shutil.which(tool):
                score += 1
                break

        if score >= 2:
            return DETECTED
        elif score >= 1:
            return PARTIAL
        return NOT_DETECTED

    # ===================================================================== #
    #  Generic Fallback Check                                                #
    # ===================================================================== #

    def _sim_generic_check(self, ttp: Dict) -> str:
        """Fallback: verify basic logging coverage for the technique."""
        return self._sim_check_logging_coverage(ttp)

    # ===================================================================== #
    #  Scorecard Formatting                                                  #
    # ===================================================================== #

    @staticmethod
    def format_scorecard(scorecard: Dict) -> str:
        """Format a scorecard for terminal display."""
        lines = []
        name = scorecard['name']
        grade = scorecard['grade']
        rate = scorecard['detection_rate']
        gaps = scorecard['critical_gaps']

        lines.append('')
        lines.append(
            'Adversary: {}  |  Grade: {}  |  Detection: {}%'.format(
                name, grade, rate
            )
        )
        lines.append(
            '{:<20s} | {:<22s} | {:<8s} | {}'.format(
                'Tactic', 'Technique', 'ATT&CK', 'Status'
            )
        )
        lines.append('-' * 20 + '-+-' + '-' * 22 + '-+-' + '-' * 8 + '-+-' + '-' * 12)

        for t in scorecard['techniques']:
            status_display = t['status'].replace('_', ' ')
            if t['status'] == DETECTED:
                status_display = 'DETECTED'
            elif t['status'] == PARTIAL:
                status_display = 'PARTIAL'
            else:
                status_display = 'NOT DET'

            lines.append(
                '{:<20s} | {:<22s} | {:<8s} | {}'.format(
                    t['tactic'][:20],
                    t['technique'][:22],
                    t['attack_id'][:8],
                    status_display,
                )
            )

        lines.append('Critical Gaps: {}'.format(gaps))
        lines.append('')
        return '\n'.join(lines)

    def get_available_profiles(self) -> List[Dict]:
        """Return list of available profiles for selection UI."""
        profiles = []
        for pid, profile in self._profiles.items():
            profiles.append({
                'id': pid,
                'name': profile['name'],
                'attribution': profile.get('attribution', ''),
                'motivation': profile.get('motivation', ''),
                'ttp_count': len(profile.get('ttps', [])),
                'sectors': profile.get('target_sectors', []),
            })
        return profiles


# =========================================================================== #
#  CLI entry point                                                            #
# =========================================================================== #

if __name__ == '__main__':
    import sys as _sys

    profile = _sys.argv[1] if len(_sys.argv) > 1 else 'scattered_spider'
    scan_type = _sys.argv[2] if len(_sys.argv) > 2 else 'standard'

    scanner = AdversaryScanner()

    print("Adversary Emulation Scanner")
    print("=" * 50)
    print("Available profiles: {}".format(len(scanner._profiles)))
    for pid, p in list(scanner._profiles.items())[:5]:
        print("  {} - {} ({} TTPs)".format(pid, p['name'], len(p['ttps'])))
    print("  ... and {} more".format(max(0, len(scanner._profiles) - 5)))
    print()

    if profile == 'list':
        for pid, p in scanner._profiles.items():
            print("  {:<25s} {} ({} TTPs) [{}]".format(
                pid, p['name'], len(p['ttps']), p.get('attribution', '')
            ))
        _sys.exit(0)

    print("Running profile: {} ({})".format(profile, scan_type))
    print()

    results = scanner.scan(profile=profile, scan_type=scan_type)

    # Print scorecards
    for sc in results.get('scorecards', []):
        print(AdversaryScanner.format_scorecard(sc))

    # Print overall
    overall = results.get('overall', {})
    print("=" * 50)
    print("OVERALL: Grade {} | Detection: {}% | Gaps: {}".format(
        overall.get('grade', '?'),
        overall.get('detection_rate', 0),
        overall.get('not_detected', 0),
    ))
    print("Techniques: {} total, {} detected, {} partial, {} not detected".format(
        overall.get('total_techniques', 0),
        overall.get('detected', 0),
        overall.get('partial', 0),
        overall.get('not_detected', 0),
    ))

    # Print findings summary
    summary = results.get('summary', {})
    print("\nFindings: {}".format(summary.get('findings_count', 0)))
    for sev, count in summary.get('findings_by_severity', {}).items():
        if count > 0:
            print("  {}: {}".format(sev, count))
