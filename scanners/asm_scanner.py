#!/usr/bin/env python3
"""
Donjon - Attack Surface Management Scanner
External attack surface discovery and monitoring.
Passive-first: CT logs and DNS lookups are default.
Active enumeration requires explicit opt-in.
"""

import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

try:
    from credential_manager import get_credential_manager
except ImportError:
    get_credential_manager = None

try:
    from asset_manager import get_asset_manager
except ImportError:
    get_asset_manager = None

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
except ImportError:
    urlopen = None


class ASMScanner(BaseScanner):
    """Attack surface management and external discovery scanner."""

    SCANNER_NAME = "asm"
    SCANNER_DESCRIPTION = "Attack surface management and external discovery"

    # Common subdomains for passive DNS enumeration
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'smtp', 'ftp', 'vpn', 'remote', 'admin',
        'dev', 'staging', 'api', 'app', 'portal', 'test'
    ]

    # Extended subdomain list for active brute-force fallback
    EXTENDED_SUBDOMAINS = [
        'www', 'mail', 'smtp', 'ftp', 'vpn', 'remote', 'admin',
        'dev', 'staging', 'api', 'app', 'portal', 'test',
        'ns1', 'ns2', 'mx', 'webmail', 'cloud', 'git', 'gitlab',
        'jenkins', 'ci', 'cd', 'jira', 'confluence', 'wiki',
        'blog', 'shop', 'store', 'cdn', 'static', 'assets',
        'media', 'img', 'images', 'files', 'download', 'upload',
        'login', 'auth', 'sso', 'id', 'accounts', 'dashboard',
        'monitor', 'status', 'health', 'metrics', 'logs',
        'db', 'database', 'redis', 'elastic', 'kibana', 'grafana',
        'proxy', 'gateway', 'lb', 'edge', 'internal', 'intranet',
        'backup', 'archive', 'old', 'legacy', 'beta', 'alpha',
        'sandbox', 'demo', 'docs', 'support', 'help', 'ticket',
    ]

    # Rate limit for CT log queries (seconds between requests)
    CT_RATE_LIMIT = 2.0

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)

    def scan(self, targets: List[str], **kwargs) -> Dict:
        """
        Execute attack surface management scan.

        Args:
            targets: List of domain names to scan.
            **kwargs:
                scan_type: 'quick', 'standard', or 'deep' (default 'standard')
                active: Enable active enumeration (default False, passive only)
        """
        self.start_time = datetime.now(timezone.utc)
        self.scan_status = 'running'
        scan_type = kwargs.get('scan_type', 'standard')
        active = kwargs.get('active', False)

        self.scan_logger.info(f"Starting ASM scan (type={scan_type}, active={active})")
        self.scan_logger.info(f"Targets: {targets}")

        results = {
            'scan_type': scan_type,
            'active': active,
            'targets': targets,
            'domains': [],
            'subdomains': [],
            'certificates': [],
            'findings': [],
            'summary': {}
        }

        for target in targets:
            self.scan_logger.info(f"Scanning target: {target}")

            # Determine if target is an IP or domain
            domain = target
            is_ip = self._is_ip_address(target)
            if is_ip:
                # Reverse DNS lookup to get domain from IP
                rdns = self._reverse_dns(target)
                if rdns:
                    self.scan_logger.info(f"Reverse DNS for {target}: {rdns}")
                    domain = rdns
                    self.add_finding(
                        severity='INFO',
                        title=f"Reverse DNS: {target} -> {rdns}",
                        description=(
                            f"IP address {target} resolves to hostname {rdns} "
                            "via reverse DNS lookup."
                        ),
                        affected_asset=target,
                        finding_type='reverse_dns',
                        remediation="Verify reverse DNS record is intentional.",
                        detection_method='reverse_dns'
                    )
                else:
                    self.scan_logger.info(
                        f"No reverse DNS for {target}, scanning as IP only"
                    )

            domain_entry = {'domain': domain, 'subdomains': [], 'certificates': []}

            # DNS record enumeration (MX, TXT, NS, CNAME)
            if not is_ip or (is_ip and domain != target):
                dns_record_results = self._check_dns_records(domain)
                results.setdefault('dns_records', []).extend(dns_record_results)

            # Always run passive checks (skip CT for bare IPs with no rDNS)
            if not is_ip or (is_ip and domain != target):
                ct_results = self._check_certificate_transparency(domain)
                domain_entry['certificates'] = ct_results
                results['certificates'].extend(ct_results)

                # Extract subdomains from CT results
                ct_subdomains = set()
                for cert in ct_results:
                    for name in cert.get('names', []):
                        if name.endswith(f'.{domain}') or name == domain:
                            ct_subdomains.add(name)
            else:
                ct_subdomains = set()

            dns_results = self._enumerate_dns(domain)
            domain_entry['subdomains'] = dns_results
            results['subdomains'].extend(dns_results)

            # Merge CT-discovered subdomains into results
            known_hosts = {r['hostname'] for r in dns_results}
            for sub in ct_subdomains:
                if sub not in known_hosts:
                    results['subdomains'].append({
                        'hostname': sub,
                        'source': 'certificate_transparency',
                        'addresses': []
                    })

            # Web fingerprinting on discovered hosts (always run, even for bare IPs)
            fingerprint_targets = set()
            fingerprint_targets.add(target)  # Always fingerprint the original target
            if domain != target:
                fingerprint_targets.add(domain)
            for sub_entry in dns_results:
                fingerprint_targets.add(sub_entry['hostname'])

            for fp_target in fingerprint_targets:
                for scheme in ['https', 'http']:
                    url = f"{scheme}://{fp_target}"
                    fp_results = self._fingerprint_web(url, domain)
                    if fp_results:
                        results.setdefault('web_fingerprints', []).append(fp_results)
                        break  # If HTTPS works, skip HTTP

            # Active enumeration only if explicitly enabled
            if active:
                self.scan_logger.warning(
                    "Active enumeration enabled - may trigger security alerts "
                    "on target infrastructure"
                )
                active_results = self._active_enumeration(domain)
                for ar in active_results:
                    if ar['hostname'] not in known_hosts:
                        domain_entry['subdomains'].append(ar)
                        results['subdomains'].append(ar)
                        known_hosts.add(ar['hostname'])

            # Shodan lookup if API key is configured
            for sub_entry in dns_results:
                for addr in sub_entry.get('addresses', []):
                    shodan_data = self._check_shodan(addr)
                    if shodan_data and shodan_data.get('ports'):
                        sub_entry['shodan'] = shodan_data

            # For bare IPs with no findings, report what was checked
            if is_ip and domain == target and len(self.findings) == 0:
                self.add_finding(
                    severity='INFO',
                    title=f"IP scanned: {target} — no web services or rDNS detected",
                    description=(
                        f"Scanned IP {target}: no reverse DNS hostname, no HTTP/HTTPS "
                        "services detected. The host may run non-web services or "
                        "be behind a firewall."
                    ),
                    affected_asset=target,
                    finding_type='ip_scan_no_services',
                    remediation="Use a network scanner for port/service discovery.",
                    detection_method='asm_scan'
                )

            results['domains'].append(domain_entry)
            self.human_delay()

        # Check for large attack surface
        total_subs = len(results['subdomains'])
        if total_subs > 50:
            self.add_finding(
                severity='INFO',
                title=f"Large attack surface detected ({total_subs} subdomains)",
                description=(
                    f"Discovered {total_subs} subdomains across scanned domains. "
                    "A large attack surface increases the risk of misconfigured "
                    "or forgotten services being exposed."
                ),
                affected_asset=', '.join(targets),
                finding_type='attack_surface',
                remediation="Review all subdomains and decommission unused services.",
                detection_method='subdomain_enumeration'
            )

        # Generate summary
        results['summary'] = {
            'total_domains': len(targets),
            'total_subdomains': total_subs,
            'total_certificates': len(results['certificates']),
            'findings_count': len(self.findings),
            'findings_by_severity': self._count_by_severity()
        }
        results['findings'] = self.findings.copy()

        self.end_time = datetime.now(timezone.utc)
        self.set_status('complete')
        self.save_results()

        return results

    def _check_certificate_transparency(self, domain: str) -> List[Dict]:
        """
        Query Certificate Transparency logs via crt.sh API.

        Returns list of certificate entries with names, issuer, and expiry info.
        Finds expired certificates (MEDIUM) and wildcard certificates (INFO).
        """
        self.scan_logger.info(f"Checking Certificate Transparency for {domain}")
        certificates = []

        if urlopen is None:
            self.scan_logger.warning("urllib not available, skipping CT check")
            return certificates

        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        if not url.startswith('https://'):
            self.scan_logger.warning(f"Refusing non-HTTPS URL: {url}")
            return certificates

        try:
            req = Request(url, headers={'User-Agent': 'Donjon-ASM/7.0'})
            response = urlopen(req, timeout=30)  # nosec B310 - URL scheme validated above
            data = json.loads(response.read().decode('utf-8'))
        except (HTTPError, URLError) as e:
            self.scan_logger.warning(f"CT log query failed for {domain}: {e}")
            return certificates
        except Exception as e:
            self.scan_logger.warning(f"CT log query error for {domain}: {e}")
            return certificates

        # Rate limit compliance
        time.sleep(self.CT_RATE_LIMIT)

        # Deduplicate by certificate serial or name set
        seen_ids = set()
        unique_certs = []
        for entry in data if isinstance(data, list) else []:
            cert_id = entry.get('id')
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)
            unique_certs.append(entry)

        for entry in unique_certs:
            common_name = entry.get('common_name', '')
            name_value = entry.get('name_value', '')
            issuer = entry.get('issuer_name', '')
            not_after = entry.get('not_after', '')
            not_before = entry.get('not_before', '')

            # Parse names (may contain newlines for SANs)
            names = set()
            for raw_name in [common_name] + name_value.split('\n'):
                name = raw_name.strip().lower()
                if name and not name.startswith('*'):
                    names.add(name)
                elif name:
                    names.add(name)

            cert_entry = {
                'id': entry.get('id'),
                'common_name': common_name,
                'names': list(names),
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'source': 'crt.sh'
            }
            certificates.append(cert_entry)

            # Check for expired certificates
            if not_after:
                try:
                    # crt.sh format: "2024-01-15T00:00:00" or similar
                    expiry_str = not_after.replace('T', ' ').split('.')[0]
                    expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
                    if expiry < datetime.now(timezone.utc):
                        self.add_finding(
                            severity='MEDIUM',
                            title=f"Expired certificate for {common_name}",
                            description=(
                                f"Certificate for {common_name} expired on {not_after}. "
                                f"Issuer: {issuer}. Expired certificates may cause "
                                "service disruptions and trust warnings."
                            ),
                            affected_asset=domain,
                            finding_type='expired_certificate',
                            remediation="Renew or remove the expired certificate.",
                            raw_data=cert_entry,
                            detection_method='ct_log_analysis'
                        )
                except (ValueError, TypeError):
                    pass

            # Check for wildcard certificates
            if '*' in common_name:
                self.add_finding(
                    severity='INFO',
                    title=f"Wildcard certificate: {common_name}",
                    description=(
                        f"Wildcard certificate detected for {common_name}. "
                        f"Issuer: {issuer}. Wildcard certificates cover all "
                        "subdomains which may mask unauthorized services."
                    ),
                    affected_asset=domain,
                    finding_type='wildcard_certificate',
                    remediation=(
                        "Consider using specific certificates for critical services "
                        "to improve certificate lifecycle management."
                    ),
                    raw_data=cert_entry,
                    detection_method='ct_log_analysis'
                )

        self.scan_logger.info(
            f"CT log results for {domain}: {len(certificates)} certificates, "
            f"{len(seen_ids)} unique"
        )
        return certificates

    def _enumerate_dns(self, domain: str) -> List[Dict]:
        """
        Enumerate subdomains via passive DNS lookups.

        Checks common subdomain prefixes using socket.getaddrinfo.
        Also attempts DNS zone transfer (AXFR) detection.
        """
        self.scan_logger.info(f"Enumerating DNS for {domain}")
        results = []
        discovered_hosts = set()

        # Check base domain
        addrs = self._resolve_hostname(domain)
        if addrs:
            results.append({
                'hostname': domain,
                'addresses': addrs,
                'source': 'dns_lookup'
            })
            discovered_hosts.add(domain)

        # Check common subdomains
        for prefix in self.COMMON_SUBDOMAINS:
            fqdn = f"{prefix}.{domain}"
            addrs = self._resolve_hostname(fqdn)
            if addrs:
                results.append({
                    'hostname': fqdn,
                    'addresses': addrs,
                    'source': 'dns_lookup'
                })
                discovered_hosts.add(fqdn)

                # Check if subdomain has HTTPS
                self._check_https_availability(fqdn, domain)

        # Check for DNS zone transfer vulnerability
        self._check_zone_transfer(domain)

        self.scan_logger.info(
            f"DNS enumeration for {domain}: {len(results)} hosts resolved"
        )
        return results

    def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve a hostname to IP addresses using socket.getaddrinfo."""
        addresses = []
        try:
            # IPv4
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET, socket.SOCK_STREAM
            )
            for result in results:
                addr = result[4][0]
                if addr not in addresses:
                    addresses.append(addr)
        except socket.gaierror:
            pass

        try:
            # IPv6
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET6, socket.SOCK_STREAM
            )
            for result in results:
                addr = result[4][0]
                if addr not in addresses:
                    addresses.append(addr)
        except socket.gaierror:
            pass

        return addresses

    def _check_https_availability(self, hostname: str, parent_domain: str):
        """Check if a discovered subdomain responds on HTTPS (port 443)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((hostname, 443))
            sock.close()

            if result != 0:
                # Port 443 not open - no HTTPS
                self.add_finding(
                    severity='MEDIUM',
                    title=f"Subdomain without HTTPS: {hostname}",
                    description=(
                        f"The subdomain {hostname} was discovered but does not "
                        "appear to have HTTPS (port 443) available. Services "
                        "without HTTPS may transmit data in cleartext."
                    ),
                    affected_asset=parent_domain,
                    finding_type='no_https',
                    remediation=(
                        f"Enable HTTPS on {hostname} or decommission the "
                        "subdomain if not in use."
                    ),
                    detection_method='port_check'
                )
        except (socket.timeout, socket.error, OSError):
            pass

    def _check_zone_transfer(self, domain: str):
        """
        Attempt DNS zone transfer (AXFR) to detect misconfigured DNS servers.
        Uses dig or host command if available. A successful zone transfer
        is a HIGH severity finding.
        """
        dig_path = shutil.which('dig')
        host_path = shutil.which('host')

        if dig_path:
            # First get nameservers
            try:
                ns_result = subprocess.run(
                    [dig_path, '+short', 'NS', domain],
                    capture_output=True, text=True, timeout=10
                )
                nameservers = [
                    ns.strip().rstrip('.')
                    for ns in ns_result.stdout.strip().split('\n')
                    if ns.strip()
                ]
            except (subprocess.TimeoutExpired, Exception):
                nameservers = []

            for ns in nameservers:
                try:
                    axfr_result = subprocess.run(
                        [dig_path, 'AXFR', domain, f'@{ns}'],
                        capture_output=True, text=True, timeout=15
                    )
                    output = axfr_result.stdout
                    # A successful zone transfer will contain multiple records
                    if axfr_result.returncode == 0 and output.count('\n') > 5:
                        # Check it is not a "Transfer failed" response
                        if 'Transfer failed' not in output and 'XFR size' in output:
                            self.add_finding(
                                severity='HIGH',
                                title=f"DNS zone transfer possible on {ns}",
                                description=(
                                    f"DNS zone transfer (AXFR) succeeded against "
                                    f"nameserver {ns} for domain {domain}. This "
                                    "exposes the entire DNS zone contents to "
                                    "unauthorized parties, revealing internal "
                                    "hostnames and network architecture."
                                ),
                                affected_asset=domain,
                                finding_type='dns_zone_transfer',
                                remediation=(
                                    f"Restrict zone transfers on {ns} to authorized "
                                    "secondary DNS servers only."
                                ),
                                raw_data={'nameserver': ns, 'domain': domain},
                                detection_method='dns_axfr'
                            )
                except (subprocess.TimeoutExpired, Exception):
                    continue

        elif host_path:
            try:
                axfr_result = subprocess.run(
                    [host_path, '-t', 'axfr', domain],
                    capture_output=True, text=True, timeout=15
                )
                output = axfr_result.stdout
                if 'has address' in output and output.count('\n') > 5:
                    self.add_finding(
                        severity='HIGH',
                        title=f"DNS zone transfer possible for {domain}",
                        description=(
                            f"DNS zone transfer (AXFR) succeeded for {domain}. "
                            "This exposes the entire DNS zone contents to "
                            "unauthorized parties."
                        ),
                        affected_asset=domain,
                        finding_type='dns_zone_transfer',
                        remediation=(
                            "Restrict zone transfers to authorized secondary "
                            "DNS servers only."
                        ),
                        raw_data={'domain': domain},
                        detection_method='dns_axfr'
                    )
            except (subprocess.TimeoutExpired, Exception):
                pass

    def _active_enumeration(self, domain: str) -> List[Dict]:
        """
        Active subdomain enumeration using external tools.
        Only called when active=True is explicitly set.

        Uses amass or subfinder if available, falls back to extended
        DNS brute-force with a larger wordlist.
        """
        self.scan_logger.info(f"Active enumeration for {domain}")
        results = []
        discovered = set()

        amass_path = shutil.which('amass')
        subfinder_path = shutil.which('subfinder')

        # Try amass (passive mode to reduce noise even in active scan)
        if amass_path:
            self.scan_logger.info("Using amass for subdomain enumeration")
            try:
                proc = subprocess.run(
                    [amass_path, 'enum', '-d', domain, '-passive'],
                    capture_output=True, text=True, timeout=300
                )
                for line in proc.stdout.strip().split('\n'):
                    hostname = line.strip().lower()
                    if hostname and hostname.endswith(f'.{domain}'):
                        if hostname not in discovered:
                            discovered.add(hostname)
                            addrs = self._resolve_hostname(hostname)
                            results.append({
                                'hostname': hostname,
                                'addresses': addrs,
                                'source': 'amass'
                            })
            except (subprocess.TimeoutExpired, Exception) as e:
                self.scan_logger.warning(f"amass error: {e}")

        # Try subfinder
        if subfinder_path:
            self.scan_logger.info("Using subfinder for subdomain enumeration")
            try:
                proc = subprocess.run(
                    [subfinder_path, '-d', domain, '-silent'],
                    capture_output=True, text=True, timeout=300
                )
                for line in proc.stdout.strip().split('\n'):
                    hostname = line.strip().lower()
                    if hostname and hostname.endswith(f'.{domain}'):
                        if hostname not in discovered:
                            discovered.add(hostname)
                            addrs = self._resolve_hostname(hostname)
                            results.append({
                                'hostname': hostname,
                                'addresses': addrs,
                                'source': 'subfinder'
                            })
            except (subprocess.TimeoutExpired, Exception) as e:
                self.scan_logger.warning(f"subfinder error: {e}")

        # Fallback: extended DNS brute-force if no external tools found results
        if not results:
            self.scan_logger.info("Fallback: extended DNS brute-force enumeration")
            for prefix in self.EXTENDED_SUBDOMAINS:
                fqdn = f"{prefix}.{domain}"
                if fqdn not in discovered:
                    addrs = self._resolve_hostname(fqdn)
                    if addrs:
                        discovered.add(fqdn)
                        results.append({
                            'hostname': fqdn,
                            'addresses': addrs,
                            'source': 'dns_bruteforce'
                        })

        self.scan_logger.info(
            f"Active enumeration for {domain}: {len(results)} additional subdomains"
        )
        return results

    def _check_shodan(self, domain_or_ip: str) -> Dict:
        """
        Query Shodan API for external exposure information.

        Requires a Shodan API key stored via credential_manager with
        cred_type 'api_key' and name containing 'shodan'.
        Returns open ports and services visible from the internet.
        """
        if urlopen is None:
            return {}

        # Try to get Shodan API key from credential manager
        api_key = None
        if get_credential_manager is not None:
            try:
                cm = get_credential_manager()
                for cred in cm.get_all_credentials(decrypt=True):
                    if 'shodan' in cred.get('name', '').lower():
                        api_key = cred.get('params', {}).get('secret')
                        if not api_key:
                            api_key = cred.get('params', {}).get('password')
                        break
            except Exception:
                pass

        if not api_key:
            self.scan_logger.debug("No Shodan API key configured, skipping")
            return {}

        url = f"https://api.shodan.io/host/{domain_or_ip}?key={api_key}"

        if not url.startswith('https://'):
            self.scan_logger.warning(f"Refusing non-HTTPS URL: {url}")
            return {}

        try:
            req = Request(url, headers={'User-Agent': 'Donjon-ASM/7.0'})
            response = urlopen(req, timeout=15)  # nosec B310 - URL scheme validated above
            data = json.loads(response.read().decode('utf-8'))
        except (HTTPError, URLError) as e:
            self.scan_logger.debug(f"Shodan query failed for {domain_or_ip}: {e}")
            return {}
        except Exception as e:
            self.scan_logger.debug(f"Shodan query error for {domain_or_ip}: {e}")
            return {}

        shodan_result = {
            'ip': domain_or_ip,
            'ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'org': data.get('org', ''),
            'os': data.get('os', ''),
            'vulns': data.get('vulns', []),
            'source': 'shodan'
        }

        # Flag unexpected externally exposed services
        unexpected_ports = set()
        common_web_ports = {80, 443, 8080, 8443}
        for port in data.get('ports', []):
            if port not in common_web_ports:
                unexpected_ports.add(port)

        if unexpected_ports:
            self.add_finding(
                severity='HIGH',
                title=f"Unexpected services exposed externally on {domain_or_ip}",
                description=(
                    f"Shodan reports the following non-standard ports are "
                    f"visible from the internet on {domain_or_ip}: "
                    f"{sorted(unexpected_ports)}. These may represent "
                    "unintended exposure of internal services."
                ),
                affected_asset=domain_or_ip,
                finding_type='external_exposure',
                remediation=(
                    "Review firewall rules and ensure only intended services "
                    "are accessible from the internet."
                ),
                raw_data=shodan_result,
                detection_method='shodan_lookup'
            )

        return shodan_result

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address (v4 or v6)."""
        try:
            socket.inet_pton(socket.AF_INET, target)
            return True
        except (socket.error, OSError):
            pass
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except (socket.error, OSError):
            pass
        return False

    def _reverse_dns(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup on an IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            # Strip trailing dot if present
            return hostname.rstrip('.')
        except (socket.herror, socket.gaierror, OSError):
            return None

    def _check_dns_records(self, domain: str) -> List[Dict]:
        """
        Enumerate DNS records: MX, TXT (SPF/DKIM/DMARC), NS, CNAME.

        Uses nslookup (available on Windows and most Linux) or dig.
        Generates findings for missing email security records.
        """
        self.scan_logger.info(f"Checking DNS records for {domain}")
        records = []

        # Use nslookup which is available cross-platform
        nslookup_path = shutil.which('nslookup')
        dig_path = shutil.which('dig')

        # --- MX Records ---
        mx_records = self._query_dns_record(domain, 'MX', nslookup_path, dig_path)
        if mx_records:
            records.append({
                'domain': domain, 'type': 'MX', 'values': mx_records
            })
            self.add_finding(
                severity='INFO',
                title=f"MX records found for {domain}",
                description=(
                    f"Mail exchange records for {domain}: "
                    f"{', '.join(mx_records[:5])}"
                ),
                affected_asset=domain,
                finding_type='dns_mx_records',
                remediation="Verify MX records point to intended mail servers.",
                detection_method='dns_enumeration'
            )

        # --- NS Records ---
        ns_records = self._query_dns_record(domain, 'NS', nslookup_path, dig_path)
        if ns_records:
            records.append({
                'domain': domain, 'type': 'NS', 'values': ns_records
            })
            self.add_finding(
                severity='INFO',
                title=f"NS records for {domain}: {len(ns_records)} nameservers",
                description=(
                    f"Nameservers for {domain}: {', '.join(ns_records[:5])}"
                ),
                affected_asset=domain,
                finding_type='dns_ns_records',
                remediation="Ensure nameservers are properly configured and redundant.",
                detection_method='dns_enumeration'
            )

        # --- TXT Records (SPF, DKIM, DMARC) ---
        txt_records = self._query_dns_record(domain, 'TXT', nslookup_path, dig_path)
        if txt_records:
            records.append({
                'domain': domain, 'type': 'TXT', 'values': txt_records
            })

        # Check for SPF
        has_spf = any('v=spf1' in r.lower() for r in txt_records)
        if has_spf:
            spf_record = next(r for r in txt_records if 'v=spf1' in r.lower())
            self.add_finding(
                severity='INFO',
                title=f"SPF record found for {domain}",
                description=f"SPF record: {spf_record[:120]}",
                affected_asset=domain,
                finding_type='dns_spf_present',
                remediation="Review SPF record for correctness.",
                detection_method='dns_enumeration'
            )
        else:
            self.add_finding(
                severity='MEDIUM',
                title=f"Missing SPF record for {domain}",
                description=(
                    f"No SPF (Sender Policy Framework) TXT record found for {domain}. "
                    "Without SPF, attackers can spoof emails from this domain."
                ),
                affected_asset=domain,
                finding_type='missing_spf',
                remediation=(
                    "Add a TXT record with SPF policy, e.g.: "
                    "v=spf1 include:_spf.google.com ~all"
                ),
                detection_method='dns_enumeration'
            )

        # Check for DMARC
        dmarc_records = self._query_dns_record(
            f"_dmarc.{domain}", 'TXT', nslookup_path, dig_path
        )
        has_dmarc = any('v=dmarc1' in r.lower() for r in dmarc_records)
        if has_dmarc:
            dmarc_record = next(r for r in dmarc_records if 'v=dmarc1' in r.lower())
            self.add_finding(
                severity='INFO',
                title=f"DMARC record found for {domain}",
                description=f"DMARC record: {dmarc_record[:120]}",
                affected_asset=domain,
                finding_type='dns_dmarc_present',
                remediation="Review DMARC policy for strictness (p=reject recommended).",
                detection_method='dns_enumeration'
            )
            # Check if DMARC policy is weak
            if 'p=none' in dmarc_record.lower():
                self.add_finding(
                    severity='LOW',
                    title=f"Weak DMARC policy (p=none) for {domain}",
                    description=(
                        f"DMARC policy is set to 'none' for {domain}, which only "
                        "monitors but does not reject spoofed emails."
                    ),
                    affected_asset=domain,
                    finding_type='weak_dmarc',
                    remediation="Upgrade DMARC policy to p=quarantine or p=reject.",
                    detection_method='dns_enumeration'
                )
        else:
            self.add_finding(
                severity='MEDIUM',
                title=f"Missing DMARC record for {domain}",
                description=(
                    f"No DMARC record found at _dmarc.{domain}. "
                    "Without DMARC, email receivers cannot verify the authenticity "
                    "of messages claiming to be from this domain."
                ),
                affected_asset=domain,
                finding_type='missing_dmarc',
                remediation=(
                    "Add a TXT record at _dmarc.{domain}: "
                    "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"
                ),
                detection_method='dns_enumeration'
            )

        return records

    def _query_dns_record(self, domain: str, record_type: str,
                          nslookup_path: Optional[str],
                          dig_path: Optional[str]) -> List[str]:
        """Query a specific DNS record type using available tools.

        Uses public DNS (1.1.1.1) to avoid local resolver limitations.
        """
        results = []

        if dig_path:
            try:
                proc = subprocess.run(
                    [dig_path, '+short', record_type, domain, '@1.1.1.1'],
                    capture_output=True, text=True, timeout=10
                )
                for line in proc.stdout.strip().split('\n'):
                    line = line.strip().strip('"')
                    if line:
                        results.append(line)
            except (subprocess.TimeoutExpired, Exception):
                pass

        if not results and nslookup_path:
            try:
                # Use public DNS server to bypass local resolver limitations
                proc = subprocess.run(
                    [nslookup_path, '-type=' + record_type, domain, '1.1.1.1'],
                    capture_output=True, text=True, timeout=10
                )
                output = proc.stdout + proc.stderr
                for line in output.split('\n'):
                    line = line.strip()
                    # Parse nslookup output for different record types
                    if record_type == 'MX' and 'mail exchanger' in line.lower():
                        # "domain MX preference = 10, mail exchanger = mx.example.com"
                        match = re.search(r'mail exchanger\s*=\s*(.+)', line, re.I)
                        if match:
                            results.append(match.group(1).strip().rstrip('.'))
                    elif record_type == 'NS' and 'nameserver' in line.lower():
                        match = re.search(r'nameserver\s*=\s*(.+)', line, re.I)
                        if match:
                            results.append(match.group(1).strip().rstrip('.'))
                    elif record_type == 'TXT' and ('text' in line.lower() or line.startswith('"')):
                        # Extract TXT value
                        match = re.search(r'text\s*=\s*"?(.+?)"?\s*$', line, re.I)
                        if match:
                            results.append(match.group(1).strip().strip('"'))
                        elif line.startswith('"'):
                            results.append(line.strip('"'))
            except (subprocess.TimeoutExpired, Exception):
                pass

        # Fallback: use socket for basic resolution if no tools available
        if not results and record_type in ('MX', 'NS'):
            # Can't get MX/NS/TXT via socket, but we tried
            pass

        return results

    def _fingerprint_web(self, url: str, parent_domain: str) -> Optional[Dict]:
        """
        HTTP header analysis and web technology fingerprinting.

        Checks:
        - Server header (Apache, nginx, IIS version)
        - X-Powered-By (PHP, ASP.NET, Express)
        - Technology detection (WordPress, Drupal, etc.)
        - SSL certificate info
        - Missing security headers
        """
        if urlopen is None:
            return None

        self.scan_logger.info(f"Fingerprinting web: {url}")
        fingerprint = {'url': url, 'headers': {}, 'technologies': [], 'security_headers': {}}

        try:
            req = Request(url, headers={'User-Agent': 'Donjon-ASM/7.0'})
            response = urlopen(req, timeout=10)  # nosec B310
            headers = dict(response.headers)
            fingerprint['status_code'] = response.status
            fingerprint['headers'] = headers
        except HTTPError as e:
            headers = dict(e.headers) if hasattr(e, 'headers') else {}
            fingerprint['status_code'] = e.code
            fingerprint['headers'] = headers
        except (URLError, Exception) as e:
            self.scan_logger.debug(f"Web fingerprint failed for {url}: {e}")
            return None

        # --- Server header ---
        server = headers.get('Server', headers.get('server', ''))
        if server:
            fingerprint['server'] = server
            self.add_finding(
                severity='INFO',
                title=f"Web server identified: {server[:60]}",
                description=(
                    f"Server header on {url}: {server}. "
                    "Exposing server version may aid attackers in identifying "
                    "known vulnerabilities."
                ),
                affected_asset=parent_domain,
                finding_type='web_server_fingerprint',
                remediation="Consider removing or obfuscating the Server header.",
                detection_method='http_header_analysis'
            )

        # --- X-Powered-By ---
        powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
        if powered_by:
            fingerprint['powered_by'] = powered_by
            self.add_finding(
                severity='LOW',
                title=f"Technology disclosed: X-Powered-By: {powered_by[:50]}",
                description=(
                    f"The X-Powered-By header on {url} reveals: {powered_by}. "
                    "This aids attackers in targeting known vulnerabilities."
                ),
                affected_asset=parent_domain,
                finding_type='technology_disclosure',
                remediation="Remove the X-Powered-By header in server configuration.",
                detection_method='http_header_analysis'
            )

        # --- Missing security headers ---
        security_headers = {
            'X-Frame-Options': (
                'MEDIUM', 'clickjacking protection',
                'Add X-Frame-Options: DENY or SAMEORIGIN header.'
            ),
            'Content-Security-Policy': (
                'MEDIUM', 'Content Security Policy',
                'Implement a Content-Security-Policy header to prevent XSS and injection attacks.'
            ),
            'Strict-Transport-Security': (
                'MEDIUM', 'HTTP Strict Transport Security (HSTS)',
                'Add Strict-Transport-Security header with appropriate max-age.'
            ),
            'X-Content-Type-Options': (
                'LOW', 'MIME-type sniffing protection',
                'Add X-Content-Type-Options: nosniff header.'
            ),
        }

        # Normalize header keys to lowercase for matching
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for header_name, (sev, desc_name, remed) in security_headers.items():
            present = header_name.lower() in lower_headers
            fingerprint['security_headers'][header_name] = present
            if not present and url.startswith('https://'):
                self.add_finding(
                    severity=sev,
                    title=f"Missing {header_name} header on {url[:50]}",
                    description=(
                        f"The {desc_name} header ({header_name}) is missing on {url}. "
                        "This may leave the application vulnerable to certain attacks."
                    ),
                    affected_asset=parent_domain,
                    finding_type=f'missing_{header_name.lower().replace("-", "_")}',
                    remediation=remed,
                    detection_method='http_header_analysis'
                )

        # --- Technology detection via common paths ---
        # Each entry: (path, tech_name, description, content_signature)
        # content_signature is required in the response body to confirm a real hit
        # (avoids false positives from soft 404 pages)
        tech_checks = [
            ('/wp-login.php', 'WordPress', 'WordPress CMS detected', 'wp-login'),
            ('/wp-admin/', 'WordPress', 'WordPress admin path accessible', 'wp-admin'),
            ('/misc/drupal.js', 'Drupal', 'Drupal CMS detected', 'Drupal'),
            ('/administrator/', 'Joomla', 'Joomla admin path detected', 'com_login'),
            ('/.git/HEAD', 'Git Repository', 'Exposed .git directory', 'ref:'),
            ('/.env', 'Environment File', 'Exposed .env file', '='),
            ('/robots.txt', 'robots.txt', 'robots.txt file found', 'User-agent'),
        ]

        base_url = url.rstrip('/')
        for path, tech_name, tech_desc, content_sig in tech_checks:
            try:
                check_url = f"{base_url}{path}"
                check_req = Request(check_url, headers={'User-Agent': 'Donjon-ASM/7.0'})
                check_resp = urlopen(check_req, timeout=5)  # nosec B310
                if check_resp.status == 200:
                    # Read response body to verify it's a real hit, not a soft 404
                    body = check_resp.read(4096).decode('utf-8', errors='replace')
                    content_type = check_resp.headers.get('Content-Type', '')

                    # For .git/HEAD and .env, the response should NOT be HTML
                    is_html = '<html' in body.lower()[:500] or 'text/html' in content_type.lower()

                    if tech_name in ('Git Repository', 'Environment File'):
                        # These files are never HTML; if we get HTML, it's a soft 404
                        if is_html or content_sig.lower() not in body.lower()[:500]:
                            continue
                    elif content_sig.lower() not in body.lower()[:4096]:
                        # Content signature not found — soft 404
                        continue

                    fingerprint['technologies'].append(tech_name)

                    # Sensitive file exposure is higher severity
                    if tech_name in ('Git Repository', 'Environment File'):
                        self.add_finding(
                            severity='HIGH',
                            title=f"Sensitive file exposed: {path} on {url[:40]}",
                            description=(
                                f"Sensitive file {path} is accessible on {base_url}. "
                                "This may expose source code, credentials, or "
                                "configuration details."
                            ),
                            affected_asset=parent_domain,
                            finding_type='sensitive_file_exposure',
                            remediation=f"Block access to {path} in web server configuration.",
                            detection_method='web_path_check'
                        )
                    elif tech_name not in ('robots.txt',):
                        self.add_finding(
                            severity='INFO',
                            title=f"Technology detected: {tech_name} on {url[:40]}",
                            description=f"{tech_desc} at {check_url}",
                            affected_asset=parent_domain,
                            finding_type='technology_detection',
                            remediation="Keep CMS and frameworks updated to latest versions.",
                            detection_method='web_path_check'
                        )
            except (HTTPError, URLError, Exception):
                continue

        # --- SSL certificate info (for HTTPS URLs) ---
        if url.startswith('https://'):
            hostname = url.split('://')[1].split('/')[0].split(':')[0]
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=hostname
                ) as ssock:
                    ssock.settimeout(5)
                    ssock.connect((hostname, 443))
                    cert = ssock.getpeercert()
                    if cert:
                        fingerprint['ssl_subject'] = dict(
                            x[0] for x in cert.get('subject', ())
                        )
                        fingerprint['ssl_issuer'] = dict(
                            x[0] for x in cert.get('issuer', ())
                        )
                        fingerprint['ssl_not_after'] = cert.get('notAfter', '')
                        fingerprint['ssl_san'] = [
                            v for t, v in cert.get('subjectAltName', ())
                            if t == 'DNS'
                        ]
            except (ssl.SSLError, socket.error, OSError, Exception) as e:
                self.scan_logger.debug(f"SSL cert check failed for {hostname}: {e}")

        return fingerprint

    def _compare_internal_external(self, internal_results: List[Dict],
                                    external_results: List[Dict]) -> List[Dict]:
        """
        Compare internal scan results with external (internet-facing) results.

        Identifies services that are visible from outside the network but
        should not be, generating HIGH severity findings.

        Args:
            internal_results: Results from internal network scans (port/service data)
            external_results: Results from Shodan or external port scans

        Returns:
            List of discrepancy findings.
        """
        discrepancies = []

        # Build external services map: ip -> set of ports
        external_map = {}
        for ext in external_results:
            ip = ext.get('ip', '')
            ports = set(ext.get('ports', []))
            if ip:
                external_map[ip] = ports

        # Internal services that are also externally visible
        internal_only_services = {22, 3306, 5432, 6379, 27017, 11211, 9200}

        for ip, ext_ports in external_map.items():
            exposed_internal = ext_ports.intersection(internal_only_services)
            if exposed_internal:
                finding = {
                    'ip': ip,
                    'exposed_ports': sorted(exposed_internal),
                    'severity': 'HIGH'
                }
                discrepancies.append(finding)

                self.add_finding(
                    severity='HIGH',
                    title=f"Internal services exposed externally on {ip}",
                    description=(
                        f"The following services on {ip} are visible from the "
                        f"internet but are typically internal-only: "
                        f"ports {sorted(exposed_internal)}. This may indicate "
                        "a firewall misconfiguration."
                    ),
                    affected_asset=ip,
                    finding_type='internal_service_exposed',
                    remediation=(
                        "Restrict access to internal services using firewall rules. "
                        "Only expose services that require internet access."
                    ),
                    raw_data=finding,
                    detection_method='internal_external_comparison'
                )

        return discrepancies


if __name__ == '__main__':
    scanner = ASMScanner()
    print("ASM Scanner initialized")
    print(f"  amass: {shutil.which('amass') is not None}")
    print(f"  subfinder: {shutil.which('subfinder') is not None}")
    print(f"  dig: {shutil.which('dig') is not None}")

    # Test passive DNS (safe to run)
    try:
        result = socket.getaddrinfo('example.com', None, socket.AF_INET)
        if result:
            print(f"\n  DNS test: example.com -> {result[0][4][0]}")
    except socket.gaierror:
        print("\n  DNS resolution not available")

    print("\nASM Scanner ready (passive-first)")
    print("  Default: Passive (CT logs, DNS)")
    print("  Active: Requires explicit opt-in (active=True)")
