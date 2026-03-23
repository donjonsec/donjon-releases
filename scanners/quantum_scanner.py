#!/usr/bin/env python3
"""
Donjon - Post-Quantum Cryptography (PQC) Readiness Scanner

Assesses an organization's exposure to quantum computing threats by
inventorying cryptographic algorithms in use across TLS, SSH, and local
systems, then measuring readiness for the NIST PQC migration.

Compliance mappings: NIST SP 800-208, NSA CNSA 2.0, NIST IR 8547.
"""

import os
import re
import ssl
import json
import socket
import struct
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# TLS ports to probe
TLS_PORTS = [443, 8443, 993, 995, 587, 636]

# SSH default port
SSH_PORT = 22

# Algorithms considered quantum-vulnerable
QUANTUM_VULNERABLE_KEX = {
    'RSA', 'ECDSA', 'ECDH', 'DH', 'DSA',
    'ECDHE', 'DHE', 'RSA-PSS',
}

# Key exchange names that indicate PQC readiness
PQC_READY_KEX = {
    'ML-KEM', 'MLKEM', 'Kyber', 'KYBER',
    'ML-DSA', 'MLDSA', 'Dilithium', 'DILITHIUM',
    'X25519Kyber768', 'X25519MLKEM768',
    'SecP256r1MLKEM768', 'X25519Kyber512Draft00',
    'sntrup761', 'sntrup761x25519-sha512',
    'ml-kem-768', 'ml-kem-1024',
}

# SSH key exchange algorithms that are quantum-vulnerable
SSH_VULNERABLE_KEX = {
    'diffie-hellman-group1-sha1',
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group14-sha256',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group18-sha512',
    'diffie-hellman-group-exchange-sha1',
    'diffie-hellman-group-exchange-sha256',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521',
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
}

# SSH key exchange algorithms that are PQC-ready
SSH_PQC_KEX = {
    'sntrup761x25519-sha512@openssh.com',
    'sntrup761x25519-sha512',
    'mlkem768x25519-sha256',
    'ml-kem-768',
}

# SSH host key types that are quantum-vulnerable
SSH_VULNERABLE_HOST_KEYS = {
    'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512',
    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    'ssh-dss',
}

# CNSA 2.0 timeline milestones
CNSA2_DEADLINES = {
    'software_firmware_signing': 2025,
    'web_browsers_servers': 2025,
    'cloud_services': 2025,
    'networking_equipment': 2026,
    'operating_systems': 2026,
    'niche_equipment': 2027,
    'legacy_equipment': 2033,
    'all_quantum_vulnerable_deprecated': 2035,
}

# PQC migration deadline used for certificate risk assessment
PQC_MIGRATION_YEAR = 2030


class QuantumReadinessScanner(BaseScanner):
    """Post-Quantum Cryptography readiness scanner."""

    SCANNER_NAME = "quantum"
    SCANNER_DESCRIPTION = "Post-Quantum Cryptography (PQC) readiness assessment"

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(self, targets: List[str], scan_type: str = 'standard',
             ports: Optional[List[int]] = None, **kwargs) -> Dict:
        """
        Execute PQC readiness scan.

        Args:
            targets: List of hosts/IPs to scan.
            scan_type: 'quick' (TLS 443 only), 'standard' (all TLS + SSH),
                       'deep' (+ local audit + file scan).
            ports: Override TLS ports list.

        Returns:
            Dict with tls_inventory, ssh_inventory, cert_analysis,
            local_audit, compliance, agility_score, and summary.
        """
        self.start_time = datetime.now(timezone.utc)
        self.scan_status = 'running'
        self.scan_logger.info(
            f"Starting PQC readiness scan ({scan_type}) on {len(targets)} target(s)"
        )

        tls_ports = ports or ([443] if scan_type == 'quick' else TLS_PORTS)

        tls_inventory: List[Dict] = []
        ssh_inventory: List[Dict] = []
        cert_analysis: List[Dict] = []
        local_audit: Dict[str, Any] = {}

        # ----- TLS / Certificate scanning -----
        for target in targets:
            for port in tls_ports:
                self.scan_logger.info(f"TLS probe: {target}:{port}")
                try:
                    tls_info = self._probe_tls(target, port)
                    if tls_info:
                        tls_inventory.append(tls_info)
                        self._assess_tls_finding(tls_info)

                        cert_info = self._analyse_certificate(tls_info)
                        if cert_info:
                            cert_analysis.append(cert_info)
                            self._assess_cert_finding(cert_info)
                except Exception as exc:
                    self.scan_logger.warning(f"TLS probe {target}:{port} failed: {exc}")
                    self.add_result('tls_error', {'error': str(exc)}, f"{target}:{port}")

                self.human_delay()

        # ----- SSH scanning (standard + deep) -----
        if scan_type in ('standard', 'deep'):
            for target in targets:
                self.scan_logger.info(f"SSH probe: {target}:{SSH_PORT}")
                try:
                    ssh_info = self._probe_ssh(target)
                    if ssh_info:
                        ssh_inventory.append(ssh_info)
                        self._assess_ssh_finding(ssh_info)
                except Exception as exc:
                    self.scan_logger.warning(f"SSH probe {target} failed: {exc}")
                    self.add_result('ssh_error', {'error': str(exc)}, target)

                self.human_delay()

        # ----- Local crypto audit (deep only) -----
        if scan_type == 'deep':
            self.scan_logger.info("Running local crypto audit")
            local_audit = self._local_crypto_audit()

        # ----- Compliance mapping -----
        compliance_map = self._build_compliance_map(
            tls_inventory, ssh_inventory, cert_analysis, local_audit
        )

        # ----- Crypto Agility Score -----
        agility_score = self._compute_agility_score(
            tls_inventory, ssh_inventory, cert_analysis, local_audit
        )

        # ----- Aggregate results -----
        self.end_time = datetime.now(timezone.utc)

        summary = {
            'scan_type': scan_type,
            'targets_scanned': len(targets),
            'tls_connections_checked': len(tls_inventory),
            'ssh_hosts_checked': len(ssh_inventory),
            'certificates_analysed': len(cert_analysis),
            'local_audit_performed': scan_type == 'deep',
            'crypto_agility_score': agility_score,
            'findings_by_severity': self._count_by_severity(),
            'duration_seconds': (
                (self.end_time - self.start_time).total_seconds()
            ),
        }

        self.add_result('pqc_summary', summary)

        result = {
            'scanner': self.SCANNER_NAME,
            'scan_type': scan_type,
            'tls_inventory': tls_inventory,
            'ssh_inventory': ssh_inventory,
            'cert_analysis': cert_analysis,
            'local_audit': local_audit,
            'compliance': compliance_map,
            'agility_score': agility_score,
            'findings': self.findings,
            'summary': summary,
        }

        self.set_status('complete')
        self.save_results()
        return result

    # ------------------------------------------------------------------
    # TLS probing
    # ------------------------------------------------------------------

    def _probe_tls(self, host: str, port: int, timeout: int = 10) -> Optional[Dict]:
        """Connect to host:port via TLS and extract crypto details."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as conn:
                    cipher = conn.cipher()  # (name, protocol, bits)
                    cert_bin = conn.getpeercert(binary_form=True)
                    peer_cert = conn.getpeercert()
                    protocol = conn.version()

                    cipher_name = cipher[0] if cipher else 'UNKNOWN'
                    cipher_bits = cipher[2] if cipher else 0

                    # Derive key exchange from cipher suite name
                    kex_algo = self._kex_from_cipher(cipher_name)

                    info: Dict[str, Any] = {
                        'host': host,
                        'port': port,
                        'protocol': protocol,
                        'cipher_suite': cipher_name,
                        'cipher_bits': cipher_bits,
                        'key_exchange': kex_algo,
                        'quantum_vulnerable': self._is_kex_vulnerable(kex_algo),
                        'pqc_ready': self._is_kex_pqc(cipher_name, kex_algo),
                        'peer_cert': peer_cert,
                        'cert_der': cert_bin,
                    }

                    self.add_result('tls_probe', {
                        k: v for k, v in info.items()
                        if k not in ('peer_cert', 'cert_der')
                    }, f"{host}:{port}")

                    return info

        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            self.scan_logger.debug(f"TLS connect {host}:{port}: {exc}")
            return None

    @staticmethod
    def _kex_from_cipher(cipher_name: str) -> str:
        """Derive key-exchange family from cipher-suite name."""
        cn = cipher_name.upper()
        if 'KYBER' in cn or 'MLKEM' in cn or 'ML-KEM' in cn:
            return 'ML-KEM'
        if cn.startswith('TLS_'):
            # TLS 1.3 suites don't embed KEX — it's negotiated separately.
            return 'TLS1.3-ECDHE-or-PQC'
        for prefix in ('ECDHE', 'ECDH', 'DHE', 'DH', 'RSA', 'DSA'):
            if prefix in cn:
                return prefix
        return 'UNKNOWN'

    @staticmethod
    def _is_kex_vulnerable(kex: str) -> bool:
        upper = kex.upper()
        for vuln in QUANTUM_VULNERABLE_KEX:
            if vuln in upper:
                return True
        return False

    @staticmethod
    def _is_kex_pqc(cipher_name: str, kex: str) -> bool:
        combined = (cipher_name + ' ' + kex).upper()
        for pqc in PQC_READY_KEX:
            if pqc.upper() in combined:
                return True
        return False

    # ------------------------------------------------------------------
    # Certificate analysis
    # ------------------------------------------------------------------

    def _analyse_certificate(self, tls_info: Dict) -> Optional[Dict]:
        """Extract PQC-relevant certificate details from a TLS probe.

        Uses the DER-encoded certificate via OpenSSL CLI as the primary
        source because ``getpeercert()`` returns an empty dict when
        ``verify_mode=CERT_NONE`` (which we need for scanning arbitrary
        hosts).  Falls back to the Python dict when available.
        """
        cert_der = tls_info.get('cert_der')
        peer = tls_info.get('peer_cert') or {}

        if not cert_der and not peer:
            return None

        host = tls_info['host']
        port = tls_info['port']

        # --- Extract crypto fields from DER via OpenSSL -----------------
        key_type, key_size, sig_algo = self._extract_cert_crypto(cert_der)
        subject_cn, issuer_cn, not_before_str, not_after_str, san_list, chain_depth = (
            self._extract_cert_metadata(cert_der)
        )

        # Override with Python peer dict if it has data (non-CERT_NONE)
        if peer:
            subject_parts = dict(x[0] for x in peer.get('subject', []) if x)
            issuer_parts = dict(x[0] for x in peer.get('issuer', []) if x)
            subject_cn = subject_parts.get('commonName', subject_cn)
            issuer_cn = issuer_parts.get('commonName', issuer_cn)
            not_after_str = peer.get('notAfter', not_after_str)
            not_before_str = peer.get('notBefore', not_before_str)
            san_list = [
                entry[1] for entry in peer.get('subjectAltName', [])
            ] or san_list
            chain_depth = max(len(peer.get('caIssuers', [])) + 1, chain_depth)

        expiry_dt = self._parse_cert_date(not_after_str)

        expires_after_pqc = (
            expiry_dt.year >= PQC_MIGRATION_YEAR if expiry_dt else False
        )

        cert_info: Dict[str, Any] = {
            'host': host,
            'port': port,
            'subject_cn': subject_cn,
            'issuer_cn': issuer_cn,
            'not_before': not_before_str,
            'not_after': not_after_str,
            'key_type': key_type,
            'key_size': key_size,
            'signature_algorithm': sig_algo,
            'chain_depth': chain_depth,
            'quantum_vulnerable_key': key_type in ('RSA', 'ECDSA', 'DSA', 'EC'),
            'quantum_vulnerable_sig': self._sig_is_vulnerable(sig_algo),
            'expires_after_pqc_deadline': expires_after_pqc,
            'san': san_list,
        }

        self.add_result('cert_analysis', {
            k: v for k, v in cert_info.items()
        }, f"{host}:{port}")

        return cert_info

    def _run_openssl_on_der(self, cert_der: bytes,
                            extra_args: List[str]) -> str:
        """Write DER cert to a temp file and run openssl x509 on it.

        Using a temp file instead of stdin because OpenSSL on Windows
        does not reliably read binary DER from piped stdin.
        """
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(suffix='.der')
            os.write(fd, cert_der)
            os.close(fd)
            proc = subprocess.run(
                ['openssl', 'x509', '-inform', 'DER', '-in', tmp_path,
                 '-noout'] + extra_args,
                capture_output=True, text=True, timeout=10,
            )
            return proc.stdout
        except Exception:
            return ''
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _extract_cert_crypto(self, cert_der: Optional[bytes]
                              ) -> Tuple[str, int, str]:
        """Use OpenSSL CLI to get key type, size, and signature algorithm."""
        if not cert_der:
            return ('UNKNOWN', 0, 'UNKNOWN')

        text = self._run_openssl_on_der(cert_der, ['-text'])

        key_type = 'UNKNOWN'
        key_size = 0
        sig_algo = 'UNKNOWN'

        # Signature Algorithm
        m = re.search(r'Signature Algorithm:\s+(\S+)', text)
        if m:
            sig_algo = m.group(1)

        # Public Key Algorithm + size
        m = re.search(r'Public Key Algorithm:\s+(\S+)', text)
        if m:
            algo = m.group(1).lower()
            if 'rsa' in algo:
                key_type = 'RSA'
            elif 'ec' in algo or 'ecdsa' in algo:
                key_type = 'EC'
            elif 'dsa' in algo:
                key_type = 'DSA'
            elif 'ed25519' in algo:
                key_type = 'Ed25519'
            elif 'ed448' in algo:
                key_type = 'Ed448'
            elif 'dilithium' in algo or 'ml-dsa' in algo or 'mldsa' in algo:
                key_type = 'ML-DSA'
            else:
                key_type = algo

        m = re.search(r'(?:Public-Key|RSA Public-Key):\s*\((\d+)\s*bit', text)
        if m:
            key_size = int(m.group(1))

        return (key_type, key_size, sig_algo)

    def _extract_cert_metadata(self, cert_der: Optional[bytes]
                                ) -> Tuple[str, str, str, str, List[str], int]:
        """Extract subject CN, issuer CN, dates, SANs from DER via OpenSSL.

        Returns (subject_cn, issuer_cn, not_before, not_after, san_list, chain_depth).
        """
        defaults = ('N/A', 'N/A', '', '', [], 1)
        if not cert_der:
            return defaults

        text = self._run_openssl_on_der(
            cert_der,
            ['-subject', '-issuer', '-dates', '-ext', 'subjectAltName'],
        )
        if not text:
            return defaults

        subject_cn = 'N/A'
        issuer_cn = 'N/A'
        not_before = ''
        not_after = ''
        san_list: List[str] = []

        for line in text.splitlines():
            line = line.strip()
            if line.startswith('subject=') or line.startswith('subject ='):
                m = re.search(r'CN\s*=\s*([^,/]+)', line)
                if m:
                    subject_cn = m.group(1).strip()
            elif line.startswith('issuer=') or line.startswith('issuer ='):
                m = re.search(r'CN\s*=\s*([^,/]+)', line)
                if m:
                    issuer_cn = m.group(1).strip()
            elif line.startswith('notBefore='):
                not_before = line.split('=', 1)[1].strip()
            elif line.startswith('notAfter='):
                not_after = line.split('=', 1)[1].strip()
            elif 'DNS:' in line:
                san_list.extend(
                    s.strip().replace('DNS:', '')
                    for s in line.split(',')
                    if 'DNS:' in s
                )

        return (subject_cn, issuer_cn, not_before, not_after, san_list, 1)

    @staticmethod
    def _sig_is_vulnerable(sig_algo: str) -> bool:
        upper = sig_algo.upper()
        for token in ('RSA', 'ECDSA', 'DSA'):
            if token in upper:
                return True
        return False

    @staticmethod
    def _parse_cert_date(date_str: str) -> Optional[datetime]:
        """Parse certificate date string."""
        for fmt in ('%b %d %H:%M:%S %Y %Z', '%b  %d %H:%M:%S %Y %Z',
                    '%Y-%m-%dT%H:%M:%S'):
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        return None

    # ------------------------------------------------------------------
    # TLS findings
    # ------------------------------------------------------------------

    @staticmethod
    def _serializable_tls(tls_info: Dict) -> Dict:
        """Return a JSON-safe copy of tls_info (strip cert_der bytes)."""
        return {
            k: v for k, v in tls_info.items()
            if k not in ('cert_der', 'peer_cert')
        }

    def _assess_tls_finding(self, tls_info: Dict) -> None:
        """Generate findings from a TLS probe result."""
        host_port = f"{tls_info['host']}:{tls_info['port']}"
        kex = tls_info['key_exchange']
        cipher = tls_info['cipher_suite']
        bits = tls_info.get('cipher_bits', 0)
        safe_data = self._serializable_tls(tls_info)

        if tls_info.get('pqc_ready'):
            self.add_finding(
                severity='INFO',
                title=f"PQC-ready key exchange detected: {kex}",
                description=(
                    f"Connection to {host_port} uses cipher {cipher} with "
                    f"post-quantum key exchange ({kex})."
                ),
                affected_asset=host_port,
                finding_type='pqc_tls_ready',
                remediation='No action needed. Continue monitoring PQC standards.',
                raw_data=safe_data,
                detection_method='tls_probe',
            )
            return

        if tls_info.get('quantum_vulnerable'):
            # Default HIGH for quantum-vulnerable KEX.
            # CRITICAL only for demonstrably weak classical key sizes
            # (DH-1024, RSA-1024). cipher_bits is symmetric strength, not
            # KEX strength, so we check the KEX name for known weak groups.
            severity = 'HIGH'
            kex_upper = kex.upper()
            if any(weak in kex_upper for weak in ('DH-1024', 'RSA-1024', 'DSA')):
                severity = 'CRITICAL'

            self.add_finding(
                severity=severity,
                title=f"Quantum-vulnerable key exchange: {kex}",
                description=(
                    f"Connection to {host_port} uses {cipher} ({bits}-bit) "
                    f"with key exchange {kex}, which is vulnerable to quantum "
                    f"attack (Shor's algorithm). Plan migration to ML-KEM / "
                    f"X25519Kyber768."
                ),
                affected_asset=host_port,
                finding_type='pqc_tls_vulnerable',
                remediation=(
                    'Migrate to PQC-hybrid key exchange (X25519Kyber768 or '
                    'ML-KEM-768). Upgrade TLS libraries to versions supporting '
                    'NIST PQC standards. Follow CNSA 2.0 timeline.'
                ),
                raw_data=safe_data,
                detection_method='tls_probe',
            )

    # ------------------------------------------------------------------
    # Certificate findings
    # ------------------------------------------------------------------

    def _assess_cert_finding(self, cert_info: Dict) -> None:
        host_port = f"{cert_info['host']}:{cert_info['port']}"

        # Weak key size
        key_type = cert_info.get('key_type', '')
        key_size = cert_info.get('key_size', 0)

        if key_type == 'RSA' and key_size and key_size <= 1024:
            self.add_finding(
                severity='CRITICAL',
                title=f"RSA-{key_size} certificate (critically weak)",
                description=(
                    f"Certificate on {host_port} uses RSA-{key_size}, which is "
                    f"trivially breakable even by classical computers and will "
                    f"be instantly broken by a CRQC."
                ),
                affected_asset=host_port,
                finding_type='pqc_cert_weak_key',
                remediation='Replace immediately with RSA-4096 or ML-DSA certificate.',
                raw_data=cert_info,
                detection_method='cert_analysis',
            )
        elif key_type == 'DSA':
            self.add_finding(
                severity='CRITICAL',
                title=f"DSA certificate key (deprecated and quantum-vulnerable)",
                description=(
                    f"Certificate on {host_port} uses DSA, which is deprecated "
                    f"and quantum-vulnerable."
                ),
                affected_asset=host_port,
                finding_type='pqc_cert_weak_key',
                remediation='Replace with ML-DSA or at minimum RSA-4096/ECDSA-P384.',
                raw_data=cert_info,
                detection_method='cert_analysis',
            )

        # Quantum-vulnerable key that will outlive PQC deadline
        if cert_info.get('expires_after_pqc_deadline') and cert_info.get('quantum_vulnerable_key'):
            self.add_finding(
                severity='HIGH',
                title=f"Certificate with quantum-vulnerable key expires after {PQC_MIGRATION_YEAR}",
                description=(
                    f"Certificate on {host_port} ({key_type}-{key_size}) "
                    f"expires {cert_info['not_after']}, past the {PQC_MIGRATION_YEAR} "
                    f"PQC migration target. Plan for certificate replacement with "
                    f"PQC-safe algorithms before expiry."
                ),
                affected_asset=host_port,
                finding_type='pqc_cert_timeline_risk',
                remediation=(
                    f'Renew certificate before {PQC_MIGRATION_YEAR} with a '
                    f'PQC-safe key (ML-DSA / Dilithium). Follow CNSA 2.0 timeline.'
                ),
                raw_data=cert_info,
                detection_method='cert_analysis',
            )

        # Quantum-vulnerable signature
        if cert_info.get('quantum_vulnerable_sig') and cert_info.get('quantum_vulnerable_key'):
            # Only add if we haven't already flagged something more severe
            if not (cert_info.get('expires_after_pqc_deadline')):
                self.add_finding(
                    severity='HIGH',
                    title=f"Quantum-vulnerable certificate: {key_type}-{key_size}",
                    description=(
                        f"Certificate on {host_port} uses {key_type}-{key_size} key "
                        f"with {cert_info['signature_algorithm']} signature. Both "
                        f"are vulnerable to quantum cryptanalysis."
                    ),
                    affected_asset=host_port,
                    finding_type='pqc_cert_vulnerable',
                    remediation=(
                        'Plan migration to ML-DSA certificates. As interim, '
                        'ensure hybrid key exchange is in use.'
                    ),
                    raw_data=cert_info,
                    detection_method='cert_analysis',
                )

    # ------------------------------------------------------------------
    # SSH probing
    # ------------------------------------------------------------------

    def _probe_ssh(self, host: str, port: int = SSH_PORT,
                   timeout: int = 10) -> Optional[Dict]:
        """Probe SSH server for key exchange and host key algorithms."""
        # Try ssh-keyscan first (most reliable, cross-platform if OpenSSH installed)
        algorithms = self._ssh_keyscan(host, port, timeout)
        kex_algos = self._ssh_kex_algorithms(host, port, timeout)

        if not algorithms and not kex_algos:
            return None

        has_pqc_kex = any(
            a in SSH_PQC_KEX for a in kex_algos
        )
        vulnerable_kex = [a for a in kex_algos if a in SSH_VULNERABLE_KEX]
        pqc_kex = [a for a in kex_algos if a in SSH_PQC_KEX]

        vulnerable_host_keys = [
            a for a in algorithms if a in SSH_VULNERABLE_HOST_KEYS
        ]

        info: Dict[str, Any] = {
            'host': host,
            'port': port,
            'host_key_types': algorithms,
            'kex_algorithms': kex_algos,
            'vulnerable_kex': vulnerable_kex,
            'pqc_kex': pqc_kex,
            'vulnerable_host_keys': vulnerable_host_keys,
            'has_pqc_kex': has_pqc_kex,
            'quantum_vulnerable': bool(vulnerable_kex or vulnerable_host_keys),
        }

        self.add_result('ssh_probe', info, f"{host}:{port}")
        return info

    def _ssh_keyscan(self, host: str, port: int, timeout: int) -> List[str]:
        """Run ssh-keyscan to discover host key types."""
        try:
            cmd = ['ssh-keyscan', '-T', str(timeout), '-p', str(port), host]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 5,
            )
            key_types = set()
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    key_types.add(parts[1])
            return sorted(key_types)
        except Exception as exc:
            self.scan_logger.debug(f"ssh-keyscan failed: {exc}")
            return []

    def _ssh_kex_algorithms(self, host: str, port: int,
                            timeout: int) -> List[str]:
        """Extract KEX algorithm list from the SSH server's KEXINIT message.

        This performs a raw TCP connection and reads the SSH banner + KEXINIT
        packet to enumerate supported key exchange algorithms without
        requiring paramiko.
        """
        kex_algos: List[str] = []
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                # Read server banner
                banner = b''
                while not banner.endswith(b'\n'):
                    chunk = sock.recv(1)
                    if not chunk:
                        break
                    banner += chunk

                # Send our banner
                sock.sendall(b'SSH-2.0-DonjonPQCScanner\r\n')

                # Read KEXINIT packet
                # SSH packet: uint32 length, byte padding_length, byte type, ...
                header = self._recv_exact(sock, 4, timeout)
                if not header:
                    return kex_algos
                pkt_len = struct.unpack('>I', header)[0]
                if pkt_len > 65536:
                    return kex_algos
                payload = self._recv_exact(sock, pkt_len, timeout)
                if not payload:
                    return kex_algos

                padding_len = payload[0]
                msg_type = payload[1]

                if msg_type != 20:  # SSH_MSG_KEXINIT
                    return kex_algos

                # Skip: padding_length(1) + msg_type(1) + cookie(16)
                offset = 2 + 16

                # First name-list is kex_algorithms
                if offset + 4 > len(payload):
                    return kex_algos
                name_len = struct.unpack('>I', payload[offset:offset + 4])[0]
                offset += 4
                if offset + name_len > len(payload):
                    return kex_algos
                kex_str = payload[offset:offset + name_len].decode(
                    'ascii', errors='replace'
                )
                kex_algos = kex_str.split(',')
        except Exception as exc:
            self.scan_logger.debug(f"SSH KEX extraction failed for {host}: {exc}")

        return kex_algos

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int, timeout: int) -> Optional[bytes]:
        """Receive exactly n bytes from a socket."""
        sock.settimeout(timeout)
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    # ------------------------------------------------------------------
    # SSH findings
    # ------------------------------------------------------------------

    def _assess_ssh_finding(self, ssh_info: Dict) -> None:
        host_port = f"{ssh_info['host']}:{ssh_info['port']}"

        if ssh_info.get('has_pqc_kex'):
            self.add_finding(
                severity='INFO',
                title=f"PQC-ready SSH key exchange available",
                description=(
                    f"SSH server at {host_port} supports PQC key exchange: "
                    f"{', '.join(ssh_info['pqc_kex'])}."
                ),
                affected_asset=host_port,
                finding_type='pqc_ssh_ready',
                remediation='No action needed. Ensure PQC KEX is preferred.',
                raw_data=ssh_info,
                detection_method='ssh_probe',
            )

        if ssh_info.get('vulnerable_kex'):
            self.add_finding(
                severity='HIGH',
                title=f"Quantum-vulnerable SSH key exchange algorithms",
                description=(
                    f"SSH server at {host_port} supports quantum-vulnerable "
                    f"key exchange algorithms: "
                    f"{', '.join(ssh_info['vulnerable_kex'][:5])}. "
                    f"These can be broken by Shor's algorithm on a CRQC."
                ),
                affected_asset=host_port,
                finding_type='pqc_ssh_vulnerable_kex',
                remediation=(
                    'Enable sntrup761x25519-sha512@openssh.com key exchange. '
                    'Upgrade OpenSSH to 9.0+ which supports hybrid PQC KEX. '
                    'Disable legacy DH/ECDH-only key exchange algorithms.'
                ),
                raw_data=ssh_info,
                detection_method='ssh_probe',
            )

        if ssh_info.get('vulnerable_host_keys'):
            # Check for truly weak keys
            has_dsa = 'ssh-dss' in ssh_info['vulnerable_host_keys']
            severity = 'CRITICAL' if has_dsa else 'HIGH'
            self.add_finding(
                severity=severity,
                title=f"Quantum-vulnerable SSH host key types",
                description=(
                    f"SSH server at {host_port} uses quantum-vulnerable "
                    f"host key types: "
                    f"{', '.join(ssh_info['vulnerable_host_keys'])}."
                ),
                affected_asset=host_port,
                finding_type='pqc_ssh_vulnerable_hostkey',
                remediation=(
                    'Generate Ed25519 host keys as minimum. Plan migration to '
                    'ML-DSA host keys when OpenSSH supports them. Remove DSA '
                    'host keys immediately.'
                ),
                raw_data=ssh_info,
                detection_method='ssh_probe',
            )

    # ------------------------------------------------------------------
    # Local crypto audit
    # ------------------------------------------------------------------

    def _local_crypto_audit(self) -> Dict[str, Any]:
        """Audit local system for PQC readiness."""
        audit: Dict[str, Any] = {
            'platform': platform.system(),
            'openssl': self._check_openssl(),
            'ssh_client': self._check_ssh_client_config(),
            'known_hosts': self._check_known_hosts(),
            'pqc_libraries': self._check_pqc_libraries(),
        }

        # Generate findings from local audit
        self._assess_local_findings(audit)
        self.add_result('local_audit', audit)

        return audit

    def _check_openssl(self) -> Dict[str, Any]:
        """Check OpenSSL version and PQC capability."""
        info: Dict[str, Any] = {
            'installed': False,
            'version': 'UNKNOWN',
            'pqc_capable': False,
        }
        try:
            result = subprocess.run(
                ['openssl', 'version'], capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                info['installed'] = True
                version_str = result.stdout.strip()
                info['version'] = version_str

                # OpenSSL 3.2+ has OQS provider support path
                m = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
                if m:
                    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
                    info['version_tuple'] = [major, minor, patch]
                    # OQS provider works with 3.2+; native PQC in 3.5+
                    if major >= 3 and minor >= 2:
                        info['pqc_capable'] = True
                    elif major >= 4:
                        info['pqc_capable'] = True

                # Check for OQS provider
                try:
                    prov_result = subprocess.run(
                        ['openssl', 'list', '-providers'],
                        capture_output=True, text=True, timeout=10,
                    )
                    if 'oqs' in prov_result.stdout.lower():
                        info['oqs_provider'] = True
                        info['pqc_capable'] = True
                except Exception:
                    pass

        except Exception as exc:
            self.scan_logger.debug(f"OpenSSL check failed: {exc}")

        return info

    def _check_ssh_client_config(self) -> Dict[str, Any]:
        """Check SSH client configuration for PQC algorithm support."""
        info: Dict[str, Any] = {
            'pqc_kex_configured': False,
            'config_file': None,
            'kex_algorithms': [],
        }

        # Determine config paths
        home = Path.home()
        ssh_config = home / '.ssh' / 'config'

        if ssh_config.exists():
            info['config_file'] = str(ssh_config)
            try:
                content = ssh_config.read_text(errors='replace')
                # Look for KexAlgorithms directive
                for line in content.splitlines():
                    stripped = line.strip().lower()
                    if stripped.startswith('kexalgorithms'):
                        algos = stripped.split(None, 1)
                        if len(algos) > 1:
                            info['kex_algorithms'] = [
                                a.strip() for a in algos[1].split(',')
                            ]
                            for pqc in SSH_PQC_KEX:
                                if pqc in algos[1]:
                                    info['pqc_kex_configured'] = True
                                    break
            except Exception:
                pass

        # Also check system-wide sshd_config
        sshd_paths = []
        if platform.system() == 'Windows':
            sshd_paths = [
                Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'ssh' / 'sshd_config',
            ]
        else:
            sshd_paths = [
                Path('/etc/ssh/sshd_config'),
                Path('/etc/ssh/sshd_config.d'),
            ]

        for sshd_config in sshd_paths:
            if sshd_config.exists() and sshd_config.is_file():
                info['sshd_config'] = str(sshd_config)
                try:
                    content = sshd_config.read_text(errors='replace')
                    for line in content.splitlines():
                        stripped = line.strip().lower()
                        if stripped.startswith('kexalgorithms'):
                            for pqc in SSH_PQC_KEX:
                                if pqc in stripped:
                                    info['pqc_kex_configured'] = True
                                    break
                except Exception:
                    pass

        return info

    def _check_known_hosts(self) -> Dict[str, Any]:
        """Analyse ~/.ssh/known_hosts for key types in use."""
        info: Dict[str, Any] = {
            'file_exists': False,
            'total_entries': 0,
            'key_type_counts': {},
            'vulnerable_entries': 0,
        }

        kh_path = Path.home() / '.ssh' / 'known_hosts'
        if not kh_path.exists():
            return info

        info['file_exists'] = True
        key_counts: Dict[str, int] = {}
        vuln_count = 0

        try:
            for line in kh_path.read_text(errors='replace').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    key_type = parts[1] if not parts[0].startswith('@') else (
                        parts[2] if len(parts) >= 3 else 'UNKNOWN'
                    )
                    # Handle hashed hostnames: "host key_type base64"
                    # Could also be "|1|salt|hash key_type base64"
                    key_counts[key_type] = key_counts.get(key_type, 0) + 1
                    info['total_entries'] += 1
                    if key_type in SSH_VULNERABLE_HOST_KEYS:
                        vuln_count += 1
        except Exception:
            pass

        info['key_type_counts'] = key_counts
        info['vulnerable_entries'] = vuln_count

        return info

    def _check_pqc_libraries(self) -> Dict[str, Any]:
        """Check for PQC-capable crypto libraries on the system."""
        libs: Dict[str, Any] = {
            'liboqs': False,
            'pqcrypto': False,
            'oqs_python': False,
            'pqc_rust': False,
        }

        # Check Python packages
        for pkg, key in [('oqs', 'oqs_python'), ('pqcrypto', 'pqcrypto')]:
            try:
                __import__(pkg)
                libs[key] = True
            except ImportError:
                pass

        # Check liboqs shared library
        if platform.system() == 'Windows':
            lib_names = ['oqs.dll', 'liboqs.dll']
            search_dirs = [
                Path(os.environ.get('ProgramFiles', 'C:/Program Files')),
                Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32',
            ]
        else:
            lib_names = ['liboqs.so', 'liboqs.so.0']
            search_dirs = [
                Path('/usr/lib'), Path('/usr/lib64'),
                Path('/usr/local/lib'), Path('/usr/local/lib64'),
            ]

        for search_dir in search_dirs:
            if search_dir.exists():
                for lib_name in lib_names:
                    if (search_dir / lib_name).exists():
                        libs['liboqs'] = True
                        break

        return libs

    # ------------------------------------------------------------------
    # Local audit findings
    # ------------------------------------------------------------------

    def _assess_local_findings(self, audit: Dict) -> None:
        """Generate findings from local crypto audit."""
        # OpenSSL version
        openssl = audit.get('openssl', {})
        if openssl.get('installed'):
            if not openssl.get('pqc_capable'):
                self.add_finding(
                    severity='MEDIUM',
                    title='OpenSSL version lacks PQC support',
                    description=(
                        f"Local OpenSSL ({openssl.get('version', 'unknown')}) "
                        f"does not support PQC algorithms. OpenSSL 3.2+ with "
                        f"OQS provider or 3.5+ with native PQC is required."
                    ),
                    affected_asset='localhost',
                    finding_type='pqc_openssl_outdated',
                    remediation=(
                        'Upgrade OpenSSL to 3.2+ and install the OQS provider, '
                        'or upgrade to 3.5+ for native PQC support.'
                    ),
                    detection_method='local_audit',
                )
            else:
                self.add_finding(
                    severity='INFO',
                    title='OpenSSL supports PQC algorithms',
                    description=(
                        f"Local OpenSSL ({openssl.get('version', 'unknown')}) "
                        f"supports post-quantum cryptography."
                    ),
                    affected_asset='localhost',
                    finding_type='pqc_openssl_ready',
                    remediation='Ensure PQC algorithms are configured as preferred.',
                    detection_method='local_audit',
                )

        # PQC libraries
        pqc_libs = audit.get('pqc_libraries', {})
        has_any = any(pqc_libs.values())
        if not has_any:
            self.add_finding(
                severity='MEDIUM',
                title='No PQC cryptographic libraries detected',
                description=(
                    'No post-quantum cryptographic libraries (liboqs, '
                    'pqcrypto, oqs-python) were found on this system.'
                ),
                affected_asset='localhost',
                finding_type='pqc_no_libraries',
                remediation=(
                    'Install liboqs and the OQS OpenSSL provider for PQC '
                    'algorithm support. For Python applications, install '
                    'oqs-python.'
                ),
                detection_method='local_audit',
            )
        else:
            self.add_finding(
                severity='LOW',
                title='PQC libraries available but may not be default',
                description=(
                    f"PQC libraries detected: "
                    f"{', '.join(k for k, v in pqc_libs.items() if v)}. "
                    f"Verify they are configured as default/preferred."
                ),
                affected_asset='localhost',
                finding_type='pqc_libraries_available',
                remediation='Configure PQC libraries as preferred in application crypto settings.',
                detection_method='local_audit',
            )

        # SSH config
        ssh_cfg = audit.get('ssh_client', {})
        if not ssh_cfg.get('pqc_kex_configured'):
            self.add_finding(
                severity='MEDIUM',
                title='SSH client/server not configured for PQC key exchange',
                description=(
                    'The local SSH configuration does not include PQC key '
                    'exchange algorithms (sntrup761x25519-sha512). '
                    'Connections are quantum-vulnerable.'
                ),
                affected_asset='localhost',
                finding_type='pqc_ssh_config_missing',
                remediation=(
                    'Add "KexAlgorithms sntrup761x25519-sha512@openssh.com,'
                    'curve25519-sha256" to SSH config. Upgrade OpenSSH to 9.0+.'
                ),
                detection_method='local_audit',
            )

        # Known hosts
        kh = audit.get('known_hosts', {})
        if kh.get('vulnerable_entries', 0) > 0:
            total = kh.get('total_entries', 0)
            vuln = kh['vulnerable_entries']
            self.add_finding(
                severity='MEDIUM',
                title=f"{vuln}/{total} known_hosts entries use quantum-vulnerable keys",
                description=(
                    f"{vuln} of {total} entries in ~/.ssh/known_hosts use "
                    f"quantum-vulnerable key types (RSA, ECDSA, DSA). These "
                    f"host identities cannot be trusted post-quantum."
                ),
                affected_asset='localhost',
                finding_type='pqc_known_hosts_vulnerable',
                remediation=(
                    'Regenerate host keys on remote servers using Ed25519 or '
                    'PQC-safe algorithms. Update known_hosts accordingly.'
                ),
                detection_method='local_audit',
            )

    # ------------------------------------------------------------------
    # Compliance mapping
    # ------------------------------------------------------------------

    def _build_compliance_map(
        self,
        tls_inv: List[Dict],
        ssh_inv: List[Dict],
        cert_inv: List[Dict],
        local_audit: Dict,
    ) -> Dict[str, Any]:
        """Map findings to PQC compliance frameworks."""
        frameworks: Dict[str, Any] = {}

        # --- NIST SP 800-208 (Stateful Hash-Based Signatures) ---
        frameworks['nist_sp_800_208'] = {
            'title': 'NIST SP 800-208 - Recommendation for Stateful Hash-Based Signature Schemes',
            'applicable': True,
            'controls': {
                'LMS_XMSS_support': {
                    'description': 'Support for LMS/XMSS stateful hash-based signatures',
                    'status': 'not_assessed',
                    'note': 'Requires firmware/code signing audit beyond network scan.',
                },
            },
        }

        # --- NSA CNSA 2.0 Suite ---
        tls_vulnerable_count = sum(
            1 for t in tls_inv if t.get('quantum_vulnerable')
        )
        tls_pqc_count = sum(1 for t in tls_inv if t.get('pqc_ready'))
        ssh_vulnerable_count = sum(
            1 for s in ssh_inv if s.get('quantum_vulnerable')
        )
        ssh_pqc_count = sum(1 for s in ssh_inv if s.get('has_pqc_kex'))

        cnsa2_status = 'non_compliant'
        if tls_vulnerable_count == 0 and ssh_vulnerable_count == 0:
            cnsa2_status = 'compliant'
        elif tls_pqc_count > 0 or ssh_pqc_count > 0:
            cnsa2_status = 'partial'

        frameworks['nsa_cnsa_2_0'] = {
            'title': 'NSA CNSA 2.0 Suite - Quantum-Resistant Requirements',
            'applicable': True,
            'status': cnsa2_status,
            'controls': {
                'key_exchange': {
                    'requirement': 'ML-KEM-768 or ML-KEM-1024 for key establishment',
                    'tls_vulnerable': tls_vulnerable_count,
                    'tls_pqc_ready': tls_pqc_count,
                    'ssh_vulnerable': ssh_vulnerable_count,
                    'ssh_pqc_ready': ssh_pqc_count,
                    'status': 'pass' if (tls_vulnerable_count == 0 and ssh_vulnerable_count == 0) else 'fail',
                },
                'digital_signatures': {
                    'requirement': 'ML-DSA-65 or ML-DSA-87 for digital signatures',
                    'certs_with_vulnerable_sig': sum(
                        1 for c in cert_inv if c.get('quantum_vulnerable_sig')
                    ),
                    'status': 'fail' if any(
                        c.get('quantum_vulnerable_sig') for c in cert_inv
                    ) else 'pass',
                },
                'symmetric_crypto': {
                    'requirement': 'AES-256 for symmetric encryption',
                    'note': 'AES-256 is quantum-safe (Grover halves effective key length to 128-bit).',
                    'status': 'info',
                },
            },
            'timeline': CNSA2_DEADLINES,
        }

        # --- NIST IR 8547 (Transition to PQC Standards) ---
        frameworks['nist_ir_8547'] = {
            'title': 'NIST IR 8547 - Transition to Post-Quantum Cryptography Standards',
            'applicable': True,
            'controls': {
                'crypto_inventory': {
                    'description': 'Complete inventory of cryptographic algorithms in use',
                    'status': 'performed',
                    'tls_connections_inventoried': len(tls_inv),
                    'ssh_hosts_inventoried': len(ssh_inv),
                    'certificates_inventoried': len(cert_inv),
                },
                'migration_priority': {
                    'description': 'Prioritize migration of highest-risk systems',
                    'high_risk_tls': tls_vulnerable_count,
                    'high_risk_ssh': ssh_vulnerable_count,
                    'certs_past_deadline': sum(
                        1 for c in cert_inv if c.get('expires_after_pqc_deadline')
                    ),
                },
                'hybrid_approach': {
                    'description': 'Use hybrid classical+PQC during transition',
                    'pqc_connections': tls_pqc_count + ssh_pqc_count,
                },
                'crypto_agility': {
                    'description': 'Systems must support algorithm agility',
                    'openssl_pqc_capable': local_audit.get('openssl', {}).get('pqc_capable', False),
                    'pqc_libraries_present': any(
                        local_audit.get('pqc_libraries', {}).values()
                    ),
                },
            },
        }

        return frameworks

    # ------------------------------------------------------------------
    # Crypto Agility Score
    # ------------------------------------------------------------------

    def _compute_agility_score(
        self,
        tls_inv: List[Dict],
        ssh_inv: List[Dict],
        cert_inv: List[Dict],
        local_audit: Dict,
    ) -> Dict[str, Any]:
        """Compute a 0-100 Crypto Agility Score.

        Breakdown (each 0-100, weighted):
          - TLS key exchange PQC %    (30%)
          - Certificate PQC %          (25%)
          - SSH key exchange PQC %     (20%)
          - Library/OpenSSL readiness  (15%)
          - Timeline risk              (10%)
        """
        scores: Dict[str, float] = {}

        # TLS KEX score
        if tls_inv:
            pqc_tls = sum(1 for t in tls_inv if t.get('pqc_ready'))
            scores['tls_kex_pqc_pct'] = (pqc_tls / len(tls_inv)) * 100
        else:
            scores['tls_kex_pqc_pct'] = 0.0  # no data = unknown risk

        # Certificate score
        if cert_inv:
            safe_certs = sum(
                1 for c in cert_inv
                if not c.get('quantum_vulnerable_key')
            )
            scores['cert_pqc_pct'] = (safe_certs / len(cert_inv)) * 100
        else:
            scores['cert_pqc_pct'] = 0.0

        # SSH KEX score
        if ssh_inv:
            pqc_ssh = sum(1 for s in ssh_inv if s.get('has_pqc_kex'))
            scores['ssh_kex_pqc_pct'] = (pqc_ssh / len(ssh_inv)) * 100
        else:
            scores['ssh_kex_pqc_pct'] = 0.0

        # Library readiness
        lib_score = 0.0
        openssl_info = local_audit.get('openssl', {})
        if openssl_info.get('pqc_capable'):
            lib_score += 50.0
        elif openssl_info.get('installed'):
            lib_score += 15.0

        pqc_libs = local_audit.get('pqc_libraries', {})
        if any(pqc_libs.values()):
            lib_score += 50.0
        scores['library_readiness'] = min(lib_score, 100.0)

        # Timeline risk: % of certs that will expire BEFORE PQC deadline (good)
        if cert_inv:
            safe_timeline = sum(
                1 for c in cert_inv
                if not c.get('expires_after_pqc_deadline')
            )
            scores['timeline_risk_pct'] = (safe_timeline / len(cert_inv)) * 100
        else:
            scores['timeline_risk_pct'] = 50.0  # unknown

        # Weighted composite
        weights = {
            'tls_kex_pqc_pct': 0.30,
            'cert_pqc_pct': 0.25,
            'ssh_kex_pqc_pct': 0.20,
            'library_readiness': 0.15,
            'timeline_risk_pct': 0.10,
        }

        composite = sum(
            scores[k] * w for k, w in weights.items()
        )

        return {
            'composite_score': round(composite, 1),
            'breakdown': {k: round(v, 1) for k, v in scores.items()},
            'weights': weights,
            'rating': self._score_rating(composite),
        }

    @staticmethod
    def _score_rating(score: float) -> str:
        if score >= 90:
            return 'EXCELLENT - Quantum-ready'
        elif score >= 70:
            return 'GOOD - Mostly ready, minor gaps'
        elif score >= 50:
            return 'FAIR - Significant migration work needed'
        elif score >= 25:
            return 'POOR - High quantum risk exposure'
        else:
            return 'CRITICAL - No PQC readiness detected'


if __name__ == '__main__':
    scanner = QuantumReadinessScanner()
    print(f"Quantum Readiness Scanner initialized")
    print(f"OpenSSL available: {scanner.check_tool('openssl')}")
    print(f"ssh-keyscan available: {scanner.check_tool('ssh-keyscan')}")
