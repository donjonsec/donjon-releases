#!/usr/bin/env python3
"""
Donjon - OpenVAS/GVM Integration Scanner
Direct integration with OpenVAS/Greenbone Vulnerability Manager.
Three modes: GMP protocol, CLI mode, and XML import mode.
Enriches imported findings with our KEV/EPSS data (value-add over standalone OpenVAS).
"""

import os
import re
import json
import sys
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner

try:
    from threat_intel import get_threat_intel
except ImportError:
    get_threat_intel = None


class OpenVASScanner(BaseScanner):
    """OpenVAS/GVM integration scanner."""

    SCANNER_NAME = "openvas"
    SCANNER_DESCRIPTION = "OpenVAS/GVM vulnerability scanner integration"

    # OpenVAS severity to our severity mapping
    SEVERITY_MAP = {
        'Log': 'INFO',
        'Low': 'LOW',
        'Medium': 'MEDIUM',
        'High': 'HIGH',
        'Critical': 'CRITICAL',
    }

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.gvm_available = False
        self.gvm_mode = None
        # Connection config — from env vars, config file, or auto-detect
        self.gvm_host = os.environ.get('GVM_HOST', '')
        self.gvm_port = int(os.environ.get('GVM_PORT', '9390'))
        self.gvm_username = os.environ.get('GVM_USERNAME', 'admin')
        self.gvm_password = os.environ.get('GVM_PASSWORD', 'admin')
        self.gvm_socket = os.environ.get('GVM_SOCKET', '/run/gvmd/gvmd.sock')
        self._load_config()
        self._detect_gvm()

    def _load_config(self):
        """Load GVM connection settings from platform config."""
        try:
            from config import Config
            cfg = Config()
            gvm_cfg = cfg.get('tools.openvas', {})
            if isinstance(gvm_cfg, dict):
                self.gvm_host = gvm_cfg.get('host', self.gvm_host)
                self.gvm_port = int(gvm_cfg.get('port', self.gvm_port))
                self.gvm_username = gvm_cfg.get('username', self.gvm_username)
                self.gvm_password = gvm_cfg.get('password', self.gvm_password)
                self.gvm_socket = gvm_cfg.get('socket', self.gvm_socket)
        except Exception:
            pass

    def _detect_gvm(self):
        """Detect available GVM integration mode.

        Priority:
        1. Remote TCP (GVM_HOST configured) — connects over network
        2. python-gvm library (local socket) — direct GMP protocol
        3. gvm-cli binary — command-line interface
        4. Docker container (local) — exec into container
        5. Import mode — always available for XML files
        """
        # 1. Remote TCP — if GVM_HOST is set, use it
        if self.gvm_host:
            self.gvm_mode = 'remote'
            self.gvm_available = True
            self.scan_logger.info(
                "GVM configured: remote TCP %s:%d", self.gvm_host, self.gvm_port
            )
            return

        # 2. python-gvm library (local socket)
        try:
            import gvm
            self.gvm_mode = 'gmp'
            self.gvm_available = True
            self.scan_logger.info("GVM detected: python-gvm library (GMP mode)")
            return
        except ImportError:
            pass

        # 3. gvm-cli binary
        import shutil
        if shutil.which('gvm-cli'):
            self.gvm_mode = 'cli'
            self.gvm_available = True
            self.scan_logger.info("GVM detected: gvm-cli (CLI mode)")
            return

        # 4. Docker container (local)
        try:
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}'],
                capture_output=True, text=True, timeout=10
            )
            if 'greenbone' in result.stdout.lower() or 'gvm' in result.stdout.lower() or 'openvas' in result.stdout.lower():
                self.gvm_mode = 'docker'
                self.gvm_available = True
                self.scan_logger.info("GVM detected: Docker container")
                return
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # 5. Auto-discover on common network addresses
        for candidate_host in ['localhost', '192.168.1.101']:
            if self._probe_gvm_port(candidate_host, 9390):
                self.gvm_host = candidate_host
                self.gvm_port = 9390
                self.gvm_mode = 'remote'
                self.gvm_available = True
                self.scan_logger.info(
                    "GVM auto-discovered: %s:%d", candidate_host, 9390
                )
                return

        # 6. Import mode is always available
        self.gvm_mode = 'import'
        self.scan_logger.info("GVM: Import mode only (no live scanner detected)")

    @staticmethod
    def _probe_gvm_port(host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a GVM instance is listening on host:port."""
        import socket
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False

    def scan(self, targets: List[str], scan_type: str = 'standard',
             report_path: str = None, **kwargs) -> Dict:
        """
        Execute OpenVAS scan or import results.

        Args:
            targets: List of hosts to scan
            scan_type: 'quick', 'standard', 'deep'
            report_path: Path to existing OpenVAS XML report to import
        """
        self.start_time = datetime.now(timezone.utc)
        self.scan_status = 'running'

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'mode': self.gvm_mode,
            'findings': [],
            'summary': {}
        }

        if report_path:
            # Import mode
            results['findings'] = self.import_openvas_report(report_path)
            results['mode'] = 'import'
        elif self.gvm_mode == 'remote':
            results['findings'] = self._scan_remote(targets, scan_type)
        elif self.gvm_mode == 'gmp':
            results['findings'] = self._scan_gmp(targets, scan_type)
        elif self.gvm_mode == 'cli':
            results['findings'] = self._scan_cli(targets, scan_type)
        else:
            self.set_status('failed', 'No OpenVAS/GVM instance found. Configure GVM_HOST or install GVM.')
            results['error'] = (
                'No live OpenVAS scanner detected. Options:\n'
                '  1. Set GVM_HOST and GVM_PORT env vars to point to your GVM instance\n'
                '  2. Configure tools.openvas.host in config/active/config.yaml\n'
                '  3. Install OpenVAS/GVM locally\n'
                '  4. Provide report_path= to import an existing OpenVAS XML report'
            )

        # Enrich all findings with KEV/EPSS
        if get_threat_intel is not None:
            self._enrich_findings(results['findings'])

        results['summary'] = self._generate_summary(results['findings'])

        self.end_time = datetime.now(timezone.utc)
        if self.scan_status != 'failed':
            self.set_status('complete')
        self.save_results()

        return results

    def _scan_remote(self, targets: List[str], scan_type: str) -> List[Dict]:
        """Scan using GMP protocol over TCP to a remote GVM instance.

        Tries connection methods in order:
        1. Unix socket (if host is localhost and socket exists)
        2. SSH tunnel (standard GVM deployment)
        3. TLS connection (GVM with TLS enabled)
        """
        findings = []
        try:
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
        except ImportError:
            self.scan_logger.warning(
                "python-gvm not installed. Install with: pip install python-gvm"
            )
            self.add_finding(
                severity='INFO',
                title='OpenVAS Remote: python-gvm library required',
                description=(
                    f'GVM remote host configured ({self.gvm_host}:{self.gvm_port}) '
                    f'but python-gvm library is not installed. '
                    f'Install with: pip install python-gvm'
                ),
                affected_asset=self.gvm_host,
                finding_type='openvas_config',
                remediation='pip install python-gvm',
            )
            return findings

        connection = None
        transform = EtreeTransform()

        # Try Unix socket first for localhost
        if self.gvm_host in ('localhost', '127.0.0.1', '::1'):
            try:
                from gvm.connections import UnixSocketConnection
                # Check common socket paths
                for sock_path in [self.gvm_socket, '/run/gvmd/gvmd.sock',
                                  '/var/run/gvmd/gvmd.sock', '/tmp/gvm/gvmd.sock']:
                    if Path(sock_path).exists():
                        connection = UnixSocketConnection(path=sock_path)
                        self.scan_logger.info("GVM: using Unix socket %s", sock_path)
                        break
                # Also try Docker exec socket
                if connection is None:
                    docker_sock = self._find_docker_gvm_socket()
                    if docker_sock:
                        connection = UnixSocketConnection(path=docker_sock)
                        self.scan_logger.info("GVM: using Docker socket %s", docker_sock)
            except Exception:
                pass

        # Try SSH connection (standard for remote GVM)
        if connection is None:
            try:
                from gvm.connections import SSHConnection
                connection = SSHConnection(
                    hostname=self.gvm_host,
                    port=22,
                    username=self.gvm_username,
                    password=self.gvm_password,
                )
                self.scan_logger.info(
                    "GVM: trying SSH to %s", self.gvm_host
                )
            except Exception:
                pass

        # Try TLS as last resort
        if connection is None:
            try:
                from gvm.connections import TLSConnection
                connection = TLSConnection(
                    hostname=self.gvm_host, port=self.gvm_port
                )
                self.scan_logger.info(
                    "GVM: trying TLS to %s:%d", self.gvm_host, self.gvm_port
                )
            except Exception as e:
                self.scan_logger.error("All GVM connection methods failed: %s", e)
                self.add_finding(
                    severity='MEDIUM',
                    title=f'OpenVAS connection failed: {self.gvm_host}',
                    description=f'Could not connect via socket, SSH, or TLS: {e}',
                    affected_asset=self.gvm_host,
                    finding_type='openvas_error',
                    remediation='Verify GVM host, port, and credentials.',
                )
                return findings

        try:
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.gvm_username, self.gvm_password)
                self.scan_logger.info(
                    "Authenticated to GVM at %s", self.gvm_host
                )
                findings = self._run_gmp_scan(gmp, targets, scan_type)
        except Exception as e:
            self.scan_logger.error("GVM scan failed: %s", e)
            self.add_finding(
                severity='MEDIUM',
                title=f'OpenVAS scan error: {self.gvm_host}',
                description=str(e)[:300],
                affected_asset=self.gvm_host,
                finding_type='openvas_error',
                remediation='Check GVM credentials and service status.',
            )
        return findings

    def _find_docker_gvm_socket(self) -> Optional[str]:
        """Find GVM socket exposed from a Docker container."""
        try:
            result = subprocess.run(
                ['docker', 'exec', 'openvas', 'ls', '/run/gvmd/gvmd.sock'],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                # Socket exists in container — map it out
                # Use docker exec approach instead
                return None  # Can't use container socket directly
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return None

    def _run_gmp_scan(self, gmp, targets: List[str], scan_type: str) -> List[Dict]:
        """Execute a scan via an authenticated GMP connection.

        Shared by both local socket and remote connection modes.
        """
        findings = []
        target_list = ', '.join(targets)

        # Create target in GVM
        target_id = gmp.create_target(
            name=f'Donjon-{datetime.now(timezone.utc).strftime("%Y%m%d%H%M")}',
            hosts=targets,
        ).get('id')

        # Select scan config by type
        config_map = {
            'quick': 'daba56c8-73ec-11df-a475-002264764cea',     # Discovery
            'standard': '085569ce-73ed-11df-83c3-002264764cea',   # Full and fast
            'deep': '698f691e-7489-11df-9d8c-002264764cea',       # Full and deep
        }
        config_id = config_map.get(scan_type, config_map['standard'])

        # Create and start task
        task_id = gmp.create_task(
            name=f'Donjon {scan_type} scan',
            config_id=config_id,
            target_id=target_id,
            scanner_id='08b69003-5fc2-4037-a479-93b440211c73',
        ).get('id')

        gmp.start_task(task_id)
        self.scan_logger.info("Started GVM task %s for %s", task_id, target_list)

        self.add_finding(
            severity='INFO',
            title=f'OpenVAS scan started: {scan_type}',
            description=(
                f'GVM task {task_id} started for targets: {target_list}. '
                f'Scan config: {scan_type}. Check GVM web UI for progress.'
            ),
            affected_asset=target_list,
            finding_type='openvas_task',
            remediation='Monitor scan progress in GVM dashboard.',
        )

        # TODO: poll for completion and retrieve results
        # For long-running scans, the orchestrator should check back later

        return findings

    def _scan_gmp(self, targets: List[str], scan_type: str) -> List[Dict]:
        """Scan using GMP protocol via python-gvm (local socket)."""
        findings = []
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform

            connection = UnixSocketConnection(path=self.gvm_socket)
            transform = EtreeTransform()

            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.gvm_username, self.gvm_password)
                findings = self._run_gmp_scan(gmp, targets, scan_type)

        except Exception as e:
            self.scan_logger.error("GMP local scan error: %s", e)

        return findings

    def _scan_cli(self, targets: List[str], scan_type: str) -> List[Dict]:
        """Scan using gvm-cli."""
        findings = []
        target_list = ' '.join(targets)

        try:
            # Create XML command for gvm-cli
            cmd = [
                'gvm-cli', '--gmp-username', self.gvm_username, '--gmp-password', self.gvm_password,
                'socket', '--xml',
                f'<get_version/>'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                self.scan_logger.info(f"GVM CLI connected: {result.stdout[:100]}")
                findings.append({
                    'title': 'OpenVAS CLI connection established',
                    'severity': 'INFO',
                    'description': f'Connected to GVM via CLI for targets: {target_list}',
                    'affected_host': target_list,
                    'tool': 'openvas-cli',
                })
            else:
                self.scan_logger.warning(f"GVM CLI error: {result.stderr}")

        except Exception as e:
            self.scan_logger.error(f"CLI scan error: {e}")

        return findings

    def import_openvas_report(self, xml_path: str) -> List[Dict]:
        """Import findings from an OpenVAS XML report."""
        findings = []
        path = Path(xml_path)

        if not path.exists():
            self.scan_logger.error(f"Report file not found: {xml_path}")
            return findings

        self.scan_logger.info(f"Importing OpenVAS report: {xml_path}")

        try:
            try:
                from defusedxml.ElementTree import parse as safe_parse
            except ImportError:
                safe_parse = ET.parse
            tree = safe_parse(str(path))  # nosec B314 -- using defusedxml when available
            root = tree.getroot()

            # Handle both report formats
            results = root.findall('.//result') or root.findall('.//results/result')

            for result_elem in results:
                finding = self._parse_openvas_result(result_elem)
                if finding:
                    findings.append(finding)
                    self._record_finding(finding)

            self.scan_logger.info(f"Imported {len(findings)} findings from OpenVAS report")

        except ET.ParseError as e:
            self.scan_logger.error(f"XML parse error: {e}")
        except Exception as e:
            self.scan_logger.error(f"Import error: {e}")

        return findings

    def _parse_openvas_result(self, result_elem) -> Optional[Dict]:
        """Parse a single OpenVAS XML result element."""
        try:
            name = result_elem.findtext('name', 'Unknown')
            host_elem = result_elem.find('host')
            host = host_elem.text if host_elem is not None else 'unknown'
            port = result_elem.findtext('port', '')
            severity_text = result_elem.findtext('threat', 'Log')

            # Get NVT details
            nvt = result_elem.find('nvt')
            cvss = 0.0
            cve_ids = []
            qod_value = 0
            oid = ''

            if nvt is not None:
                oid = nvt.get('oid', '')
                cvss_text = nvt.findtext('cvss_base', '0')
                try:
                    cvss = float(cvss_text)
                except (ValueError, TypeError):
                    cvss = 0.0

                # Extract CVEs
                cve_text = nvt.findtext('cve', '')
                if cve_text and cve_text != 'NOCVE':
                    cve_ids = [c.strip() for c in cve_text.split(',') if c.strip().startswith('CVE-')]

                # Get QoD
                qod_elem = result_elem.find('qod')
                if qod_elem is not None:
                    qod_text = qod_elem.findtext('value', '0')
                    try:
                        qod_value = float(qod_text)
                    except (ValueError, TypeError):
                        qod_value = 0

            severity = self.SEVERITY_MAP.get(severity_text, 'INFO')

            description = result_elem.findtext('description', '')
            solution = ''
            if nvt is not None:
                solution = nvt.findtext('solution', '') or nvt.findtext('fix', '')

            return {
                'title': name,
                'severity': severity,
                'description': description,
                'affected_host': host,
                'affected_port': port,
                'cvss_score': cvss,
                'cve_ids': cve_ids,
                'qod': qod_value,
                'oid': oid,
                'remediation': solution,
                'tool': 'openvas',
            }

        except Exception as e:
            self.scan_logger.warning(f"Error parsing OpenVAS result: {e}")
            return None

    def _record_finding(self, finding: Dict):
        """Record an imported finding using the standard add_finding method."""
        self.add_finding(
            severity=finding['severity'],
            title=finding['title'],
            description=finding.get('description', ''),
            affected_asset=finding.get('affected_host', ''),
            finding_type='cve_vulnerability' if finding.get('cve_ids') else 'openvas_finding',
            cvss_score=finding.get('cvss_score', 0.0),
            cve_ids=finding.get('cve_ids', []),
            remediation=finding.get('remediation', ''),
            raw_data=finding,
            detection_method='openvas_import'
        )

    def _enrich_findings(self, findings: List[Dict]):
        """Enrich OpenVAS findings with KEV/EPSS data."""
        if not get_threat_intel:
            return

        try:
            ti = get_threat_intel()

            # Collect all CVEs
            all_cves = []
            for f in findings:
                all_cves.extend(f.get('cve_ids', []))

            if all_cves:
                enrichments = ti.enrich_findings_batch(list(set(all_cves)))

                for finding in findings:
                    for cve_id in finding.get('cve_ids', []):
                        if cve_id in enrichments:
                            e = enrichments[cve_id]
                            finding['kev_status'] = e.get('kev_status', False)
                            finding['epss_score'] = max(
                                finding.get('epss_score', 0),
                                e.get('epss_score', 0)
                            )
                            finding['epss_percentile'] = max(
                                finding.get('epss_percentile', 0),
                                e.get('epss_percentile', 0)
                            )

                self.scan_logger.info(f"Enriched {len(findings)} findings with KEV/EPSS data")

        except Exception as e:
            self.scan_logger.warning(f"Enrichment error: {e}")

    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate scan summary."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        kev_count = 0
        hosts = set()
        cves = set()

        for f in findings:
            sev = f.get('severity', 'INFO').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            hosts.add(f.get('affected_host', ''))
            for cve in f.get('cve_ids', []):
                cves.add(cve)
            if f.get('kev_status'):
                kev_count += 1

        return {
            'total_findings': len(findings),
            'by_severity': severity_counts,
            'unique_cves': len(cves),
            'hosts_affected': len(hosts),
            'kev_findings': kev_count,
            'mode': self.gvm_mode,
        }

    def sync_findings(self):
        """Two-way sync between our DB and OpenVAS (placeholder for GMP mode)."""
        if self.gvm_mode != 'gmp':
            self.scan_logger.info("Sync only available in GMP mode")
            return

        self.scan_logger.info("Syncing findings with OpenVAS...")
        # Implementation would pull latest results from GVM and update our DB


if __name__ == '__main__':
    scanner = OpenVASScanner()
    print(f"OpenVAS Scanner initialized")
    print(f"GVM available: {scanner.gvm_available}")
    print(f"Mode: {scanner.gvm_mode}")

    import sys
    if len(sys.argv) > 1:
        report_path = sys.argv[1]
        print(f"\nImporting report: {report_path}")
        findings = scanner.import_openvas_report(report_path)
        print(f"Imported {len(findings)} findings")
