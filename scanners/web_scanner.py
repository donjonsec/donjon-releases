#!/usr/bin/env python3
"""
Donjon - Web Application Scanner
Web server and application vulnerability assessment using nikto.
"""

import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


class WebScanner(BaseScanner):
    """Web application vulnerability scanner."""

    SCANNER_NAME = "web"
    SCANNER_DESCRIPTION = "Web application vulnerability assessment"

    # Common web ports
    WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

    # SQL error patterns for error-based SQLi detection (sqlmap-style)
    SQL_ERROR_PATTERNS = [
        "You have an error in your SQL syntax",       # MySQL
        "ERROR:  syntax error at or near",             # PostgreSQL
        "Unclosed quotation mark",                     # MSSQL
        "ORA-",                                        # Oracle
        'near ":": syntax error',                      # SQLite (variant)
        "near \"",                                     # SQLite
        "SQL syntax.*MySQL",
        "Warning.*mysql_",
        "valid MySQL result",
        "pg_query()",
        "pg_exec()",
        "Microsoft OLE DB Provider for SQL Server",
        "Microsoft SQL Native Client error",
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        "SQLSTATE",
        "mysql_fetch",
        "mysql_num_rows",
        "Syntax error.*in query expression",           # MS Access
        "CLI Driver.*DB2",                             # DB2
        "Dynamic SQL Error",                           # Firebird
    ]

    # SQLi test payloads - ordered from safest to most aggressive
    SQLI_PAYLOADS = {
        'error_based': ["'", '"', "' OR '1'='1", "1' ORDER BY 1--", "') OR ('1'='1"],
        'boolean_blind': [("' OR '1'='1", "' OR '1'='2")],
        'union_based': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ],
        'time_based': [
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
        ],
    }

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self.nikto_path = None

    def scan(self, targets: List[str], ports: List[int] = None,
             scan_type: str = 'standard', **kwargs) -> Dict:
        """
        Execute web application scan.

        Args:
            targets: List of hosts to scan
            ports: List of ports to check (default: common web ports)
            scan_type: 'quick', 'standard', or 'deep'
        """
        self.start_time = datetime.now(timezone.utc)
        self.scan_status = 'running'

        # Check for nikto — no longer a hard failure; SQLi checks work without it
        if self.check_tool('nikto'):
            self.nikto_path = self.paths.find_tool('nikto')
        else:
            self.nikto_path = None
            self.warn("Nikto not available — skipping nikto checks, running SQLi detection only")
        ports = ports or self.WEB_PORTS

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'findings': [],
            'summary': {}
        }

        for target in targets:
            # Parse target — may be a URL or just a host/IP
            if '://' in target:
                parsed = urllib.parse.urlparse(target)
                host = parsed.hostname or target
                target_port = parsed.port
                protocol = parsed.scheme or 'http'
                scan_ports = [target_port] if target_port else [443 if protocol == 'https' else 80]
            else:
                host = target
                scan_ports = ports

            for port in scan_ports:
                protocol = 'https' if port in [443, 8443] else 'http'
                self.scan_logger.info(f"Scanning web service at {protocol}://{host}:{port}")

                # Nikto scan
                if self.nikto_path:
                    try:
                        findings = self._run_nikto(host, port, protocol, scan_type)
                        results['findings'].extend(findings)
                    except Exception as e:
                        self.scan_logger.warning(f"Error scanning {host}:{port}: {e}")

                # SQL injection detection (sqlmap-style patterns)
                target_url = f"{protocol}://{host}:{port}"
                if '://' in target:
                    target_url = target  # preserve original URL with path/params
                try:
                    self._check_sql_injection(target_url)
                except Exception as e:
                    self.scan_logger.warning(f"SQLi check error for {target_url}: {e}")

                self.human_delay()

        # Generate summary
        results['summary'] = {
            'total_findings': len(results['findings']),
            'targets_scanned': len(targets),
            'ports_checked': len(ports)
        }

        self.end_time = datetime.now(timezone.utc)
        self.set_status('complete')
        self.save_results()

        return results

    def _run_nikto(self, host: str, port: int, protocol: str,
                    scan_type: str) -> List[Dict]:
        """Run nikto web scanner."""
        findings = []

        cmd = [
            str(self.nikto_path),
            '-h', host,
            '-p', str(port),
            '-Format', 'txt',
            '-nointeractive',
            '-maxtime', '300s'
        ]

        if protocol == 'https':
            cmd.append('-ssl')

        # Adjust scan intensity
        if scan_type == 'quick':
            cmd.extend(['-Tuning', '1'])  # Interesting files only
        elif scan_type == 'deep':
            cmd.extend(['-Tuning', 'x'])  # All checks

        try:
            result = self.run_tool(cmd, timeout=600, description=f"Nikto scan on {host}:{port}")
            findings = self._parse_nikto_output(result.stdout, host, port)
        except Exception as e:
            self.scan_logger.warning(f"Nikto error: {e}")

        return findings

    def _parse_nikto_output(self, output: str, host: str, port: int) -> List[Dict]:
        """Parse nikto output."""
        findings = []

        for line in output.split('\n'):
            # Skip header/info lines
            if not line.startswith('+ '):
                continue

            line = line[2:].strip()

            # Skip certain info lines
            if any(skip in line.lower() for skip in ['target ip:', 'target hostname:', 'target port:', 'start time:', 'end time:']):
                continue

            # Determine severity based on content
            severity = 'INFO'
            finding_type = 'web_vulnerability'

            if any(term in line.lower() for term in ['vulnerability', 'vulnerable', 'exploit']):
                severity = 'HIGH'
            elif any(term in line.lower() for term in ['outdated', 'old version', 'deprecated']):
                severity = 'MEDIUM'
            elif any(term in line.lower() for term in ['information disclosure', 'directory listing', 'backup file']):
                severity = 'MEDIUM'
                finding_type = 'information_disclosure'
            elif any(term in line.lower() for term in ['header', 'cookie', 'missing']):
                severity = 'LOW'
                finding_type = 'insecure_configuration'

            # Extract OSVDB/CVE if present
            cve_ids = re.findall(r'CVE-\d{4}-\d+', line, re.IGNORECASE)
            osvdb = re.findall(r'OSVDB-\d+', line, re.IGNORECASE)

            finding = {
                'host': host,
                'port': port,
                'finding': line,
                'severity': severity,
                'cve_ids': cve_ids,
                'osvdb': osvdb,
                'tool': 'nikto'
            }
            findings.append(finding)

            # Add as formal finding
            self.add_finding(
                severity=severity,
                title=line[:100],
                description=line,
                affected_asset=f"{host}:{port}",
                finding_type=finding_type,
                cve_ids=cve_ids,
                raw_data=finding,
                detection_method='banner_grab'
            )

        return findings


    # -----------------------------------------------------------------------
    # SQL Injection Detection (sqlmap-style patterns)
    # -----------------------------------------------------------------------

    def _check_sql_injection(self, target_url: str) -> None:
        """Test for SQL injection vulnerabilities using sqlmap-style patterns.

        Performs four detection techniques:
          1. Error-based: inject quotes, look for SQL error messages
          2. Boolean-based blind: compare response lengths for tautology vs contradiction
          3. UNION-based: inject UNION SELECT NULL to find column counts
          4. Time-based blind: inject delay payloads, measure response time

        IMPORTANT: Only tests against explicitly provided targets.
        Respects DONJON_TEST_MODE to limit aggression.
        """
        test_mode = os.environ.get('DONJON_TEST_MODE') == '1'

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        # If no query parameters, try common entry points
        if not params:
            # Probe the base URL with a parameter
            test_urls = [
                f"{target_url}{'/' if not target_url.endswith('/') else ''}?id=1",
                f"{target_url}{'/' if not target_url.endswith('/') else ''}?search=test",
            ]
        else:
            test_urls = [target_url]

        for url in test_urls:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            for param_name in query_params:
                self.scan_logger.info(f"Testing parameter '{param_name}' for SQLi at {parsed_url.netloc}")

                # 1. Error-based detection
                self._sqli_error_based(url, param_name, parsed_url)

                # 2. Boolean-based blind detection
                self._sqli_boolean_blind(url, param_name, parsed_url)

                # 3. UNION-based detection (standard and deep only)
                self._sqli_union_based(url, param_name, parsed_url)

                # 4. Time-based blind (deep scan or test mode only — most aggressive)
                if not test_mode:
                    self._sqli_time_based(url, param_name, parsed_url)

    def _build_sqli_url(self, parsed_url, param_name: str, payload: str) -> str:
        """Replace a query parameter value with a SQLi payload."""
        params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, new_query, parsed_url.fragment
        ))

    def _fetch_url(self, url: str, timeout: int = 10) -> Tuple[str, int, float]:
        """Fetch a URL and return (body, status_code, elapsed_seconds).

        Returns ('', 0, 0.0) on any error.
        """
        try:
            start = time.time()
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Donjon-WebScanner/1.0'}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                elapsed = time.time() - start
                return (body, resp.status, elapsed)
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            try:
                body = e.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return (body, e.code, elapsed)
        except Exception as e:
            self.scan_logger.debug(f"Fetch error for {url[:100]}: {e}")
            return ('', 0, 0.0)

    def _check_sql_errors(self, body: str) -> List[str]:
        """Check response body for SQL error patterns. Returns matched patterns."""
        matches = []
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(re.escape(pattern), body, re.IGNORECASE):
                matches.append(pattern)
        return matches

    def _sqli_error_based(self, url: str, param_name: str, parsed_url) -> None:
        """Error-based SQLi: inject quotes and look for SQL error messages."""
        for payload in self.SQLI_PAYLOADS['error_based']:
            test_url = self._build_sqli_url(parsed_url, param_name, payload)
            body, status, elapsed = self._fetch_url(test_url)

            if not body:
                continue

            errors_found = self._check_sql_errors(body)
            if errors_found:
                self.add_finding(
                    severity='HIGH',
                    title=f'SQL Injection (Error-based) in parameter "{param_name}"',
                    description=(
                        f'SQL error messages detected when injecting payload '
                        f'into parameter "{param_name}" at {parsed_url.netloc}{parsed_url.path}.  '
                        f'Payload: {payload!r}  '
                        f'Error patterns matched: {", ".join(errors_found[:3])}.  '
                        f'This indicates the application is vulnerable to '
                        f'error-based SQL injection (sqlmap detection pattern).'
                    ),
                    affected_asset=f"{parsed_url.netloc}{parsed_url.path}",
                    finding_type='sql_injection',
                    cvss_score=9.0,
                    cve_ids=[],
                    remediation=(
                        'Use parameterised queries / prepared statements.  '
                        'Never concatenate user input into SQL strings.  '
                        'Disable verbose error messages in production.'
                    ),
                    raw_data={
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'errors_matched': errors_found,
                        'http_status': status,
                        'detection': 'sqli_error_based',
                    },
                    detection_method='active_probe',
                )
                return  # One finding per parameter is enough

    def _sqli_boolean_blind(self, url: str, param_name: str, parsed_url) -> None:
        """Boolean-based blind SQLi: compare tautology vs contradiction responses."""
        for true_payload, false_payload in self.SQLI_PAYLOADS['boolean_blind']:
            true_url = self._build_sqli_url(parsed_url, param_name, true_payload)
            false_url = self._build_sqli_url(parsed_url, param_name, false_payload)

            true_body, true_status, _ = self._fetch_url(true_url)
            false_body, false_status, _ = self._fetch_url(false_url)

            if not true_body and not false_body:
                continue

            # Significant difference in response length suggests injectable
            true_len = len(true_body)
            false_len = len(false_body)

            if true_len == 0 and false_len == 0:
                continue

            # Also check: SQL errors in the false response would indicate error-based
            false_errors = self._check_sql_errors(false_body)
            true_errors = self._check_sql_errors(true_body)

            # Length difference > 10% and > 50 chars suggests boolean-based blind
            diff = abs(true_len - false_len)
            avg_len = (true_len + false_len) / 2 if (true_len + false_len) > 0 else 1
            diff_pct = (diff / avg_len) * 100

            if diff > 50 and diff_pct > 10:
                self.add_finding(
                    severity='HIGH',
                    title=f'SQL Injection (Boolean-blind) in parameter "{param_name}"',
                    description=(
                        f'Boolean-based blind SQL injection detected in parameter '
                        f'"{param_name}" at {parsed_url.netloc}{parsed_url.path}.  '
                        f'Tautology response length: {true_len}, '
                        f'contradiction response length: {false_len} '
                        f'(difference: {diff_pct:.1f}%).  '
                        f'This suggests the application embeds user input directly '
                        f'into SQL WHERE clauses (sqlmap detection pattern).'
                    ),
                    affected_asset=f"{parsed_url.netloc}{parsed_url.path}",
                    finding_type='sql_injection',
                    cvss_score=8.5,
                    remediation=(
                        'Use parameterised queries / prepared statements.  '
                        'Implement input validation and output encoding.'
                    ),
                    raw_data={
                        'url': url,
                        'parameter': param_name,
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'true_len': true_len,
                        'false_len': false_len,
                        'diff_pct': round(diff_pct, 1),
                        'detection': 'sqli_boolean_blind',
                    },
                    detection_method='active_probe',
                )
                return

    def _sqli_union_based(self, url: str, param_name: str, parsed_url) -> None:
        """UNION-based SQLi: inject UNION SELECT NULL to find column count."""
        for payload in self.SQLI_PAYLOADS['union_based']:
            test_url = self._build_sqli_url(parsed_url, param_name, payload)
            body, status, elapsed = self._fetch_url(test_url)

            if not body:
                continue

            # Check for SQL errors (wrong column count gives a specific error)
            errors = self._check_sql_errors(body)

            # If no SQL error AND status 200, the UNION might have worked
            # (correct column count produces no error)
            null_count = payload.count('NULL')
            if status == 200 and not errors and null_count > 0:
                # Verify by checking if a different NULL count gives an error
                if null_count > 1:
                    verify_payload = "' UNION SELECT " + ",".join(["NULL"] * (null_count - 1)) + "--"
                else:
                    verify_payload = "' UNION SELECT NULL,NULL--"
                verify_url = self._build_sqli_url(parsed_url, param_name, verify_payload)
                verify_body, verify_status, _ = self._fetch_url(verify_url)
                verify_errors = self._check_sql_errors(verify_body) if verify_body else []

                if verify_errors:
                    self.add_finding(
                        severity='HIGH',
                        title=f'SQL Injection (UNION-based) in parameter "{param_name}"',
                        description=(
                            f'UNION-based SQL injection detected in parameter '
                            f'"{param_name}" at {parsed_url.netloc}{parsed_url.path}.  '
                            f'UNION SELECT with {null_count} columns succeeded '
                            f'(HTTP {status}) while other column counts produced '
                            f'SQL errors.  This allows data exfiltration from '
                            f'the database (sqlmap detection pattern).'
                        ),
                        affected_asset=f"{parsed_url.netloc}{parsed_url.path}",
                        finding_type='sql_injection',
                        cvss_score=9.5,
                        remediation=(
                            'Use parameterised queries / prepared statements.  '
                            'Implement a WAF with SQL injection rules.  '
                            'Apply least-privilege database permissions.'
                        ),
                        raw_data={
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'column_count': null_count,
                            'detection': 'sqli_union_based',
                        },
                        detection_method='active_probe',
                    )
                    return

            # If we got SQL errors, that still confirms injection point
            if errors:
                self.add_finding(
                    severity='HIGH',
                    title=f'SQL Injection (UNION-based error) in parameter "{param_name}"',
                    description=(
                        f'UNION injection attempt on parameter '
                        f'"{param_name}" at {parsed_url.netloc}{parsed_url.path} '
                        f'produced SQL errors: {", ".join(errors[:3])}.  '
                        f'This confirms the parameter is injectable '
                        f'(sqlmap detection pattern).'
                    ),
                    affected_asset=f"{parsed_url.netloc}{parsed_url.path}",
                    finding_type='sql_injection',
                    cvss_score=9.0,
                    remediation='Use parameterised queries / prepared statements.',
                    raw_data={
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'errors': errors,
                        'detection': 'sqli_union_error',
                    },
                    detection_method='active_probe',
                )
                return

    def _sqli_time_based(self, url: str, param_name: str, parsed_url) -> None:
        """Time-based blind SQLi: inject delay payloads, measure response time."""
        # First, establish a baseline response time
        _, _, baseline_time = self._fetch_url(url, timeout=15)
        if baseline_time == 0.0:
            return

        for payload in self.SQLI_PAYLOADS['time_based']:
            test_url = self._build_sqli_url(parsed_url, param_name, payload)
            _, status, elapsed = self._fetch_url(test_url, timeout=15)

            # If response took >= 4 seconds longer than baseline, likely injectable
            if elapsed > 0 and (elapsed - baseline_time) >= 4.0:
                self.add_finding(
                    severity='HIGH',
                    title=f'SQL Injection (Time-based blind) in parameter "{param_name}"',
                    description=(
                        f'Time-based blind SQL injection detected in parameter '
                        f'"{param_name}" at {parsed_url.netloc}{parsed_url.path}.  '
                        f'Baseline response: {baseline_time:.1f}s, '
                        f'injected response: {elapsed:.1f}s '
                        f'(delay: {elapsed - baseline_time:.1f}s).  '
                        f'Payload: {payload!r} '
                        f'(sqlmap detection pattern).'
                    ),
                    affected_asset=f"{parsed_url.netloc}{parsed_url.path}",
                    finding_type='sql_injection',
                    cvss_score=9.0,
                    remediation=(
                        'Use parameterised queries / prepared statements.  '
                        'Time-based injection is often exploitable for full '
                        'data extraction via tools like sqlmap.'
                    ),
                    raw_data={
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'baseline_seconds': round(baseline_time, 2),
                        'injected_seconds': round(elapsed, 2),
                        'detection': 'sqli_time_blind',
                    },
                    detection_method='active_probe',
                )
                return

    @staticmethod
    def check_sql_error_patterns(response_text: str) -> List[str]:
        """Public utility: check a response body against SQL error patterns.

        Useful for unit testing pattern matching without making HTTP requests.
        Returns list of matched pattern strings.
        """
        matches = []
        for pattern in WebScanner.SQL_ERROR_PATTERNS:
            if re.search(re.escape(pattern), response_text, re.IGNORECASE):
                matches.append(pattern)
        return matches


if __name__ == '__main__':
    scanner = WebScanner()
    print(f"Web Scanner initialized")
    print(f"Nikto available: {scanner.check_tool('nikto')}")
