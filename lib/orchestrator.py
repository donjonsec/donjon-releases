#!/usr/bin/env python3
"""
Donjon Platform — Assessment Orchestrator

Runs all applicable scanners in sequence against target infrastructure,
collects findings into a unified evidence session, and produces a
consolidated report.

Scan types:
  quick     — Windows + network port check (5 min)
  standard  — All applicable scanners, standard depth (1-2 hrs)
  deep      — All scanners, deep depth + AI analysis (2-4 hrs)
"""
from __future__ import annotations

import logging
import os
import platform
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from .evidence import get_evidence_manager
except ImportError:
    from evidence import get_evidence_manager

try:
    from .config import Config
except ImportError:
    from config import Config

try:
    from .tui import TUI
except ImportError:
    TUI = None

try:
    from .ai_engine import get_ai_engine
except ImportError:
    get_ai_engine = None

logger = logging.getLogger(__name__)

# Scanner registry: id → (module_path, class_name, requires_targets, platform_filter)
_SCANNER_REGISTRY = [
    ('windows',       'scanners.windows_scanner',       'WindowsScanner',          False,  'Windows'),
    ('linux',         'scanners.linux_scanner',          'LinuxScanner',            False,  'Linux'),
    ('network',       'scanners.network_scanner',        'NetworkScanner',          True,   None),
    ('ssl',           'scanners.ssl_scanner',            'SSLScanner',              True,   None),
    ('web',           'scanners.web_scanner',            'WebScanner',              True,   None),
    ('ad',            'scanners.ad_scanner',             'ADScanner',               True,   None),
    ('vulnerability', 'scanners.vulnerability_scanner',  'VulnerabilityScanner',    True,   None),
    ('compliance',    'scanners.compliance_scanner',     'ComplianceScanner',       False,  None),
    ('cloud',         'scanners.cloud_scanner',          'CloudScanner',            False,  None),
    ('container',     'scanners.container_scanner',      'ContainerScanner',        False,  None),
    ('credential',    'scanners.credential_scanner',     'CredentialScanner',       True,   None),
    ('sbom',          'scanners.sbom_scanner',           'SBOMScanner',             False,  None),
    ('shadow_ai',     'scanners.shadow_ai_scanner',      'ShadowAIScanner',         True,   None),
    ('quantum',       'scanners.quantum_scanner',        'QuantumReadinessScanner', True,   None),
    ('asm',           'scanners.asm_scanner',            'ASMScanner',              True,   None),
    ('malware',       'scanners.malware_scanner',        'MalwareScanner',          False,  None),
    ('adversary',     'scanners.adversary_scanner',      'AdversaryScanner',        True,   None),
]

# Which scanners run at each tier
_SCAN_TIERS = {
    'quick': ['windows', 'linux', 'network', 'shadow_ai'],
    'standard': [
        'windows', 'linux', 'network', 'ssl', 'web', 'vulnerability',
        'compliance', 'credential', 'shadow_ai', 'quantum', 'cloud', 'container',
    ],
    'deep': [
        'windows', 'linux', 'network', 'ssl', 'web', 'ad', 'vulnerability',
        'compliance', 'cloud', 'container', 'credential', 'sbom', 'shadow_ai',
        'quantum', 'asm', 'malware', 'adversary',
    ],
}


class AssessmentOrchestrator:
    """Orchestrates a full security assessment across all scanners."""

    def __init__(self):
        self.em = get_evidence_manager()
        self.config = Config()
        self.tui = TUI() if TUI else None

    def run_full_assessment(
        self,
        assessment_type: str = 'standard',
        targets: Optional[List[str]] = None,
        exclude_scanners: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run a full assessment across all applicable scanners.

        Args:
            assessment_type: 'quick', 'standard', or 'deep'
            targets: Network targets (IPs, CIDRs). Auto-detected if None.
            exclude_scanners: Scanner IDs to skip.

        Returns:
            Dict with session_id, findings, scanner_results, summary.
        """
        exclude = set(exclude_scanners or [])
        scanner_ids = _SCAN_TIERS.get(assessment_type, _SCAN_TIERS['standard'])
        current_os = platform.system()

        # Start evidence session
        session_id = self.em.start_session(
            scan_type=f'full_{assessment_type}',
            target_networks=','.join(targets) if targets else 'auto',
        )

        if self.tui:
            self.tui.section(f"{assessment_type.title()} Assessment", '\033[36m')
            self.tui.info(f"Session: {session_id}")

        all_findings: List[Dict] = []
        scanner_results: Dict[str, Dict] = {}
        scanner_errors: Dict[str, str] = {}
        total_scanners = 0
        completed_scanners = 0

        for scanner_id, module_path, class_name, needs_targets, os_filter in _SCANNER_REGISTRY:
            if scanner_id not in scanner_ids:
                continue
            if scanner_id in exclude:
                continue
            # Platform filter
            if os_filter and os_filter != current_os:
                continue
            # Skip target-requiring scanners if no targets
            if needs_targets and not targets:
                targets = targets or ['localhost']

            total_scanners += 1

            if self.tui:
                self.tui.info(f"[{completed_scanners + 1}/{len(scanner_ids)}] Running {scanner_id} scanner...")

            try:
                # Dynamic import
                import importlib
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                scanner = cls(session_id)

                # Determine scan depth based on assessment type
                scan_depth = {
                    'quick': 'quick',
                    'standard': 'standard',
                    'deep': 'deep',
                }.get(assessment_type, 'standard')

                # Run scanner
                if needs_targets:
                    result = scanner.scan(targets=targets or ['localhost'], scan_type=scan_depth)
                else:
                    result = scanner.scan(scan_type=scan_depth)

                # Collect findings
                findings = []
                if isinstance(result, dict):
                    findings = result.get('findings', [])
                    if not findings and hasattr(scanner, 'findings'):
                        findings = scanner.findings

                finding_count = len(findings)
                all_findings.extend(findings)

                # Check scanner status — did it actually scan or just fail silently?
                scan_stat = getattr(scanner, 'scan_status', 'complete')
                warnings = getattr(scanner, 'warnings', [])

                scanner_results[scanner_id] = {
                    'status': scan_stat if scan_stat != 'pending' else 'completed',
                    'findings': finding_count,
                    'warnings': warnings,
                    'summary': result.get('summary', {}) if isinstance(result, dict) else {},
                }
                completed_scanners += 1

                if self.tui:
                    if scan_stat == 'failed':
                        self.tui.warning(f"  {scanner_id}: FAILED — {warnings[0] if warnings else 'unknown'}")
                    elif scan_stat == 'partial':
                        self.tui.warning(f"  {scanner_id}: {finding_count} findings (partial — {warnings[0][:50] if warnings else ''})")
                    elif finding_count == 0 and not result.get('error'):
                        self.tui.success(f"  {scanner_id}: clean (0 findings)")
                    else:
                        self.tui.success(f"  {scanner_id}: {finding_count} findings")

            except KeyboardInterrupt:
                if self.tui:
                    self.tui.warning("Assessment cancelled by user")
                self.em.end_session(session_id, status='cancelled')
                break
            except Exception as e:
                error_msg = str(e)
                scanner_errors[scanner_id] = error_msg
                scanner_results[scanner_id] = {
                    'status': 'error', 'error': error_msg,
                }
                logger.warning("Scanner %s failed: %s", scanner_id, error_msg)
                if self.tui:
                    self.tui.warning(f"  {scanner_id}: ERROR — {error_msg[:60]}")

        # Store findings in evidence
        for finding in all_findings:
            try:
                self.em.add_finding(
                    session_id=session_id,
                    severity=finding.get('severity', 'INFO'),
                    title=finding.get('title', 'Unknown'),
                    description=finding.get('description', ''),
                    affected_asset=finding.get('affected_asset', ''),
                    cvss_score=finding.get('cvss_score', 0.0),
                    cve_ids=finding.get('cve_ids', []),
                    remediation=finding.get('remediation', ''),
                    scanner_name=finding.get('scanner', ''),
                )
            except Exception:
                pass

        # AI summary (if available and assessment is standard/deep)
        ai_summary = None
        if assessment_type in ('standard', 'deep') and get_ai_engine:
            try:
                ai = get_ai_engine()
                if ai.backend != 'template':
                    ai_summary = ai.summarize_scan({
                        'session_id': session_id,
                        'findings_count': len(all_findings),
                        'scanners_completed': completed_scanners,
                        'scanners_failed': len(scanner_errors),
                    })
            except Exception:
                pass

        # Build summary
        severity_counts = {}
        for f in all_findings:
            sev = f.get('severity', 'INFO').upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = {
            'session_id': session_id,
            'assessment_type': assessment_type,
            'scanners_total': total_scanners,
            'scanners_completed': completed_scanners,
            'scanners_failed': len(scanner_errors),
            'total_findings': len(all_findings),
            'severity_counts': severity_counts,
            'scanner_results': scanner_results,
            'scanner_errors': scanner_errors,
            'ai_summary': ai_summary,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

        # End session
        status = 'completed' if not scanner_errors else 'completed_with_errors'
        self.em.end_session(session_id, status=status)

        if self.tui:
            self.tui.section("Assessment Complete")
            self.tui.info(f"Session: {session_id}")
            self.tui.info(f"Scanners: {completed_scanners}/{total_scanners} completed")
            self.tui.info(f"Findings: {len(all_findings)} total")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = severity_counts.get(sev, 0)
                if count:
                    self.tui.info(f"  {sev}: {count}")

        return summary
