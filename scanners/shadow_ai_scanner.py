#!/usr/bin/env python3
"""
Donjon Platform - Shadow AI Detection Scanner

Detects unauthorized AI usage across the environment:
  - Local LLM servers (Ollama, LM Studio, GPT4All, etc.)
  - AI web service access (ChatGPT, Claude, Gemini, etc.)
  - AI browser extensions
  - AI API keys in config files
  - AI model files on disk
  - AI Python packages
  - AI Docker containers
  - AI scheduled tasks
  - AI network firewall rules
"""

import os
import sys
import json
import platform
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


class ShadowAIScanner(BaseScanner):
    """Detects unauthorized AI usage: local LLMs, web AI services,
    browser extensions, API keys, model files."""

    SCANNER_NAME = "shadow_ai"
    SCANNER_DESCRIPTION = (
        "Detect unauthorized AI: local LLMs, web AI, browser extensions, "
        "API keys, model files"
    )

    # -----------------------------------------------------------------
    # Constants
    # -----------------------------------------------------------------

    AI_PROCESSES = {
        'ollama': 'Ollama (local LLM)',
        'lm-studio': 'LM Studio',
        'localai': 'LocalAI',
        'koboldcpp': 'KoboldCpp',
        'text-generation': 'Text Generation WebUI',
        'gpt4all': 'GPT4All',
        'llama': 'llama.cpp',
        'whisper': 'Whisper (speech-to-text)',
        'stable-diffusion': 'Stable Diffusion',
        'comfyui': 'ComfyUI',
        'automatic1111': 'AUTOMATIC1111',
        'jan': 'Jan.ai',
        'msty': 'Msty',
        'anything-llm': 'AnythingLLM',
        'open-webui': 'Open WebUI',
        'vllm': 'vLLM',
        'tabbyml': 'Tabby (code completion)',
        'continue': 'Continue.dev',
    }

    AI_PORTS = {
        11434: 'Ollama API',
        1234: 'LM Studio API',
        8080: 'LocalAI / KoboldCpp',
        5000: 'Text Generation WebUI',
        7860: 'Gradio (AI WebUI)',
        3000: 'Open WebUI',
        8188: 'ComfyUI',
        7861: 'AUTOMATIC1111',
        39281: 'Jan.ai',
    }

    AI_WEB_DOMAINS = [
        'chat.openai.com', 'chatgpt.com', 'api.openai.com',
        'claude.ai', 'api.anthropic.com',
        'gemini.google.com', 'generativelanguage.googleapis.com',
        'copilot.microsoft.com', 'bing.com/chat',
        'perplexity.ai', 'poe.com', 'you.com',
        'huggingface.co', 'replicate.com',
        'together.ai', 'api.together.xyz',
        'openrouter.ai', 'groq.com',
    ]

    AI_BROWSER_EXTENSIONS = {
        'ChatGPT': ['obdikmjkoamkpfgeejaaefgpecpikloj'],
        'Claude': ['claidefghijklmnopqrstuvwxyz0123'],
        'GitHub Copilot': ['copilotgithubextensionidentif'],
        'Grammarly AI': ['kbfnbcaeplbcioakkpcpgfkobkghlhen'],
        'Monica': ['ofhbbkphhbklhfoeikjpcbhemlocgigb'],
        'Merlin': ['camppjleccjaphfdbohjdohecfnoikec'],
    }

    AI_API_KEY_PATTERNS = [
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI'),
        (r'sk-ant-[a-zA-Z0-9\-]{20,}', 'Anthropic'),
        (r'AIza[a-zA-Z0-9_\-]{35}', 'Google AI'),
        (r'gsk_[a-zA-Z0-9]{20,}', 'Groq'),
        (r'r8_[a-zA-Z0-9]{20,}', 'Replicate'),
    ]

    AI_MODEL_EXTENSIONS = [
        '.gguf', '.ggml', '.safetensors', '.bin', '.pth', '.pt', '.onnx',
    ]

    AI_PYTHON_PACKAGES = [
        'openai', 'anthropic', 'langchain', 'llama-cpp-python',
        'transformers', 'torch', 'tensorflow', 'diffusers',
        'huggingface-hub', 'ollama', 'replicate', 'together',
        'chromadb', 'pinecone-client', 'weaviate-client',
        'sentence-transformers', 'auto-gptq', 'vllm',
    ]

    # -----------------------------------------------------------------
    # Main scan entry point
    # -----------------------------------------------------------------

    def scan(self, targets: List[str], **kwargs) -> Dict:
        """Execute Shadow AI detection scan."""
        scan_type = kwargs.get('scan_type', 'standard')
        self.scan_logger.info(
            "Starting Shadow AI scan (type=%s) on %d target(s)",
            scan_type, len(targets),
        )
        self.start_time = datetime.now(timezone.utc)
        self.results = []
        self.findings = []

        target = targets[0] if targets else platform.node()

        # Quick checks (always run)
        self._check_ai_processes(target)
        self._check_ai_ports(target)

        # Standard checks
        if scan_type in ('standard', 'deep'):
            self._check_ai_services(target)
            self._check_ai_installations(target)
            self._check_ai_python_packages(target)
            self._check_ai_docker_containers(target)

        # Deep checks
        if scan_type == 'deep':
            self._check_ai_model_files(target)
            self._check_ai_browser_extensions(target)
            self._check_ai_api_keys(target)
            self._check_ai_network_rules(target)
            self._check_ai_scheduled_tasks(target)

        self.end_time = datetime.now(timezone.utc)
        duration = (self.end_time - self.start_time).total_seconds()

        summary = {
            'scanner': self.SCANNER_NAME,
            'scan_type': scan_type,
            'target': target,
            'duration_seconds': round(duration, 2),
            'findings_count': len(self.findings),
            'results_count': len(self.results),
        }

        self.scan_logger.info(
            "Shadow AI scan complete: %d findings in %.1fs",
            len(self.findings), duration,
        )
        return summary

    # -----------------------------------------------------------------
    # Helper: run a command safely
    # -----------------------------------------------------------------

    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> Optional[str]:
        """Run a command and return stdout, or None on failure."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout
        except Exception:
            return None

    def _run_ps(self, script: str, timeout: int = 30) -> Optional[str]:
        """Run a PowerShell command and return stdout."""
        cmd = ['powershell', '-NoProfile', '-Command', script]
        return self._run_cmd(cmd, timeout)

    # -----------------------------------------------------------------
    # Check: AI processes
    # -----------------------------------------------------------------

    def _check_ai_processes(self, target: str) -> None:
        """Check for running AI-related processes."""
        self.scan_logger.info("Checking for AI processes...")

        if platform.system() == 'Windows':
            output = self._run_ps(
                "Get-Process | Select-Object -ExpandProperty ProcessName"
            )
        else:
            output = self._run_cmd(['ps', 'aux'])

        if not output:
            self.add_result('ai_processes', {'status': 'unable_to_check'}, target)
            return

        output_lower = output.lower()
        found = []
        for proc_key, proc_name in self.AI_PROCESSES.items():
            if proc_key.lower() in output_lower:
                found.append({'process': proc_key, 'name': proc_name})

        self.add_result('ai_processes', {'found': found}, target)

        for item in found:
            # Check if it's listening on network vs localhost only
            is_network = self._is_process_network_accessible(item['process'])
            if is_network:
                severity = 'HIGH'
                desc = (
                    f"{item['name']} is running and accessible on the network. "
                    f"This local LLM server could expose sensitive data to "
                    f"unauthorized users on the network."
                )
            else:
                severity = 'MEDIUM'
                desc = (
                    f"{item['name']} is running on this system. "
                    f"Local AI tools may process sensitive data outside "
                    f"approved channels."
                )

            self.add_finding(
                severity=severity,
                title=f"AI Process Detected: {item['name']}",
                description=desc,
                affected_asset=target,
                finding_type='shadow_ai_process',
                remediation=(
                    f"Review whether {item['name']} is authorized. "
                    f"If not approved, stop the process and remove the software. "
                    f"If approved, ensure it is documented in the AI inventory."
                ),
                detection_method='process_enumeration',
            )

    def _is_process_network_accessible(self, process_name: str) -> bool:
        """Check if a process is listening on 0.0.0.0 (network accessible)."""
        try:
            if platform.system() == 'Windows':
                output = self._run_ps(
                    "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                    "Select-Object LocalAddress,LocalPort,OwningProcess | Format-List"
                )
            else:
                output = self._run_cmd(['ss', '-tlnp'])
            if output and '0.0.0.0' in output:
                return True
        except Exception:
            pass
        return False

    # -----------------------------------------------------------------
    # Check: AI ports
    # -----------------------------------------------------------------

    def _check_ai_ports(self, target: str) -> None:
        """Check for AI services listening on known ports."""
        self.scan_logger.info("Checking AI-related ports...")

        if platform.system() == 'Windows':
            output = self._run_ps(
                "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty LocalPort"
            )
        else:
            output = self._run_cmd(['ss', '-tlnp'])

        if not output:
            self.add_result('ai_ports', {'status': 'unable_to_check'}, target)
            return

        found = []
        for port, service_name in self.AI_PORTS.items():
            if str(port) in output:
                found.append({'port': port, 'service': service_name})

        self.add_result('ai_ports', {'found': found}, target)

        for item in found:
            self.add_finding(
                severity='MEDIUM',
                title=f"AI Service Port Open: {item['port']} ({item['service']})",
                description=(
                    f"Port {item['port']} is listening, commonly used by "
                    f"{item['service']}. This may indicate an unauthorized "
                    f"AI service running on the system."
                ),
                affected_asset=target,
                finding_type='shadow_ai_port',
                remediation=(
                    f"Investigate what service is running on port {item['port']}. "
                    f"If unauthorized, stop the service and block the port."
                ),
                detection_method='port_scan',
            )

    # -----------------------------------------------------------------
    # Check: AI services (systemd / Windows services)
    # -----------------------------------------------------------------

    def _check_ai_services(self, target: str) -> None:
        """Check for AI-related system services."""
        self.scan_logger.info("Checking AI system services...")

        if platform.system() == 'Windows':
            output = self._run_ps(
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                "Select-Object -ExpandProperty Name"
            )
        else:
            output = self._run_cmd(
                ['systemctl', 'list-units', '--type=service', '--state=running',
                 '--no-pager', '--no-legend']
            )

        if not output:
            self.add_result('ai_services', {'status': 'unable_to_check'}, target)
            return

        output_lower = output.lower()
        found = []
        for proc_key, proc_name in self.AI_PROCESSES.items():
            if proc_key.lower() in output_lower:
                found.append({'service': proc_key, 'name': proc_name})

        self.add_result('ai_services', {'found': found}, target)

        for item in found:
            self.add_finding(
                severity='MEDIUM',
                title=f"AI Service Installed: {item['name']}",
                description=(
                    f"{item['name']} is registered as a system service, "
                    f"indicating a persistent AI installation."
                ),
                affected_asset=target,
                finding_type='shadow_ai_service',
                remediation=(
                    f"Review whether {item['name']} is authorized. "
                    f"If not, disable and remove the service."
                ),
                detection_method='service_enumeration',
            )

    # -----------------------------------------------------------------
    # Check: AI installations (common paths)
    # -----------------------------------------------------------------

    def _check_ai_installations(self, target: str) -> None:
        """Check common AI installation paths."""
        self.scan_logger.info("Checking AI installation paths...")

        home = Path.home()
        is_windows = sys.platform == 'win32'

        # Cross-platform paths (dot-dirs work everywhere)
        install_paths = [
            home / '.ollama',
            home / '.lmstudio',
            home / 'lm-studio',
            home / '.cache' / 'huggingface',
            home / '.cache' / 'torch',
        ]

        if is_windows:
            install_paths.extend([
                home / 'AppData' / 'Local' / 'Ollama',
                home / 'AppData' / 'Local' / 'LM Studio',
                home / 'AppData' / 'Local' / 'Jan',
                home / 'AppData' / 'Local' / 'Programs' / 'LM Studio',
                home / 'AppData' / 'Local' / 'nomic.ai' / 'GPT4All',
            ])
        else:
            install_paths.extend([
                home / '.local' / 'share' / 'ollama',
                Path('/usr/local/bin/ollama'),
                Path('/opt/ollama'),
                Path('/opt/lm-studio'),
            ])

        found = []
        for p in install_paths:
            try:
                if p.exists():
                    found.append(str(p))
            except (PermissionError, OSError):
                continue

        self.add_result('ai_installations', {'found': found}, target)

        for path in found:
            self.add_finding(
                severity='LOW',
                title=f"AI Software Installation Found: {Path(path).name}",
                description=(
                    f"AI software installation detected at {path}. "
                    f"This indicates AI tools have been installed on the system."
                ),
                affected_asset=target,
                finding_type='shadow_ai_installation',
                remediation=(
                    f"Review the AI installation at {path}. "
                    f"If unauthorized, remove the directory and associated software."
                ),
                detection_method='filesystem_check',
            )

    # -----------------------------------------------------------------
    # Check: AI model files
    # -----------------------------------------------------------------

    def _check_ai_model_files(self, target: str) -> None:
        """Search for AI model files on disk (deep scan only)."""
        self.scan_logger.info("Searching for AI model files...")

        search_dirs = [Path.home()]
        if platform.system() == 'Windows':
            downloads = Path.home() / 'Downloads'
            if downloads.exists():
                search_dirs.append(downloads)
        else:
            search_dirs.append(Path('/tmp'))

        found = []
        for search_dir in search_dirs:
            try:
                for ext in self.AI_MODEL_EXTENSIONS:
                    for match in search_dir.rglob(f'*{ext}'):
                        try:
                            size_mb = match.stat().st_size / (1024 * 1024)
                            if size_mb > 10:  # Only flag files > 10MB
                                found.append({
                                    'path': str(match),
                                    'size_mb': round(size_mb, 1),
                                    'extension': ext,
                                })
                                if len(found) >= 50:  # Limit results
                                    break
                        except (PermissionError, OSError):
                            continue
                    if len(found) >= 50:
                        break
            except (PermissionError, OSError):
                continue

        self.add_result('ai_model_files', {'found': found[:20]}, target)

        for item in found[:20]:
            self.add_finding(
                severity='INFO',
                title=f"AI Model File: {Path(item['path']).name} ({item['size_mb']}MB)",
                description=(
                    f"AI model file detected: {item['path']} "
                    f"({item['size_mb']}MB, type: {item['extension']}). "
                    f"Large model files may indicate local AI inference capability."
                ),
                affected_asset=target,
                finding_type='shadow_ai_model_file',
                remediation=(
                    "Review whether this AI model file is authorized. "
                    "Consider data classification implications of local AI models."
                ),
                detection_method='filesystem_scan',
            )

    # -----------------------------------------------------------------
    # Check: AI browser extensions
    # -----------------------------------------------------------------

    def _check_ai_browser_extensions(self, target: str) -> None:
        """Check for AI-related browser extensions."""
        self.scan_logger.info("Checking for AI browser extensions...")

        found = []
        home = Path.home()

        # Chrome extension paths
        chrome_paths = []
        if platform.system() == 'Windows':
            chrome_paths.append(
                home / 'AppData' / 'Local' / 'Google' / 'Chrome' /
                'User Data' / 'Default' / 'Extensions'
            )
        elif platform.system() == 'Darwin':
            chrome_paths.append(
                home / 'Library' / 'Application Support' / 'Google' /
                'Chrome' / 'Default' / 'Extensions'
            )
        else:
            chrome_paths.append(
                home / '.config' / 'google-chrome' / 'Default' / 'Extensions'
            )

        for ext_dir in chrome_paths:
            if not ext_dir.exists():
                continue
            try:
                installed_ids = [d.name for d in ext_dir.iterdir() if d.is_dir()]
                for ext_name, ext_ids in self.AI_BROWSER_EXTENSIONS.items():
                    for ext_id in ext_ids:
                        if ext_id in installed_ids:
                            found.append({
                                'extension': ext_name,
                                'browser': 'Chrome',
                                'id': ext_id,
                            })
            except (PermissionError, OSError):
                continue

        self.add_result('ai_browser_extensions', {'found': found}, target)

        for item in found:
            self.add_finding(
                severity='LOW',
                title=f"AI Browser Extension: {item['extension']} ({item['browser']})",
                description=(
                    f"AI browser extension '{item['extension']}' detected in "
                    f"{item['browser']}. Browser-based AI tools may transmit "
                    f"sensitive data to external AI services."
                ),
                affected_asset=target,
                finding_type='shadow_ai_browser_extension',
                remediation=(
                    f"Review whether the {item['extension']} extension is "
                    f"authorized by your organization's AI usage policy."
                ),
                detection_method='browser_extension_check',
            )

    # -----------------------------------------------------------------
    # Check: AI Python packages
    # -----------------------------------------------------------------

    def _check_ai_python_packages(self, target: str) -> None:
        """Check for AI-related Python packages installed."""
        self.scan_logger.info("Checking for AI Python packages...")

        output = self._run_cmd(
            [sys.executable, '-m', 'pip', 'list', '--format=json'],
            timeout=30,
        )

        if not output:
            self.add_result('ai_python_packages', {'status': 'unable_to_check'}, target)
            return

        try:
            packages = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            self.add_result('ai_python_packages', {'status': 'parse_error'}, target)
            return

        installed_names = {p.get('name', '').lower() for p in packages}
        found = []
        for pkg in self.AI_PYTHON_PACKAGES:
            if pkg.lower() in installed_names:
                found.append(pkg)

        self.add_result('ai_python_packages', {'found': found}, target)

        if found:
            self.add_finding(
                severity='INFO',
                title=f"AI Python Packages Installed: {', '.join(found[:5])}{'...' if len(found) > 5 else ''}",
                description=(
                    f"Found {len(found)} AI-related Python package(s): "
                    f"{', '.join(found)}. These packages enable AI/ML capabilities."
                ),
                affected_asset=target,
                finding_type='shadow_ai_python_package',
                remediation=(
                    "Review whether these AI packages are authorized. "
                    "Consider whether they should be in production environments."
                ),
                detection_method='package_enumeration',
            )

    # -----------------------------------------------------------------
    # Check: AI API keys in config files
    # -----------------------------------------------------------------

    def _check_ai_api_keys(self, target: str) -> None:
        """Search for AI API keys in common config locations."""
        self.scan_logger.info("Checking for AI API keys...")

        config_files = []
        home = Path.home()
        search_patterns = [
            '.env', '.env.local', '.env.production',
            '.bashrc', '.zshrc', '.profile', '.bash_profile',
        ]

        for pattern in search_patterns:
            p = home / pattern
            if p.exists() and p.is_file():
                config_files.append(p)

        # Also check common project dirs
        for d in [home / 'Projects', home / 'repos', home / 'code',
                   home / 'Documents', home / 'Desktop']:
            if d.exists():
                try:
                    for env_file in d.rglob('.env'):
                        config_files.append(env_file)
                        if len(config_files) >= 100:
                            break
                except (PermissionError, OSError):
                    continue

        found = []
        for cfg_file in config_files[:100]:
            try:
                content = cfg_file.read_text(encoding='utf-8', errors='ignore')
                for pattern, provider in self.AI_API_KEY_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        masked = match[:8] + '...' + match[-4:]
                        found.append({
                            'file': str(cfg_file),
                            'provider': provider,
                            'key_masked': masked,
                        })
            except (PermissionError, OSError):
                continue

        self.add_result('ai_api_keys', {'found_count': len(found)}, target)

        for item in found[:10]:
            self.add_finding(
                severity='HIGH',
                title=f"AI API Key Found: {item['provider']} in {Path(item['file']).name}",
                description=(
                    f"An API key for {item['provider']} ({item['key_masked']}) "
                    f"was found in {item['file']}. API keys indicate active "
                    f"use of external AI services."
                ),
                affected_asset=target,
                finding_type='shadow_ai_api_key',
                remediation=(
                    f"Review authorization for {item['provider']} API usage. "
                    f"Ensure the key is stored securely (vault, not plaintext). "
                    f"Rotate the key if it was exposed."
                ),
                detection_method='config_file_scan',
            )

    # -----------------------------------------------------------------
    # Check: AI network / firewall rules
    # -----------------------------------------------------------------

    def _check_ai_network_rules(self, target: str) -> None:
        """Check if AI domains are blocked or allowed in firewall/hosts."""
        self.scan_logger.info("Checking AI network rules...")

        # Check hosts file for AI domain blocks
        hosts_path = (
            Path('C:/Windows/System32/drivers/etc/hosts')
            if platform.system() == 'Windows'
            else Path('/etc/hosts')
        )

        blocked_domains = []
        unblocked_domains = list(self.AI_WEB_DOMAINS)

        try:
            if hosts_path.exists():
                content = hosts_path.read_text(encoding='utf-8', errors='ignore')
                for domain in self.AI_WEB_DOMAINS:
                    if domain in content:
                        blocked_domains.append(domain)
                        if domain in unblocked_domains:
                            unblocked_domains.remove(domain)
        except (PermissionError, OSError):
            pass

        self.add_result('ai_network_rules', {
            'blocked_domains': blocked_domains,
            'unblocked_domains': unblocked_domains,
        }, target)

        if unblocked_domains and not blocked_domains:
            self.add_finding(
                severity='INFO',
                title="No AI Domain Blocking Detected",
                description=(
                    f"None of the {len(self.AI_WEB_DOMAINS)} known AI web "
                    f"domains are blocked in the hosts file. Users can freely "
                    f"access AI services like ChatGPT, Claude, Gemini, etc."
                ),
                affected_asset=target,
                finding_type='shadow_ai_network',
                remediation=(
                    "Consider implementing DNS-level or firewall blocking for "
                    "unauthorized AI services if your policy restricts AI usage."
                ),
                detection_method='network_rule_check',
            )

    # -----------------------------------------------------------------
    # Check: AI scheduled tasks
    # -----------------------------------------------------------------

    def _check_ai_scheduled_tasks(self, target: str) -> None:
        """Check for AI-related scheduled tasks."""
        self.scan_logger.info("Checking for AI scheduled tasks...")

        if platform.system() == 'Windows':
            output = self._run_ps(
                "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
                "Select-Object TaskName,TaskPath | Format-List"
            )
        else:
            output = self._run_cmd(['crontab', '-l'])

        if not output:
            self.add_result('ai_scheduled_tasks', {'status': 'unable_to_check'}, target)
            return

        output_lower = output.lower()
        found = []
        for proc_key, proc_name in self.AI_PROCESSES.items():
            if proc_key.lower() in output_lower:
                found.append({'task': proc_key, 'name': proc_name})

        self.add_result('ai_scheduled_tasks', {'found': found}, target)

        for item in found:
            self.add_finding(
                severity='MEDIUM',
                title=f"AI Scheduled Task: {item['name']}",
                description=(
                    f"A scheduled task related to {item['name']} was detected. "
                    f"This indicates automated/persistent AI tool usage."
                ),
                affected_asset=target,
                finding_type='shadow_ai_scheduled_task',
                remediation=(
                    f"Review the scheduled task for {item['name']}. "
                    f"If unauthorized, remove the scheduled task."
                ),
                detection_method='scheduled_task_check',
            )

    # -----------------------------------------------------------------
    # Check: AI Docker containers
    # -----------------------------------------------------------------

    def _check_ai_docker_containers(self, target: str) -> None:
        """Check for AI-related Docker containers."""
        self.scan_logger.info("Checking for AI Docker containers...")

        output = self._run_cmd(
            ['docker', 'ps', '--format', '{{.Names}} {{.Image}}'],
            timeout=15,
        )

        if not output:
            self.add_result('ai_docker_containers', {'status': 'unable_to_check'}, target)
            return

        output_lower = output.lower()
        found = []
        ai_docker_keywords = [
            'ollama', 'localai', 'text-generation', 'vllm',
            'open-webui', 'llama', 'stable-diffusion', 'comfyui',
            'whisper', 'huggingface', 'triton',
        ]

        for line in output.strip().split('\n'):
            line_lower = line.lower()
            for keyword in ai_docker_keywords:
                if keyword in line_lower:
                    found.append({'container': line.strip(), 'keyword': keyword})
                    break

        self.add_result('ai_docker_containers', {'found': found}, target)

        for item in found:
            self.add_finding(
                severity='MEDIUM',
                title=f"AI Docker Container Running: {item['keyword']}",
                description=(
                    f"Docker container related to AI detected: {item['container']}. "
                    f"Containerized AI services may process data outside "
                    f"approved channels."
                ),
                affected_asset=target,
                finding_type='shadow_ai_docker',
                remediation=(
                    "Review whether this AI container is authorized. "
                    "If not, stop and remove the container."
                ),
                detection_method='docker_enumeration',
            )
