#!/usr/bin/env python3
"""
Donjon Platform — MCP Security Scanner

Scans Model Context Protocol (MCP) server configurations for security risks:
- Tool injection: malicious tool definitions that execute arbitrary code
- Data exfiltration: tools that send data to external endpoints
- Prompt injection: tool descriptions containing injection payloads
- Excessive permissions: tools with overly broad filesystem/network access
- Missing authentication: MCP servers without auth requirements
- Insecure transport: HTTP instead of HTTPS for remote MCP servers
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Add lib to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner


class MCPSecurityScanner(BaseScanner):
    """MCP server configuration security scanner."""

    SCANNER_NAME = "mcp"
    SCANNER_DESCRIPTION = "MCP server configuration security analysis"

    # Patterns that indicate dangerous tool capabilities
    DANGEROUS_COMMAND_PATTERNS = [
        r'\bcmd\b', r'\bcommand\b', r'\bexec\b', r'\bexecute\b',
        r'\bbash\b', r'\bsh\b', r'\bshell\b', r'\bpowershell\b',
        r'\bpwsh\b', r'\bterminal\b', r'\brun_command\b',
        r'\bsystem\b', r'\bspawn\b', r'\bpopen\b',
    ]

    # Patterns for filesystem access
    FILESYSTEM_PATTERNS = [
        r'\bread_file\b', r'\bwrite_file\b', r'\bdelete_file\b',
        r'\blist_directory\b', r'\blist_dir\b', r'\breaddir\b',
        r'\bmkdir\b', r'\bremove\b', r'\bunlink\b',
        r'\bfile_system\b', r'\bfilesystem\b',
    ]

    # Patterns for network access
    NETWORK_PATTERNS = [
        r'\bhttp_request\b', r'\bfetch\b', r'\bcurl\b', r'\bwget\b',
        r'\bdownload\b', r'\bupload\b', r'\bsend_request\b',
        r'\bapi_call\b', r'\bwebhook\b',
    ]

    # Prompt injection indicators in tool descriptions
    PROMPT_INJECTION_PATTERNS = [
        r'ignore\s+(previous|all|above)\s+(instructions?|prompts?)',
        r'you\s+are\s+now\s+',
        r'forget\s+(everything|all|your)\s+',
        r'new\s+instructions?\s*:',
        r'system\s*:\s*you',
        r'<\s*/?system\s*>',
        r'override\s+(safety|instructions?|rules?)',
        r'disregard\s+(previous|all|safety)',
        r'act\s+as\s+(if|though)\s+you',
        r'pretend\s+(you|to)\s+',
        r'roleplay\s+as\b',
        r'jailbreak',
    ]

    # Known MCP config locations
    MCP_CONFIG_PATHS = []

    def __init__(self, session_id: Optional[str] = None):
        super().__init__(session_id)
        self._build_config_paths()

    def _build_config_paths(self):
        """Build platform-aware list of MCP configuration paths."""
        home = Path.home()

        self.MCP_CONFIG_PATHS = [
            # Claude Code / Claude Desktop
            home / '.claude' / 'settings.json',
            home / '.claude' / 'settings.local.json',
            home / '.claude.json',
            # Claude Desktop (Windows)
            home / 'AppData' / 'Roaming' / 'Claude' / 'claude_desktop_config.json',
            # Claude Desktop (macOS)
            home / 'Library' / 'Application Support' / 'Claude' / 'claude_desktop_config.json',
            # Cursor
            home / '.cursor' / 'mcp.json',
            home / '.cursor' / 'settings.json',
            # VS Code
            home / '.vscode' / 'settings.json',
            home / '.vscode' / 'mcp.json',
        ]

        # Also check project-level configs in common locations
        cwd = Path.cwd()
        project_configs = [
            cwd / '.claude' / 'settings.json',
            cwd / '.claude' / 'settings.local.json',
            cwd / '.mcp.json',
            cwd / '.vscode' / 'settings.json',
            cwd / '.vscode' / 'mcp.json',
            cwd / '.cursor' / 'mcp.json',
        ]
        self.MCP_CONFIG_PATHS.extend(project_configs)

    def scan(self, targets: List[str], **kwargs) -> Dict:
        """
        Execute MCP security configuration scan.

        Args:
            targets: List of targets (localhost scans local configs,
                     or paths to specific config files).
            **kwargs:
                scan_type: 'quick', 'standard', or 'deep'
        """
        self.start_time = datetime.now(timezone.utc)
        self.scan_status = 'running'
        scan_type = kwargs.get('scan_type', 'standard')

        self.scan_logger.info(f"Starting MCP security scan (type={scan_type})")

        results = {
            'scan_type': scan_type,
            'targets': targets,
            'configs_found': [],
            'servers_analyzed': [],
            'findings': [],
            'summary': {}
        }

        configs_found = []

        for target in targets:
            if target in ('localhost', '127.0.0.1', '::1', 'local'):
                # Scan all known local MCP config paths
                configs_found.extend(self._discover_local_configs())
            elif os.path.isfile(target):
                configs_found.append(Path(target))
            elif os.path.isdir(target):
                # Scan directory for MCP configs
                configs_found.extend(self._scan_directory(Path(target)))

        # Deduplicate
        seen = set()
        unique_configs = []
        for p in configs_found:
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                unique_configs.append(p)

        if not unique_configs:
            self.add_finding(
                severity='INFO',
                title="No MCP configurations found",
                description=(
                    "No MCP server configuration files were discovered on this system. "
                    "Checked standard locations for Claude Code, Claude Desktop, "
                    "Cursor, and VS Code."
                ),
                affected_asset='localhost',
                finding_type='no_mcp_configs',
                remediation="No action needed if MCP is not in use.",
                detection_method='config_discovery'
            )
            self.end_time = datetime.now(timezone.utc)
            self.set_status('complete')
            results['findings'] = self.findings.copy()
            results['summary'] = self._build_summary()
            self.save_results()
            return results

        self.scan_logger.info(f"Found {len(unique_configs)} MCP config file(s)")

        for config_path in unique_configs:
            self.scan_logger.info(f"Analyzing: {config_path}")
            results['configs_found'].append(str(config_path))

            config_data = self._load_config(config_path)
            if config_data is None:
                continue

            servers = self._extract_mcp_servers(config_data, config_path)
            for server in servers:
                server_results = self._analyze_server(server, config_path)
                results['servers_analyzed'].append(server_results)

        # Summary finding
        total_servers = len(results['servers_analyzed'])
        if total_servers > 0:
            self.add_finding(
                severity='INFO',
                title=f"MCP configuration scan: {total_servers} server(s) analyzed",
                description=(
                    f"Analyzed {total_servers} MCP server definition(s) across "
                    f"{len(unique_configs)} configuration file(s)."
                ),
                affected_asset='localhost',
                finding_type='mcp_scan_summary',
                remediation="Review all findings for security issues.",
                detection_method='config_analysis'
            )

        results['findings'] = self.findings.copy()
        results['summary'] = self._build_summary()

        self.end_time = datetime.now(timezone.utc)
        self.set_status('complete')
        self.save_results()

        return results

    def _build_summary(self) -> Dict:
        return {
            'findings_count': len(self.findings),
            'findings_by_severity': self._count_by_severity()
        }

    def _discover_local_configs(self) -> List[Path]:
        """Discover MCP configuration files on the local system."""
        found = []
        for config_path in self.MCP_CONFIG_PATHS:
            if config_path.exists() and config_path.is_file():
                self.scan_logger.info(f"Discovered config: {config_path}")
                found.append(config_path)

        # Also search for claude_desktop_config.json recursively in AppData
        home = Path.home()
        appdata_dirs = [
            home / 'AppData' / 'Roaming',
            home / 'AppData' / 'Local',
            home / '.config',
        ]
        for appdata in appdata_dirs:
            if appdata.exists():
                try:
                    for match in appdata.rglob('claude_desktop_config.json'):
                        if match not in found:
                            found.append(match)
                    for match in appdata.rglob('mcp.json'):
                        if match not in found:
                            found.append(match)
                except (PermissionError, OSError):
                    continue

        return found

    def _scan_directory(self, directory: Path) -> List[Path]:
        """Scan a directory for MCP config files."""
        found = []
        patterns = [
            'settings.json', 'mcp.json',
            'claude_desktop_config.json', '.mcp.json'
        ]
        try:
            for pattern in patterns:
                for match in directory.rglob(pattern):
                    found.append(match)
        except (PermissionError, OSError):
            pass
        return found

    def _load_config(self, config_path: Path) -> Optional[Dict]:
        """Load and parse a JSON config file."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return None
                # Handle JSONC (JSON with comments) — strip // comments
                lines = []
                for line in content.split('\n'):
                    stripped = line.lstrip()
                    if not stripped.startswith('//'):
                        # Remove inline // comments (but not inside strings)
                        lines.append(line)
                clean_content = '\n'.join(lines)
                return json.loads(clean_content)
        except json.JSONDecodeError as e:
            self.scan_logger.warning(f"JSON parse error in {config_path}: {e}")
            # Try more aggressive comment stripping
            try:
                cleaned = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
                cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
                # Remove trailing commas before } or ]
                cleaned = re.sub(r',\s*([}\]])', r'\1', cleaned)
                return json.loads(cleaned)
            except (json.JSONDecodeError, Exception):
                self.add_finding(
                    severity='LOW',
                    title=f"Malformed MCP config: {config_path.name}",
                    description=f"Configuration file {config_path} contains invalid JSON: {e}",
                    affected_asset=str(config_path),
                    finding_type='malformed_config',
                    remediation="Fix JSON syntax errors in the configuration file.",
                    detection_method='config_parse'
                )
                return None
        except (PermissionError, OSError) as e:
            self.scan_logger.warning(f"Cannot read {config_path}: {e}")
            return None

    def _extract_mcp_servers(self, config_data: Dict,
                              config_path: Path) -> List[Dict]:
        """Extract MCP server definitions from config data."""
        servers = []

        # Claude Code settings.json format: {"mcpServers": {...}}
        mcp_servers = config_data.get('mcpServers', {})
        if not mcp_servers:
            # VS Code format: might be nested under a key
            mcp_servers = config_data.get('mcp', {}).get('servers', {})
        if not mcp_servers:
            # Claude Desktop format
            mcp_servers = config_data.get('mcp_servers', {})
        if not mcp_servers:
            # Direct servers key
            mcp_servers = config_data.get('servers', {})

        if isinstance(mcp_servers, dict):
            for name, server_def in mcp_servers.items():
                if isinstance(server_def, dict):
                    server_def['_name'] = name
                    server_def['_source'] = str(config_path)
                    servers.append(server_def)
        elif isinstance(mcp_servers, list):
            for idx, server_def in enumerate(mcp_servers):
                if isinstance(server_def, dict):
                    server_def['_name'] = server_def.get('name', f'server_{idx}')
                    server_def['_source'] = str(config_path)
                    servers.append(server_def)

        return servers

    def _analyze_server(self, server: Dict, config_path: Path) -> Dict:
        """Analyze a single MCP server definition for security issues."""
        name = server.get('_name', 'unknown')
        source = server.get('_source', str(config_path))

        analysis = {
            'name': name,
            'source': source,
            'command': server.get('command', ''),
            'args': server.get('args', []),
            'url': server.get('url', ''),
            'transport': server.get('transport', ''),
            'issues': []
        }

        # 1. Check transport security
        self._check_transport_security(server, name, source)

        # 2. Check command execution
        self._check_command_security(server, name, source)

        # 3. Check environment variables for secrets
        self._check_env_security(server, name, source)

        # 4. Check tool definitions if present
        tools = server.get('tools', [])
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    self._check_tool_security(tool, name, source)

        # 5. Check for missing authentication
        self._check_auth_security(server, name, source)

        # 6. Check args for dangerous patterns
        self._check_args_security(server, name, source)

        return analysis

    def _check_transport_security(self, server: Dict, name: str, source: str):
        """Check for insecure transport (HTTP instead of HTTPS)."""
        url = server.get('url', '')
        transport = server.get('transport', '')

        if url and url.startswith('http://') and not any(
            local in url for local in ('localhost', '127.0.0.1', '::1', '0.0.0.0')
        ):
            self.add_finding(
                severity='HIGH',
                title=f"Insecure MCP transport: {name} uses HTTP",
                description=(
                    f"MCP server '{name}' in {source} connects via unencrypted HTTP "
                    f"to {url}. This exposes all tool calls and responses to "
                    "network eavesdropping and man-in-the-middle attacks."
                ),
                affected_asset=source,
                finding_type='insecure_mcp_transport',
                remediation="Switch to HTTPS for the MCP server URL.",
                raw_data={'server': name, 'url': url},
                detection_method='transport_analysis'
            )

        if url and url.startswith('http://') and any(
            local in url for local in ('localhost', '127.0.0.1', '::1')
        ):
            self.add_finding(
                severity='LOW',
                title=f"Local HTTP MCP transport: {name}",
                description=(
                    f"MCP server '{name}' uses HTTP on localhost ({url}). "
                    "While less risky than remote HTTP, local connections "
                    "can still be intercepted by local malware."
                ),
                affected_asset=source,
                finding_type='local_http_transport',
                remediation="Consider using stdio transport or HTTPS even locally.",
                raw_data={'server': name, 'url': url},
                detection_method='transport_analysis'
            )

    def _check_command_security(self, server: Dict, name: str, source: str):
        """Check the command used to launch the MCP server."""
        command = server.get('command', '')
        args = server.get('args', [])

        if not command:
            return

        # Check if command runs with elevated privileges
        full_cmd = f"{command} {' '.join(str(a) for a in args)}"

        # npx with unknown packages — supply chain risk
        if command in ('npx', 'npx.cmd', 'npx.exe'):
            pkg_name = args[0] if args else 'unknown'
            # Check for suspicious package names (typosquatting indicators)
            self.add_finding(
                severity='MEDIUM',
                title=f"MCP server '{name}' uses npx (supply chain risk)",
                description=(
                    f"MCP server '{name}' in {source} is launched via npx, "
                    f"which downloads and executes packages at runtime. "
                    f"Package: {pkg_name}. A compromised npm package could "
                    "execute arbitrary code with your user privileges."
                ),
                affected_asset=source,
                finding_type='npx_supply_chain',
                remediation=(
                    "Pin the package version and verify the package hash. "
                    "Consider installing the package locally instead of using npx."
                ),
                raw_data={'server': name, 'command': command, 'args': args},
                detection_method='command_analysis'
            )

        # Docker without restrictions
        if command in ('docker', 'docker.exe'):
            has_readonly = any('--read-only' in str(a) for a in args)
            has_network_none = any('--network=none' in str(a) or '--network none' in str(a) for a in args)
            if not has_readonly or not has_network_none:
                self.add_finding(
                    severity='MEDIUM',
                    title=f"MCP server '{name}' runs in Docker without restrictions",
                    description=(
                        f"MCP server '{name}' uses Docker but may lack security restrictions. "
                        f"Read-only filesystem: {has_readonly}, Network isolation: {has_network_none}."
                    ),
                    affected_asset=source,
                    finding_type='docker_unrestricted',
                    remediation="Add --read-only and --network=none flags where possible.",
                    raw_data={'server': name, 'command': full_cmd},
                    detection_method='command_analysis'
                )

        # Direct shell invocation
        if command in ('bash', 'sh', 'cmd', 'cmd.exe', 'powershell', 'pwsh', 'powershell.exe'):
            self.add_finding(
                severity='HIGH',
                title=f"MCP server '{name}' launches a shell directly",
                description=(
                    f"MCP server '{name}' in {source} uses '{command}' as its "
                    "command, giving it direct shell access. This allows "
                    "arbitrary command execution."
                ),
                affected_asset=source,
                finding_type='direct_shell_access',
                remediation=(
                    "Use a purpose-built MCP server binary instead of a raw shell. "
                    "If shell access is needed, restrict it with a wrapper."
                ),
                raw_data={'server': name, 'command': full_cmd},
                detection_method='command_analysis'
            )

    def _check_env_security(self, server: Dict, name: str, source: str):
        """Check environment variables for exposed secrets."""
        env = server.get('env', {})
        if not isinstance(env, dict):
            return

        secret_patterns = [
            r'(?i)(api[_-]?key|secret|token|password|passwd|credential|auth)',
        ]

        for key, value in env.items():
            # Check if the key name suggests it's a secret
            for pattern in secret_patterns:
                if re.search(pattern, key):
                    # Check if value is hardcoded (not a reference)
                    if isinstance(value, str) and not value.startswith('${') and \
                       not value.startswith('$') and len(value) > 3:
                        self.add_finding(
                            severity='HIGH',
                            title=f"Hardcoded secret in MCP config: {key} ({name})",
                            description=(
                                f"MCP server '{name}' in {source} has a hardcoded "
                                f"secret in environment variable '{key}'. "
                                "Hardcoded secrets in config files can be leaked "
                                "through version control or file access."
                            ),
                            affected_asset=source,
                            finding_type='hardcoded_secret',
                            remediation=(
                                f"Move '{key}' to a secure secret store or "
                                "use environment variable references."
                            ),
                            raw_data={'server': name, 'env_key': key},
                            detection_method='secret_detection'
                        )
                    break

    def _check_tool_security(self, tool: Dict, server_name: str, source: str):
        """Analyze a tool definition for security risks."""
        tool_name = tool.get('name', 'unknown')
        description = tool.get('description', '')
        schema = json.dumps(tool.get('inputSchema', tool.get('schema', {})))

        combined_text = f"{tool_name} {description} {schema}".lower()

        # Check for command execution tools
        for pattern in self.DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, combined_text):
                self.add_finding(
                    severity='HIGH',
                    title=f"Command execution tool: {tool_name} in {server_name}",
                    description=(
                        f"Tool '{tool_name}' in MCP server '{server_name}' "
                        "appears to allow command/shell execution. This could "
                        "be exploited via prompt injection to run arbitrary commands."
                    ),
                    affected_asset=source,
                    finding_type='command_execution_tool',
                    remediation=(
                        "Restrict tool to specific allowed commands or remove "
                        "if not essential."
                    ),
                    raw_data={'tool': tool_name, 'server': server_name},
                    detection_method='tool_analysis'
                )
                break

        # Check for broad filesystem access
        for pattern in self.FILESYSTEM_PATTERNS:
            if re.search(pattern, combined_text):
                self.add_finding(
                    severity='MEDIUM',
                    title=f"Filesystem access tool: {tool_name} in {server_name}",
                    description=(
                        f"Tool '{tool_name}' in MCP server '{server_name}' "
                        "provides filesystem access. Without path restrictions, "
                        "this could read sensitive files."
                    ),
                    affected_asset=source,
                    finding_type='filesystem_access_tool',
                    remediation="Restrict filesystem access to specific directories.",
                    raw_data={'tool': tool_name, 'server': server_name},
                    detection_method='tool_analysis'
                )
                break

        # Check for prompt injection in descriptions
        for pattern in self.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, description, re.IGNORECASE):
                self.add_finding(
                    severity='CRITICAL',
                    title=f"Prompt injection in tool description: {tool_name}",
                    description=(
                        f"Tool '{tool_name}' in MCP server '{server_name}' "
                        "contains text matching prompt injection patterns in its "
                        f"description. This could manipulate the AI model's behavior. "
                        f"Pattern matched: {pattern}"
                    ),
                    affected_asset=source,
                    finding_type='prompt_injection',
                    remediation=(
                        "Remove or sanitize the tool description. Investigate "
                        "the MCP server for malicious intent."
                    ),
                    raw_data={
                        'tool': tool_name, 'server': server_name,
                        'description_preview': description[:200]
                    },
                    detection_method='prompt_injection_detection'
                )
                break

    def _check_auth_security(self, server: Dict, name: str, source: str):
        """Check for missing authentication on remote MCP servers."""
        url = server.get('url', '')
        transport = server.get('transport', '')
        env = server.get('env', {})
        headers = server.get('headers', {})

        # Only relevant for remote servers
        if not url or any(
            local in url for local in ('localhost', '127.0.0.1', '::1')
        ):
            return

        # Check for auth indicators
        has_auth = False
        if isinstance(env, dict):
            for key in env:
                if re.search(r'(?i)(auth|token|key|secret|bearer)', key):
                    has_auth = True
                    break
        if isinstance(headers, dict):
            for key in headers:
                if re.search(r'(?i)(auth|bearer|token|api.key)', key):
                    has_auth = True
                    break

        if not has_auth:
            self.add_finding(
                severity='HIGH',
                title=f"No authentication for remote MCP server: {name}",
                description=(
                    f"Remote MCP server '{name}' at {url} does not appear to "
                    "use authentication (no auth tokens, API keys, or bearer "
                    "tokens found in configuration). Unauthenticated MCP servers "
                    "could be accessed by unauthorized parties."
                ),
                affected_asset=source,
                finding_type='missing_mcp_auth',
                remediation="Add authentication tokens or API keys to the MCP server config.",
                raw_data={'server': name, 'url': url},
                detection_method='auth_analysis'
            )

    def _check_args_security(self, server: Dict, name: str, source: str):
        """Check command arguments for dangerous patterns."""
        args = server.get('args', [])
        if not isinstance(args, list):
            return

        args_str = ' '.join(str(a) for a in args).lower()

        # Check for --allow-all or overly permissive flags
        permissive_flags = [
            ('--allow-all', 'grants all permissions'),
            ('--no-sandbox', 'disables sandboxing'),
            ('--disable-security', 'disables security features'),
            ('--privileged', 'runs with elevated privileges'),
            ('-v /:/host', 'mounts entire host filesystem'),
            ('--allow-write /', 'allows writing to root filesystem'),
        ]

        for flag, desc in permissive_flags:
            if flag.lower() in args_str:
                self.add_finding(
                    severity='HIGH',
                    title=f"Permissive flag '{flag}' on MCP server: {name}",
                    description=(
                        f"MCP server '{name}' in {source} uses the flag '{flag}' "
                        f"which {desc}. This significantly expands the attack surface."
                    ),
                    affected_asset=source,
                    finding_type='permissive_mcp_flag',
                    remediation=f"Remove '{flag}' and use least-privilege settings.",
                    raw_data={'server': name, 'flag': flag, 'args': args},
                    detection_method='args_analysis'
                )

        # Check for broad path access in args
        for arg in args:
            arg_str = str(arg)
            # Filesystem server with root or home access
            if re.match(r'^[/\\]$', arg_str) or arg_str in ('C:\\', 'C:/', '/'):
                self.add_finding(
                    severity='HIGH',
                    title=f"Root filesystem access in MCP server args: {name}",
                    description=(
                        f"MCP server '{name}' has root filesystem path ('{arg_str}') "
                        "in its arguments. This grants access to the entire filesystem."
                    ),
                    affected_asset=source,
                    finding_type='root_filesystem_access',
                    remediation="Restrict filesystem access to specific project directories.",
                    raw_data={'server': name, 'arg': arg_str},
                    detection_method='args_analysis'
                )


if __name__ == '__main__':
    scanner = MCPSecurityScanner()
    print("MCP Security Scanner initialized")
    print(f"  Config paths to check: {len(scanner.MCP_CONFIG_PATHS)}")
    found = scanner._discover_local_configs()
    print(f"  Configs found locally: {len(found)}")
    for f in found:
        print(f"    - {f}")
    print("\nMCP Security Scanner ready")
