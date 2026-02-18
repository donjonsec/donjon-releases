# Donjon Platform v7.0 -- REST API Reference

Base URL: `http://localhost:8443` (default)

All endpoints return JSON unless otherwise noted. Authentication is required for all endpoints except those listed as public.

---

## Authentication

API key authentication via HTTP header or query parameter:

```bash
# Header (preferred)
curl -H "X-API-Key: your-key" http://localhost:8443/api/v1/stats

# Query parameter
curl http://localhost:8443/api/v1/stats?api_key=your-key
```

### Key Management

```bash
# Generate a new API key
python bin/start-server.py --generate-key

# Set via environment variable (comma-separated for multiple keys)
export DONJON_API_KEYS=key1,key2,key3

# Register at startup
python bin/start-server.py --add-key your-key

# Disable auth (development only)
python bin/start-server.py --no-auth
```

### Public Endpoints (No Auth Required)

| Method | Path | Description |
|---|---|---|
| GET | `/` | Dashboard HTML |
| GET | `/api/v1/health` | Health check |

---

## Tier Enforcement

Community tier requests that exceed limits receive a `403 Forbidden` response:

```json
{
  "error": true,
  "message": "Deep scans are a Pro feature. Community includes quick and standard depth. Upgrade to unlock deep scanning.",
  "upgrade_required": "pro",
  "feature": "scan_depths"
}
```

Paid tiers (Pro, Enterprise, Managed) have no API restrictions.

### Community Restrictions

| Resource | Limit | Enforced On |
|---|---|---|
| Scan depth | Quick, Standard only (no Deep) | `POST /api/v1/scans` |
| Targets per scan | 16 | `POST /api/v1/scans` |
| Scheduled scans | Disabled | `POST /api/v1/schedules` |
| Export formats | CSV, JSON only | `POST /api/v1/export` |
| Notification channels | Email, webhook only | `POST /api/v1/notifications/channels` |
| AI queries | 10/day | All `POST /api/v1/ai/*` |
| AI scan summaries | Disabled | `POST /api/v1/ai/summarize/*` |

---

## Health and Stats

### GET /api/v1/health

Returns server health status and loaded module availability.

**Response:**
```json
{
  "status": "healthy",
  "version": "7.0",
  "uptime_seconds": 3600.5,
  "timestamp": "2026-02-15T12:00:00",
  "modules": {
    "evidence": true,
    "asset_inventory": true,
    "remediation": true,
    "risk_register": true,
    "audit": true,
    "exceptions": true,
    "export": true,
    "discovery": true,
    "reports": true,
    "compliance": true,
    "scheduler": true,
    "notifications": true,
    "ai_engine": true,
    "licensing": true
  }
}
```

### GET /api/v1/stats

Returns aggregate statistics across all modules (asset counts, open findings by severity, remediation metrics, risk posture, agent count).

---

## Assets

### GET /api/v1/assets

List assets from the asset inventory.

**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `business_unit` | string | Filter by business unit |
| `os_type` | string | Filter by OS type |
| `status` | string | Filter by status (default: `active`) |

**Response:**
```json
{
  "count": 5,
  "assets": [...]
}
```

### POST /api/v1/assets

Create a new asset.

**Body:**
```json
{
  "hostname": "web-server-01",
  "ip_address": "10.0.1.50",
  "os_type": "linux",
  "business_unit": "engineering"
}
```

**Response:** `201 Created`
```json
{
  "asset_id": "ast-abc123"
}
```

### GET /api/v1/assets/{id}

Get a single asset by ID.

### PUT /api/v1/assets/{id}

Update an asset. Body contains fields to update.

---

## Scans

### POST /api/v1/scans

Start a new scan session.

**Body:**
```json
{
  "scan_type": "vulnerability",
  "targets": ["10.0.1.0/24", "192.168.1.1"],
  "metadata": {
    "depth": "standard",
    "scanner": "network"
  }
}
```

**Response:** `201 Created`
```json
{
  "session_id": "sess-abc123",
  "status": "running"
}
```

**Tier restrictions:**
- Community: `depth` cannot be `deep`; max 16 targets

### GET /api/v1/scans

List scan sessions.

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 50 | Maximum sessions to return |

### GET /api/v1/scans/{session_id}

Get scan session summary (status, finding counts by severity, evidence count).

### GET /api/v1/scans/{session_id}/findings

Get all findings for a scan session.

### GET /api/v1/scans/{session_id}/export

Export scan findings.

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `format` | string | `json` | Export format: `json` or `csv` |

---

## Findings

### GET /api/v1/findings

List findings with optional filters.

**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `severity` | string | Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) |
| `session_id` | string | Filter by scan session |
| `status` | string | Filter by status (default: `open`) |
| `asset` | string | Filter by asset (substring match) |

### GET /api/v1/findings/{id}

Get a single finding by ID.

---

## Remediation

### GET /api/v1/remediation

List remediation items.

**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `status` | string | Filter by status |
| `assigned_to` | string | Filter by assignee |
| `overdue` | boolean | Show only overdue items |

### POST /api/v1/remediation

Create a remediation item.

**Body:**
```json
{
  "finding_id": "find-abc123",
  "title": "Patch OpenSSL vulnerability",
  "severity": "critical",
  "assigned_to": "ops-team",
  "due_date": "2026-03-01"
}
```

### PUT /api/v1/remediation/{id}

Update a remediation item (change status, reassign, add notes).

**Body:**
```json
{
  "status": "in_progress",
  "assigned_to": "jdoe",
  "notes": "Patch scheduled for next maintenance window",
  "changed_by": "admin"
}
```

### GET /api/v1/remediation/metrics

Get remediation metrics: SLA status, completion rates, statistics.

---

## Risk Register

### GET /api/v1/risks

List risks.

**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `category` | string | Filter by category |
| `status` | string | Filter by status |
| `business_unit` | string | Filter by business unit |
| `min_score` | int | Minimum risk score |

### POST /api/v1/risks

Create a risk entry.

**Body:**
```json
{
  "title": "Unpatched public-facing web server",
  "category": "technical",
  "likelihood": 4,
  "impact": 5,
  "business_unit": "engineering"
}
```

### GET /api/v1/risks/posture

Get overall risk posture calculation.

### GET /api/v1/risks/matrix

Get the risk scoring matrix.

---

## Exceptions

### GET /api/v1/exceptions

List risk exceptions/acceptances.

**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `status` | string | Filter: `pending`, `active`, `expiring`, or all |

### POST /api/v1/exceptions

Create a risk exception.

**Body:**
```json
{
  "finding_type": "ssl_weak_cipher",
  "title_pattern": "TLS 1.0 on legacy-*",
  "exception_type": "risk_acceptance",
  "justification": "Legacy system decommission scheduled for Q2"
}
```

### PUT /api/v1/exceptions/{id}/approve

Approve a pending exception.

**Body:**
```json
{
  "approved_by": "ciso@company.com",
  "notes": "Approved with 90-day expiry"
}
```

---

## Reports

### GET /api/v1/reports/executive

Generate an executive summary report (HTML).

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `days` | int | 30 | Reporting period in days |

### GET /api/v1/reports/compliance/{framework}

Generate a compliance report for a specific framework (HTML).

**Path Parameters:**
| Parameter | Description |
|---|---|
| `framework` | Framework ID (e.g., `NIST-800-53`, `HIPAA`, `PCI-DSS-v4`) |

---

## Export

### POST /api/v1/export

Export scan data in multiple formats.

**Body:**
```json
{
  "session_id": "sess-abc123",
  "formats": ["json", "csv", "html", "sarif"]
}
```

**Tier restrictions:** Community limited to `csv` and `json`.

**Response:**
```json
{
  "exported": {
    "json": "/path/to/report.json",
    "csv": "/path/to/report.csv"
  }
}
```

---

## Schedules

All schedule endpoints require Pro tier or above.

### GET /api/v1/schedules

List all scan schedules.

### POST /api/v1/schedules

Create a scheduled scan.

**Body:**
```json
{
  "name": "Weekly network scan",
  "scanner_type": "network",
  "cron_expression": "0 2 * * 1",
  "targets": ["10.0.0.0/24"],
  "scan_type": "standard",
  "description": "Monday 2 AM network scan",
  "created_by": "admin"
}
```

### GET /api/v1/schedules/{id}

Get a specific schedule.

### PUT /api/v1/schedules/{id}

Update a schedule.

### DELETE /api/v1/schedules/{id}

Delete a schedule.

### GET /api/v1/schedules/{id}/history

Get run history for a schedule.

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 20 | Maximum history entries |

---

## Notifications

### GET /api/v1/notifications/channels

List notification channels (sensitive config fields are masked).

### POST /api/v1/notifications/channels

Create a notification channel.

**Body:**
```json
{
  "name": "Ops Slack",
  "channel_type": "slack",
  "config": {
    "webhook_url": "https://hooks.slack.com/services/..."
  }
}
```

**Supported channel types:** `email`, `webhook`, `slack`, `teams`, `sms`

**Tier restrictions:** Community limited to `email` and `webhook`.

### PUT /api/v1/notifications/channels/{id}

Update a notification channel.

### DELETE /api/v1/notifications/channels/{id}

Delete a notification channel.

### POST /api/v1/notifications/test

Send a test notification.

**Body:**
```json
{
  "channel_id": "chan-abc123"
}
```

### GET /api/v1/notifications/history

Get notification delivery history.

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 50 | Maximum entries |
| `event_type` | string | -- | Filter by event type |
| `status` | string | -- | Filter by delivery status |

### GET /api/v1/notifications/stats

Get notification statistics (delivery rates, channel health).

---

## AI Engine

### GET /api/v1/ai/status

Get AI engine status (backend type, model name, availability). No tier restrictions.

**Response:**
```json
{
  "available": true,
  "backend": "ollama",
  "model": "llama3.2:latest",
  "message": "AI engine ready (ollama)"
}
```

### POST /api/v1/ai/analyze

Analyze a single security finding.

**Body:**
```json
{
  "finding": {
    "title": "SQL Injection in Login Form",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "epss_score": 0.92,
    "finding_type": "sql_injection",
    "affected_asset": "10.0.0.5"
  }
}
```

**Response:** Analysis result with `severity_validated`, `exploit_likelihood`, `business_impact`, `attack_vector`, `mitre_techniques`, and `confidence`.

### POST /api/v1/ai/triage

Prioritize a batch of findings.

**Body:**
```json
{
  "findings": [
    {"title": "...", "severity": "...", "cvss_score": 9.8},
    {"title": "...", "severity": "...", "cvss_score": 5.3}
  ]
}
```

### POST /api/v1/ai/remediate

Generate remediation instructions for a finding.

**Body:**
```json
{
  "finding": {
    "title": "Weak TLS Configuration",
    "severity": "HIGH",
    "remediation": "Upgrade to TLS 1.3"
  }
}
```

### POST /api/v1/ai/summarize/{session_id}

Generate an executive summary for a scan session. **Requires Pro tier or above.**

### POST /api/v1/ai/query

Ask a natural-language question with optional scan context.

**Body:**
```json
{
  "question": "What is the most critical finding and why?",
  "context": {
    "findings": [...]
  }
}
```

### GET /api/v1/ai/config

Get current AI configuration (API keys are masked).

### POST /api/v1/ai/config

Save AI configuration and hot-reload the engine.

**Body:**
```json
{
  "backend": "ollama",
  "ollama_url": "http://localhost:11434",
  "ollama_model": "llama3.2"
}
```

Supported backend values: `ollama`, `anthropic`, `openai`, `stepfun`, `gemini`, `custom`, `auto`

### POST /api/v1/ai/test

Test the AI backend connection. Returns success/failure with response preview.

---

## License

### GET /api/v1/license

Get current license information and tier limits.

**Response:**
```json
{
  "tier": "community",
  "label": "Community",
  "limits": {
    "scanners": ["network", "vulnerability", "web", "ssl", "windows", "linux", "compliance"],
    "scan_depths": ["quick", "standard"],
    "max_targets_per_scan": 16,
    "ai_queries_per_day": 10,
    "export_formats": ["csv", "json"],
    "scheduled_scans": false,
    "max_users": 1
  },
  "license": {
    "tier": "community",
    "organization": "",
    "expires": "",
    "license_id": "",
    "format_version": 0,
    "valid": true
  }
}
```

### POST /api/v1/license/activate

Activate a license by providing a signed license JSON payload.

**Body:** The complete signed license JSON from the license admin tool.

```json
{
  "format_version": 2,
  "license_id": "DJ-2026-0001",
  "tier": "pro",
  "organization": "Acme Corp",
  "expires": "2027-01-15T00:00:00Z",
  "signatures": {
    "classical": "<base64>",
    "pqc": "<base64>"
  }
}
```

**Response:**
```json
{
  "activated": true,
  "tier": "pro",
  "label": "Pro",
  "organization": "Acme Corp",
  "expires": "2027-01-15T00:00:00Z"
}
```

---

## Discovery

### POST /api/v1/discovery/scan

Run a network discovery scan.

**Body:**
```json
{
  "cidr": "10.0.1.0/24",
  "methods": ["arp", "icmp", "tcp"]
}
```

### GET /api/v1/discovery/hosts

List discovered hosts.

**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `status` | string | Filter by status |
| `os` | string | Filter by OS guess |

---

## Scanners

### GET /api/v1/scanners

List all available scanners with metadata (ID, name, description, supported depths).

---

## Agents

### POST /api/v1/agents/checkin

Remote agent check-in. Agents report scan results which are ingested into the evidence database.

**Body:**
```json
{
  "agent_id": "agent-01",
  "hostname": "remote-scanner",
  "ip_address": "10.0.2.100",
  "results": {
    "session_id": "sess-abc123",
    "findings": [...]
  }
}
```

### GET /api/v1/agents

List connected agents.

---

## Audit

### GET /api/v1/audit

Get audit log entries.

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int | 100 | Maximum entries |
| `action` | string | -- | Filter by action type |
| `actor` | string | -- | Filter by actor |
| `since` | string | -- | ISO 8601 timestamp |

---

## Network

### GET /api/v1/network/local

Get local network information for auto-populating scan targets. Returns hostname, interfaces with IPs and subnets, suggested targets, and known assets from inventory.

---

## Maintenance

### POST /api/v1/maintenance/purge-scans

Purge old scan data.

**Body:**
```json
{
  "older_than_days": 30
}
```

### POST /api/v1/maintenance/purge-notifications

Purge old notification history.

### POST /api/v1/maintenance/purge-audit

Purge old audit log entries (default: 90 days).

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": true,
  "message": "Description of the error"
}
```

| Status Code | Meaning |
|---|---|
| 400 | Bad request (missing or invalid parameters) |
| 401 | Unauthorized (missing or invalid API key) |
| 403 | Forbidden (tier limit exceeded -- includes `upgrade_required` and `feature` fields) |
| 404 | Resource not found |
| 500 | Internal server error |
| 503 | Module not available (the required backend module is not loaded) |
