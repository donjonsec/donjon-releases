# Donjon Platform v7.0 - API Reference

REST API served at `http://localhost:8443/api/v1/`. All endpoints return JSON unless otherwise noted. The dashboard is served at `GET /`.

---

## Authentication

All endpoints except `/`, `/api/v1/health`, and `/api/v1/legal/eula` require an API key.

**Passing the key:** Include an `X-API-Key` header with every request. Query-parameter authentication is not supported (prevents key leakage in logs and referer headers).

```bash
curl -H "X-API-Key: donjon_abc123..." http://localhost:8443/api/v1/stats
```

**Key sources:**

| Method | Details |
|---|---|
| Environment variable | `DONJON_API_KEYS=key1,key2` (comma-separated) |
| Admin keys | `DONJON_ADMIN_KEYS=admin_key` (required for destructive operations) |
| Auto-generated | If no keys are configured, one is printed to stderr on first start |
| CLI generation | `python web/auth.py` generates a key |

**Key format:** `donjon_<48 hex chars>` (24 random bytes).

**Admin paths** (require `DONJON_ADMIN_KEYS`):
- `POST /api/v1/maintenance/purge-scans`
- `POST /api/v1/maintenance/purge-audit`
- `POST /api/v1/maintenance/purge-notifications`
- `POST /api/v1/auth/rotate`
- `POST /api/v1/agents/register`

---

## Error Format

All errors return a consistent JSON structure:

```json
{
  "error": true,
  "message": "Description of what went wrong"
}
```

**Tier-gated errors** include additional fields:

```json
{
  "error": true,
  "message": "Scheduled scans require a Pro license...",
  "upgrade_required": "pro",
  "feature": "scheduled_scans"
}
```

**HTTP status codes:**

| Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (missing/invalid parameters) |
| 401 | Unauthorized (missing or invalid API key) |
| 403 | Forbidden (tier restriction or insufficient privileges) |
| 404 | Not found |
| 413 | Request entity too large (max 10 MB) |
| 500 | Internal server error |
| 503 | Module not available |

---

## Pagination

List endpoints accept `limit` as a query parameter:

```
GET /api/v1/scans?limit=20
GET /api/v1/audit?limit=100&since=2026-01-01T00:00:00Z
```

Default limits vary by endpoint (typically 50-100). Responses include a `count` field with the number of items returned.

---

## Health

### GET /api/v1/health

Check server status and module availability. **No auth required.**

```bash
curl http://localhost:8443/api/v1/health
```

**Response:**

```json
{
  "status": "healthy",
  "version": "7.0",
  "uptime_seconds": 3600.12,
  "timestamp": "2026-03-16T14:30:00+00:00",
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

Aggregate statistics across all modules.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/stats
```

**Response:**

```json
{
  "assets": { "total": 24, "active": 20, "by_os": {} },
  "sessions_total": 15,
  "open_findings": 47,
  "findings_by_severity": { "CRITICAL": 2, "HIGH": 8, "MEDIUM": 15, "LOW": 12, "INFO": 10 },
  "remediation": { "open": 12, "closed": 35, "overdue": 3 },
  "risks": { "total": 8, "high": 2, "medium": 4, "low": 2 },
  "agents": { "connected": 2, "agent_ids": ["agent-01", "agent-02"] }
}
```

---

## Assets

### GET /api/v1/assets

List assets with optional filters.

| Parameter | Type | Description |
|---|---|---|
| `business_unit` | query | Filter by business unit |
| `os_type` | query | Filter by OS type |
| `status` | query | Filter by status (default: `active`) |

```bash
curl -H "X-API-Key: KEY" "http://localhost:8443/api/v1/assets?os_type=linux"
```

**Response:** `{"count": N, "assets": [...]}`

### POST /api/v1/assets

Create an asset.

```bash
curl -X POST http://localhost:8443/api/v1/assets \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "hostname": "webserver-01",
    "ip_address": "10.0.1.10",
    "os_type": "linux",
    "business_unit": "engineering",
    "criticality": "high"
  }'
```

**Response:** `{"asset_id": "asset_abc123"}` (201)

### GET /api/v1/assets/\<id\>

Get a single asset by ID.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/assets/asset_abc123
```

### PUT /api/v1/assets/\<id\>

Update an asset.

```bash
curl -X PUT http://localhost:8443/api/v1/assets/asset_abc123 \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"criticality": "critical", "notes": "Production database server"}'
```

**Response:** `{"updated": true, "asset_id": "asset_abc123"}`

---

## Scans

### POST /api/v1/scans

Start a new scan session. **Community tier:** max 16 targets, no deep scans.

```bash
curl -X POST http://localhost:8443/api/v1/scans \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "scan_type": "standard",
    "targets": ["192.168.1.0/24", "10.0.0.5"],
    "metadata": {
      "scanner": "network",
      "depth": "standard",
      "description": "Weekly network scan"
    }
  }'
```

**Response:** `{"session_id": "SESSION-20260316-143022", "status": "running"}` (201)

### GET /api/v1/scans

List scan sessions.

| Parameter | Type | Description |
|---|---|---|
| `limit` | query | Max results (default: 50) |

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/scans?limit=10
```

**Response:** `{"count": N, "sessions": [...]}`

### GET /api/v1/scans/\<session_id\>

Get scan session summary.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/scans/SESSION-20260316-143022
```

### GET /api/v1/scans/\<session_id\>/findings

Get all findings for a scan session.

```bash
curl -H "X-API-Key: KEY" \
  http://localhost:8443/api/v1/scans/SESSION-20260316-143022/findings
```

**Response:** `{"count": N, "findings": [...]}`

### GET /api/v1/scans/\<session_id\>/export

Export scan findings as CSV or JSON.

| Parameter | Type | Description |
|---|---|---|
| `format` | query | `json` (default) or `csv` |

```bash
curl -H "X-API-Key: KEY" \
  "http://localhost:8443/api/v1/scans/SESSION_ID/export?format=csv"
```

---

## Findings

### GET /api/v1/findings

List findings across all sessions.

| Parameter | Type | Description |
|---|---|---|
| `severity` | query | Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) |
| `session_id` | query | Filter by scan session |
| `status` | query | Filter by status (default: `open`) |
| `asset` | query | Filter by asset (substring match) |

```bash
curl -H "X-API-Key: KEY" \
  "http://localhost:8443/api/v1/findings?severity=CRITICAL&status=open"
```

**Response:**

```json
{
  "count": 2,
  "findings": [
    {
      "finding_id": "f_001",
      "severity": "CRITICAL",
      "title": "SQL Injection in login endpoint",
      "description": "...",
      "affected_asset": "10.0.0.5",
      "cvss_score": 9.8,
      "cve_ids": ["CVE-2024-12345"],
      "kev_status": "true",
      "epss_score": 0.85,
      "quality_of_detection": 90,
      "remediation": "Parameterize all SQL queries...",
      "status": "open",
      "timestamp": "2026-03-16T14:30:00+00:00"
    }
  ]
}
```

### GET /api/v1/findings/\<id\>

Get a single finding by ID.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/findings/f_001
```

---

## Remediation

### GET /api/v1/remediation

List remediation items.

| Parameter | Type | Description |
|---|---|---|
| `status` | query | Filter by status |
| `assigned_to` | query | Filter by assignee |
| `overdue` | query | `true` to show only overdue items |

```bash
curl -H "X-API-Key: KEY" \
  "http://localhost:8443/api/v1/remediation?overdue=true"
```

**Response:** `{"count": N, "items": [...]}`

### POST /api/v1/remediation

Create a remediation item.

```bash
curl -X POST http://localhost:8443/api/v1/remediation \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "finding_id": "f_001",
    "title": "Patch OpenSSH to 9.x",
    "severity": "high",
    "assigned_to": "ops-team",
    "due_date": "2026-04-01"
  }'
```

**Response:** `{"item_id": "rem_001"}` (201)

### PUT /api/v1/remediation/\<id\>

Update remediation status or assignment.

```bash
curl -X PUT http://localhost:8443/api/v1/remediation/rem_001 \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "status": "completed",
    "notes": "Patched to OpenSSH 9.6",
    "changed_by": "admin"
  }'
```

### GET /api/v1/remediation/metrics

Remediation SLA metrics and statistics.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/remediation/metrics
```

**Response:**

```json
{
  "sla": { "critical_met": 95.0, "high_met": 88.0 },
  "metrics": { "mttr_days": 12.5, "closure_rate": 0.82 },
  "statistics": { "open": 12, "closed": 35, "overdue": 3 }
}
```

---

## Risk Register

### GET /api/v1/risks

List risks with optional filters.

| Parameter | Type | Description |
|---|---|---|
| `category` | query | Filter by category (technical, operational, compliance) |
| `status` | query | Filter by status |
| `business_unit` | query | Filter by business unit |
| `min_score` | query | Minimum risk score |

```bash
curl -H "X-API-Key: KEY" "http://localhost:8443/api/v1/risks?category=technical"
```

### POST /api/v1/risks

Create a risk entry.

```bash
curl -X POST http://localhost:8443/api/v1/risks \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "title": "Unpatched production database",
    "category": "technical",
    "likelihood": 4,
    "impact": 5,
    "business_unit": "engineering",
    "owner": "cto"
  }'
```

**Response:** `{"risk_id": "risk_001"}` (201)

### GET /api/v1/risks/posture

Get overall risk posture score.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/risks/posture
```

### GET /api/v1/risks/matrix

Get the risk matrix (likelihood x impact grid).

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/risks/matrix
```

**Response:** `{"matrix": [[...], ...]}`

---

## Exceptions

### GET /api/v1/exceptions

List finding exceptions (accepted risks, false positives).

| Parameter | Type | Description |
|---|---|---|
| `status` | query | `pending`, `active`, `expiring`, or omit for all |

```bash
curl -H "X-API-Key: KEY" "http://localhost:8443/api/v1/exceptions?status=pending"
```

### POST /api/v1/exceptions

Create an exception request.

```bash
curl -X POST http://localhost:8443/api/v1/exceptions \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "finding_type": "weak_cipher",
    "title_pattern": "TLS 1.0 on legacy*",
    "exception_type": "accepted_risk",
    "justification": "Legacy system decommission scheduled Q2 2026",
    "expires_at": "2026-06-30"
  }'
```

### PUT /api/v1/exceptions/\<id\>/approve

Approve a pending exception.

```bash
curl -X PUT http://localhost:8443/api/v1/exceptions/exc_001/approve \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"approved_by": "ciso", "notes": "Approved with compensating control"}'
```

---

## Compliance & Reports

### GET /api/v1/reports/executive

Generate an executive summary report (HTML).

| Parameter | Type | Description |
|---|---|---|
| `days` | query | Lookback period in days (default: 30) |

```bash
curl -H "X-API-Key: KEY" "http://localhost:8443/api/v1/reports/executive?days=90"
```

### GET /api/v1/reports/compliance/\<framework\>

Generate a compliance report for a specific framework (HTML).

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/NIST-800-53
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/HIPAA
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/reports/compliance/PCI-DSS-v4
```

---

## Export

### POST /api/v1/export

Export scan data in multiple formats. **Community tier:** CSV and JSON only. **Pro+:** all formats.

```bash
curl -X POST http://localhost:8443/api/v1/export \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "session_id": "SESSION-20260316-143022",
    "formats": ["json", "csv", "html", "pdf", "sarif", "xml"]
  }'
```

**Response:**

```json
{
  "exported": {
    "json": "data/reports/SESSION-20260316-143022.json",
    "csv": "data/reports/SESSION-20260316-143022.csv",
    "html": "data/reports/SESSION-20260316-143022.html",
    "pdf": "data/reports/SESSION-20260316-143022.pdf",
    "sarif": "data/reports/SESSION-20260316-143022.sarif",
    "xml": "data/reports/SESSION-20260316-143022.xml"
  }
}
```

---

## Schedules (Pro+)

### GET /api/v1/schedules

List all scheduled scans.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/schedules
```

### POST /api/v1/schedules

Create a scheduled scan. **Requires Pro tier or above.**

```bash
curl -X POST http://localhost:8443/api/v1/schedules \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "name": "Weekly Network Scan",
    "scanner_type": "network",
    "cron_expression": "0 2 * * 1",
    "targets": ["192.168.1.0/24"],
    "scan_type": "standard",
    "description": "Monday 2AM network scan",
    "created_by": "admin"
  }'
```

**Response:** `{"schedule_id": "sched_001"}` (201)

### GET /api/v1/schedules/\<id\>

Get a specific schedule.

### PUT /api/v1/schedules/\<id\>

Update a schedule.

```bash
curl -X PUT http://localhost:8443/api/v1/schedules/sched_001 \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"cron_expression": "0 3 * * 1", "scan_type": "deep"}'
```

### DELETE /api/v1/schedules/\<id\>

Delete a schedule.

```bash
curl -X DELETE -H "X-API-Key: KEY" \
  http://localhost:8443/api/v1/schedules/sched_001
```

### GET /api/v1/schedules/\<id\>/history

Get execution history for a schedule.

| Parameter | Type | Description |
|---|---|---|
| `limit` | query | Max results (default: 20) |

---

## Notifications

### GET /api/v1/notifications/channels

List configured notification channels.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/notifications/channels
```

### POST /api/v1/notifications/channels

Create a notification channel. **Community tier:** email and webhook only. **Pro+:** all types.

```bash
curl -X POST http://localhost:8443/api/v1/notifications/channels \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "name": "Security Team Slack",
    "channel_type": "webhook",
    "config": {
      "webhook_url": "https://hooks.slack.com/services/T.../B.../xxx"
    }
  }'
```

**Response:** `{"channel_id": "ch_001"}` (201)

### PUT /api/v1/notifications/channels/\<id\>

Update a notification channel.

### DELETE /api/v1/notifications/channels/\<id\>

Delete a notification channel.

### POST /api/v1/notifications/test

Send a test notification.

```bash
curl -X POST http://localhost:8443/api/v1/notifications/test \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"channel_id": "ch_001"}'
```

### GET /api/v1/notifications/history

Notification delivery history.

| Parameter | Type | Description |
|---|---|---|
| `limit` | query | Max results (default: 50) |
| `event_type` | query | Filter by event type |
| `status` | query | Filter by delivery status |

### GET /api/v1/notifications/stats

Notification delivery statistics.

---

## AI Engine

### POST /api/v1/ai/analyze

Analyze a single finding with AI. **Community tier:** 10 queries/day.

```bash
curl -X POST http://localhost:8443/api/v1/ai/analyze \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "finding": {
      "title": "SQL Injection in login",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "description": "User input passed directly to SQL query..."
    }
  }'
```

### POST /api/v1/ai/triage

Triage a batch of findings by priority.

```bash
curl -X POST http://localhost:8443/api/v1/ai/triage \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"findings": [...]}'
```

### POST /api/v1/ai/remediate

Generate remediation guidance for a finding.

```bash
curl -X POST http://localhost:8443/api/v1/ai/remediate \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"finding": {...}}'
```

### POST /api/v1/ai/summarize/\<session_id\>

Generate an AI summary of a scan session. **Pro+ only.**

```bash
curl -X POST -H "X-API-Key: KEY" \
  http://localhost:8443/api/v1/ai/summarize/SESSION-20260316-143022
```

### POST /api/v1/ai/query

Ask a free-form security question.

```bash
curl -X POST http://localhost:8443/api/v1/ai/query \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"question": "What is the risk of running TLS 1.0?", "context": "PCI-DSS environment"}'
```

**Response:** `{"answer": "..."}`

### GET /api/v1/ai/status

Check AI engine availability and backend. **No auth required for status check (counts against no quota).**

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/ai/status
```

**Response:**

```json
{
  "available": true,
  "backend": "ollama",
  "model": "qwen2.5-coder:14b",
  "message": "AI engine ready (ollama)"
}
```

### GET /api/v1/ai/config

Get current AI configuration.

### POST /api/v1/ai/config

Update AI configuration.

```bash
curl -X POST http://localhost:8443/api/v1/ai/config \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"backend": "ollama", "ollama_url": "http://localhost:11434", "model": "qwen2.5-coder:14b"}'
```

### POST /api/v1/ai/test

Test AI backend connection.

```bash
curl -X POST -H "X-API-Key: KEY" http://localhost:8443/api/v1/ai/test
```

---

## License

### GET /api/v1/license

Get current license tier and limits.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/license
```

**Response:**

```json
{
  "tier": "community",
  "label": "Community (Free)",
  "limits": {
    "max_targets_per_scan": 16,
    "scan_depths": ["quick", "standard"],
    "export_formats": ["csv", "json"],
    "ai_queries_per_day": 10,
    "compliance_frameworks": 3,
    "scheduled_scans": false
  },
  "license": null
}
```

### POST /api/v1/license/activate

Activate a Pro/Enterprise/Managed license.

```bash
curl -X POST http://localhost:8443/api/v1/license/activate \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d @data/license.json
```

The license JSON must contain dual ML-DSA-65 + Ed25519 signatures from the Donjon license admin tool.

**Response:**

```json
{
  "activated": true,
  "tier": "pro",
  "label": "Professional",
  "organization": "Acme Corp",
  "expires": "2027-03-16"
}
```

---

## Scanners (Metadata)

### GET /api/v1/scanners

List all available scanners with descriptions and scan depths.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/scanners
```

---

## Discovery

### POST /api/v1/discovery/scan

Run a network discovery scan.

```bash
curl -X POST http://localhost:8443/api/v1/discovery/scan \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{"cidr": "192.168.1.0/24", "methods": ["arp", "icmp", "tcp"]}'
```

**Response:** `{"cidr": "192.168.1.0/24", "hosts_found": 12, "hosts": [...]}`

### GET /api/v1/discovery/hosts

List previously discovered hosts.

| Parameter | Type | Description |
|---|---|---|
| `status` | query | Filter by status |
| `os` | query | Filter by OS guess |

---

## Network Info

### GET /api/v1/network/local

Get local network information for auto-populating scan targets.

```bash
curl -H "X-API-Key: KEY" http://localhost:8443/api/v1/network/local
```

**Response:**

```json
{
  "hostname": "scanner-01",
  "interfaces": [
    {"ip": "192.168.1.50", "netmask": "255.255.255.0", "subnet": "192.168.1.0/24", "interface": "eth0"}
  ],
  "suggested_targets": ["192.168.1.50", "192.168.1.0/24"],
  "known_assets": [...]
}
```

---

## Agents

### POST /api/v1/agents/register

Register a remote scanning agent and receive its authentication token. **Admin key required.**

```bash
curl -X POST http://localhost:8443/api/v1/agents/register \
  -H "X-API-Key: ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"agent_id": "agent-dmz-01"}'
```

**Response:**

```json
{
  "agent_id": "agent-dmz-01",
  "token": "donjon_agent_abc123...",
  "message": "Store this token securely. It will not be shown again."
}
```

### POST /api/v1/agents/checkin

Agent check-in with optional scan results.

```bash
curl -X POST http://localhost:8443/api/v1/agents/checkin \
  -H "X-API-Key: KEY" -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-dmz-01",
    "token": "donjon_agent_abc123...",
    "hostname": "dmz-scanner",
    "ip_address": "10.0.0.50",
    "results": {
      "session_id": "SESSION_ID",
      "findings": [...]
    }
  }'
```

### GET /api/v1/agents

List connected agents.

---

## Auth Management

### POST /api/v1/auth/rotate

Rotate an API key with a grace period. **Admin key required.**

```bash
curl -X POST http://localhost:8443/api/v1/auth/rotate \
  -H "X-API-Key: ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"api_key": "donjon_old_key_here", "grace_seconds": 3600}'
```

**Response:**

```json
{
  "new_key": "donjon_new_key_here",
  "old_key_masked": "donj...here",
  "grace_expires": 1710601200.0,
  "grace_seconds": 3600,
  "expired_keys_cleaned": 0
}
```

---

## Audit Log

### GET /api/v1/audit

Query the audit trail.

| Parameter | Type | Description |
|---|---|---|
| `limit` | query | Max results (default: 100) |
| `action` | query | Filter by action type |
| `actor` | query | Filter by actor |
| `since` | query | ISO 8601 timestamp |

```bash
curl -H "X-API-Key: KEY" \
  "http://localhost:8443/api/v1/audit?action=scan_started&limit=20"
```

---

## Maintenance (Admin)

All maintenance endpoints require `DONJON_ADMIN_KEYS`.

### POST /api/v1/maintenance/purge-scans

Purge scan data older than N days.

```bash
curl -X POST http://localhost:8443/api/v1/maintenance/purge-scans \
  -H "X-API-Key: ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"older_than_days": 90}'
```

### POST /api/v1/maintenance/purge-notifications

Purge notification history older than N days.

```bash
curl -X POST http://localhost:8443/api/v1/maintenance/purge-notifications \
  -H "X-API-Key: ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"older_than_days": 30}'
```

### POST /api/v1/maintenance/purge-audit

Purge audit log entries older than N days (default: 90).

```bash
curl -X POST http://localhost:8443/api/v1/maintenance/purge-audit \
  -H "X-API-Key: ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"older_than_days": 365}'
```

---

## Legal

### GET /api/v1/legal/eula

Get the EULA text and acceptance status. **No auth required.**

```bash
curl http://localhost:8443/api/v1/legal/eula
```

---

## Enterprise Features (Enterprise Tier)

### RBAC (Role-Based Access Control)

Enterprise tier enables RBAC with roles, permissions, and user assignments. Managed through the `lib/rbac.py` module. Roles are scoped to actions (read, write, delete) on resources (scans, assets, reports).

### SSO (Single Sign-On)

Enterprise tier supports SAML-based SSO integration via `lib/sso.py`.

### Multi-Tenant

Enterprise tier enables tenant isolation with separate data paths per tenant. Each tenant gets isolated storage, RBAC roles, and data boundaries.

### Audit Trail

Enterprise audit trail records all user actions with actor, action, resource, timestamp, and detail fields. Supports CSV/JSON export for compliance evidence.

---

## MSSP Features (Managed Tier)

### Client Provisioning

MSSP tier supports multi-client management with isolated environments per client.

### Rollup Reporting

Generate aggregated reports across all clients or a specific subset:

- Cross-client metric comparison
- Delta analysis between clients
- Aggregated risk posture

### Sub-Licensing

MSSP operators can provision sub-licenses for their managed clients.

---

## PowerShell Examples (Windows)

```powershell
# Health check
Invoke-RestMethod -Uri http://localhost:8443/api/v1/health

# Start a scan
$headers = @{"X-API-Key" = "YOUR_KEY"; "Content-Type" = "application/json"}
$body = '{"scan_type":"quick","targets":["192.168.1.0/24"]}'
Invoke-RestMethod -Uri http://localhost:8443/api/v1/scans -Method POST -Headers $headers -Body $body

# Get findings
Invoke-RestMethod -Uri http://localhost:8443/api/v1/findings -Headers @{"X-API-Key" = "YOUR_KEY"}
```
