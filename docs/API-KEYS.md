# Donjon Platform - API Keys & Secrets Reference

All API keys are configured via **environment variables**. No keys are hardcoded or stored in config files.

---

## GitHub Repository Secrets

Set these in **Settings > Secrets and variables > Actions** for CI/CD workflows:

| Secret Name | Required By | Purpose | How to Get |
|-------------|-------------|---------|------------|
| `NVD_API_KEY` | `update-intel-db.yml` | NVD CVE database queries (increases rate limit 5 -> 50 req/30s) | Free: https://nvd.nist.gov/developers/request-an-api-key |
| `ABUSECH_API_KEY` | `update-intel-db.yml` | URLhaus + ThreatFox threat intel feeds | Free: https://auth.abuse.ch/ |
| `GITHUB_TOKEN` | All workflows | GitHub API access (auto-provided by Actions) | Automatic |

---

## All Environment Variables

### Intelligence & Scanning (set these for full functionality)

| Variable | Used In | Purpose | Required? |
|----------|---------|---------|-----------|
| `NVD_API_KEY` | `lib/vuln_database.py`, `bin/update-intel.py` | NVD API 2.0 - CVE lookups. Without it: 5 req/30s (6s delay). With it: 50 req/30s (0.7s delay). | Recommended |
| `GITHUB_TOKEN` | `lib/intel_feeds.py`, `bin/update-frameworks.py` | GitHub Advisories API + framework sync. Without it: 60 req/hr. With it: 5000 req/hr. | Recommended |
| `ABUSECH_API_KEY` | `lib/intel_feeds.py` | abuse.ch URLhaus + ThreatFox feeds. Without it: feeds are skipped entirely. | Required for abuse.ch |

### AI Backends (set ONE of these for AI-powered analysis)

| Variable | Used In | Purpose | Required? |
|----------|---------|---------|-----------|
| `OPENAI_API_KEY` | `lib/ai_engine.py` | OpenAI API (GPT-4, etc.) | No (template fallback) |
| `ANTHROPIC_API_KEY` | `lib/ai_engine.py` | Anthropic API (Claude) | No (template fallback) |
| `GEMINI_API_KEY` | `lib/ai_engine.py` | Google Gemini API | No (template fallback) |
| `STEPFUN_API_KEY` | `lib/ai_engine.py` | StepFun API | No (template fallback) |
| `OPENROUTER_API_KEY` | `lib/ai_engine.py` | OpenRouter API (multi-model) | No (template fallback) |

AI provider is selected in `config/active/config.yaml` under `ai.provider`. The template backend (rule-based, no API needed) is always available as fallback.

### Platform Infrastructure

| Variable | Used In | Purpose | Required? |
|----------|---------|---------|-----------|
| `DONJON_HOME` | `lib/paths.py` | Override platform root directory | No (auto-detected) |
| `DONJON_API_KEYS` | `web/auth.py`, `bin/start-server.py` | REST API authentication keys (comma-separated) | Required for API server |
| `DONJON_DB_BACKEND` | `lib/database.py`, `bin/migrate-db.py` | Database backend: `sqlite` (default) or `postgres` | No (defaults to sqlite) |
| `DONJON_DB_URL` | `lib/database.py`, `bin/migrate-db.py` | PostgreSQL connection URL | Only if using postgres |
| `NO_COLOR` | `lib/tui.py` | Disable ANSI colors in terminal output | No |

### CI/CD Detection (auto-set by CI platforms)

| Variable | Purpose |
|----------|---------|
| `CI` | Generic CI detection |
| `GITHUB_ACTIONS` | GitHub Actions |
| `GITLAB_CI` | GitLab CI |
| `JENKINS_URL` | Jenkins |
| `CIRCLECI` | CircleCI |
| `TF_BUILD` | Azure DevOps |
| `CODEBUILD_BUILD_ID` | AWS CodeBuild |
| `BUILDKITE` | Buildkite |

---

## Config File Credentials (stored in `config/active/config.yaml`)

These are **not** environment variables. They're stored in the config file and managed through the platform UI:

| Config Path | Purpose |
|-------------|---------|
| `notifications.slack.webhook_url` | Slack notification webhook |
| `notifications.teams.webhook_url` | Microsoft Teams webhook |
| `integrations.thehive.api_key` | TheHive SOAR integration |
| `integrations.wazuh.api_key` | Wazuh SIEM integration |
| `integrations.jira.url` + `.email` | Jira ticket creation |
| `integrations.servicenow.instance_url` | ServiceNow integration |
| `integrations.shodan.enabled` | Shodan (key via credential manager) |
| `integrations.censys.enabled` | Censys (key via credential manager) |

Shodan and Censys API keys are stored via the platform's credential manager (Settings > Manage Credentials), not in config files or environment variables.

---

## Quick Setup for New Repository

```bash
# Required for CI/CD intel feed workflow
gh secret set NVD_API_KEY --body "your-nvd-key"
gh secret set ABUSECH_API_KEY --body "your-abusech-key"

# Optional but recommended for local development
export NVD_API_KEY="your-nvd-key"
export GITHUB_TOKEN="your-github-pat"
export ABUSECH_API_KEY="your-abusech-key"

# Optional: AI backend (pick one)
export OPENAI_API_KEY="sk-..."
# or
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

Donjon Platform v7.0
February 2026
