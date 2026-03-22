#!/usr/bin/env bash
# Donjon Platform — Weekly Intel Update & Bundle Builder
#
# Runs on CT 100 via cron. Pulls incremental updates from all authoritative
# sources, builds a differential bundle, and publishes to Forgejo releases.
#
# Cron entry (Sundays at 02:00 UTC):
#   0 2 * * 0 /opt/donjon-platform/tools/weekly-intel-update.sh >> /var/log/donjon-intel-update.log 2>&1
#
# Sources (all authoritative, auditable):
#   NVD CVEs         — NIST (US Gov)           — https://services.nvd.nist.gov
#   CISA KEV         — CISA (US Gov)           — https://www.cisa.gov
#   EPSS Scores      — FIRST.org               — https://api.first.org
#   ExploitDB        — OffSec                  — https://gitlab.com/exploit-database
#   OSV              — Google OSS              — https://api.osv.dev
#   GitHub Advisories — GitHub/MITRE           — https://api.github.com
#   CISA Alerts      — CISA (US Gov)           — https://www.cisa.gov
#   MITRE ATT&CK     — MITRE Corp             — https://github.com/mitre/cti
#   URLhaus          — abuse.ch                — https://urlhaus-api.abuse.ch
#   ThreatFox        — abuse.ch                — https://threatfox-api.abuse.ch
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_PREFIX="[$(date -u +%Y-%m-%dT%H:%M:%SZ)]"

log() { echo "$LOG_PREFIX $1"; }
die() { log "ERROR: $1" >&2; exit 1; }

# Configuration
FORGEJO_URL="${FORGEJO_URL:-http://192.168.1.116:3000}"
FORGEJO_ORG="${FORGEJO_ORG:-donjonsec}"
FORGEJO_REPO="${FORGEJO_REPO:-donjon-platform}"
FORGEJO_TOKEN_FILE="${FORGEJO_TOKEN_FILE:-/opt/darkfactory/data/.forgejo-token}"
BUNDLE_DIR="${PROJECT_ROOT}/data/bundles"
DATA_DIR="${PROJECT_ROOT}/data"

# Load NVD API key
if [ -f /etc/environment ]; then
    source /etc/environment 2>/dev/null || true
fi

cd "$PROJECT_ROOT"

log "=== Donjon Intel Weekly Update ==="
log "NVD API Key: ${NVD_API_KEY:+ACTIVE (50 req/30s)}${NVD_API_KEY:-MISSING (slow mode)}"

# Step 1: Incremental NVD update
log "--- Step 1: NVD Incremental Update ---"
python3 bin/update-intel.py --incremental 2>&1 | while read -r line; do log "  NVD: $line"; done || true

# Step 2: CISA KEV refresh
log "--- Step 2: CISA KEV Refresh ---"
python3 bin/update-intel.py --kev-only 2>&1 | while read -r line; do log "  KEV: $line"; done || true

# Step 3: EPSS scores
log "--- Step 3: EPSS Score Refresh ---"
python3 bin/update-intel.py --epss-only 2>&1 | while read -r line; do log "  EPSS: $line"; done || true

# Step 4: Intel feeds (ExploitDB, OSV, GitHub, CISA Alerts, MITRE, abuse.ch)
log "--- Step 4: Intel Feed Update ---"
python3 bin/update-intel.py --feeds-only 2>&1 | while read -r line; do log "  FEEDS: $line"; done || true

# Step 5: Build bundle
log "--- Step 5: Build Bundle ---"
PREV_MANIFEST="${DATA_DIR}/last-bundle-manifest.json"
if [ -f "$PREV_MANIFEST" ]; then
    log "Previous manifest found — building differential bundle"
    python3 tools/build-intel-bundle.py --differential --data-dir "$DATA_DIR" --output-dir "$BUNDLE_DIR" 2>&1 | while read -r line; do log "  BUNDLE: $line"; done
    BUNDLE_TYPE="differential"
else
    log "No previous manifest — building full bundle"
    python3 tools/build-intel-bundle.py --full --data-dir "$DATA_DIR" --output-dir "$BUNDLE_DIR" 2>&1 | while read -r line; do log "  BUNDLE: $line"; done
    BUNDLE_TYPE="full"
fi

# Find the latest bundle file
LATEST_BUNDLE=$(ls -t "$BUNDLE_DIR"/intel-*.tar.gz 2>/dev/null | head -1)
LATEST_MANIFEST=$(ls -t "$BUNDLE_DIR"/intel-manifest-*.json 2>/dev/null | head -1)

if [ -z "$LATEST_BUNDLE" ]; then
    log "WARNING: No bundle produced (no changes?)"
    exit 0
fi

BUNDLE_SIZE=$(du -h "$LATEST_BUNDLE" | cut -f1)
DATE_TAG=$(date -u +%Y-%m-%d)
log "Bundle: $LATEST_BUNDLE ($BUNDLE_SIZE)"

# Save manifest as baseline for next differential
cp "$LATEST_MANIFEST" "$PREV_MANIFEST" 2>/dev/null || true

# Step 6: Publish to Forgejo releases
log "--- Step 6: Publish to Forgejo ---"
if [ ! -f "$FORGEJO_TOKEN_FILE" ]; then
    log "WARNING: No Forgejo token at $FORGEJO_TOKEN_FILE — skipping publish"
    log "  Create token: echo 'your-pat-here' > $FORGEJO_TOKEN_FILE"
    exit 0
fi

FORGEJO_TOKEN=$(cat "$FORGEJO_TOKEN_FILE" | tr -d '[:space:]')
RELEASE_TAG="intel-${DATE_TAG}"
RELEASE_NAME="Intel Bundle ${DATE_TAG} (${BUNDLE_TYPE})"

# Read manifest for release body
RECORDS=$(python3 -c "import json; m=json.load(open('$LATEST_MANIFEST')); print(m['totals']['records'])" 2>/dev/null || echo "?")
SOURCES=$(python3 -c "
import json
m = json.load(open('$LATEST_MANIFEST'))
for sid, info in m.get('sources', {}).items():
    if info['records'] > 0:
        print(f\"- **{info['authority']}**: {info['records']:,} records ({info['license']})\")
" 2>/dev/null || echo "- See manifest for details")

RELEASE_BODY="## Intel Data Bundle — ${DATE_TAG}

Type: **${BUNDLE_TYPE}**
Total records: **${RECORDS}**

### Sources (all authoritative, auditable)

${SOURCES}

### Verification

\`\`\`bash
python tools/build-intel-bundle.py --verify ${LATEST_BUNDLE##*/}
\`\`\`

### Import (air-gap)

\`\`\`bash
python tools/build-intel-bundle.py --import ${LATEST_BUNDLE##*/}
\`\`\`
"

# Create release
RESPONSE=$(curl -s -X POST "${FORGEJO_URL}/api/v1/repos/${FORGEJO_ORG}/${FORGEJO_REPO}/releases" \
    -H "Authorization: token ${FORGEJO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c "
import json, sys
print(json.dumps({
    'tag_name': '${RELEASE_TAG}',
    'name': '${RELEASE_NAME}',
    'body': '''${RELEASE_BODY}''',
    'draft': False,
    'prerelease': False
}))
")" 2>/dev/null)

RELEASE_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

if [ -z "$RELEASE_ID" ]; then
    log "WARNING: Could not create Forgejo release — response: $RESPONSE"
    exit 0
fi

log "Release created: ID=$RELEASE_ID, tag=$RELEASE_TAG"

# Upload bundle as release asset
curl -s -X POST "${FORGEJO_URL}/api/v1/repos/${FORGEJO_ORG}/${FORGEJO_REPO}/releases/${RELEASE_ID}/assets" \
    -H "Authorization: token ${FORGEJO_TOKEN}" \
    -F "attachment=@${LATEST_BUNDLE}" \
    > /dev/null 2>&1

# Upload manifest as release asset
if [ -n "$LATEST_MANIFEST" ]; then
    curl -s -X POST "${FORGEJO_URL}/api/v1/repos/${FORGEJO_ORG}/${FORGEJO_REPO}/releases/${RELEASE_ID}/assets" \
        -H "Authorization: token ${FORGEJO_TOKEN}" \
        -F "attachment=@${LATEST_MANIFEST}" \
        > /dev/null 2>&1
fi

log "Assets uploaded to release $RELEASE_TAG"
log "=== Weekly Intel Update Complete ==="
