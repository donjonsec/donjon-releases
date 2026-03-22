#!/usr/bin/env bash
# Donjon Platform v7.0 - Intel Database Sync
#
# Downloads the latest intel database bundle from GitHub Releases.
# Run this instead of re-crawling all APIs for hours.
#
# Usage:
#   bash bin/sync-intel-db.sh                    # Download all databases
#   bash bin/sync-intel-db.sh --feeds-only       # Only intel_feeds.db
#   bash bin/sync-intel-db.sh --nvd-only         # Only vuln_intel.db
#   bash bin/sync-intel-db.sh --check            # Show manifest only
#
# Requirements: curl or gh CLI

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Repository — supports both GitHub and Forgejo
# Set DONJON_REPO env var to override (e.g., "donjonsec/donjon-platform")
# Set DONJON_RELEASE_URL for Forgejo (e.g., "http://192.168.1.116:3000")
REPO="${DONJON_REPO:-DonjonSec/donjon-platform}"
RELEASE_TAG="intel-latest"
FORGEJO_URL="${DONJON_RELEASE_URL:-}"

# Colors (auto-disable if not a TTY)
if [ -t 1 ]; then
    GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'
    BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; BOLD=''; DIM=''; RESET=''
fi

banner() {
    echo ""
    echo -e "${BOLD}  ============================================================${RESET}"
    echo -e "${BOLD}   Donjon Platform v7.0 - Intel Database Sync${RESET}"
    echo -e "${BOLD}  ============================================================${RESET}"
    echo ""
}

die() { echo -e "${RED}ERROR: $1${RESET}" >&2; exit 1; }

download_file() {
    local filename="$1" dest="$2"
    echo -e "  Downloading ${BOLD}${filename}${RESET}..."

    # Try Forgejo first if configured
    if [[ -n "$FORGEJO_URL" ]] && command -v curl &>/dev/null; then
        local forgejo_release_url="${FORGEJO_URL}/api/v1/repos/${REPO}/releases/tags/${RELEASE_TAG}"
        local asset_url
        asset_url=$(curl -sf "$forgejo_release_url" 2>/dev/null | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
for asset in data.get('assets', []):
    if asset['name'] == '${filename}':
        print(asset['browser_download_url'])
        break
" 2>/dev/null || echo "")
        if [[ -n "$asset_url" ]]; then
            if curl -fsSL "$asset_url" -o "$dest" 2>/dev/null; then
                return 0
            fi
        fi
    fi

    # Fall back to GitHub (gh CLI)
    if command -v gh &>/dev/null; then
        local tmpdir
        tmpdir=$(mktemp -d)
        if gh release download "$RELEASE_TAG" --repo "$REPO" --pattern "$filename" --dir "$tmpdir" --clobber 2>/dev/null; then
            mv "$tmpdir/$filename" "$dest"
            rm -rf "$tmpdir"
            return 0
        fi
        rm -rf "$tmpdir"
    fi

    # Fall back to GitHub (curl)
    if command -v curl &>/dev/null; then
        if curl -fsSL "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${filename}" -o "$dest" 2>/dev/null; then
            return 0
        fi
    fi

    # Fall back to GitHub (wget)
    if command -v wget &>/dev/null; then
        if wget -q "https://github.com/${REPO}/releases/download/${RELEASE_TAG}/${filename}" -O "$dest" 2>/dev/null; then
            return 0
        fi
    fi

    echo -e "  ${YELLOW}Could not download ${filename}${RESET}"
    return 1
}

show_manifest() {
    local tmpfile
    tmpfile=$(mktemp)
    if download_file "manifest.json" "$tmpfile"; then
        echo -e "  ${GREEN}Latest release manifest:${RESET}"
        echo ""
        python3 -m json.tool "$tmpfile" 2>/dev/null || cat "$tmpfile"
        rm -f "$tmpfile"
    else
        rm -f "$tmpfile"
        die "Could not fetch manifest — no release found at ${REPO}@${RELEASE_TAG}"
    fi
}

sync_feeds() {
    mkdir -p "$PROJECT_ROOT/data"
    local dest="$PROJECT_ROOT/data/intel_feeds.db"

    if download_file "intel_feeds.db" "$dest"; then
        local size
        size=$(du -h "$dest" | cut -f1)
        echo -e "  ${GREEN}intel_feeds.db: ${size}${RESET}"
    else
        return 1
    fi
}

sync_nvd() {
    mkdir -p "$PROJECT_ROOT/data/vuln_db"
    local dest="$PROJECT_ROOT/data/vuln_db/vuln_intel.db"

    if download_file "vuln_intel.db" "$dest"; then
        local size
        size=$(du -h "$dest" | cut -f1)
        echo -e "  ${GREEN}vuln_intel.db: ${size}${RESET}"
    else
        return 1
    fi
}

sync_json() {
    mkdir -p "$PROJECT_ROOT/data/threat_intel"

    for f in cisa_kev.json epss_cache.json; do
        local dest="$PROJECT_ROOT/data/threat_intel/$f"
        if download_file "$f" "$dest"; then
            local size
            size=$(du -h "$dest" | cut -f1)
            echo -e "  ${GREEN}${f}: ${size}${RESET}"
        fi
    done
}

# --- Main ---

banner

MODE="${1:-all}"

case "$MODE" in
    --check)
        show_manifest
        ;;
    --feeds-only)
        echo "  Syncing intel feeds database..."
        echo ""
        sync_feeds
        ;;
    --nvd-only)
        echo "  Syncing NVD CVE database..."
        echo ""
        sync_nvd
        ;;
    --json-only)
        echo "  Syncing KEV + EPSS JSON files..."
        echo ""
        sync_json
        ;;
    all|--all|"")
        echo "  Syncing all intel databases..."
        echo ""
        ERRORS=0
        sync_feeds  || ((ERRORS++))
        sync_nvd    || ((ERRORS++))
        sync_json

        echo ""
        if [ "$ERRORS" -eq 0 ]; then
            echo -e "  ${GREEN}All databases synced successfully.${RESET}"
        else
            echo -e "  ${YELLOW}${ERRORS} database(s) not available — run bin/update-intel.py to build them.${RESET}"
        fi
        ;;
    *)
        echo "Usage: $0 [--all|--feeds-only|--nvd-only|--json-only|--check]"
        exit 2
        ;;
esac

echo ""
