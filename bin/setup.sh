#!/usr/bin/env bash
# ============================================================
# Donjon Platform v7.0 - Linux/macOS Setup
# Creates venv and installs dependencies.
# Mirror of setup-windows.bat for Unix systems.
# ============================================================

set -e

# Resolve DONJON_HOME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DONJON_HOME="$(dirname "$SCRIPT_DIR")"

echo ""
echo "  ============================================================"
echo "   Donjon Platform v7.0 - Setup"
echo "  ============================================================"
echo ""
echo "  Installation directory: $DONJON_HOME"
echo ""

# --- Find Python ---
PYTHON_CMD=""

if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    # Verify it's Python 3
    if python -c "import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)" 2>/dev/null; then
        PYTHON_CMD="python"
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "  [ERROR] Python 3 not found."
    echo ""
    if [ "$(uname)" = "Darwin" ]; then
        echo "  Install Python 3 via Homebrew:"
        echo "    brew install python@3.11"
    else
        echo "  Install Python 3 for your distribution:"
        echo "    Ubuntu/Debian/Kali: sudo apt install python3 python3-venv python3-pip"
        echo "    Fedora/RHEL:        sudo dnf install python3 python3-pip"
        echo "    Arch:               sudo pacman -S python python-pip"
    fi
    echo ""
    exit 1
fi

# --- Check Python version ---
PY_VERSION=$($PYTHON_CMD --version 2>&1)
echo "  [*] Found Python: $PYTHON_CMD"
echo "  [*] Version: $PY_VERSION"

if ! $PYTHON_CMD -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
    echo ""
    echo "  [ERROR] Python 3.10 or later is required."
    echo "  Current version: $PY_VERSION"
    echo ""
    exit 1
fi

echo "  [OK] Python version is 3.10+"
echo ""

# --- Check for venv module ---
if ! $PYTHON_CMD -m venv --help &>/dev/null; then
    echo "  [ERROR] Python venv module not found."
    echo ""
    echo "  Install it:"
    echo "    Ubuntu/Debian/Kali: sudo apt install python3-venv"
    echo "    Fedora/RHEL:        sudo dnf install python3-virtualenv"
    echo ""
    exit 1
fi

# --- Check for requirements.txt ---
if [ ! -f "$DONJON_HOME/requirements.txt" ]; then
    echo "  [ERROR] requirements.txt not found."
    echo "  Cannot install dependencies without requirements.txt."
    echo "  Ensure you're running setup.sh from the project root."
    exit 1
fi

# --- Create virtual environment ---
VENV_DIR="$DONJON_HOME/venv"

if [ -f "$VENV_DIR/bin/python3" ] || [ -f "$VENV_DIR/bin/python" ]; then
    echo "  [*] Virtual environment already exists at:"
    echo "    $VENV_DIR"
    echo ""
    if [ -t 0 ]; then
        read -p "  Recreate venv? (y/N): " RECREATE
    else
        RECREATE="N"
    fi
    if [[ "$RECREATE" =~ ^[Yy] ]]; then
        echo "  [*] Removing existing venv..."
        rm -rf "$VENV_DIR"
        echo "  [*] Creating new virtual environment..."
        $PYTHON_CMD -m venv "$VENV_DIR"
        echo "  [OK] Virtual environment created."
    else
        echo "  [*] Keeping existing venv."
    fi
else
    echo "  [*] Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo "  [ERROR] Failed to create virtual environment."
        exit 1
    fi
    echo "  [OK] Virtual environment created at:"
    echo "    $VENV_DIR"
fi

echo ""

# --- Determine venv Python and pip ---
if [ -f "$VENV_DIR/bin/python3" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python3"
elif [ -f "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
fi
VENV_PIP="$VENV_DIR/bin/pip"

# --- Check build dependencies ---
check_build_deps() {
    echo "  [*] Checking build dependencies..."

    # Detect distro family
    DISTRO_FAMILY=""
    DISTRO_NAME="Unknown"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_NAME="${PRETTY_NAME:-$NAME}"
        case "${ID:-} ${ID_LIKE:-}" in
            *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
            *rhel*|*fedora*|*centos*) DISTRO_FAMILY="rhel" ;;
            *suse*) DISTRO_FAMILY="suse" ;;
            *arch*) DISTRO_FAMILY="arch" ;;
        esac
    fi

    if [ "$(uname)" = "Darwin" ]; then
        DISTRO_FAMILY="macos"
        DISTRO_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
    fi

    echo "  [*] Detected distro: $DISTRO_NAME"

    # Check for gcc
    MISSING=""
    if ! command -v gcc &>/dev/null; then
        MISSING="$MISSING gcc"
    fi

    # Check for Python.h
    PYTHON_INCLUDE=$("$VENV_PYTHON" -c "import sysconfig; print(sysconfig.get_path('include'))" 2>/dev/null)
    if [ -z "$PYTHON_INCLUDE" ] || [ ! -d "$PYTHON_INCLUDE" ]; then
        MISSING="$MISSING python-dev-headers"
    fi

    # Check for openssl headers
    HAVE_OPENSSL=false
    for d in /usr/include/openssl /usr/local/include/openssl /usr/include/*/openssl; do
        if [ -d "$d" ]; then
            HAVE_OPENSSL=true
            break
        fi
    done
    if [ "$HAVE_OPENSSL" = false ]; then
        MISSING="$MISSING openssl-headers"
    fi

    if [ -n "$MISSING" ]; then
        echo "  [WARNING] Missing build dependencies:$MISSING"

        INSTALL_CMD=""
        case "$DISTRO_FAMILY" in
            debian) INSTALL_CMD="sudo apt install -y python3-dev build-essential libssl-dev libffi-dev" ;;
            rhel)   INSTALL_CMD="sudo dnf install -y python3-devel gcc openssl-devel libffi-devel" ;;
            suse)   INSTALL_CMD="sudo zypper install -y python3-devel gcc libopenssl-devel libffi-devel" ;;
            arch)   INSTALL_CMD="sudo pacman -S --noconfirm base-devel openssl" ;;
            macos)  echo "  [INFO] Install Xcode CLI tools: xcode-select --install" ;;
        esac

        if [ -n "$INSTALL_CMD" ]; then
            echo ""
            echo "  Suggested fix:"
            echo "    $INSTALL_CMD"
            echo ""
            if [ -t 0 ]; then
                read -p "  Install now? (y/N): " DO_INSTALL
            else
                echo "  [INFO] Non-interactive mode - skipping auto-install."
                DO_INSTALL="N"
            fi
            if [[ "$DO_INSTALL" =~ ^[Yy] ]]; then
                echo "  [*] Installing build dependencies..."
                $INSTALL_CMD
                echo "  [OK] Build dependencies installed."
            else
                echo "  [*] Skipping - some pip packages may fail to build."
            fi
        fi
    else
        echo "  [OK] Build dependencies present (gcc, Python headers, OpenSSL headers)."
    fi
    echo ""
}

# --- Install requirements ---
check_build_deps

echo "  [*] Upgrading pip..."
"$VENV_PYTHON" -m pip install --upgrade pip -q
echo "  [OK] pip upgraded."
echo ""

echo "  [*] Installing requirements..."
echo "    Source: $DONJON_HOME/requirements.txt"
echo ""

if "$VENV_PIP" install -r "$DONJON_HOME/requirements.txt"; then
    echo ""
    echo "  [OK] All requirements installed successfully."
else
    echo ""
    echo "  [WARNING] Some packages failed to install."
    echo "  You may need development headers:"
    echo "    Ubuntu/Debian: sudo apt install python3-dev build-essential"
    echo "    Fedora/RHEL:   sudo dnf install python3-devel gcc"
    echo ""
    echo "  The platform may still work with reduced functionality."
fi

echo ""

# --- Create data directories ---
echo "  [*] Ensuring data directories exist..."
mkdir -p "$DONJON_HOME/data/results"
mkdir -p "$DONJON_HOME/data/evidence"
mkdir -p "$DONJON_HOME/data/reports"
mkdir -p "$DONJON_HOME/data/logs"
echo "  [OK] Data directories ready."
echo ""

# --- Verify installation ---
echo "  ============================================================"
echo "   Verification"
echo "  ============================================================"
echo ""

echo "  [*] Checking Python in venv..."
"$VENV_PYTHON" --version
echo ""

echo "  [*] Checking core imports..."
"$VENV_PYTHON" -c "
import sys
sys.path.insert(0, '$DONJON_HOME/lib')
from paths import paths
from config import config
print('  [OK] Core modules load successfully')
print(f'  [OK] Platform home: {paths.home}')
" 2>/dev/null || echo "  [WARNING] Some imports may not be available."

echo ""

# --- Platform detection ---
echo "  [*] Detecting deployment mode..."
"$VENV_PYTHON" -c "
import sys
sys.path.insert(0, '$DONJON_HOME/lib')
from platform_detect import get_platform_info
pi = get_platform_info()
print(f'  [OK] OS: {pi.os_name}')
print(f'  [OK] Mode: {pi.deployment_mode}')
print(f'  [OK] Admin: {pi.is_admin}')
" 2>/dev/null || true

# --- Download vulnerability intelligence database ---
echo "  [*] Checking vulnerability intelligence database..."
VULN_DB="$DONJON_HOME/data/vuln_db/vuln_intel.db"
FEEDS_DB="$DONJON_HOME/data/intel_feeds.db"
mkdir -p "$DONJON_HOME/data/vuln_db"

NEED_DOWNLOAD=false
if [ ! -f "$VULN_DB" ] || [ "$(stat -c%s "$VULN_DB" 2>/dev/null || stat -f%z "$VULN_DB" 2>/dev/null)" -lt 10000 ]; then
    NEED_DOWNLOAD=true
fi

if [ "$NEED_DOWNLOAD" = true ]; then
    if command -v gh &>/dev/null; then
        DONJON_REPO="${DONJON_REPO:-DonjonSec/donjon-platform}"
        echo "  [*] Downloading pre-built database from GitHub Release..."
        gh release download intel-latest --repo "$DONJON_REPO" --pattern "vuln_intel.db" --dir "$DONJON_HOME/data/vuln_db/" --clobber 2>/dev/null && \
            echo "  [OK] vuln_intel.db downloaded" || \
            echo "  [INFO] No release DB found - run 'python3 bin/update-intel.py --all' to build"
        gh release download intel-latest --repo "$DONJON_REPO" --pattern "intel_feeds.db" --dir "$DONJON_HOME/data/" --clobber 2>/dev/null && \
            echo "  [OK] intel_feeds.db downloaded" || true

        # Verify integrity via manifest checksums
        gh release download intel-latest --repo "$DONJON_REPO" --pattern "manifest.json" --dir "/tmp/" --clobber 2>/dev/null
        if [ -f "/tmp/manifest.json" ] && command -v sha256sum &>/dev/null; then
            echo "  [*] Verifying download integrity..."
            FAIL=0
            for db_file in "$DONJON_HOME/data/vuln_db/vuln_intel.db" "$DONJON_HOME/data/intel_feeds.db"; do
                if [ -f "$db_file" ]; then
                    BASENAME=$(basename "$db_file")
                    EXPECTED=$(python3 -c "import json; m=json.load(open('/tmp/manifest.json')); print(m.get('checksums',{}).get('$BASENAME',''))" 2>/dev/null)
                    if [ -n "$EXPECTED" ]; then
                        ACTUAL=$(sha256sum "$db_file" | cut -d' ' -f1)
                        if [ "$ACTUAL" = "$EXPECTED" ]; then
                            echo "  [OK] $BASENAME: SHA-256 verified"
                        else
                            echo "  [WARNING] $BASENAME: SHA-256 mismatch (expected ${EXPECTED:0:16}..., got ${ACTUAL:0:16}...)"
                            FAIL=1
                        fi
                    fi
                fi
            done
            rm -f /tmp/manifest.json
            if [ "$FAIL" -eq 1 ]; then
                echo "  [WARNING] Integrity check failed. Re-download or rebuild: python3 bin/update-intel.py --all"
            fi
        fi
    else
        echo "  [INFO] gh CLI not found. To download pre-built DB:"
        echo "         gh release download intel-latest --pattern '*.db'"
        echo "         Or build from sources: python3 bin/update-intel.py --all"
    fi
else
    VULN_SIZE=$(du -sh "$VULN_DB" 2>/dev/null | cut -f1)
    echo "  [OK] vuln_intel.db exists ($VULN_SIZE)"
fi

echo "  [*] Validating critical dependencies..."
"$VENV_PYTHON" -c "
import yaml
import psutil
import cryptography
print('  [OK] All critical packages imported successfully')
" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "  [ERROR] Critical packages missing after installation."
    echo "  Try: $VENV_PYTHON -m pip install -r $DONJON_HOME/requirements.txt"
    exit 1
fi

echo ""
echo "  ============================================================"
echo "   Setup Complete"
echo "  ============================================================"
echo ""
echo "  To launch the platform:"
echo "    python3 $DONJON_HOME/bin/donjon-launcher"
echo ""
echo "  Or use the bash wrapper:"
echo "    $DONJON_HOME/bin/donjon"
echo ""
echo "  Quick scan:"
echo "    python3 $DONJON_HOME/bin/donjon-launcher quick"
echo ""
echo "  ============================================================"
echo ""
