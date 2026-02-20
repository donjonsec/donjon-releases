# Donjon Platform v7.0 - Errors & Programmatic Fixes

Tested all launcher options on Linux (Kali 6.17.10, Python 3.x) by running
every CLI command and menu path both interactively and with `--non-interactive`.

---

## Summary

| # | Severity | Component | Error | Impact |
|---|----------|-----------|-------|--------|
| 1 | **HIGH** | `paths.py` | `find_tool('nmap')` returns a **directory** instead of a binary | All scans (quick/standard/deep) fail with `PermissionError` |
| 2 | **HIGH** | `tool_discovery.py` | Hardcoded `.exe` paths used on Linux | nmap, nuclei, gobuster wrongly resolved to Windows binaries |
| 3 | **HIGH** | `reporter.py` | `rq.business_context` attribute does not exist | Risk report generation crashes with `AttributeError` |
| 4 | **MEDIUM** | `malware_scanner.py` | Relative import without fallback | `ImportError` when blue-team malware scan is selected |
| 5 | **MEDIUM** | `shadow_ai_scanner.py` | Relative import without fallback | `ImportError` when shadow AI scanner is loaded |
| 6 | **LOW** | `donjon-launcher:1418` | Bare `input()` instead of `safe_input()` | `EOFError` crash in non-interactive/CI/CD mode |

---

## Error 1: `paths.find_tool()` returns directory instead of file

**File:** `lib/paths.py:178-181`

**Symptom:**
```
orchestrator | ERROR | Assessment failed: [Errno 13] Permission denied: '.../tools/nmap'
```
All quick, standard, and deep scans fail because the orchestrator tries to
execute the `tools/nmap` **directory** as a binary.

**Root cause:**
`find_tool()` checks `bundled.exists() and os.access(bundled, os.X_OK)` but on
Linux, directories always have the execute bit set (it means "searchable").
`tools/nmap` is a directory containing `nmap.exe`, so the check passes and a
directory path is returned.

**Fix:**
```python
# lib/paths.py, line 180 — add .is_file() check
# BEFORE:
if bundled.exists() and os.access(bundled, os.X_OK):
    return bundled

# AFTER:
if bundled.is_file() and os.access(bundled, os.X_OK):
    return bundled
```

---

## Error 2: `tool_discovery.py` hardcodes `.exe` filenames on Linux

**File:** `lib/tool_discovery.py:419-495`

**Symptom:**
```
✓ nmap: ... (/bin/sh: 1: .../tools/nmap/nmap.exe: Permission denied)
✓ nuclei: ... (/bin/sh: 1: .../tools/nuclei.exe: Permission denied)
✓ gobuster: ... (/bin/sh: 1: .../tools/gobuster/gobuster.exe: Permission denied)
```
Tools are "discovered" but their version check fails because `.exe` files can't
run on Linux. When scanners later use these paths, they also fail.

**Root cause:**
`_check_local_tools_dir()` looks for `.exe` files unconditionally (lines 426,
442, 459), regardless of the OS. On Linux, these PE32 binaries exist but cannot
execute.

**Fix:**
```python
# lib/tool_discovery.py — wrap .exe checks in a platform guard
import sys

def _check_local_tools_dir(self):
    tools_dir = paths.home / 'tools'
    if not tools_dir.exists():
        return

    is_windows = sys.platform == 'win32'

    # Check for nuclei
    candidates = ['nuclei.exe', 'nuclei'] if is_windows else ['nuclei', 'nuclei.exe']
    for name in candidates:
        nuclei_path = tools_dir / name
        if nuclei_path.exists() and (is_windows or not name.endswith('.exe')):
            self.tools['nuclei'].in_tools_dir = True
            self.tools['nuclei'].path = str(nuclei_path)
            break

    # Check for nmap portable — only use nmap.exe on Windows
    if is_windows:
        nmap_path = tools_dir / 'nmap' / 'nmap.exe'
        if nmap_path.exists():
            self.tools['nmap'].in_tools_dir = True
            self.tools['nmap'].path = str(nmap_path)

    # Check for gobuster — prefer native binary over .exe on Linux
    gobuster_dir = tools_dir / 'gobuster'
    if gobuster_dir.exists():
        candidates = ['gobuster.exe', 'gobuster'] if is_windows else ['gobuster', 'gobuster.exe']
        for name in candidates:
            gob_path = gobuster_dir / name
            if gob_path.exists() and (is_windows or not name.endswith('.exe')):
                self.tools['gobuster'].in_tools_dir = True
                self.tools['gobuster'].path = str(gob_path)
                break

    # ... (rest of method unchanged)
```

Alternatively, a simpler approach — skip `.exe` files entirely on non-Windows:
```python
# At the top of _check_local_tools_dir:
def _is_runnable(self, path: Path) -> bool:
    """Check if a tool path is actually executable on this OS."""
    if not path.exists():
        return False
    if sys.platform != 'win32' and path.suffix.lower() == '.exe':
        return False  # Skip Windows binaries on Linux/macOS
    return True
```

---

## Error 3: `reporter.py` accesses nonexistent `rq.business_context`

**File:** `utilities/reporter.py:431,450`

**Symptom:**
```
AttributeError: 'RiskQuantifier' object has no attribute 'business_context'.
  Did you mean: 'set_business_context'?
```
Triggered when selecting "Generate risk report (HTML)" from the risk
quantification menu.

**Root cause:**
The HTML template in `generate_risk_report()` uses f-string references to
`rq.business_context.get(...)` (lines 431 and 450), but `RiskQuantifier` stores
business context in private attributes (`_industry`, `_revenue`, etc.) and
does not expose a public `business_context` property.

**Fix — Option A (add property to RiskQuantifier):**
```python
# lib/risk_quantification.py — add after set_business_context method (after line 170)
@property
def business_context(self) -> dict:
    """Public accessor for business context (used by reporter)."""
    return {
        'industry': self._industry,
        'revenue': self._revenue,
        'record_count': self._record_count,
        'asset_values': self._asset_values,
        'business_criticality': self._business_criticality,
        'benchmark_year': 2025,
    }
```

**Fix — Option B (fix the reporter template):**
```python
# utilities/reporter.py
# Line 431 — BEFORE:
#   Benchmark data: IBM/Ponemon {rq.business_context.get('benchmark_year', 2025)}.
# AFTER:
    Benchmark data: IBM/Ponemon 2025.

# Line 450 — BEFORE:
#   {rq.business_context.get('industry', 'default').title()}
# AFTER:
    {rq._industry.title()}
```

Option A is recommended — it keeps the reporter clean and provides a proper API.

---

## Error 4: `malware_scanner.py` — relative import without fallback

**File:** `scanners/malware_scanner.py:32`

**Symptom:**
```
ImportError: attempted relative import with no known parent package
```
Triggered when selecting Blue Team > Malware Detection (option 2).

**Root cause:**
`malware_scanner.py` uses `from .base import BaseScanner` (a package-relative
import). When the scanners directory is added to `sys.path` and modules are
imported directly (not as a package), relative imports fail. Every other
scanner (network, vulnerability, web, etc.) uses a try/except fallback.

**Fix:**
```python
# scanners/malware_scanner.py, line 32
# BEFORE:
from .base import BaseScanner

# AFTER:
try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner
```

---

## Error 5: `shadow_ai_scanner.py` — relative import without fallback

**File:** `scanners/shadow_ai_scanner.py:27`

**Symptom:**
```
ImportError: attempted relative import with no known parent package
```
Same issue as Error 4.

**Fix:**
```python
# scanners/shadow_ai_scanner.py, line 27
# BEFORE:
from .base import BaseScanner

# AFTER:
try:
    from .base import BaseScanner
except ImportError:
    from base import BaseScanner
```

---

## Error 6: Bare `input()` in vuln intelligence loop

**File:** `bin/donjon-launcher:1418`

**Symptom:**
```
EOFError: EOF when reading a line
```
Crash when running vulndb in non-interactive/CI mode.

**Root cause:**
Line 1418 uses bare `input()` instead of the project's `safe_input()` wrapper.
All other ~60 input calls in the launcher use `safe_input()`, making this an
oversight.

**Fix:**
```python
# bin/donjon-launcher, line 1418
# BEFORE:
            input(f"{C.DIM}Press Enter to continue...{C.RESET}")

# AFTER:
            safe_input(f"\n{C.DIM}Press Enter to continue...{C.RESET}")
```

---

## Non-Error Observations

These aren't bugs but may be worth noting:

### Sysinternals tools show as "available" on Linux
The Sysinternals `.exe` files exist in `tools/sysinternals/` and are reported
as available even on Linux. They can't actually run. Same platform-guard
logic from Error 2 should apply here.

### Quick/Standard/Deep scans produce 0 findings when nmap isn't installed
Because of Errors 1 & 2, the network scanner phase silently fails and
subsequent phases have no targets. The orchestrator catches the exception
and returns a session with 0 findings — no crash, but misleading results.

### `requests` and `python-dateutil` in pre-flight but not in `requirements.txt`
The launcher pre-flight check (lines 26-49) expects `requests` and
`python-dateutil` to be installed, but `requirements.txt` only lists `pyyaml`,
`psutil`, `dilithium-py`, and `cryptography`. On a clean install these would
trigger an auto-install from `requirements.txt` which won't include them,
causing the pre-flight to loop. They happen to be present on this system
via other packages.

### `scanners/__init__.py` also uses relative import
`scanners/__init__.py:5` uses `from .base import BaseScanner` which works
when the package is imported as a package but would fail if someone does
`import scanners` after `sys.path.insert(0, 'scanners')`. Currently this
doesn't cause issues because the launcher imports individual scanner modules
directly.

---

## Quick-Apply Script

All six fixes can be applied programmatically:

```bash
#!/bin/bash
# Apply all fixes to Donjon Platform v7.0
cd "$(dirname "$0")"

# Fix 1: paths.py — check .is_file() not just .exists()
sed -i 's/if bundled.exists() and os.access(bundled, os.X_OK):/if bundled.is_file() and os.access(bundled, os.X_OK):/' lib/paths.py

# Fix 2: tool_discovery.py — skip .exe on non-Windows
sed -i '0,/def _check_local_tools_dir/!b; /def _check_local_tools_dir/a\        import sys as _sys' lib/tool_discovery.py
# (Full fix requires manual editing — see Error 2 details above)

# Fix 3: risk_quantification.py — add business_context property
sed -i '/def set_business_context/i\    @property\n    def business_context(self) -> dict:\n        """Public accessor for business context."""\n        return {\n            '\''industry'\'': self._industry,\n            '\''revenue'\'': self._revenue,\n            '\''record_count'\'': self._record_count,\n            '\''asset_values'\'': self._asset_values,\n            '\''business_criticality'\'': self._business_criticality,\n            '\''benchmark_year'\'': 2025,\n        }\n' lib/risk_quantification.py

# Fix 4: malware_scanner.py — add import fallback
sed -i 's/^from \.base import BaseScanner$/try:\n    from .base import BaseScanner\nexcept ImportError:\n    from base import BaseScanner/' scanners/malware_scanner.py

# Fix 5: shadow_ai_scanner.py — add import fallback
sed -i 's/^from \.base import BaseScanner$/try:\n    from .base import BaseScanner\nexcept ImportError:\n    from base import BaseScanner/' scanners/shadow_ai_scanner.py

# Fix 6: donjon-launcher — replace bare input() with safe_input()
sed -i 's/            input(f"{C.DIM}Press Enter to continue...{C.RESET}")/            safe_input(f"\\n{C.DIM}Press Enter to continue...{C.RESET}")/' bin/donjon-launcher

echo "All fixes applied."
```

> **Note:** Fix 2 (tool_discovery) is complex enough that the sed command above
> only partially applies it. See the detailed fix in Error 2 for the full
> platform-guard implementation.
