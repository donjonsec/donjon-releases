# Task — Skip SSH, Test AD Scanner Directly

SSH is fighting us. You're already on the VM so run the tests directly.

## 1. Test AD Scanner

```powershell
cd C:\donjon-platform
$env:DONJON_ACCEPT_EULA = "yes"
$env:DONJON_TEST_MODE = "1"
$env:PYTHONPATH = "C:\donjon-platform"

python -c @"
import sys
sys.path.insert(0, 'C:\\donjon-platform')
from scanners.ad_scanner import ADScanner
scanner = ADScanner('AD-TEST-001')
print('AD Scanner created')
result = scanner.scan(targets=['localhost'], scan_type='quick')
print('Result type:', type(result).__name__)
if isinstance(result, dict):
    print('Keys:', list(result.keys()))
    findings = result.get('findings', result.get('results', []))
    print('Findings:', len(findings) if isinstance(findings, list) else 'N/A')
    for f in (findings if isinstance(findings, list) else [])[:5]:
        if isinstance(f, dict):
            print('  [' + f.get('severity', '?') + '] ' + str(f.get('title', f.get('finding', '')))[:80])
    if result.get('error'):
        print('Error:', result['error'])
    print('Summary:', result.get('summary', {}))
else:
    print('Raw:', str(result)[:500])
"@
```

## 2. Test Windows Scanner on This VM

```powershell
python -c @"
import sys
sys.path.insert(0, 'C:\\donjon-platform')
from scanners.windows_scanner import WindowsScanner
scanner = WindowsScanner('WIN-VM-TEST')
result = scanner.scan(scan_type='quick')
print('Checks:', result.get('checks_completed', 0))
print('Findings:', result.get('findings_count', 0))
"@
```

## 3. Test Full Functional Harness

```powershell
python tools/functional-test-harness.py --skip-scanners --server http://localhost:8443 --output results/ 2>&1 | Select-Object -Last 20
```

## 4. Push Results

```powershell
$out = @()
$out += "# VM Test Results"
$out += ""
$out += "## AD Scanner"
# Run and capture
$ad_result = python -c "import sys; sys.path.insert(0,'C:\\donjon-platform'); from scanners.ad_scanner import ADScanner; s=ADScanner('test'); r=s.scan(targets=['localhost'],scan_type='quick'); print(type(r).__name__); print(list(r.keys()) if isinstance(r,dict) else 'not dict'); print('findings:',len(r.get('findings',r.get('results',[]))) if isinstance(r,dict) else 0)" 2>&1
$out += $ad_result
$out += ""
$out += "## Windows Scanner"
$win_result = python -c "import sys; sys.path.insert(0,'C:\\donjon-platform'); from scanners.windows_scanner import WindowsScanner; s=WindowsScanner('test'); r=s.scan(scan_type='quick'); print('checks:',r.get('checks_completed',0)); print('findings:',r.get('findings_count',0))" 2>&1
$out += $win_result

$out | Set-Content C:\donjon-platform\VM-STATUS.md
cd C:\donjon-platform
git add VM-STATUS.md results/ 2>$null
git commit -m "VM: AD scanner + Windows scanner test results"
git push origin main
```
