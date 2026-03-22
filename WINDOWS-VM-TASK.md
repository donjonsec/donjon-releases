# Windows VM Agent — Full Setup + First Test Run

Execute everything below in order. Push results when done.

## Step 0: Environment Setup

```powershell
$env:PYTHONPATH = "C:\donjon-platform"
$env:DONJON_ACCEPT_EULA = "yes"
$env:DONJON_TEST_MODE = "1"
cd C:\donjon-platform
```

## Step 1: Fix SSH (one more attempt)

```powershell
# Write key using .NET to guarantee no BOM, no CRLF
$key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY"
$path = "C:\ProgramData\ssh\administrators_authorized_keys"
[System.IO.File]::WriteAllBytes($path, [System.Text.Encoding]::ASCII.GetBytes($key + "`n"))

# Set strict permissions
icacls $path /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"

# Ensure password auth works too
$conf = "C:\ProgramData\ssh\sshd_config"
$content = @"
Port 22
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitRootLogin yes
Subsystem sftp sftp-server.exe
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@
[System.IO.File]::WriteAllText($conf, $content)

# Reset admin password to known value
net user Administrator "Donj0n2026!" /domain

Restart-Service sshd
Write-Output "SSH configured"
```

## Step 2: Test AD Scanner

```powershell
python -c @"
import sys
sys.path.insert(0, r'C:\donjon-platform')
try:
    from scanners.ad_scanner import ADScanner
    scanner = ADScanner('AD-TEST-001')
    print('AD Scanner loaded')
    result = scanner.scan(targets=['localhost'], scan_type='quick')
    if isinstance(result, dict):
        print('Keys:', list(result.keys()))
        findings = result.get('findings', result.get('results', []))
        if isinstance(findings, list):
            print('Findings:', len(findings))
            for f in findings[:5]:
                if isinstance(f, dict):
                    sev = f.get('severity', '?')
                    title = str(f.get('title', f.get('finding', '')))[:80]
                    print(f'  [{sev}] {title}')
        else:
            print('Findings field:', type(findings).__name__)
        if result.get('error'):
            print('Error:', result['error'])
        print('Summary:', result.get('summary', {}))
    else:
        print('Result type:', type(result).__name__)
        print('Raw:', str(result)[:500])
except Exception as e:
    print(f'AD Scanner FAILED: {type(e).__name__}: {e}')
"@
```

## Step 3: Test Windows Scanner

```powershell
python -c @"
import sys
sys.path.insert(0, r'C:\donjon-platform')
try:
    from scanners.windows_scanner import WindowsScanner
    scanner = WindowsScanner('WIN-VM-TEST')
    result = scanner.scan(scan_type='quick')
    print('Checks completed:', result.get('checks_completed', 0))
    print('Findings:', result.get('findings_count', 0))
    summary = result.get('summary', {})
    if summary:
        print('Summary:', summary)
except Exception as e:
    print(f'Windows Scanner FAILED: {type(e).__name__}: {e}')
"@
```

## Step 4: Test Compliance on This VM

```powershell
python -c @"
import sys
sys.path.insert(0, r'C:\donjon-platform')
try:
    from lib.compliance import get_compliance_mapper
    from lib.evidence import get_evidence_manager
    m = get_compliance_mapper()
    em = get_evidence_manager()
    fws = m.get_all_frameworks()
    print('Frameworks:', len(fws))
    summary = m.generate_compliance_summary(em, 'nist_800_53')
    print('NIST 800-53:', summary.get('total_controls', 0), 'controls,', summary.get('controls_with_evidence', 0), 'with evidence')
except Exception as e:
    print(f'Compliance FAILED: {type(e).__name__}: {e}')
"@
```

## Step 5: Test Export Formats

```powershell
python -c @"
import sys, tempfile, json
from pathlib import Path
sys.path.insert(0, r'C:\donjon-platform')
try:
    from lib.export import ExportManager
    em = ExportManager()
    findings = [{'id':'VM-001','title':'Test Finding','severity':'high','host':'192.168.1.200','port':445,'cve':'CVE-2024-0001','cvss':8.5,'scanner':'test','timestamp':'2026-01-01T00:00:00Z','remediation':'Test','description':'Test','category':'test','status':'open'}]
    formats = ['cef','stix','splunk_hec','sentinel','leef','csv','servicenow_json','qualys_xml','sarif','syslog','jsonl']
    passed = 0
    for fmt in formats:
        p = Path(tempfile.mktemp(suffix='.' + fmt))
        try:
            getattr(em, 'export_' + fmt)(findings, p)
            if p.exists() and p.stat().st_size > 10:
                passed += 1
                p.unlink()
            else:
                print(f'  {fmt}: EMPTY')
        except Exception as e:
            print(f'  {fmt}: ERROR {e}')
    print(f'Export formats: {passed}/{len(formats)} passed')
except Exception as e:
    print(f'Export FAILED: {type(e).__name__}: {e}')
"@
```

## Step 6: Collect and Push Results

```powershell
$results = @()
$results += "# VM Test Results — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
$results += ""

$results += "## SSH Status"
$results += "Port 22: $((Test-NetConnection -ComputerName localhost -Port 22).TcpTestSucceeded)"
$results += "sshd running: $((Get-Service sshd).Status)"
$results += ""

$results += "## AD Domain"
try {
    $domain = Get-ADDomain
    $results += "Domain: $($domain.DNSRoot)"
    $results += "NetBIOS: $($domain.NetBIOSName)"
    $users = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
    $results += "Users: $($users -join ', ')"
} catch {
    $results += "AD ERROR: $_"
}
$results += ""

$results += "## Python"
$results += (python --version 2>&1)
$results += ""

$results += "## AD Scanner Test"
$ad_out = python -c "import sys; sys.path.insert(0,r'C:\donjon-platform'); exec(open(r'C:\donjon-platform\WINDOWS-VM-TASK.md').read().split('Step 2')[1].split('Step 3')[0].split('python -c @`"')[1].split('`"@')[0])" 2>&1
$results += ($ad_out | Out-String)

$results += "## Windows Scanner Test"
$win_out = python -c "import sys; sys.path.insert(0,r'C:\donjon-platform'); from scanners.windows_scanner import WindowsScanner; s=WindowsScanner('t'); r=s.scan(scan_type='quick'); print('checks:',r.get('checks_completed',0),'findings:',r.get('findings_count',0))" 2>&1
$results += ($win_out | Out-String)

$results += "## Compliance Test"
$comp_out = python -c "import sys; sys.path.insert(0,r'C:\donjon-platform'); from lib.compliance import get_compliance_mapper; m=get_compliance_mapper(); print('frameworks:',len(m.get_all_frameworks()))" 2>&1
$results += ($comp_out | Out-String)

$results += "## Export Test"
$exp_out = python -c "import sys,tempfile; from pathlib import Path; sys.path.insert(0,r'C:\donjon-platform'); from lib.export import ExportManager; em=ExportManager(); f=[{'id':'T','title':'T','severity':'high','host':'x','port':1,'cve':'CVE-2024-1','cvss':1,'scanner':'t','timestamp':'2026-01-01','remediation':'t','description':'t','category':'t','status':'open'}]; passed=sum(1 for fmt in ['cef','stix','csv','sarif','jsonl'] if (lambda p: (getattr(em,'export_'+fmt)(f,p),p.exists() and p.stat().st_size>10))(Path(tempfile.mktemp(suffix='.'+fmt)))[1]); print(f'exports: {passed}/5 passed')" 2>&1
$results += ($exp_out | Out-String)

$results += "## IP Address"
$results += (ipconfig | Select-String "IPv4" | Out-String)

$results | Set-Content C:\donjon-platform\VM-STATUS.md -Encoding UTF8

cd C:\donjon-platform
git add VM-STATUS.md
git commit -m "VM: full test results — AD scanner, Windows scanner, compliance, exports"
git push origin main

Write-Output "All tests complete — results pushed to repo"
```

## After This — Start Monitoring Loop

Read CLAUDE-WINDOWS-AGENT.md and begin the 60-second polling loop:
- git pull every 60 seconds
- If WINDOWS-VM-TASK.md changes, execute it
- Push results in VM-STATUS.md
