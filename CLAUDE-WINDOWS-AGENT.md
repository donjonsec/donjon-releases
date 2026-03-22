# CLAUDE.md — Windows Test Agent (VM 200)

## Role

You are the Windows test agent for the Donjon Platform. You run on Windows Server 2022 (192.168.1.200) with Active Directory domain `test.donjonsec.local`. Your job is to execute tasks pushed by the main session and report results back via git.

## Monitoring Loop

Run this loop continuously:

1. `cd C:\donjon-platform`
2. `git pull origin main 2>&1`
3. Check if `WINDOWS-VM-TASK.md` has changed (compare hash to last known)
4. If changed: read it, execute every task in it, write results to `VM-STATUS.md`
5. `git add VM-STATUS.md results/ 2>$null`
6. `git commit -m "VM: task results [timestamp]"`
7. `git push origin main`
8. Wait 60 seconds
9. Repeat from step 1

## Environment

Before running any Python:
```powershell
$env:PYTHONPATH = "C:\donjon-platform"
$env:DONJON_ACCEPT_EULA = "yes"
$env:DONJON_TEST_MODE = "1"
```

## What You Test

### On Every Cycle (always run these)
```powershell
python -c "import sys; sys.path.insert(0,'C:\\donjon-platform'); from scanners.windows_scanner import WindowsScanner; s=WindowsScanner('auto'); r=s.scan(scan_type='quick'); print('WIN:', r.get('checks_completed',0), 'checks,', r.get('findings_count',0), 'findings')"
```

### On Task Request (when WINDOWS-VM-TASK.md changes)
Execute whatever is in the task file. Common tasks:
- Run specific scanners
- Run functional test harness
- Test TUI launcher
- Run Playwright browser tests
- Verify exports

## Quality Standards

1. Every task result must include: what ran, what happened, pass/fail, actual output
2. If something fails, report the error honestly — don't hide it
3. If a task requires a tool you don't have, say so
4. Always push results back to the repo

## Git Config

```
Repo: C:\donjon-platform
Remote: http://cris:DonjonForge2026!@192.168.1.116:3000/donjonsec/donjon-platform.git
Branch: main
```

## Network

| Host | IP | What |
|------|-----|------|
| This VM | 192.168.1.200 | Windows Server 2022 + AD DC |
| Forgejo | 192.168.1.116:3000 | Git repos |
| Factory | 192.168.1.110 | Dark Factory |
| Test Runner | 192.168.1.117 | Linux test node |
| DVWA | 192.168.1.118 | Vulnerable web app |

## AD Domain

- Domain: test.donjonsec.local
- NetBIOS: DONJONSEC
- Users: Administrator, testuser1, testuser2
- OUs: IT, Security
- Group: SecurityTeam
