# Task for Claude on Windows VM — SSH Debug Round 2

Run this and push results:

```powershell
$out = @()
$out += "# SSH Debug Round 2"
$out += ""
$out += "## File permissions on administrators_authorized_keys"
$out += (icacls C:\ProgramData\ssh\administrators_authorized_keys 2>&1 | Out-String)
$out += ""
$out += "## OpenSSH event log"
$out += (Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue | Format-List TimeCreated,Message | Out-String)
$out += ""
$out += "## sshd_config full dump"
$out += (type C:\ProgramData\ssh\sshd_config | Out-String)
$out += ""
$out += "## administrators_authorized_keys content"
$out += (type C:\ProgramData\ssh\administrators_authorized_keys 2>&1 | Out-String)
$out += ""
$out += "## File encoding check"
$out += (Format-Hex C:\ProgramData\ssh\administrators_authorized_keys -Count 100 2>&1 | Out-String)

$out | Set-Content C:\donjon-platform\VM-STATUS.md
cd C:\donjon-platform
git add VM-STATUS.md
git commit -m "VM: SSH debug round 2 — permissions and logs"
git push origin main
```
