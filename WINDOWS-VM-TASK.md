# Task for Claude on Windows VM — DEBUG SSH

Run these commands and write the output to C:\donjon-platform\VM-STATUS.md, then git add, commit, and push to origin main.

```powershell
$out = @()
$out += "# VM Status Report"
$out += ""
$out += "## sshd_config contents"
$out += '```'
$out += (Get-Content C:\ProgramData\ssh\sshd_config)
$out += '```'
$out += ""
$out += "## sshd service status"
$out += (Get-Service sshd | Format-List Status, StartType | Out-String)
$out += ""
$out += "## Port 22 listening"
$out += (netstat -an | Select-String ":22 " | Out-String)
$out += ""
$out += "## authorized_keys files"
$out += "### ProgramData"
$out += (Get-Content C:\ProgramData\ssh\administrators_authorized_keys -ErrorAction SilentlyContinue) ?? "FILE NOT FOUND"
$out += "### User .ssh"
$out += (Get-Content C:\Users\Administrator\.ssh\authorized_keys -ErrorAction SilentlyContinue) ?? "FILE NOT FOUND"
$out += ""
$out += "## AD Status"
$out += (Get-ADDomain | Select-Object DNSRoot, NetBIOSName | Format-List | Out-String)
$out += ""
$out += "## AD Users"
$out += (Get-ADUser -Filter * | Select-Object Name, SamAccountName | Format-Table | Out-String)
$out += ""
$out += "## Python"
$out += (python --version 2>&1)
$out += ""
$out += "## IP"
$out += (ipconfig | Select-String "IPv4" | Out-String)

$out | Set-Content C:\donjon-platform\VM-STATUS.md
cd C:\donjon-platform
git add VM-STATUS.md
git commit -m "VM status report — SSH debug info"
git push origin main
```

Run this entire block. The output will be pushed to the repo so the main session can read it.
