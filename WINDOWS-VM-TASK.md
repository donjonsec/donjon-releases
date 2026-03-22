# Task — Fix SSH on Domain Controller (Research-Backed)

Execute in order. These are the top fixes from GitHub issues and Microsoft docs.

## Fix 1: Change sshd to run as LocalSystem
```powershell
sc.exe config sshd obj= "LocalSystem"
Restart-Service sshd
Write-Output "sshd now runs as LocalSystem"
```

## Fix 2: Re-enable key auth with proper config
```powershell
$config = @"
Port 22
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
LogLevel DEBUG
Subsystem sftp sftp-server.exe
"@
[System.IO.File]::WriteAllText("C:\ProgramData\ssh\sshd_config", $config, [System.Text.Encoding]::ASCII)

# Write the SSH key properly — ASCII, LF only
$key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($key + [char]10)
[System.IO.File]::WriteAllBytes("C:\ProgramData\ssh\administrators_authorized_keys", $bytes)
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"

Restart-Service sshd
Write-Output "sshd config reset with key auth + password auth"
```

## Fix 3: Fix GPO logon rights
```powershell
# Check current rights
secedit /export /cfg C:\donjon-agent\secpol2.cfg
$deny = Select-String -Path C:\donjon-agent\secpol2.cfg -Pattern "SeDenyNetworkLogonRight"
$allow = Select-String -Path C:\donjon-agent\secpol2.cfg -Pattern "SeNetworkLogonRight"
Write-Output "Deny network logon: $deny"
Write-Output "Allow network logon: $allow"

# Force GPO refresh
gpupdate /force
```

## Fix 4: Check Security Event Log for exact failure
```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 -ErrorAction SilentlyContinue
if ($events) {
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $subStatus = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubStatus'}).'#text'
        $logonType = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
        $targetUser = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        Write-Output "4625: User=$targetUser LogonType=$logonType SubStatus=$subStatus"
    }
} else {
    Write-Output "No 4625 events found"
}
```

## Fix 5: Check sshd service account
```powershell
$svc = Get-WmiObject win32_service | Where-Object {$_.Name -eq 'sshd'}
Write-Output "sshd runs as: $($svc.StartName)"
Write-Output "sshd state: $($svc.State)"
```

## Push Results
```powershell
$out = @()
$out += "# SSH Fix Results — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$out += ""
$out += "## sshd service account"
$svc = Get-WmiObject win32_service | Where-Object {$_.Name -eq 'sshd'}
$out += "Runs as: $($svc.StartName)"
$out += "State: $($svc.State)"
$out += ""
$out += "## sshd_config"
$out += (type C:\ProgramData\ssh\sshd_config | Out-String)
$out += ""
$out += "## Security Event 4625 (logon failures)"
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 5 -ErrorAction SilentlyContinue
if ($events) {
    foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $sub = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubStatus'}).'#text'
        $lt = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
        $usr = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        $out += "  User=$usr LogonType=$lt SubStatus=$sub"
    }
} else {
    $out += "  No 4625 events"
}
$out += ""
$out += "## GPO Network Logon Rights"
secedit /export /cfg C:\donjon-agent\secpol2.cfg 2>$null
$out += (Select-String -Path C:\donjon-agent\secpol2.cfg -Pattern "SeNetworkLogonRight|SeDenyNetworkLogonRight" | Out-String)
$out += ""
$out += "## SSH Self-Test (password)"
$out += (ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 administrator@localhost "echo SSH_WORKS" 2>&1 | Out-String)

$out | Set-Content C:\donjon-platform\VM-STATUS.md -Encoding UTF8
cd C:\donjon-platform
git add VM-STATUS.md
git commit -m "VM: SSH fix with LocalSystem + security event analysis"
git push origin main
```
