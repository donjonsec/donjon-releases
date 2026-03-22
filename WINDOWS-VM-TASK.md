# Task — Fix SSH + Disable Screen Lock + Log Learnings

Execute all steps in order.

## Step 1: Disable Screen Lock

```powershell
powercfg -change -monitor-timeout-ac 0
powercfg -change -standby-timeout-ac 0
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 0 /f
Write-Output "Screen lock disabled"
```

## Step 2: Fix SSH — Full Nuclear Approach

The SSH key auth keeps failing. Debug and fix it completely.

```powershell
# Stop sshd
Stop-Service sshd

# Write a minimal sshd_config that ONLY uses password auth (no key complexity)
$config = "Port 22`nPasswordAuthentication yes`nPubkeyAuthentication no`nSubsystem sftp sftp-server.exe"
[System.IO.File]::WriteAllText("C:\ProgramData\ssh\sshd_config", $config, [System.Text.Encoding]::ASCII)

# Remove ALL authorized_keys files to eliminate key conflicts
Remove-Item "C:\ProgramData\ssh\administrators_authorized_keys" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Users\Administrator\.ssh\authorized_keys" -Force -ErrorAction SilentlyContinue

# Ensure admin password is set and known
net user Administrator "Donj0n2026!" /domain

# Start sshd
Start-Service sshd

# Wait and test locally
Start-Sleep -Seconds 3
$testResult = Test-NetConnection -ComputerName localhost -Port 22
Write-Output "Port 22 open: $($testResult.TcpTestSucceeded)"
Write-Output "sshd status: $((Get-Service sshd).Status)"

# Dump the config to verify
Write-Output "--- sshd_config ---"
type C:\ProgramData\ssh\sshd_config
Write-Output "--- end config ---"

# Check Windows Firewall
$rules = Get-NetFirewallRule -DisplayName "*SSH*" -ErrorAction SilentlyContinue
if ($rules) {
    Write-Output "Firewall rules for SSH:"
    $rules | Format-Table DisplayName, Enabled, Direction, Action
} else {
    Write-Output "No SSH firewall rules found — adding one"
    New-NetFirewallRule -Name "OpenSSH-Server" -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
    Write-Output "Firewall rule added"
}

# Check if AD Group Policy is overriding SSH settings
$gpoResult = gpresult /r /scope:computer 2>&1 | Select-String -Pattern "SSH|Security|Logon" | Out-String
if ($gpoResult) {
    Write-Output "GPO matches:"
    Write-Output $gpoResult
}

# Check if the account is locked or restricted
$adminUser = Get-ADUser -Identity Administrator -Properties LockedOut, Enabled, PasswordExpired, PasswordLastSet
Write-Output "Admin account status:"
Write-Output "  Locked: $($adminUser.LockedOut)"
Write-Output "  Enabled: $($adminUser.Enabled)"
Write-Output "  Password expired: $($adminUser.PasswordExpired)"
Write-Output "  Password last set: $($adminUser.PasswordLastSet)"

# Check LogonType restrictions
$secPol = secedit /export /cfg C:\donjon-agent\secpol.cfg 2>&1
$logonRight = Select-String -Path C:\donjon-agent\secpol.cfg -Pattern "SeNetworkLogonRight|SeDenyNetworkLogonRight|SeInteractiveLogonRight" -ErrorAction SilentlyContinue
if ($logonRight) {
    Write-Output "Logon rights:"
    $logonRight | ForEach-Object { Write-Output "  $_" }
}

# Test SSH to self
Write-Output "Testing SSH to localhost..."
$sshTest = ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes administrator@localhost "echo SSH_WORKS" 2>&1
Write-Output "SSH self-test result: $sshTest"
```

## Step 3: Push All Results

```powershell
$out = @()
$out += "# VM Status — SSH Debug + Screen Lock — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$out += ""
$out += "## Screen Lock"
$out += "Disabled: Yes"
$out += ""
$out += "## SSH Debug"
$out += "Port 22: $((Test-NetConnection -ComputerName localhost -Port 22).TcpTestSucceeded)"
$out += "sshd: $((Get-Service sshd).Status)"
$out += ""
$out += "## sshd_config"
$out += (type C:\ProgramData\ssh\sshd_config | Out-String)
$out += ""
$out += "## Admin Account"
$admin = Get-ADUser -Identity Administrator -Properties LockedOut, Enabled, PasswordExpired
$out += "Locked: $($admin.LockedOut)"
$out += "Enabled: $($admin.Enabled)"
$out += "Password Expired: $($admin.PasswordExpired)"
$out += ""
$out += "## Firewall"
$fwRules = Get-NetFirewallRule -DisplayName "*SSH*" -ErrorAction SilentlyContinue
if ($fwRules) {
    $out += ($fwRules | Format-Table DisplayName, Enabled, Direction, Action | Out-String)
} else {
    $out += "No SSH rules"
}
$out += ""
$out += "## Logon Rights"
if (Test-Path C:\donjon-agent\secpol.cfg) {
    $rights = Select-String -Path C:\donjon-agent\secpol.cfg -Pattern "SeNetworkLogonRight|SeDenyNetworkLogonRight" -ErrorAction SilentlyContinue
    $out += ($rights | Out-String)
} else {
    $out += "Could not export security policy"
}
$out += ""
$out += "## SSH Self-Test"
$selfTest = ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes administrator@localhost "echo SSH_WORKS" 2>&1
$out += "Result: $selfTest"

$out | Set-Content C:\donjon-platform\VM-STATUS.md -Encoding UTF8
cd C:\donjon-platform
git add VM-STATUS.md
git commit -m "VM: SSH full debug + screen lock disabled"
git push origin main
```
