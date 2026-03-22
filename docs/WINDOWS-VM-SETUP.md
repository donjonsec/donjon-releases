# Windows Server 2022 VM Setup — Donjon Platform Testing

You are setting up this Windows Server 2022 VM as part of the Donjon Platform testing infrastructure on Proxmox (R630).

## Tasks

### 1. Set Static IP
- Adapter: Ethernet (Red Hat VirtIO)
- IP: 192.168.1.200
- Subnet: 255.255.255.0
- Gateway: 192.168.1.1
- DNS: 1.1.1.1, 8.8.8.8

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.200 -PrefixLength 24 -DefaultGateway 192.168.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 1.1.1.1,8.8.8.8
```

### 2. Enable OpenSSH Server with Password Auth
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Enable password authentication
$conf = "C:\ProgramData\ssh\sshd_config"
(Get-Content $conf) -replace '#PasswordAuthentication yes','PasswordAuthentication yes' | Set-Content $conf

# Comment out the admin key-only block at the bottom
(Get-Content $conf) -replace '^Match Group administrators','#Match Group administrators' | Set-Content $conf
(Get-Content $conf) -replace '^\s+AuthorizedKeysFile __PROGRAMDATA__','#       AuthorizedKeysFile __PROGRAMDATA__' | Set-Content $conf

Restart-Service sshd
```

### 3. Install Python 3.12+
```powershell
# Download and install Python
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe" -OutFile "$env:TEMP\python-installer.exe"
Start-Process "$env:TEMP\python-installer.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
# Refresh PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
python --version
```

### 4. Install Active Directory Domain Services
```powershell
# Install AD DS role
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote to domain controller
# This will reboot the server
Install-ADDSForest `
    -DomainName "test.donjonsec.local" `
    -DomainNetBIOSName "DONJONSEC" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "Tracy328!" -AsPlainText -Force) `
    -InstallDns `
    -Force
```

**Note:** The server will reboot after AD promotion. After reboot, log in as `DONJONSEC\Administrator` with password `Tracy328`.

### 5. Install QEMU Guest Agent
```powershell
# Install from the VirtIO CD (drive D: or E:)
$virtio = Get-Volume | Where-Object { $_.FileSystemLabel -eq "virtio-win*" -or $_.DriveLetter -eq "D" } | Select-Object -First 1
$drive = $virtio.DriveLetter
Start-Process msiexec -ArgumentList "/i ${drive}:\guest-agent\qemu-ga-x86_64.msi /qn" -Wait
Start-Service QEMU-GA
Set-Service -Name QEMU-GA -StartupType Automatic
```

### 6. Clone Donjon Platform
```powershell
# Install git if not present
winget install Git.Git --accept-package-agreements --accept-source-agreements 2>$null
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Clone from Forgejo
cd C:\
git clone http://192.168.1.116:3000/donjonsec/donjon-platform.git
cd donjon-platform
pip install -r requirements.txt
```

### 7. Create Test Users and OUs in AD (after reboot)
```powershell
# Run after AD promotion reboot
Import-Module ActiveDirectory

# Create test OUs
New-ADOrganizationalUnit -Name "IT" -Path "DC=test,DC=donjonsec,DC=local"
New-ADOrganizationalUnit -Name "Security" -Path "DC=test,DC=donjonsec,DC=local"

# Create test users
New-ADUser -Name "Test User 1" -SamAccountName "testuser1" -UserPrincipalName "testuser1@test.donjonsec.local" -Path "OU=IT,DC=test,DC=donjonsec,DC=local" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Test User 2" -SamAccountName "testuser2" -UserPrincipalName "testuser2@test.donjonsec.local" -Path "OU=Security,DC=test,DC=donjonsec,DC=local" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true

# Create a test group
New-ADGroup -Name "SecurityTeam" -GroupScope Global -Path "OU=Security,DC=test,DC=donjonsec,DC=local"
Add-ADGroupMember -Identity "SecurityTeam" -Members "testuser2"
```

### 8. Verify Setup
```powershell
# Verify AD
Get-ADDomain
Get-ADUser -Filter * | Select-Object Name, SamAccountName

# Verify Python
python --version
python -c "import sys; sys.path.insert(0,'C:\\donjon-platform'); from lib.config import Config; print('Donjon imports OK')"

# Verify SSH accepts connections
# From another machine: ssh administrator@192.168.1.200

# Verify network connectivity to test targets
Test-NetConnection 192.168.1.110 -Port 8443
Test-NetConnection 192.168.1.116 -Port 3000
```

## Purpose

This VM serves as:
1. **AD Scanner test target** — the only scanner we can't test without a Windows AD domain controller
2. **Windows functional testing** — TUI launcher, START.bat, browser dashboard
3. **End-to-end Windows experience** — what a customer on Windows actually sees

## Network

| Host | IP | Role |
|------|-----|------|
| This VM | 192.168.1.200 | Windows test target + AD DC |
| CT 100 (factory-core) | 192.168.1.110 | Factory, Ollama, OpenJarvis |
| CT 106 (Forgejo) | 192.168.1.116 | Git repos |
| CT 107 (test-runner) | 192.168.1.117 | Linux test runner |
| CT 108 (DVWA) | 192.168.1.118 | Vulnerable web app target |

## After Setup

Tell the main Claude session on your Windows PC:
"Windows VM is ready at 192.168.1.200 with AD domain test.donjonsec.local"
