# Task for Claude on Windows VM (192.168.1.200)

## Fix SSH — Do This Now

Replace the entire sshd_config with this minimal working config:

```powershell
Set-Content "C:\ProgramData\ssh\sshd_config" @"
Port 22
PasswordAuthentication yes
PermitRootLogin yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp sftp-server.exe
"@

# Remove the administrators_authorized_keys file that overrides user keys
Remove-Item "C:\ProgramData\ssh\administrators_authorized_keys" -Force -ErrorAction SilentlyContinue

# Place the SSH key for the main workstation
mkdir C:\Users\Administrator\.ssh -Force -ErrorAction SilentlyContinue
Set-Content "C:\Users\Administrator\.ssh\authorized_keys" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY"

Restart-Service sshd
```

## After SSH Works — Verify AD

```powershell
Get-ADDomain
Get-ADUser -Filter * | Select-Object Name, SamAccountName
```

## Report Back

Create a file at `C:\donjon-platform\VM-STATUS.md` with:
- SSH status (working/not)
- AD domain name
- AD users created
- Python version
- IP address
