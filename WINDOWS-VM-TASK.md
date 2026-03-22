# Task for Claude on Windows VM — FIX SSH (Final)

The problem: Windows OpenSSH ignores AuthorizedKeysFile for Administrator accounts and ALWAYS reads C:\ProgramData\ssh\administrators_authorized_keys regardless of config.

Run this:

```powershell
# Create the file Windows actually reads for admin accounts
Set-Content "C:\ProgramData\ssh\administrators_authorized_keys" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY"

# Fix permissions — Windows SSH requires SYSTEM and Administrators ONLY
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"

Restart-Service sshd

Write-Output "SSH fix applied — administrators_authorized_keys created with correct permissions"
```

Then push confirmation:
```powershell
cd C:\donjon-platform
"SSH FIXED — administrators_authorized_keys created with SYSTEM+Administrators permissions" | Set-Content VM-STATUS.md
git add VM-STATUS.md
git commit -m "VM: SSH fixed — admin authorized_keys with correct perms"
git push origin main
```
