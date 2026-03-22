# Task — Reset Admin Password and Fix SSH

```powershell
# Reset password to meet AD complexity requirements
net user Administrator Donj0n2026! /domain

# Verify who we are
whoami

# Also write the key file using cmd.exe to avoid PowerShell encoding issues
cmd /c "echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY> C:\ProgramData\ssh\administrators_authorized_keys"

# Fix permissions
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"

Restart-Service sshd

# Push confirmation
cd C:\donjon-platform
"Password reset to Donj0n2026! and key rewritten via cmd.exe" | Set-Content VM-STATUS.md
git add VM-STATUS.md
git commit -m "VM: password reset and key rewritten"
git push origin main
```
