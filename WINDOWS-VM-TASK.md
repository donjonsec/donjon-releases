# Task — Fix SSH key encoding (CRLF → LF)

The authorized_keys file has Windows CRLF line endings (0D 0A). OpenSSH rejects this. Fix:

```powershell
# Write key with no trailing newline or carriage return
[System.IO.File]::WriteAllText("C:\ProgramData\ssh\administrators_authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8Tk83o5SPqwXlm148ZsUoRXjf4CQOJ+1dxgjnRjyXY`n")

# Verify — should end with 0A only, NOT 0D 0A
Format-Hex C:\ProgramData\ssh\administrators_authorized_keys | Select-Object -Last 1

# Fix permissions again
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"

Restart-Service sshd

Write-Output "Fixed — LF encoding applied"
```

Then push confirmation:
```powershell
cd C:\donjon-platform
"SSH key encoding fixed — CRLF replaced with LF" | Set-Content VM-STATUS.md
git add VM-STATUS.md && git commit -m "VM: SSH key CRLF fix" && git push origin main
```
