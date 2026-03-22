# Task — Disable Screen Lock + Power Timeouts

```powershell
# Disable monitor timeout
powercfg -change -monitor-timeout-ac 0
powercfg -change -standby-timeout-ac 0

# Disable lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f

# Disable screen saver
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f

# Disable auto-lock on idle
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 0 /f

Write-Output "Screen lock and power timeouts disabled"

# Push confirmation
cd C:\donjon-platform
"Screen lock disabled, power timeouts set to 0 at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Set-Content VM-STATUS.md
git add VM-STATUS.md
git commit -m "VM: screen lock and power timeouts disabled"
git push origin main
```
