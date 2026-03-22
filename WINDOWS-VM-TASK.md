# Task — Fix Agent to Use Dangerously Mode

The `claude -p` invocation needs the `--dangerously-skip-permissions` flag to run autonomously without permission prompts.

```powershell
# Update the agent script
$agentPath = "C:\donjon-agent\agent.ps1"
$content = Get-Content $agentPath -Raw
$content = $content -replace 'claude -p \$prompt', 'claude -p $prompt --dangerously-skip-permissions'
$content = $content -replace 'claude -p "\$prompt"', 'claude -p "$prompt" --dangerously-skip-permissions'
$content | Set-Content $agentPath -Encoding UTF8

# Also add it directly if the replace didn't catch it
if (-not (Select-String -Path $agentPath -Pattern "dangerously-skip-permissions" -Quiet)) {
    $content = Get-Content $agentPath -Raw
    $content = $content -replace 'claude -p \$prompt ([^-])', 'claude -p $prompt --dangerously-skip-permissions $1'
    $content | Set-Content $agentPath -Encoding UTF8
}

# Verify
if (Select-String -Path $agentPath -Pattern "dangerously-skip-permissions" -Quiet) {
    Write-Output "FIXED: --dangerously-skip-permissions added to claude invocation"
} else {
    Write-Output "WARNING: flag not found in script — manual check needed"
    Select-String -Path $agentPath -Pattern "claude" | ForEach-Object { Write-Output $_.Line }
}

# Restart the scheduled task to pick up changes
Stop-ScheduledTask -TaskName "DonjonTestAgent" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName "DonjonTestAgent"

# Push confirmation
cd C:\donjon-platform
"Agent updated with --dangerously-skip-permissions at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Set-Content VM-STATUS.md
git add VM-STATUS.md
git commit -m "VM: agent updated with dangerously-skip-permissions flag"
git push origin main
```
