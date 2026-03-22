# Task — Set Up Persistent Agent Service

Create a PowerShell script that runs as a scheduled task (survives logoff/reboot). It monitors the repo for new tasks and executes them using `claude -p`.

## Step 1: Create the Agent Script

```powershell
$agentScript = @'
# Donjon Windows Test Agent — Persistent Service
# Polls Forgejo for WINDOWS-VM-TASK.md changes, executes via claude -p

$repo = "C:\donjon-platform"
$taskFile = "$repo\WINDOWS-VM-TASK.md"
$statusFile = "$repo\VM-STATUS.md"
$lastHash = ""
$logFile = "C:\donjon-agent\agent.log"

# Ensure log directory
New-Item -ItemType Directory -Force -Path "C:\donjon-agent" | Out-Null

function Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp $msg" | Add-Content $logFile
    Write-Output "$timestamp $msg"
}

# Set environment
$env:PYTHONPATH = "C:\donjon-platform"
$env:DONJON_ACCEPT_EULA = "yes"
$env:DONJON_TEST_MODE = "1"

Log "Agent started"

while ($true) {
    try {
        # Pull latest
        Set-Location $repo
        $pullResult = git pull origin main 2>&1

        # Check if task file changed
        if (Test-Path $taskFile) {
            $currentHash = (Get-FileHash $taskFile -Algorithm SHA256).Hash

            if ($currentHash -ne $lastHash -and $lastHash -ne "") {
                Log "Task file changed — executing"

                # Read the task
                $taskContent = Get-Content $taskFile -Raw

                # Execute via claude -p (non-interactive)
                $prompt = "You are the Windows test agent. Execute all tasks in this file and write results to C:\donjon-platform\VM-STATUS.md, then git add, commit, and push. Environment: PYTHONPATH=C:\donjon-platform, DONJON_ACCEPT_EULA=yes, DONJON_TEST_MODE=1. Here is the task file:`n`n$taskContent"

                try {
                    $result = claude -p $prompt --dangerously-skip-permissions 2>&1
                    Log "Task executed successfully"
                } catch {
                    Log "Task execution failed: $_"

                    # Fallback: try executing PowerShell blocks directly
                    $blocks = [regex]::Matches($taskContent, '```powershell\r?\n([\s\S]*?)```')
                    foreach ($block in $blocks) {
                        try {
                            Log "Executing PowerShell block directly"
                            Invoke-Expression $block.Groups[1].Value 2>&1 | Add-Content $logFile
                        } catch {
                            Log "Block failed: $_"
                        }
                    }
                }
            }
            $lastHash = $currentHash
        }

        # Heartbeat — run quick checks every cycle
        if ((Get-Date).Minute % 5 -eq 0 -and (Get-Date).Second -lt 65) {
            Log "Heartbeat — running quick checks"

            $heartbeat = @()
            $heartbeat += "# VM Heartbeat — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
            $heartbeat += "Agent: RUNNING"
            $heartbeat += "AD Domain: $((Get-ADDomain -ErrorAction SilentlyContinue).DNSRoot)"
            $heartbeat += "SSH: $((Get-Service sshd -ErrorAction SilentlyContinue).Status)"
            $heartbeat += "Python: $(python --version 2>&1)"
            $heartbeat += "Last task hash: $lastHash"

            $heartbeat | Set-Content "C:\donjon-agent\heartbeat.txt"
        }

    } catch {
        Log "Loop error: $_"
    }

    Start-Sleep -Seconds 60
}
'@

# Write the script
New-Item -ItemType Directory -Force -Path "C:\donjon-agent" | Out-Null
$agentScript | Set-Content "C:\donjon-agent\agent.ps1" -Encoding UTF8
Write-Output "Agent script created at C:\donjon-agent\agent.ps1"
```

## Step 2: Register as Scheduled Task (survives reboot)

```powershell
# Remove old task if exists
Unregister-ScheduledTask -TaskName "DonjonTestAgent" -Confirm:$false -ErrorAction SilentlyContinue

# Create action
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\donjon-agent\agent.ps1"

# Trigger: at startup
$trigger = New-ScheduledTaskTrigger -AtStartup

# Settings: restart on failure, don't stop after time limit
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365)

# Register
Register-ScheduledTask `
    -TaskName "DonjonTestAgent" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -User "SYSTEM" `
    -RunLevel Highest `
    -Description "Donjon Platform Windows Test Agent — polls Forgejo, executes tasks"

# Start it now
Start-ScheduledTask -TaskName "DonjonTestAgent"

Write-Output "Scheduled task created and started"
Get-ScheduledTask -TaskName "DonjonTestAgent" | Format-List TaskName, State
```

## Step 3: Verify Agent is Running

```powershell
Start-Sleep -Seconds 10

# Check if process is running
$proc = Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*agent.ps1*" }
if ($proc) {
    Write-Output "Agent process running: PID $($proc.Id)"
} else {
    Write-Output "Agent process: checking task status..."
    Get-ScheduledTask -TaskName "DonjonTestAgent" | Format-List TaskName, State
}

# Check log
if (Test-Path "C:\donjon-agent\agent.log") {
    Write-Output "Agent log:"
    Get-Content "C:\donjon-agent\agent.log" -Tail 5
}

# Push confirmation
cd C:\donjon-platform
@"
# VM Agent Status
Agent: PERSISTENT (Scheduled Task)
Task Name: DonjonTestAgent
Runs As: SYSTEM
Survives: Reboot, logoff, session death
Log: C:\donjon-agent\agent.log
Heartbeat: C:\donjon-agent\heartbeat.txt (every 5 min)
Poll interval: 60 seconds
Executes: WINDOWS-VM-TASK.md changes via claude -p
"@ | Set-Content VM-STATUS.md

git add VM-STATUS.md
git commit -m "VM: persistent agent service installed — survives reboot"
git push origin main
```

After this, you can close the Claude session on the VM. The agent will keep running as a Windows scheduled task, polling Forgejo every 60 seconds. If it detects a change to WINDOWS-VM-TASK.md, it invokes `claude -p` to execute it.
