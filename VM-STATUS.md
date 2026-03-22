# VM Agent Status
Agent: PERSISTENT (Scheduled Task)
Task Name: DonjonTestAgent
Runs As: SYSTEM
Survives: Reboot, logoff, session death
Log: C:\donjon-agent\agent.log
Heartbeat: C:\donjon-agent\heartbeat.txt (every 5 min)
Poll interval: 60 seconds
Executes: WINDOWS-VM-TASK.md changes via claude -p
