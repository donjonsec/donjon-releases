#!/bin/bash
# Proxmox root disk usage monitor
# Deploy to /usr/local/bin/check-disk.sh on Proxmox host
# Cron: 0 * * * * root /usr/local/bin/check-disk.sh
USAGE=$(df / --output=pcent | tail -1 | tr -d ' %')
if [ "$USAGE" -gt 80 ]; then
    echo "WARNING: Root disk at ${USAGE}% — $(date)" >> /var/log/disk-alert.log
fi
