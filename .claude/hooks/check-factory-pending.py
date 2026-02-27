"""
SessionStart hook — checks factory for pending reviews and stuck tasks.

Outputs JSON to stdout that Claude Code injects as session context.
Runs on every session start (timeout: 10s).
"""

import json
import sys
import urllib.request
import urllib.error

FACTORY_URL = "http://192.168.1.110:8000"
API_KEY = "dfk_b0d15dc205eed9c6e8e53de066ae6518352451dad9288639"
TIMEOUT = 8  # seconds (hook timeout is 10s, leave margin)


def _get(path: str, auth: bool = True) -> dict | None:
    """Simple GET request. Returns parsed JSON or None on failure."""
    url = f"{FACTORY_URL}{path}"
    req = urllib.request.Request(url)
    if auth:
        req.add_header("Authorization", f"Bearer {API_KEY}")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def main():
    lines = []

    # Check pending reviews
    pending = _get("/api/v1/pipeline/pending-reviews")
    if pending and pending.get("pending_reviews"):
        reviews = pending["pending_reviews"]
        lines.append(f"Factory: {len(reviews)} pending review(s):")
        for r in reviews[:5]:
            lines.append(f"  - [{r.get('project_name', '?')}] Task #{r['id']}: {r['title']} (assigned: {r.get('agent_id', 'unassigned')})")

    # Check orphaned/stuck tasks
    orphans = _get("/api/v1/pipeline/orphans")
    if orphans:
        oc = orphans.get("orphaned_count", 0)
        sc = orphans.get("stuck_count", 0)
        if oc > 0 or sc > 0:
            lines.append(f"Factory: {oc} orphaned task(s), {sc} stuck task(s) detected")

    # Check active projects
    projects = _get("/api/v1/projects/", auth=False)
    if projects and projects.get("projects"):
        active = [p for p in projects["projects"] if p.get("status") == "active"]
        if active:
            lines.append(f"Factory: {len(active)} active project(s):")
            for p in active[:3]:
                phase = p.get("pipeline_phase", "?")
                done = p.get("completed_tasks", 0)
                total = p.get("total_tasks", 0)
                lines.append(f"  - [{p['name']}] Phase: {phase}, Tasks: {done}/{total}")

    if not lines:
        # Factory unreachable or nothing to report
        result = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": "Factory status: No pending work or factory unreachable."
            },
            "continue": True,
            "suppressOutput": True
        }
    else:
        result = {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": "\n".join(lines)
            },
            "continue": True,
            "suppressOutput": False
        }

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
