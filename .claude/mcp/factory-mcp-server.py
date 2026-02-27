"""
Dark Factory MCP Server — Stdio transport for Claude Code.

Bridges the factory REST API as native Claude Code tools.
All 10 agents (Wraith, Cipher, Jackal, Scribe, Specter, Phantom,
Glitch, Hawk, Raven, Oracle) can interact with the factory pipeline
through these tools.

Environment variables:
    FACTORY_API_URL  — Base URL (default: http://192.168.1.110:8000)
    FACTORY_API_KEY  — Agent API key (dfk_ prefix, required for pipeline ops)
"""

import json
import logging
import os
import sys

import httpx
from mcp.server.fastmcp import FastMCP

# --- Logging (stderr only — stdout is JSON-RPC) ---
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("factory-mcp")

# --- Configuration ---
API_URL = os.environ.get("FACTORY_API_URL", "http://192.168.1.110:8000")
API_KEY = os.environ.get("FACTORY_API_KEY", "")
TIMEOUT = 30.0

# --- MCP Server ---
mcp = FastMCP("dark-factory")


def _auth_headers() -> dict[str, str]:
    """Return Authorization header for pipeline endpoints."""
    if not API_KEY:
        return {}
    return {"Authorization": f"Bearer {API_KEY}"}


async def _get(path: str, *, auth: bool = True, params: dict | None = None) -> str:
    """HTTP GET helper. Returns JSON string or error message."""
    headers = _auth_headers() if auth else {}
    async with httpx.AsyncClient(base_url=API_URL, timeout=TIMEOUT) as client:
        try:
            resp = await client.get(path, headers=headers, params=params)
            resp.raise_for_status()
            return json.dumps(resp.json(), indent=2)
        except httpx.HTTPStatusError as e:
            body = e.response.text[:500]
            logger.error("HTTP %s on GET %s: %s", e.response.status_code, path, body)
            return json.dumps({
                "error": f"HTTP {e.response.status_code}",
                "detail": body,
            })
        except httpx.ConnectError:
            logger.error("Cannot reach factory at %s", API_URL)
            return json.dumps({
                "error": "connection_failed",
                "detail": f"Cannot reach factory at {API_URL}. Is the server running?",
            })
        except Exception as e:
            logger.error("Unexpected error on GET %s: %s", path, e)
            return json.dumps({"error": str(e)})


async def _post(path: str, *, auth: bool = True, body: dict | None = None) -> str:
    """HTTP POST helper. Returns JSON string or error message."""
    headers = _auth_headers() if auth else {}
    async with httpx.AsyncClient(base_url=API_URL, timeout=TIMEOUT) as client:
        try:
            resp = await client.post(path, headers=headers, json=body or {})
            resp.raise_for_status()
            return json.dumps(resp.json(), indent=2)
        except httpx.HTTPStatusError as e:
            body_text = e.response.text[:500]
            logger.error("HTTP %s on POST %s: %s", e.response.status_code, path, body_text)
            return json.dumps({
                "error": f"HTTP {e.response.status_code}",
                "detail": body_text,
            })
        except httpx.ConnectError:
            logger.error("Cannot reach factory at %s", API_URL)
            return json.dumps({
                "error": "connection_failed",
                "detail": f"Cannot reach factory at {API_URL}. Is the server running?",
            })
        except Exception as e:
            logger.error("Unexpected error on POST %s: %s", path, e)
            return json.dumps({"error": str(e)})


# ===================================================================
# Tools — Pipeline
# ===================================================================


@mcp.tool()
async def factory_status(project_id: int) -> str:
    """Get the full pipeline status for a project.

    Returns current phase, per-phase task counts, and any pending reviews.

    Args:
        project_id: The project ID to check
    """
    return await _get(f"/api/v1/pipeline/{project_id}/status")


@mcp.tool()
async def factory_decompose(project_id: int, tasks: str) -> str:
    """Submit task decomposition for a project (planning phase).

    Wraith uses this to break a project spec into executable tasks
    assigned to specific agents and phases.

    Args:
        project_id: The project to decompose tasks for
        tasks: JSON array of task objects. Each task needs: title (str),
               description (str), phase (str: planning/implement/validate/
               review/commit/done), and optionally agent_id (str) and
               priority (int, 1-10, default 5).
               Example: [{"title": "Implement auth", "description": "Add
               Bearer token validation", "phase": "implement",
               "agent_id": "coder-1", "priority": 3}]
    """
    try:
        task_list = json.loads(tasks)
    except json.JSONDecodeError as e:
        return json.dumps({"error": "invalid_json", "detail": str(e)})

    if not isinstance(task_list, list) or len(task_list) == 0:
        return json.dumps({"error": "validation", "detail": "tasks must be a non-empty JSON array"})

    return await _post(
        f"/api/v1/pipeline/{project_id}/decompose",
        body={"tasks": task_list},
    )


@mcp.tool()
async def factory_review(
    project_id: int,
    task_id: int,
    verdict: str,
    findings: str = "[]",
    reviewer_id: str = "",
) -> str:
    """Submit a PASS/FAIL review verdict for a task.

    Used by Specter (code review) and Phantom (security audit) to record
    their assessment of completed work.

    Args:
        project_id: The project being reviewed
        task_id: The specific task being reviewed
        verdict: Must be exactly "PASS" or "FAIL"
        findings: JSON array of finding objects. Each finding has: severity
                  (CRITICAL/HIGH/MEDIUM/LOW/INFO), location (file:line),
                  description (str), remediation (str), and optionally
                  cwe_id (str). Default: empty array.
        reviewer_id: Agent ID of the reviewer (e.g. "reviewer-1", "security-1")
    """
    if verdict not in ("PASS", "FAIL"):
        return json.dumps({"error": "validation", "detail": "verdict must be PASS or FAIL"})

    try:
        findings_list = json.loads(findings)
    except json.JSONDecodeError as e:
        return json.dumps({"error": "invalid_json", "detail": f"findings: {e}"})

    body: dict = {
        "task_id": task_id,
        "verdict": verdict,
        "findings": findings_list,
    }
    if reviewer_id:
        body["reviewer_id"] = reviewer_id

    return await _post(f"/api/v1/pipeline/{project_id}/review", body=body)


@mcp.tool()
async def factory_advance(project_id: int) -> str:
    """Advance a project's pipeline to the next phase.

    Only advances if all tasks in the current phase are completed.
    Returns the new phase, or a waiting/remediation/escalated status.

    Args:
        project_id: The project to advance
    """
    return await _post(f"/api/v1/pipeline/{project_id}/advance")


@mcp.tool()
async def factory_pending() -> str:
    """List all tasks across all projects that are waiting for review.

    Returns tasks in the review phase that haven't received a verdict yet.
    Used to check if Specter or Phantom have work to do.
    """
    return await _get("/api/v1/pipeline/pending-reviews")


@mcp.tool()
async def factory_orphans() -> str:
    """Detect orphaned and stuck tasks across all projects.

    Returns tasks assigned to non-existent agents and tasks that have
    been in_progress for too long without completion.
    """
    return await _get("/api/v1/pipeline/orphans")


# ===================================================================
# Tools — Projects
# ===================================================================


@mcp.tool()
async def factory_projects(show_archived: bool = False) -> str:
    """List all projects in the factory.

    Args:
        show_archived: Include archived projects in the list (default: false)
    """
    params = {"show_archived": str(show_archived).lower()}
    return await _get("/api/v1/projects/", auth=False, params=params)


@mcp.tool()
async def factory_create_project(
    name: str,
    description: str = "",
    spec_product: str = "",
) -> str:
    """Create a new project in the factory.

    Args:
        name: Project name (required)
        description: Brief description of the project
        spec_product: Full PRODUCT_SPEC content for the project
    """
    return await _post(
        "/api/v1/projects/",
        auth=False,
        body={
            "name": name,
            "description": description,
            "spec_product": spec_product,
        },
    )


@mcp.tool()
async def factory_export(project_id: int) -> str:
    """Export full project data as JSON.

    Returns the project record, all tasks, and complete audit trail.
    Useful for archiving, reporting, or debugging pipeline issues.

    Args:
        project_id: The project to export
    """
    return await _get(f"/api/v1/pipeline/{project_id}/export")


# ===================================================================
# Tools — Agents
# ===================================================================


@mcp.tool()
async def factory_agents() -> str:
    """List all agents in the factory roster.

    Returns agent IDs, names, roles, models, status, task counts,
    and capabilities for all 10 registered agents.
    """
    return await _get("/api/v1/agents/", auth=False)


# ===================================================================
# Entry point
# ===================================================================

def main():
    """Run the MCP server on stdio transport."""
    logger.info("Starting Dark Factory MCP server (API: %s)", API_URL)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
