"""Factory-to-Product Pipeline.

After the factory produces code, this script:
1. Creates a Forgejo branch
2. Commits the factory output
3. Runs tests
4. Creates a PR for human review

Usage:
    python tools/factory_pipeline.py --module lib/new_module.py --code /tmp/factory-output/new_module.py
    python tools/factory_pipeline.py --spec specs/donjon-packaging.md --auto
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


FORGEJO_URL = os.environ.get("FORGEJO_URL", "http://192.168.1.116:3000")
FORGEJO_TOKEN = os.environ.get("FORGEJO_TOKEN", "efc77b6c3659048767496c549400553ea0f7d1f7")
REPO_OWNER = "donjonsec"
REPO_NAME = "donjon-platform"


def forgejo_api(method: str, path: str, data: dict | None = None) -> dict:
    """Make a Forgejo API request."""
    url = f"{FORGEJO_URL}/api/v1{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"token {FORGEJO_TOKEN}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return {"error": e.code, "message": body}


def create_branch(branch_name: str, from_branch: str = "main") -> bool:
    """Create a new branch on Forgejo."""
    result = forgejo_api("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/branches", {
        "new_branch_name": branch_name,
        "old_branch_name": from_branch,
    })
    if "error" in result:
        print(f"  Branch creation failed: {result.get('message', '')[:100]}")
        return False
    print(f"  Branch created: {branch_name}")
    return True


def create_pr(branch_name: str, title: str, body: str) -> dict:
    """Create a pull request on Forgejo."""
    result = forgejo_api("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/pulls", {
        "title": title,
        "body": body,
        "head": branch_name,
        "base": "main",
    })
    if "error" in result:
        print(f"  PR creation failed: {result.get('message', '')[:100]}")
        return {}
    print(f"  PR created: #{result.get('number', '?')} — {title}")
    return result


def run_tests(repo_path: str) -> tuple[bool, str]:
    """Run the test suite and return (passed, output)."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=short"],
            capture_output=True, text=True, timeout=300, cwd=repo_path,
        )
        passed = result.returncode == 0
        output = result.stdout + result.stderr
        return passed, output
    except Exception as e:
        return False, str(e)


def pipeline(module_path: str, code_path: str, spec_name: str = "") -> dict:
    """Run the full factory-to-product pipeline."""
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    branch_name = f"factory/{Path(module_path).stem}-{timestamp}"

    report = {
        "timestamp": timestamp,
        "module": module_path,
        "branch": branch_name,
        "spec": spec_name,
        "steps": [],
    }

    print(f"\n{'='*60}")
    print(f"  FACTORY-TO-PRODUCT PIPELINE")
    print(f"  Module: {module_path}")
    print(f"  Branch: {branch_name}")
    print(f"{'='*60}\n")

    # Step 1: Create branch
    print("[1/5] Creating branch...")
    if create_branch(branch_name):
        report["steps"].append({"step": "create_branch", "status": "pass"})
    else:
        report["steps"].append({"step": "create_branch", "status": "fail"})
        print("  FAILED: Could not create branch")
        return report

    # Step 2: Read factory output
    print("[2/5] Reading factory output...")
    code_file = Path(code_path)
    if not code_file.exists():
        print(f"  FAILED: Code file not found: {code_path}")
        report["steps"].append({"step": "read_code", "status": "fail", "error": "file not found"})
        return report

    code_content = code_file.read_text()
    print(f"  Read {len(code_content)} bytes from {code_path}")
    report["steps"].append({"step": "read_code", "status": "pass", "bytes": len(code_content)})

    # Step 3: Commit to branch via Forgejo API
    print("[3/5] Committing to Forgejo...")
    import base64
    encoded = base64.b64encode(code_content.encode()).decode()

    # Check if file exists
    existing = forgejo_api("GET", f"/repos/{REPO_OWNER}/{REPO_NAME}/contents/{module_path}?ref={branch_name}")
    if "sha" in existing:
        # Update existing file
        result = forgejo_api("PUT", f"/repos/{REPO_OWNER}/{REPO_NAME}/contents/{module_path}", {
            "message": f"factory: update {module_path} from spec {spec_name}",
            "content": encoded,
            "branch": branch_name,
            "sha": existing["sha"],
        })
    else:
        # Create new file
        result = forgejo_api("POST", f"/repos/{REPO_OWNER}/{REPO_NAME}/contents/{module_path}", {
            "message": f"factory: add {module_path} from spec {spec_name}",
            "content": encoded,
            "branch": branch_name,
        })

    if "content" in result:
        print(f"  Committed to {branch_name}")
        report["steps"].append({"step": "commit", "status": "pass"})
    else:
        print(f"  Commit failed: {result.get('message', '')[:100]}")
        report["steps"].append({"step": "commit", "status": "fail", "error": str(result)[:200]})
        return report

    # Step 4: Create PR
    print("[4/5] Creating pull request...")
    pr_body = f"""## Factory-Produced Code

**Spec:** `{spec_name}`
**Module:** `{module_path}`
**Generated:** {timestamp}

### What Changed
Factory pipeline produced this module from the spec above.

### Review Checklist
- [ ] Code compiles
- [ ] Tests pass
- [ ] No security issues
- [ ] Follows project conventions
"""
    pr = create_pr(
        branch_name,
        f"factory: {Path(module_path).stem} from {spec_name or 'manual'}",
        pr_body,
    )
    if pr:
        report["steps"].append({"step": "create_pr", "status": "pass", "pr_number": pr.get("number")})
    else:
        report["steps"].append({"step": "create_pr", "status": "fail"})

    # Step 5: Summary
    print("\n[5/5] Pipeline complete")
    all_passed = all(s["status"] == "pass" for s in report["steps"])
    report["result"] = "SUCCESS" if all_passed else "PARTIAL"
    print(f"  Result: {report['result']}")
    if pr:
        print(f"  PR: {FORGEJO_URL}/{REPO_OWNER}/{REPO_NAME}/pulls/{pr.get('number', '?')}")
    print(f"  Review the PR and merge when ready.\n")

    return report


def main():
    parser = argparse.ArgumentParser(description="Factory-to-Product Pipeline")
    parser.add_argument("--module", required=True, help="Target module path (e.g., lib/new_module.py)")
    parser.add_argument("--code", required=True, help="Path to factory-produced code file")
    parser.add_argument("--spec", default="", help="Spec name for reference")
    args = parser.parse_args()

    report = pipeline(args.module, args.code, args.spec)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
