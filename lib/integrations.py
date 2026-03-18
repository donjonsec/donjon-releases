from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


def _build_auth_header(username: str, password: str) -> str:
    creds = f"{username}:{password}"
    encoded = base64.b64encode(creds.encode("utf-8")).decode("utf-8")
    return f"Basic {encoded}"


def _http_post(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)  # type: ignore[no-any-return]


def _create_jira_ticket(finding_id: str, config: dict[str, Any]) -> dict[str, Any]:
    url = config["url"].rstrip("/") + "/rest/api/2/issue"
    auth = _build_auth_header(config["username"], config["api_token"])
    headers = {
        "Authorization": auth,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload: dict[str, Any] = {
        "fields": {
            "project": {"key": config["project_key"]},
            "summary": f"Security Finding: {finding_id}",
            "description": f"Automated ticket created for finding ID: {finding_id}",
            "issuetype": {"name": config.get("issue_type", "Bug")},
        }
    }
    result = _http_post(url, payload, headers)
    return {
        "integration": "jira",
        "finding_id": finding_id,
        "ticket_id": result.get("key", ""),
        "ticket_url": f"{config['url'].rstrip('/')}/browse/{result.get('key', '')}",
    }


def _create_snow_ticket(finding_id: str, config: dict[str, Any]) -> dict[str, Any]:
    table = config.get("table", "incident")
    instance = config["instance_url"].rstrip("/")
    url = f"{instance}/api/now/table/{table}"
    auth = _build_auth_header(config["username"], config["password"])
    headers = {
        "Authorization": auth,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload: dict[str, Any] = {
        "short_description": f"Security Finding: {finding_id}",
        "description": f"Automated ticket created for finding ID: {finding_id}",
        "category": config.get("category", "security"),
        "urgency": config.get("urgency", "2"),
        "impact": config.get("impact", "2"),
    }
    result = _http_post(url, payload, headers)
    record = result.get("result", {})
    sys_id = record.get("sys_id", "")
    number = record.get("number", "")
    return {
        "integration": "snow",
        "finding_id": finding_id,
        "ticket_id": number or sys_id,
        "ticket_url": f"{instance}/{table}.do?sys_id={sys_id}",
    }


def create_tickets(
    finding_ids: list[str],
    config: dict[str, Any],
) -> dict[str, list[Any]]:
    if not isinstance(finding_ids, list):
        raise TypeError(f"finding_ids must be a list, got {type(finding_ids).__name__}")
    if not isinstance(config, dict):
        raise TypeError(f"config must be a dict, got {type(config).__name__}")

    tickets: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    jira_cfg: dict[str, Any] | None = config.get("jira")
    snow_cfg: dict[str, Any] | None = config.get("snow")

    if jira_cfg is None and snow_cfg is None:
        logger.warning("No integration configured in config (expected 'jira' and/or 'snow' keys)")

    for finding_id in finding_ids:
        if not isinstance(finding_id, str) or not finding_id.strip():
            errors.append({"finding_id": finding_id, "error": "Invalid or empty finding_id"})
            continue

        if jira_cfg is not None:
            required_jira = {"url", "username", "api_token", "project_key"}
            missing = required_jira - jira_cfg.keys()
            if missing:
                errors.append(
                    {
                        "finding_id": finding_id,
                        "integration": "jira",
                        "error": f"Missing Jira config keys: {sorted(missing)}",
                    }
                )
            else:
                try:
                    ticket = _create_jira_ticket(finding_id, jira_cfg)
                    tickets.append(ticket)
                    logger.info("Jira ticket created for finding %s: %s", finding_id, ticket["ticket_id"])
                except urllib.error.HTTPError as exc:
                    body = ""
                    try:
                        body = exc.read().decode("utf-8")
                    except Exception:
                        pass
                    errors.append(
                        {
                            "finding_id": finding_id,
                            "integration": "jira",
                            "error": f"HTTP {exc.code}: {body}",
                        }
                    )
                except Exception as exc:
                    errors.append(
                        {
                            "finding_id": finding_id,
                            "integration": "jira",
                            "error": str(exc),
                        }
                    )

        if snow_cfg is not None:
            required_snow = {"instance_url", "username", "password"}
            missing = required_snow - snow_cfg.keys()
            if missing:
                errors.append(
                    {
                        "finding_id": finding_id,
                        "integration": "snow",
                        "error": f"Missing ServiceNow config keys: {sorted(missing)}",
                    }
                )
            else:
                try:
                    ticket = _create_snow_ticket(finding_id, snow_cfg)
                    tickets.append(ticket)
                    logger.info("ServiceNow ticket created for finding %s: %s", finding_id, ticket["ticket_id"])
                except urllib.error.HTTPError as exc:
                    body = ""
                    try:
                        body = exc.read().decode("utf-8")
                    except Exception:
                        pass
                    errors.append(
                        {
                            "finding_id": finding_id,
                            "integration": "snow",
                            "error": f"HTTP {exc.code}: {body}",
                        }
                    )
                except Exception as exc:
                    errors.append(
                        {
                            "finding_id": finding_id,
                            "integration": "snow",
                            "error": str(exc),
                        }
                    )

    return {"tickets": tickets, "errors": errors}
