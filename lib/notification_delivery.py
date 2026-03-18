from __future__ import annotations

import logging
import smtplib
import urllib.request
import urllib.parse
import urllib.error
import json
from email.mime.text import MIMEText
from typing import Any

logger = logging.getLogger(__name__)


def deliver_notification(
    channel_type: str,
    config: dict[str, Any],
    message: str,
) -> dict[str, str | bool]:
    try:
        if channel_type == "email":
            return _deliver_email(config, message)
        elif channel_type == "webhook":
            return _deliver_webhook(config, message)
        elif channel_type == "slack":
            return _deliver_slack(config, message)
        elif channel_type == "log":
            return _deliver_log(config, message)
        else:
            return {"delivered": False, "error": f"Unknown channel_type: {channel_type}"}
    except Exception as exc:
        logger.error("Notification delivery failed: %s", exc)
        return {"delivered": False, "error": str(exc)}


def _deliver_email(config: dict[str, Any], message: str) -> dict[str, str | bool]:
    host = str(config.get("host", "localhost"))
    port_raw = config.get("port", 25)
    if not isinstance(port_raw, (int, float)):
        return {"delivered": False, "error": "config.port must be a number"}
    port = int(port_raw)
    sender = str(config.get("from", "noreply@localhost"))
    recipient = str(config.get("to", ""))
    subject = str(config.get("subject", "Notification"))

    if not recipient:
        return {"delivered": False, "error": "config.to is required for email channel"}

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    use_tls = bool(config.get("tls", False))
    username = config.get("username")
    password = config.get("password")

    if use_tls:
        smtp: smtplib.SMTP = smtplib.SMTP_SSL(host, port)
    else:
        smtp = smtplib.SMTP(host, port)

    with smtp:
        if username is not None and password is not None:
            smtp.login(str(username), str(password))
        smtp.sendmail(sender, [recipient], msg.as_string())

    return {"delivered": True, "error": ""}


def _deliver_webhook(config: dict[str, Any], message: str) -> dict[str, str | bool]:
    url = str(config.get("url", ""))
    if not url:
        return {"delivered": False, "error": "config.url is required for webhook channel"}

    method = str(config.get("method", "POST")).upper()
    headers: dict[str, str] = {}
    raw_headers = config.get("headers", {})
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            headers[str(k)] = str(v)

    payload_type = str(config.get("payload_type", "json"))
    if payload_type == "json":
        body = json.dumps({"message": message}).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    else:
        body = message.encode("utf-8")
        headers.setdefault("Content-Type", "text/plain")

    timeout_raw = config.get("timeout", 10)
    if not isinstance(timeout_raw, (int, float)):
        timeout = 10
    else:
        timeout = int(timeout_raw)

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status: int = resp.status
            if 200 <= status < 300:
                return {"delivered": True, "error": ""}
            return {"delivered": False, "error": f"HTTP {status}"}
    except urllib.error.HTTPError as exc:
        return {"delivered": False, "error": f"HTTP {exc.code}: {exc.reason}"}
    except urllib.error.URLError as exc:
        return {"delivered": False, "error": str(exc.reason)}


def _deliver_slack(config: dict[str, Any], message: str) -> dict[str, str | bool]:
    webhook_url = str(config.get("webhook_url", ""))
    if not webhook_url:
        return {"delivered": False, "error": "config.webhook_url is required for slack channel"}

    channel = config.get("channel")
    payload: dict[str, Any] = {"text": message}
    if channel is not None:
        payload["channel"] = str(channel)

    username = config.get("username")
    if username is not None:
        payload["username"] = str(username)

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            if 200 <= status < 300:
                return {"delivered": True, "error": ""}
            return {"delivered": False, "error": f"HTTP {status}"}
    except urllib.error.HTTPError as exc:
        return {"delivered": False, "error": f"HTTP {exc.code}: {exc.reason}"}
    except urllib.error.URLError as exc:
        return {"delivered": False, "error": str(exc.reason)}


def _deliver_log(config: dict[str, Any], message: str) -> dict[str, str | bool]:
    level_str = str(config.get("level", "INFO")).upper()
    level = getattr(logging, level_str, logging.INFO)
    if not isinstance(level, int):
        level = logging.INFO
    logger.log(level, "%s", message)
    return {"delivered": True, "error": ""}
