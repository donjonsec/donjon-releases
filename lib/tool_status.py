from __future__ import annotations

import logging
from typing import TypedDict

logger = logging.getLogger(__name__)


class ToolStatusInput(TypedDict):
    scanner_id: str


class ToolStatusOutput(TypedDict):
    tools: dict[str, object]
    ready: bool


_SCANNER_REGISTRY: dict[str, dict[str, object]] = {}


def get_tool_status(scanner_id: str) -> ToolStatusOutput:
    if not scanner_id or not isinstance(scanner_id, str):
        raise ValueError(f"scanner_id must be a non-empty string, got: {scanner_id!r}")

    scanner_id = scanner_id.strip()
    if not scanner_id:
        raise ValueError("scanner_id must not be blank")

    logger.debug("Fetching tool status for scanner_id=%r", scanner_id)

    tools = _SCANNER_REGISTRY.get(scanner_id, {})
    ready = bool(tools) and all(isinstance(v, dict) and v.get("status") == "ready" for v in tools.values())

    logger.debug("scanner_id=%r tools_count=%d ready=%s", scanner_id, len(tools), ready)

    return ToolStatusOutput(tools=tools, ready=ready)


def register_scanner_tools(scanner_id: str, tools: dict[str, object]) -> None:
    if not scanner_id or not isinstance(scanner_id, str):
        raise ValueError(f"scanner_id must be a non-empty string, got: {scanner_id!r}")
    if not isinstance(tools, dict):
        raise TypeError(f"tools must be a dict, got: {type(tools).__name__}")

    _SCANNER_REGISTRY[scanner_id.strip()] = tools
    logger.info("Registered %d tool(s) for scanner_id=%r", len(tools), scanner_id)
