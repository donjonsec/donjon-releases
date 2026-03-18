from __future__ import annotations

import logging
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


class ProxyHandler:
    """Wraps urllib ProxyHandler with configuration state."""

    _handler: urllib.request.ProxyHandler
    _configured: bool
    _proxies: dict[str, str]

    def __init__(self, proxies: dict[str, str]) -> None:
        self._proxies = proxies
        self._handler = urllib.request.ProxyHandler(proxies)
        self._configured = bool(proxies)

    @property
    def configured(self) -> bool:
        return self._configured

    @property
    def proxies(self) -> dict[str, str]:
        return dict(self._proxies)

    def get_urllib_handler(self) -> urllib.request.ProxyHandler:
        return self._handler

    def build_opener(self) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(self._handler)


def create_proxy_handler(config: dict[str, Any]) -> dict[str, Any]:
    """

    Recognised config keys:
      http    – proxy URL for HTTP traffic   (e.g. "http://proxy.example.com:3128")
      https   – proxy URL for HTTPS traffic
      no_proxy / no_proxy_hosts – comma-separated hostnames to bypass
    """
    if not isinstance(config, dict):
        raise TypeError(f"config must be a dict, got {type(config).__name__}")

    proxies: dict[str, str] = {}

    http_proxy = config.get("http") or config.get("http_proxy")
    if http_proxy:
        if not isinstance(http_proxy, str):
            raise ValueError("http proxy must be a string")
        proxies["http"] = http_proxy

    https_proxy = config.get("https") or config.get("https_proxy")
    if https_proxy:
        if not isinstance(https_proxy, str):
            raise ValueError("https proxy must be a string")
        proxies["https"] = https_proxy

    no_proxy = config.get("no_proxy") or config.get("no_proxy_hosts")
    if no_proxy:
        if not isinstance(no_proxy, str):
            raise ValueError("no_proxy must be a string")
        proxies["no"] = no_proxy

    handler = ProxyHandler(proxies)

    if handler.configured:
        logger.debug("Proxy handler configured with schemes: %s", list(proxies.keys()))
    else:
        logger.debug("No proxy configuration provided; handler is a pass-through")

    return {"handler": handler, "configured": handler.configured}
