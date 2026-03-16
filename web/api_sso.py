from __future__ import annotations

import logging
from typing import Any, Callable

from lib.config import get_config
from lib.license_guard import require_feature, LicenseError

logger = logging.getLogger(__name__)

# SSO/SAML backend is not yet implemented — guard all routes
_SSO_AVAILABLE = False
try:
    from lib.sso import (  # type: ignore[import]
        SamlProvider,
        initiate_saml_login,
        handle_saml_callback,
        handle_saml_logout,
        get_saml_metadata,
    )
    _SSO_AVAILABLE = True
except (ImportError, AttributeError):
    pass


def _json_ok(data: dict[str, Any], status: int = 200) -> Callable[[], dict[str, Any]]:
    def response() -> dict[str, Any]:
        return {"status": status, "body": data}

    return response


def _json_error(message: str, status: int = 400) -> Callable[[], dict[str, Any]]:
    def response() -> dict[str, Any]:
        return {"status": status, "body": {"error": message}}

    return response


def handle_sso_request(
    request_path: str,
    request_body: dict[str, Any] | None,
) -> dict[str, Callable[[], dict[str, Any]]]:
    """Route SSO-related requests and return a json_response callable."""
    try:
        config = get_config()
    except Exception as exc:
        logger.error("Failed to load config: %s", exc)
        return {"json_response": _json_error("Service configuration error", 500)}

    try:
        require_feature("sso")
    except (LicenseError, PermissionError) as exc:
        logger.warning("SSO feature not licensed: %s", exc)
        return {"json_response": _json_error("SSO feature not available in current license", 403)}
    except Exception as exc:
        logger.error("License check failed: %s", exc)
        return {"json_response": _json_error("License validation error", 500)}

    if not _SSO_AVAILABLE:
        return {"json_response": _json_error("SSO/SAML backend not yet implemented", 501)}

    path = request_path.rstrip("/")

    # GET /sso/metadata — return SAML SP metadata XML
    if path in ("/sso/metadata", "/api/sso/metadata"):
        try:
            metadata_xml: str = get_saml_metadata(config=config)

            def _xml_response() -> dict[str, Any]:
                return {"status": 200, "body": {"metadata": metadata_xml}, "content_type": "application/xml"}

            return {"json_response": _xml_response}
        except Exception as exc:
            logger.error("Failed to generate SAML metadata: %s", exc)
            return {"json_response": _json_error("Failed to generate metadata", 500)}

    # POST /sso/login — initiate SAML login, returns redirect URL
    if path in ("/sso/login", "/api/sso/login"):
        body: dict[str, Any] = request_body or {}
        relay_state: str = str(body.get("relay_state", ""))
        idp_id: str | None = body.get("idp_id")  # type: ignore[assignment]
        try:
            provider = SamlProvider(config=config, idp_id=idp_id)
            redirect_url: str = initiate_saml_login(provider=provider, relay_state=relay_state)
            return {"json_response": _json_ok({"redirect_url": redirect_url})}
        except ValueError as exc:
            logger.warning("Invalid SSO login request: %s", exc)
            return {"json_response": _json_error(str(exc), 400)}
        except Exception as exc:
            logger.error("SSO login initiation failed: %s", exc)
            return {"json_response": _json_error("SSO login initiation failed", 500)}

    # POST /sso/callback — handle SAML assertion, return session token
    if path in ("/sso/callback", "/api/sso/callback"):
        if not request_body:
            return {"json_response": _json_error("Request body required for SSO callback", 400)}
        saml_response: str | None = request_body.get("SAMLResponse")  # type: ignore[assignment]
        relay_state_cb: str = str(request_body.get("RelayState", ""))
        if not saml_response:
            return {"json_response": _json_error("Missing SAMLResponse in callback body", 400)}
        try:
            provider_cb = SamlProvider(config=config, idp_id=None)
            session_data: dict[str, Any] = handle_saml_callback(
                provider=provider_cb,
                saml_response=saml_response,
                relay_state=relay_state_cb,
            )
            return {"json_response": _json_ok(session_data)}
        except ValueError as exc:
            logger.warning("SAML callback validation failed: %s", exc)
            return {"json_response": _json_error(str(exc), 401)}
        except Exception as exc:
            logger.error("SAML callback processing failed: %s", exc)
            return {"json_response": _json_error("SSO callback processing failed", 500)}

    # POST /sso/logout — initiate or complete SAML SLO
    if path in ("/sso/logout", "/api/sso/logout"):
        body_logout: dict[str, Any] = request_body or {}
        session_index: str | None = body_logout.get("session_index")  # type: ignore[assignment]
        name_id: str | None = body_logout.get("name_id")  # type: ignore[assignment]
        try:
            provider_lo = SamlProvider(config=config, idp_id=None)
            logout_result: dict[str, Any] = handle_saml_logout(
                provider=provider_lo,
                session_index=session_index,
                name_id=name_id,
            )
            return {"json_response": _json_ok(logout_result)}
        except ValueError as exc:
            logger.warning("SAML logout request invalid: %s", exc)
            return {"json_response": _json_error(str(exc), 400)}
        except Exception as exc:
            logger.error("SAML logout failed: %s", exc)
            return {"json_response": _json_error("SSO logout failed", 500)}

    logger.debug("No SSO route matched for path: %s", request_path)
    return {"json_response": _json_error(f"SSO route not found: {request_path}", 404)}
