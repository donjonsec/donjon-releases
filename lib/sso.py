from __future__ import annotations

import base64
import hashlib
import logging
import re
import uuid
import zlib
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

# SAML XML namespaces
_NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "xs": "http://www.w3.org/2001/XMLSchema",
}

for _prefix, _uri in _NS.items():
    ET.register_namespace(_prefix, _uri)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return "_" + uuid.uuid4().hex


def _require(config: dict[str, Any], *keys: str) -> None:
    missing = [k for k in keys if not config.get(k)]
    if missing:
        raise ValueError(f"Missing required config keys: {', '.join(missing)}")


def _build_sp_metadata(config: dict[str, Any]) -> str:
    _require(config, "sp_entity_id", "sp_acs_url")
    entity_id: str = config["sp_entity_id"]
    acs_url: str = config["sp_acs_url"]
    name_id_format: str = config.get(
        "name_id_format",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    )

    root = ET.Element(
        "{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor",
        attrib={
            "entityID": entity_id,
            "xmlns": "urn:oasis:names:tc:SAML:2.0:metadata",
        },
    )
    sp = ET.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor",
        attrib={
            "AuthnRequestsSigned": "false",
            "WantAssertionsSigned": "true",
            "protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
    )
    ET.SubElement(
        sp,
        "{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat",
    ).text = name_id_format
    ET.SubElement(
        sp,
        "{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService",
        attrib={
            "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "Location": acs_url,
            "index": "1",
        },
    )
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def _build_authn_request(config: dict[str, Any]) -> dict[str, Any]:
    _require(config, "sp_entity_id", "sp_acs_url", "idp_sso_url")
    entity_id: str = config["sp_entity_id"]
    acs_url: str = config["sp_acs_url"]
    idp_sso_url: str = config["idp_sso_url"]
    name_id_format: str = config.get(
        "name_id_format",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    )
    request_id = _new_id()
    issue_instant = _utcnow()

    root = ET.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
        attrib={
            "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "ID": request_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
            "Destination": idp_sso_url,
            "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "AssertionConsumerServiceURL": acs_url,
        },
    )
    ET.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer",
    ).text = entity_id
    name_id_policy = ET.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy",
        attrib={
            "Format": name_id_format,
            "AllowCreate": "true",
        },
    )
    _ = name_id_policy  # used structurally

    xml_str = ET.tostring(root, encoding="unicode")
    deflated = zlib.compress(xml_str.encode("utf-8"))[2:-4]  # raw deflate
    encoded = base64.b64encode(deflated).decode("ascii")
    params: dict[str, str] = {"SAMLRequest": encoded}
    relay_state: str | None = config.get("relay_state")
    if relay_state:
        params["RelayState"] = relay_state
    redirect_url = idp_sso_url + "?" + urlencode(params, quote_via=quote)

    return {
        "request_id": request_id,
        "redirect_url": redirect_url,
        "saml_request_xml": xml_str,
    }


def _extract_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return (element.text or "").strip()


def _parse_saml_response(config: dict[str, Any]) -> dict[str, Any]:
    _require(config, "saml_response")
    raw: str = config["saml_response"]

    try:
        xml_bytes = base64.b64decode(raw)
    except Exception as exc:
        raise ValueError(f"Invalid base64 in saml_response: {exc}") from exc

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed SAML response XML: {exc}") from exc

    # Check status
    status_code = root.find(".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
    if status_code is not None:
        value = status_code.get("Value", "")
        if "Success" not in value:
            status_msg_el = root.find(".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage")
            status_msg = _extract_text(status_msg_el) if status_msg_el is not None else value
            raise ValueError(f"SAML authentication failed: {status_msg}")

    # Extract NameID
    name_id_el = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    name_id = _extract_text(name_id_el)

    # Validate conditions
    conditions_el = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
    if conditions_el is not None:
        not_before_str = conditions_el.get("NotBefore", "")
        not_on_or_after_str = conditions_el.get("NotOnOrAfter", "")
        now_str = _utcnow()
        if not_before_str and now_str < not_before_str:
            raise ValueError(f"SAML assertion not yet valid (NotBefore={not_before_str})")
        if not_on_or_after_str and now_str >= not_on_or_after_str:
            raise ValueError(f"SAML assertion has expired (NotOnOrAfter={not_on_or_after_str})")

    # Extract attributes
    attributes: dict[str, Any] = {}
    for attr_el in root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
        attr_name = attr_el.get("Name", attr_el.get("FriendlyName", ""))
        if not attr_name:
            continue
        values = [_extract_text(v) for v in attr_el.findall("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")]
        attributes[attr_name] = values[0] if len(values) == 1 else values

    # Normalize common attribute names
    def _pick(*candidates: str) -> str:
        for c in candidates:
            if c in attributes:
                return str(attributes[c])
            # case-insensitive + short-name match
            for k, v in attributes.items():
                if k.lower().endswith(c.lower()) or k == c:
                    return str(v)
        return ""

    email = (
        _pick(
            "email",
            "mail",
            "emailAddress",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        )
        or name_id
    )
    first_name = _pick(
        "firstName",
        "givenName",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    )
    last_name = _pick(
        "lastName",
        "surname",
        "sn",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    )
    display_name = (
        _pick(
            "displayName",
            "cn",
            "name",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        )
        or f"{first_name} {last_name}".strip()
    )

    groups_raw = attributes.get(
        "groups",
        attributes.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", []),
    )
    groups: list[str] = groups_raw if isinstance(groups_raw, list) else [groups_raw] if groups_raw else []

    # Stable user ID derived from name_id
    user_id = hashlib.sha256(name_id.encode()).hexdigest()[:32] if name_id else ""

    user: dict[str, Any] = {
        "id": user_id,
        "name_id": name_id,
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
        "display_name": display_name,
        "groups": groups,
        "attributes": attributes,
    }
    return user


def _parse_idp_metadata(metadata_xml: str) -> dict[str, str]:
    """Extract IdP SSO URL and certificate from IdP metadata XML."""
    try:
        root = ET.fromstring(metadata_xml)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid IdP metadata XML: {exc}") from exc

    sso_url = ""
    idp_descriptor = root.find(".//{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor")
    if idp_descriptor is not None:
        for sso_el in idp_descriptor.findall("{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"):
            binding = sso_el.get("Binding", "")
            if "HTTP-Redirect" in binding or "HTTP-POST" in binding:
                sso_url = sso_el.get("Location", "")
                if "HTTP-Redirect" in binding:
                    break

    cert_el = None
    if idp_descriptor is not None:
        cert_el = idp_descriptor.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
    cert = _extract_text(cert_el) if cert_el is not None else ""
    cert = re.sub(r"\s+", "", cert)

    return {"sso_url": sso_url, "certificate": cert}


def handle(action: str, config: dict[str, Any]) -> dict[str, Any]:
    """
    Dispatch SAML SSO actions.

    Actions:
      - "metadata"     : Return SP metadata XML (no user extraction).
      - "initiate"     : Build an AuthnRequest and return redirect URL.
      - "authenticate" : Parse a SAMLResponse and return user attributes.
      - "parse_idp"    : Parse IdP metadata XML from config["idp_metadata_xml"].

    Returns {"user": dict, "metadata_xml": str} per contract.
    """
    if not action:
        raise ValueError("action must be a non-empty string")
    if not isinstance(config, dict):
        raise TypeError("config must be a dict")

    user: dict[str, Any] = {}
    metadata_xml: str = ""

    # Optionally parse bundled IdP metadata to enrich config
    if config.get("idp_metadata_xml") and not config.get("idp_sso_url"):
        idp_info = _parse_idp_metadata(str(config["idp_metadata_xml"]))
        config = {**config, "idp_sso_url": idp_info["sso_url"], **config}

    if action == "metadata":
        metadata_xml = _build_sp_metadata(config)

    elif action == "initiate":
        authn = _build_authn_request(config)
        metadata_xml = _build_sp_metadata(config) if config.get("sp_entity_id") else ""
        user = {
            "request_id": authn["request_id"],
            "redirect_url": authn["redirect_url"],
            "saml_request_xml": authn["saml_request_xml"],
        }

    elif action == "authenticate":
        user = _parse_saml_response(config)
        if config.get("sp_entity_id"):
            try:
                metadata_xml = _build_sp_metadata(config)
            except ValueError:
                pass  # SP metadata is supplementary; don't fail auth

    elif action == "parse_idp":
        _require(config, "idp_metadata_xml")
        idp_info = _parse_idp_metadata(str(config["idp_metadata_xml"]))
        user = idp_info

    else:
        raise ValueError(f"Unknown action '{action}'. Expected one of: metadata, initiate, authenticate, parse_idp")

    logger.debug("sso.handle action=%s user_keys=%s", action, list(user.keys()))
    return {"user": user, "metadata_xml": metadata_xml}
