from __future__ import annotations

import logging
from typing import Any, Callable

from flask import Blueprint, Response, jsonify, request

from darkfactory.multi_tenant import TenantService
from darkfactory.license_guard import LicenseGuard

logger = logging.getLogger(__name__)

bp = Blueprint("tenants", __name__, url_prefix="/api/tenants")

_tenant_service = TenantService()
_license_guard = LicenseGuard()


def _json(data: dict[str, Any], status: int = 200) -> Response:
    resp: Response = jsonify(data)
    resp.status_code = status
    return resp


@bp.before_request
def _check_license() -> Response | None:
    if not _license_guard.is_valid():
        return _json({"error": "license invalid or expired"}, 403)
    return None


@bp.route("/", methods=["GET"])
def list_tenants() -> Response:
    try:
        tenants = _tenant_service.list_tenants()
        return _json({"tenants": tenants})
    except Exception as exc:
        logger.error("list_tenants failed: %s", exc)
        return _json({"error": str(exc)}, 500)


@bp.route("/", methods=["POST"])
def create_tenant() -> Response:
    body: dict[str, Any] | None = request.get_json(silent=True)
    if not body:
        return _json({"error": "request body required"}, 400)
    name: str | None = body.get("name")
    if not name or not isinstance(name, str):
        return _json({"error": "field 'name' is required and must be a string"}, 400)
    try:
        tenant = _tenant_service.create_tenant(name=name, metadata=body.get("metadata", {}))
        return _json({"tenant": tenant}, 201)
    except ValueError as exc:
        return _json({"error": str(exc)}, 409)
    except Exception as exc:
        logger.error("create_tenant failed: %s", exc)
        return _json({"error": str(exc)}, 500)


@bp.route("/<tenant_id>", methods=["GET"])
def get_tenant(tenant_id: str) -> Response:
    try:
        tenant = _tenant_service.get_tenant(tenant_id)
        if tenant is None:
            return _json({"error": "tenant not found"}, 404)
        return _json({"tenant": tenant})
    except Exception as exc:
        logger.error("get_tenant failed: %s", exc)
        return _json({"error": str(exc)}, 500)


@bp.route("/<tenant_id>", methods=["PUT", "PATCH"])
def update_tenant(tenant_id: str) -> Response:
    body: dict[str, Any] | None = request.get_json(silent=True)
    if not body:
        return _json({"error": "request body required"}, 400)
    try:
        tenant = _tenant_service.update_tenant(tenant_id, updates=body)
        if tenant is None:
            return _json({"error": "tenant not found"}, 404)
        return _json({"tenant": tenant})
    except ValueError as exc:
        return _json({"error": str(exc)}, 400)
    except Exception as exc:
        logger.error("update_tenant failed: %s", exc)
        return _json({"error": str(exc)}, 500)


@bp.route("/<tenant_id>", methods=["DELETE"])
def delete_tenant(tenant_id: str) -> Response:
    try:
        deleted = _tenant_service.delete_tenant(tenant_id)
        if not deleted:
            return _json({"error": "tenant not found"}, 404)
        return _json({"deleted": True})
    except Exception as exc:
        logger.error("delete_tenant failed: %s", exc)
        return _json({"error": str(exc)}, 500)


@bp.route("/<tenant_id>/members", methods=["GET"])
def list_members(tenant_id: str) -> Response:
    try:
        members = _tenant_service.list_members(tenant_id)
        if members is None:
            return _json({"error": "tenant not found"}, 404)
        return _json({"members": members})
    except Exception as exc:
        logger.error("list_members failed: %s", exc)
        return _json({"error": str(exc)}, 500)


@bp.route("/<tenant_id>/members", methods=["POST"])
def add_member(tenant_id: str) -> Response:
    body: dict[str, Any] | None = request.get_json(silent=True)
    if not body:
        return _json({"error": "request body required"}, 400)
    user_id: str | None = body.get("user_id")
    if not user_id or not isinstance(user_id, str):
        return _json({"error": "field 'user_id' is required and must be a string"}, 400)
    role: str = body.get("role", "member")
    try:
        member = _tenant_service.add_member(tenant_id, user_id=user_id, role=role)
        if member is None:
            return _json({"error": "tenant not found"}, 404)
        return _json({"member": member}, 201)
    except ValueError as exc:
        return _json({"error": str(exc)}, 409)
    except Exception as exc:
        logger.error("add_member failed: %s", exc)
        return _json({"error": str(exc)}, 500)


@bp.route("/<tenant_id>/members/<user_id>", methods=["DELETE"])
def remove_member(tenant_id: str, user_id: str) -> Response:
    try:
        removed = _tenant_service.remove_member(tenant_id, user_id=user_id)
        if not removed:
            return _json({"error": "member not found"}, 404)
        return _json({"removed": True})
    except Exception as exc:
        logger.error("remove_member failed: %s", exc)
        return _json({"error": str(exc)}, 500)


def json_response() -> Callable[..., Response]:
    """Return the Blueprint's dispatch callable as required by the contract output."""
    return bp.make_response  # type: ignore[return-value]
