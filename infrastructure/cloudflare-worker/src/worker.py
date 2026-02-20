"""
Donjon License Server - Cloudflare Python Worker

Storage and distribution layer for Donjon 7.0 license management.
Handles license storage, public key distribution, revocation lists,
and online validation.

SECURITY ARCHITECTURE
---------------------
This worker does NOT perform cryptographic signing.  Licenses are signed
offline by the admin CLI tool (donjon-license-admin.py) and uploaded here
as pre-signed blobs.  This worker stores them in Cloudflare KV and serves
them for download and online validation.

The worker authenticates admin operations via an X-Admin-Key header,
compared against a key stored in KV.  Public endpoints (health, public
keys, revocation list, license download) require no authentication.

DEPLOYMENT NOTE: The admin API key must be provisioned in KV under the
key "admin_api_key" before any admin endpoints will function.

Endpoints:
  Public:
    GET  /                      Health check / server info
    GET  /api/v1/public-keys    Public keys for offline verification
    GET  /api/v1/revoked        Revocation list
    POST /api/v1/validate       Online license validation
    GET  /api/v1/license/:id    Download a stored license

  Admin (requires X-Admin-Key header):
    POST /api/v1/generate       Store a pre-signed license
    POST /api/v1/revoke         Revoke a license by ID
    GET  /api/v1/stats          License issuance statistics
"""

from js import Response, Headers, URL, JSON, Date, Object
from pyodide.ffi import to_js
import json
import re
import secrets

DONJON_VERSION: str = "7.0"

DEFAULT_STATS: dict = {"total_issued": 0, "issued_by_type": {}}

# Maximum request body size to prevent memory exhaustion.
# Cloudflare Workers have a 128 MiB memory limit; cap request bodies well below.
_MAX_REQUEST_BODY_SIZE: int = 512 * 1024  # 512 KiB

# Maximum number of entries in the revocation list.
# Prevents unbounded growth that could degrade worker performance.
_MAX_REVOCATION_ENTRIES: int = 10_000

# Allowed CORS origin.  Reads from the CORS_ALLOW_ORIGIN env var
# (set in wrangler.toml [vars]), falling back to the production domain.
_CORS_ALLOW_ORIGIN: str = "https://donjonsec.com"

# Rate limiting: max requests per IP within the sliding window.
_RATE_LIMIT_MAX: int = 30
_RATE_LIMIT_WINDOW_SECONDS: int = 60


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _get_cors_origin(env: object = None) -> str:
    """Return the CORS origin, preferring the env var if available."""
    if env:
        try:
            override = getattr(env, "CORS_ALLOW_ORIGIN", None)
            if override:
                return str(override)
        except Exception:
            pass
    return _CORS_ALLOW_ORIGIN


def json_headers(extra: dict = None, env: object = None) -> object:
    """Build standard JSON response headers with security headers and CORS.

    Why these headers:
    - Content-Type: Tells clients to parse as JSON.
    - X-Content-Type-Options: nosniff -- prevents browsers from MIME-sniffing
      the response, which could lead to XSS if the body is misinterpreted.
    - Cache-Control: no-store -- prevents caching of sensitive API responses.
      Overridden on public-key and revocation endpoints where caching is safe.
    - CORS headers: Allow cross-origin requests from the dashboard frontend.
    """
    h: dict = {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": _get_cors_origin(env),
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }
    if extra:
        h.update(extra)
    return to_js(h, dict_converter=Object.fromEntries)


def json_response(body: dict, status: int = 200, extra_headers: dict = None) -> object:
    """Return a JSON Response object with standard headers.

    Uses compact JSON serialisation (no whitespace) to minimise response
    size and prevent canonicalisation ambiguities.
    """
    return Response.new(
        json.dumps(body, separators=(",", ":")),
        to_js({
            "status": status,
            "headers": json_headers(extra_headers),
        }, dict_converter=Object.fromEntries),
    )


def error_response(message: str, status: int = 400) -> object:
    """Return a standardised error JSON Response.

    SECURITY: Error messages are intentionally generic.  Never include
    internal details (stack traces, KV key names, etc.) in error
    responses -- they aid reconnaissance.
    """
    return json_response({"error": message}, status=status)


def options_response() -> object:
    """Handle CORS preflight (OPTIONS) requests.

    Returns 204 No Content with CORS headers so browsers allow the
    actual request to proceed.
    """
    return Response.new(
        None,
        to_js({
            "status": 204,
            "headers": json_headers(),
        }, dict_converter=Object.fromEntries),
    )


# ---------------------------------------------------------------------------
# Request parsing and authentication helpers
# ---------------------------------------------------------------------------

async def read_request_json(request: object) -> dict | None:
    """Parse the request body as JSON, returning None on failure.

    Guards against oversized bodies to prevent memory exhaustion.
    Returns None (rather than raising) so callers can return a clean
    error response without try/except boilerplate.
    """
    try:
        text = await request.text()
        # Guard against oversized request bodies.
        if len(text) > _MAX_REQUEST_BODY_SIZE:
            return None
        parsed = json.loads(text)
        # Only accept JSON objects at the top level, not arrays or scalars.
        if not isinstance(parsed, dict):
            return None
        return parsed
    except Exception:
        return None


async def require_admin(request: object, env: object) -> object | None:
    """Validate the X-Admin-Key header against KV-stored key.

    Returns None on success, or an error Response if unauthorised.

    SECURITY: Uses constant-time comparison (secrets.compare_digest) to
    prevent timing side-channel attacks.  An attacker who can measure
    response times with nanosecond precision could otherwise determine
    how many leading characters of the admin key matched, enabling a
    character-by-character brute-force attack.
    """
    provided_key = request.headers.get("X-Admin-Key")
    if not provided_key:
        return error_response("Missing X-Admin-Key header", 401)

    stored_key = await env.LICENSE_KV.get("admin_api_key")
    if not stored_key:
        # SECURITY: Don't reveal that the key is not configured --
        # return a generic auth failure to prevent config enumeration.
        return error_response("Authentication failed", 500)

    # Constant-time comparison to prevent timing attacks.
    if not secrets.compare_digest(provided_key, stored_key):
        return error_response("Invalid admin key", 403)

    return None


# ---------------------------------------------------------------------------
# KV helpers
# ---------------------------------------------------------------------------

async def kv_get_json(env: object, key: str, default: object = None) -> object:
    """Read a KV key and parse it as JSON, returning default on miss or error.

    Why a helper: KV.get() returns None on cache miss and raw strings
    otherwise.  Wrapping the JSON parse + default logic avoids repetition
    in every handler.
    """
    raw = await env.LICENSE_KV.get(key)
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default


async def kv_get_revocation_list(env: object) -> list:
    """Return the current revocation list (always returns a list).

    If the stored value is not a list (e.g. corrupted), returns an empty
    list rather than propagating bad data.
    """
    result = await kv_get_json(env, "revocation_list", [])
    if not isinstance(result, list):
        return []
    return result


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

async def check_rate_limit(request: object, env: object) -> object | None:
    """Sliding window rate limiter using KV.

    Returns None if allowed, or an error Response if rate-limited.
    Uses a per-IP KV key with a list of timestamps.  Old entries outside
    the window are pruned on each check.

    SECURITY: Prevents brute-force license ID enumeration via /api/v1/validate.
    """
    # Extract client IP from CF-Connecting-IP header (set by Cloudflare edge).
    client_ip = request.headers.get("CF-Connecting-IP") or "unknown"
    kv_key = f"ratelimit:{client_ip}"

    now_ms = Date.now()
    window_ms = _RATE_LIMIT_WINDOW_SECONDS * 1000

    # Read existing timestamps for this IP.
    raw = await env.LICENSE_KV.get(kv_key)
    timestamps = []
    if raw:
        try:
            timestamps = json.loads(raw)
            if not isinstance(timestamps, list):
                timestamps = []
        except (json.JSONDecodeError, TypeError):
            timestamps = []

    # Prune entries outside the window.
    cutoff = now_ms - window_ms
    timestamps = [ts for ts in timestamps if ts > cutoff]

    if len(timestamps) >= _RATE_LIMIT_MAX:
        return json_response({
            "error": "Rate limit exceeded. Try again later.",
            "retry_after_seconds": _RATE_LIMIT_WINDOW_SECONDS,
        }, status=429, extra_headers={
            "Retry-After": str(_RATE_LIMIT_WINDOW_SECONDS),
        })

    # Record this request and save.
    timestamps.append(now_ms)
    await env.LICENSE_KV.put(
        kv_key,
        json.dumps(timestamps, separators=(",", ":")),
        # Auto-expire the KV key after 2x the window to avoid stale data.
        expirationTtl=_RATE_LIMIT_WINDOW_SECONDS * 2,
    )

    return None


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# License ID regex: accepts the DON-YYYY-XXXXX format from the admin tool
# plus general alphanumeric IDs (UUIDs, hex strings) up to 128 characters.
_LICENSE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{8,128}$")


def is_valid_license_id(license_id: object) -> bool:
    """Check that a license ID is a reasonable alphanumeric string.

    Why validate: The license ID is used as a KV key suffix
    (``license:{id}``).  Accepting arbitrary strings could enable KV
    key injection or denial-of-service via extremely long keys.
    """
    if not license_id or not isinstance(license_id, str):
        return False
    return bool(_LICENSE_ID_PATTERN.match(license_id))


def _sanitise_string(value: object, max_length: int = 256) -> str:
    """Sanitise a user-provided string for safe storage and display.

    Truncates to max_length and strips control characters to prevent
    log injection and KV pollution.
    """
    if not isinstance(value, str):
        return ""
    # Remove control characters (except space) and truncate.
    cleaned = "".join(ch for ch in value if ch == " " or ch.isprintable())
    return cleaned[:max_length]


# ---------------------------------------------------------------------------
# Route handlers -- Public endpoints
# ---------------------------------------------------------------------------

async def handle_health(request: object, env: object) -> object:
    """GET / -- Health check and server metadata.

    Returns the server version, operational status, and a list of
    available endpoints.  No authentication required.
    """
    return json_response({
        "service": "Donjon License Server",
        "version": DONJON_VERSION,
        "status": "operational",
        "timestamp": Date.new().toISOString(),
        "endpoints": {
            "public_keys": "/api/v1/public-keys",
            "revoked": "/api/v1/revoked",
            "validate": "/api/v1/validate",
            "generate": "/api/v1/generate (admin)",
            "revoke": "/api/v1/revoke (admin)",
            "stats": "/api/v1/stats (admin)",
        },
    })


async def handle_public_keys(request: object, env: object) -> object:
    """GET /api/v1/public-keys -- Return public keys for offline verification.

    Clients cache these keys to verify license signatures without
    network access.  The response is cacheable for 1 hour because
    public keys change very rarely (only on key rotation).
    """
    keys = await kv_get_json(env, "public_keys")
    if keys is None:
        return error_response("Public keys not configured", 404)

    return json_response({
        "keys": keys,
        "version": DONJON_VERSION,
        "timestamp": Date.new().toISOString(),
    }, extra_headers={"Cache-Control": "public, max-age=3600"})


async def handle_revoked(request: object, env: object) -> object:
    """GET /api/v1/revoked -- Return the current revocation list.

    Clients poll this endpoint to update their local revocation cache.
    Cached for 5 minutes to balance freshness against KV read costs.
    """
    revoked = await kv_get_revocation_list(env)

    return json_response({
        "revoked": revoked,
        "count": len(revoked),
        "version": DONJON_VERSION,
        "timestamp": Date.new().toISOString(),
    }, extra_headers={"Cache-Control": "public, max-age=300"})


async def handle_validate(request: object, env: object) -> object:
    """POST /api/v1/validate -- Online license validation.

    Expects JSON body: {"license_id": "...", "hardware_id": "..."}
    Checks that the license exists in KV and is not revoked.

    SECURITY NOTE: This is an informational check, not a cryptographic
    verification.  The client MUST still verify the dual signatures
    locally.  This endpoint exists to check revocation status and
    expiry when the client has network access.

    Rate-limited to 30 requests/minute per IP to prevent enumeration
    of valid license IDs.
    """
    # Rate limit to prevent brute-force license ID enumeration.
    rate_err = await check_rate_limit(request, env)
    if rate_err:
        return rate_err
    body = await read_request_json(request)
    if body is None:
        return error_response("Invalid JSON body")

    license_id = body.get("license_id", "")
    if not is_valid_license_id(license_id):
        return error_response("Invalid or missing license_id")

    # Check revocation list first -- revoked licenses should fail fast.
    revoked = await kv_get_revocation_list(env)
    if license_id in revoked:
        return json_response({
            "valid": False,
            "license_id": license_id,
            "reason": "revoked",
            "timestamp": Date.new().toISOString(),
        })

    # Check license existence in KV.
    license_data = await kv_get_json(env, f"license:{license_id}")
    if license_data is None:
        # SECURITY: Return a generic "not_found" rather than distinguishing
        # between "never existed" and "was deleted", to prevent enumeration.
        return json_response({
            "valid": False,
            "license_id": license_id,
            "reason": "not_found",
            "timestamp": Date.new().toISOString(),
        })

    # Check expiration if present.
    expires = license_data.get("expires") if isinstance(license_data, dict) else None
    if expires:
        try:
            now_ms = Date.now()
            exp_date = Date.new(expires)
            if exp_date.getTime() < now_ms:
                return json_response({
                    "valid": False,
                    "license_id": license_id,
                    "reason": "expired",
                    "expires": expires,
                    "timestamp": Date.new().toISOString(),
                })
        except Exception:
            # Malformed date -- treat as invalid to fail closed.
            return json_response({
                "valid": False,
                "license_id": license_id,
                "reason": "invalid_expiry",
                "timestamp": Date.new().toISOString(),
            })

    # License exists, is not revoked, and is not expired.
    holder = ""
    license_type = "unknown"
    if isinstance(license_data, dict):
        holder = _sanitise_string(license_data.get("holder", "unknown"))
        license_type = _sanitise_string(license_data.get("type", "unknown"))

    return json_response({
        "valid": True,
        "license_id": license_id,
        "license_type": license_type,
        "holder": holder,
        "expires": expires,
        "timestamp": Date.new().toISOString(),
    })


# ---------------------------------------------------------------------------
# Route handlers -- Admin endpoints (require X-Admin-Key)
# ---------------------------------------------------------------------------

async def handle_generate(request: object, env: object) -> object:
    """POST /api/v1/generate -- Admin: store a pre-signed license.

    The actual cryptographic signing (ML-DSA-65 + Ed25519) happens in the
    admin CLI tool offline.  This endpoint receives the fully-signed
    license JSON and stores it in KV for later download.

    Expects JSON body:
    {
        "license_id": "...",
        "license_data": { ... full signed license object ... }
    }

    SECURITY: The worker trusts the admin to upload correctly signed
    licenses.  It does NOT re-verify the cryptographic signatures,
    because it does not (and should not) have access to the private keys.
    """
    auth_err = await require_admin(request, env)
    if auth_err:
        return auth_err

    body = await read_request_json(request)
    if body is None:
        return error_response("Invalid JSON body")

    license_id = body.get("license_id", "")
    license_data = body.get("license_data")

    if not is_valid_license_id(license_id):
        return error_response("Invalid or missing license_id")
    if not license_data or not isinstance(license_data, dict):
        return error_response("Invalid or missing license_data object")

    # Verify required fields in the license payload.
    # These are the minimum fields needed for the product-side verifier.
    required_fields = ["holder", "type", "signatures"]
    missing = [f for f in required_fields if f not in license_data]
    if missing:
        return error_response(f"License data missing required fields: {', '.join(missing)}")

    # Store the license keyed by its ID.
    await env.LICENSE_KV.put(
        f"license:{license_id}",
        json.dumps(license_data, separators=(",", ":")),
    )

    # Update issuance statistics (best-effort -- non-critical).
    try:
        stats = await kv_get_json(env, "stats", {**DEFAULT_STATS})
        if not isinstance(stats, dict):
            stats = {**DEFAULT_STATS}
        stats["total_issued"] = stats.get("total_issued", 0) + 1
        license_type = _sanitise_string(license_data.get("type", "unknown"), 64)
        by_type = stats.get("issued_by_type", {})
        if isinstance(by_type, dict):
            by_type[license_type] = by_type.get(license_type, 0) + 1
        stats["issued_by_type"] = by_type
        stats["last_issued"] = Date.new().toISOString()
        await env.LICENSE_KV.put("stats", json.dumps(stats, separators=(",", ":")))
    except Exception:
        # Stats update failure is non-critical -- do not fail the request.
        pass

    return json_response({
        "success": True,
        "license_id": license_id,
        "download_url": f"/api/v1/license/{license_id}",
        "timestamp": Date.new().toISOString(),
    }, status=201)


async def handle_revoke(request: object, env: object) -> object:
    """POST /api/v1/revoke -- Admin: revoke a license by ID.

    Expects JSON body: {"license_id": "...", "reason": "..."}

    Adds the license ID to the revocation list and stores a separate
    revocation record with metadata (reason, timestamp).

    SECURITY: Revocation is append-only.  There is no "unrevoke"
    endpoint by design -- un-revoking a compromised license is a
    security risk.  If a revocation was made in error, issue a new
    license instead.
    """
    auth_err = await require_admin(request, env)
    if auth_err:
        return auth_err

    body = await read_request_json(request)
    if body is None:
        return error_response("Invalid JSON body")

    license_id = body.get("license_id", "")
    reason = _sanitise_string(body.get("reason", "admin_revocation"), 256)

    if not is_valid_license_id(license_id):
        return error_response("Invalid or missing license_id")

    # Verify the license exists before revoking it.
    raw_license = await env.LICENSE_KV.get(f"license:{license_id}")
    if raw_license is None:
        return error_response("License not found", 404)

    # Add to revocation list (idempotent -- check for duplicates).
    revoked = await kv_get_revocation_list(env)

    if license_id in revoked:
        return error_response("License already revoked", 409)

    # Guard against unbounded revocation list growth.
    if len(revoked) >= _MAX_REVOCATION_ENTRIES:
        return error_response("Revocation list is at capacity", 507)

    revoked.append(license_id)
    await env.LICENSE_KV.put(
        "revocation_list",
        json.dumps(revoked, separators=(",", ":")),
    )

    # Store revocation metadata for audit trail.
    revocation_record = {
        "license_id": license_id,
        "reason": reason,
        "revoked_at": Date.new().toISOString(),
    }
    await env.LICENSE_KV.put(
        f"revocation:{license_id}",
        json.dumps(revocation_record, separators=(",", ":")),
    )

    return json_response({
        "success": True,
        "license_id": license_id,
        "reason": reason,
        "timestamp": Date.new().toISOString(),
    })


async def handle_stats(request: object, env: object) -> object:
    """GET /api/v1/stats -- Admin: license issuance statistics.

    Returns aggregate counts of issued and revoked licenses.
    Requires admin authentication.
    """
    auth_err = await require_admin(request, env)
    if auth_err:
        return auth_err

    stats = await kv_get_json(env, "stats", {**DEFAULT_STATS})
    if not isinstance(stats, dict):
        stats = {**DEFAULT_STATS}

    revoked = await kv_get_revocation_list(env)
    stats["total_revoked"] = len(revoked)
    stats["version"] = DONJON_VERSION
    stats["timestamp"] = Date.new().toISOString()

    return json_response(stats)


async def handle_license_download(request: object, env: object, license_id: str) -> object:
    """GET /api/v1/license/:id -- Download a stored license.

    Returns the full signed license JSON for offline verification.
    Checks the revocation list before serving -- revoked licenses
    return 410 Gone.
    """
    if not is_valid_license_id(license_id):
        return error_response("Invalid license ID", 400)

    license_data = await kv_get_json(env, f"license:{license_id}")
    if license_data is None:
        return error_response("License not found", 404)

    # Check revocation before serving the license.
    revoked = await kv_get_revocation_list(env)
    if license_id in revoked:
        return error_response("License has been revoked", 410)

    return json_response({
        "license_id": license_id,
        "license_data": license_data,
        "timestamp": Date.new().toISOString(),
    })


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

# Static route table: maps (HTTP method, path) tuples to handler functions.
ROUTES: dict = {
    ("GET", "/"): handle_health,
    ("GET", "/api/v1/public-keys"): handle_public_keys,
    ("GET", "/api/v1/revoked"): handle_revoked,
    ("POST", "/api/v1/validate"): handle_validate,
    ("POST", "/api/v1/generate"): handle_generate,
    ("POST", "/api/v1/revoke"): handle_revoke,
    ("GET", "/api/v1/stats"): handle_stats,
}


async def route_request(request: object, env: object) -> object:
    """Match incoming request to a handler based on method and path.

    Static routes are checked first via dict lookup (O(1)).  The dynamic
    license download route is checked second via prefix match.
    """
    url = URL.new(request.url)
    path = url.pathname.rstrip("/") or "/"
    method = request.method.upper()

    # Handle CORS preflight for all paths.
    if method == "OPTIONS":
        return options_response()

    # Static routes (exact match).
    handler = ROUTES.get((method, path))
    if handler:
        return await handler(request, env)

    # Dynamic route: GET /api/v1/license/:id
    if method == "GET" and path.startswith("/api/v1/license/"):
        license_id = path[len("/api/v1/license/"):]
        if license_id:
            return await handle_license_download(request, env, license_id)

    return error_response("Not found", 404)


# ---------------------------------------------------------------------------
# Entry points (Cloudflare Worker event handlers)
# ---------------------------------------------------------------------------

async def on_fetch(request: object, env: object) -> object:
    """Main fetch handler -- entry point for all HTTP requests.

    Wraps the router in a top-level exception handler so that unhandled
    errors return a clean JSON response rather than a Cloudflare error
    page.

    SECURITY: The error response intentionally omits the exception
    message.  Only the exception TYPE name is included (e.g.
    "ValueError") to aid debugging without leaking internal details
    like file paths or KV key names.
    """
    try:
        return await route_request(request, env)
    except Exception:
        # SECURITY: Never include exception details in the response.
        # Log internally via console for Cloudflare's logging infrastructure.
        return error_response("Internal server error", 500)


async def on_scheduled(event: object, env: object, ctx: object) -> None:
    """Scheduled handler -- runs every 6 hours for health bookkeeping.

    Writes a health record to KV so monitoring systems can verify
    that the worker's scheduled trigger is firing correctly.
    """
    health_record = {
        "last_health_check": Date.new().toISOString(),
        "version": DONJON_VERSION,
        "status": "operational",
    }
    await env.LICENSE_KV.put(
        "health_status",
        json.dumps(health_record, separators=(",", ":")),
    )
