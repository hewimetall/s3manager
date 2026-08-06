"""
Another S3 Manager - Lightweight S3 file management interface
Provides file browsing, upload, and deletion capabilities for S3 buckets
"""

from another_s3_manager.logging_setup import configure_logging, install_access_log_filter

configure_logging()

import base64
import json
import logging
import os
import secrets as _secrets
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from alembic import command
from alembic.config import Config

# Load environment variables from .env file (if it exists)
# This must be done before importing modules that use environment variables
try:
    from dotenv import load_dotenv

    # Load .env file from the same directory as this file
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        # Also try to load from current working directory
        load_dotenv()
except ImportError:
    # python-dotenv is optional, continue without it
    pass


from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

import another_s3_manager.config as config_module
from another_s3_manager.auth import (
    get_current_admin_user,
    get_current_user,
    get_jwt_secret_key,
    has_valid_session,
    issue_session_cookie,
    verify_csrf_token,
)
from another_s3_manager.config import load_config, resolve_max_file_size, resolve_presigned_ttls, save_config
from another_s3_manager.constants import (
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    PRESIGNED_STS_WARNING_THRESHOLD,
    PRESIGNED_URL_HARD_CEILING,
    PRESIGNED_URL_MIN_TTL,
    STATIC_DIR,
)
from another_s3_manager.errors import S3OperationError
from another_s3_manager.metrics import (
    REGISTRY,
    _seed_zero_series,
    http_request_duration_seconds,
    http_requests_in_flight,
    http_requests_total,
    roles_gauge,
    upload_rejected_total,
)
from another_s3_manager.s3_client import (
    clear_s3_clients_cache,
    delete_object_for_role,
    iter_object_for_role,
    list_buckets_for_role,
    list_objects_client_load_for_role,
    list_objects_for_role,
    list_objects_paginated_for_role,
    role_uses_temporary_credentials,
    upload_fileobj_for_role,
)
from another_s3_manager.s3_client import (
    generate_presigned_url_for_role as s3_generate_presigned_url_for_role,
)
from another_s3_manager.utils import (
    format_boto_error,
    format_content_disposition,
    sanitize_bucket_name,
    sanitize_path,
    sanitize_search_prefix,
)

# Validate required environment variables at startup
try:
    get_jwt_secret_key()
except ValueError as e:
    print(f"ERROR: {e}")
    print("Please set the JWT_SECRET_KEY environment variable.")
    print("Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'")
    sys.exit(1)

# Set up logging
logger = logging.getLogger(__name__)


def _run_alembic_upgrade() -> None:
    """Run `alembic upgrade head` programmatically.

    Looks for alembic.ini and migrations/ in the current working directory.
    Local dev: run from repo root, both are present.
    Docker: WORKDIR /app, Dockerfile copies migrations/ + alembic.ini to /app.
    """
    cwd = Path.cwd()
    alembic_cfg_path = cwd / "alembic.ini"
    if not alembic_cfg_path.exists():
        # Fallback for environments where cwd isn't repo root: try resolving from __file__
        repo_root = Path(__file__).resolve().parent.parent.parent
        alembic_cfg_path = repo_root / "alembic.ini"
        cwd = repo_root
    cfg = Config(str(alembic_cfg_path))
    # Force alembic to materialize `Config.file_config` (its parsed view of alembic.ini) NOW,
    # while `config_file_name` still points at the real file. `file_config` is a
    # `@util.memoized_property`: the FIRST access parses the ini (if `config_file_name` is set)
    # or falls back to a bare, section-only ConfigParser (if it is None) -- and either way, the
    # result is cached on this Config instance forever, unaffected by later reassignments of
    # `config_file_name`. `set_main_option`/`get_main_option` below (and env.py's own
    # `set_main_option("sqlalchemy.url", ...)`) all read/write through this same cached object,
    # so the entire [alembic] section (script_location, prepend_sys_path, etc.) only survives
    # nulling `config_file_name` below because it was materialized from the real ini right here.
    # Without this explicit call, that survival would depend on `set_main_option` two lines down
    # happening to be the thing that triggers the first access -- true today, but a silent trap
    # for anyone reordering this function (verified against alembic 1.18.4: materializing AFTER
    # nulling `config_file_name` yields an empty file_config -- `prepend_sys_path`/
    # `sqlalchemy.url` both come back None instead of the ini's values, no exception raised).
    _ = cfg.file_config
    cfg.set_main_option("script_location", str(cwd / "migrations"))
    # migrations/env.py calls `logging.config.fileConfig(config.config_file_name)` when this
    # attribute is set. fileConfig's stdlib default (disable_existing_loggers=True) sets
    # .disabled = True on EVERY already-created logger not named in alembic.ini's [loggers]
    # section. Migrations run at app startup, after logging is configured and after every
    # module-level `logging.getLogger(__name__)` has run -- so this silently kills every
    # another_s3_manager.* logger AND uvicorn's own loggers (uvicorn.error, uvicorn.access)
    # for the remaining life of the process.
    #
    # alembic.ini's [loggers]/[handlers] sections exist for the standalone `alembic` CLI;
    # when we drive `upgrade` programmatically we have already configured logging ourselves
    # (logging_setup.configure_logging). Clearing config_file_name makes env.py's
    # `if config.config_file_name is not None` guard skip fileConfig() -- alembic's own Config
    # docstring sanctions exactly this ("the call to Python logging.fileConfig() is omitted if
    # the programmatic configuration doesn't actually include logging directives"). This must run
    # AFTER `cfg.file_config` above is materialized (see that comment) -- moving it earlier would
    # silently drop the whole [alembic] section instead of raising.
    cfg.config_file_name = None
    command.upgrade(cfg, "head")


from contextlib import asynccontextmanager

from another_s3_manager.mcp_server import mcp as _mcp_instance


def run_startup_tasks() -> None:
    """Everything the app does on startup EXCEPT entering the MCP session manager.

    Synchronous and side-effect-only. Split out of `lifespan` so it can be driven
    directly by tests. Identity is gateway-header only — no local user bootstrap.
    """
    install_access_log_filter()

    # Keep alembic running so existing PVC schemas stay migratable; web auth no
    # longer reads the users/bans/api_tokens tables.
    try:
        _run_alembic_upgrade()
    except Exception:
        logger.critical("alembic upgrade failed", exc_info=True)
        raise


@asynccontextmanager
async def lifespan(app_: FastAPI):
    """App startup + MCP session manager lifecycle.

    Phase 5 added MCP via FastMCP (SDK 1.12.x). FastMCP's session_manager
    needs an async task group that's only created inside its run() context
    manager — without entering it during startup, every request to /mcp/*
    fails with 'Task group is not initialized.' (We learned the hard way.)

    Migration from on_event('startup') to lifespan also resolves the
    deprecation warning that's been firing since the FastAPI 0.136 bump.

    The startup work itself lives in run_startup_tasks() — see its docstring for
    why it is a separate, directly-callable function.
    """
    run_startup_tasks()

    # Enter FastMCP session manager — REQUIRED for /mcp/* to work.
    async with _mcp_instance.session_manager.run():
        yield


app = FastAPI(title=APP_NAME, description=APP_DESCRIPTION, lifespan=lifespan)

# No application-level rate limiting. Brute-force defense lives in the
# username-based ban (auth.record_login_attempt: 3 fails → 1h ban, admins exempt).
# For production deployments expecting public exposure, put the app behind
# Cloudflare Access / WAF (or any reverse proxy with auth) — that is the right
# layer for IP-level rate limiting and DoS protection.
#
# Distinct from rate limiting: SINGLE-REQUEST resource exhaustion (one
# unauthenticated request streaming an unbounded body to the temp dir) is
# handled in-app by _upload_body_guard below, because no reverse-proxy body
# cap is guaranteed to exist on a bare `docker compose` deployment.


# resolve_max_file_size() itself now lives in config.py (imported above) — it
# used to be hand-copied in mcp_server.py too, and the two could silently
# drift apart. Both main.py's guard/route and mcp_server.py's upload_file
# tool now call the single config.py implementation.


# Fixed headroom (bytes) added on top of the base64 inflation below, for the
# JSON-RPC envelope wrapped around content_base64: `{"jsonrpc":"2.0","id":...,
# "method":"tools/call","params":{"name":"upload_file","arguments":{"role":
# ...,"bucket":...,"path":...,"content_base64":"..."}}}` plus whatever
# role/bucket/path strings the caller passes. Generous on purpose — role,
# bucket, and path names are short in practice, and the cost of this headroom
# is a few KB of RAM per request, not per byte of upload.
MCP_JSON_ENVELOPE_OVERHEAD_BYTES = 8192


def resolve_mcp_body_max_bytes() -> int:
    """Bound the /mcp request body size so a legitimate upload_file call fits.

    upload_file carries the file's bytes as base64 in `content_base64` — 4/3
    of the raw byte count (rounded up to a multiple of 4 for padding) — inside
    a JSON-RPC envelope. A body cap set equal to max_file_size would reject
    uploads that are well WITHIN the operator's configured limit, because the
    wire body is always larger than the decoded payload it carries.

    DO NOT simplify this to `return resolve_max_file_size()` — that would
    silently break every upload_file call whose file is bigger than ~75% of
    max_file_size (the base64 overhead alone already exceeds a same-sized cap;
    see the module's upload-guard tests for the regression this closes).

    Every other MCP tool call (list_roles, list_buckets, delete_file, ...) is
    small — role/bucket/path strings, no binary payload — and never
    approaches this bound regardless of how generous it is.
    """
    max_file_size = resolve_max_file_size()
    # ceil(n / 3) * 4 — exact base64-with-padding length for n raw bytes.
    base64_len = ((max_file_size + 2) // 3) * 4
    return base64_len + MCP_JSON_ENVELOPE_OVERHEAD_BYTES


# Upload body-guard — MUST stay registered BEFORE _http_metrics in module
# order. Starlette's add_middleware() prepends, so the LAST-registered
# middleware is outermost; registering the guard first keeps _http_metrics
# wrapped AROUND it, and a guard-rejected request (401/411/413) is still
# counted in as3m_http_requests_total. Routing never runs for guard-rejected
# requests, so _http_metrics' path_template label falls back to the concrete
# path (same posture as its existing no-route-404 fallback).
@app.middleware("http")
async def _upload_body_guard(request: Request, call_next):
    """Reject unauth / length-less / oversize uploads BEFORE the body is read.

    FastAPI parses the multipart body — Starlette spools each part to a
    SpooledTemporaryFile (disk above 1 MB) — to satisfy the route's
    `File(...)` parameter BEFORE dependencies like get_current_user run.
    Without this guard, an unauthenticated multi-GB POST fills the temp dir
    and only then receives its 401. Returning here without calling call_next
    means the request body is never read from the socket.

    The auth-gate below uses has_valid_session (a cheap, DB-free JWT decode),
    NOT get_current_user, because this is a bare synchronous call inside an
    `async def` middleware: get_current_user runs get_user_by_username() (a
    blocking SQLAlchemy query) and calling it here would block the event loop thread
    on every upload request. The authoritative, DB-backed check still runs
    in the handler via Depends(get_current_user) — this guard only rejects
    the cheap, unauthenticated case before the body is read.

    CSRF is deliberately NOT checked here: a CSRF failure requires an
    already-valid session (not an unauthenticated-DoS vector), and such a
    client's body is already bounded by the Content-Length check below.
    """
    path = request.url.path
    if request.method == "POST" and path.startswith("/api/buckets/") and path.endswith("/upload"):
        # Stamp a BOUNDED path template into scope so _http_metrics' route-less
        # fallback (routing never runs for a guard-rejected request) doesn't key
        # on the concrete, attacker-controlled bucket-name path. Without this, an
        # unauthenticated client varying the bucket name mints one unbounded
        # label series per bucket in as3m_http_requests_total (and ~15 per
        # series in the duration histogram), held forever in the registry --
        # the same unauth resource-exhaustion class this middleware closes,
        # relocated from disk to metrics-registry RAM. Set once, before any of
        # the three reject responses below, so all of them benefit. Must match
        # the route decorator's path exactly: @app.post("/api/buckets/{bucket_name}/upload").
        # Generic key name (`guard_path_template`, not `upload_*`) because
        # _mcp_body_guard below stamps the same key for the same reason.
        request.scope["guard_path_template"] = "/api/buckets/{bucket_name}/upload"

        # 1. Auth-gate. has_valid_session is a pure JWT decode (no DB query),
        #    so it's safe to call synchronously off the event loop. It cannot
        #    raise HTTPException, so this returns the response directly
        #    rather than the try/except HTTPException pattern used elsewhere.
        if not has_valid_session(request):
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

        # 2. Strict Content-Length requirement (411) — closes the
        #    chunked-transfer bypass. Browsers' XHR/fetch and `curl -T`
        #    always send Content-Length. Malformed values count as missing.
        #    Deliberately NOT counted in upload_rejected_total: protocol
        #    error, not a business reject (spec decision 2026-07-11).
        content_length = request.headers.get("content-length")
        try:
            declared_size = int(content_length) if content_length is not None else None
        except ValueError:
            declared_size = None
        # A negative declared size is nonsensical and must not fall through:
        # int("-5") is neither None (no 411 above) nor > max_file_size (no 413
        # below), so without this check it would reach call_next and the body
        # would be spooled before the handler's own true-size check runs.
        # Upstream uvicorn/h11 usually reject this at the framing layer, but
        # the guard's own logic shouldn't rely on that.
        if declared_size is None or declared_size < 0:
            return JSONResponse(
                status_code=411,
                content={"detail": "Content-Length header is required for uploads"},
            )

        # 3. Bound the declared size (413). The handler re-checks the true
        #    spooled size as defense-in-depth against under-reported values.
        max_file_size = resolve_max_file_size()
        if declared_size > max_file_size:
            upload_rejected_total.labels(reason="size_limit").inc()
            size_mb = max_file_size / (1024 * 1024)
            return JSONResponse(
                status_code=413,
                content={"detail": f"File size exceeds maximum allowed size of {size_mb}MB"},
            )
    return await call_next(request)


# MCP body-guard — MUST stay registered BEFORE _http_metrics in module order,
# same reasoning as _upload_body_guard above: the LAST-registered middleware
# is outermost, so registering this one first keeps _http_metrics wrapped
# AROUND it and a guard-rejected /mcp request is still counted in
# as3m_http_requests_total.
@app.middleware("http")
async def _mcp_body_guard(request: Request, call_next):
    """Reject oversize /mcp request bodies BEFORE they are read off the socket.

    By the time an MCP tool body runs (including upload_file's own
    FILE_TOO_LARGE check — see mcp_server.py), the JSON-RPC request has
    already been fully read and parsed into a Python str/dict by FastMCP's
    Streamable HTTP transport. A tool-level check cannot prevent that RAM
    from being spent; only a transport-level body bound can. This mirrors
    _upload_body_guard's posture for the web upload route: require
    Content-Length (closes the chunked-transfer bypass — a body with no
    declared size can't be size-checked before reading it) and 413 above a
    ceiling derived from max_file_size (see resolve_mcp_body_max_bytes) before
    call_next ever runs.

    No auth-gate here, unlike _upload_body_guard: the web guard can cheaply
    pre-check the session cookie with has_valid_session (a pure JWT decode).
    MCP auth is a Bearer token validated per-tool-call inside the tool body
    (authenticate_mcp_request, which does a DB lookup) — there is no
    equivalent cheap pre-body check to hoist in front of the read, and this
    guard's job is narrower anyway: bound the body size regardless of who is
    asking, not decide who is allowed to ask.

    The `request.method == "POST"` scoping below is LOAD-BEARING, not an
    incidental narrowing: the MCP streamable-HTTP transport's SSE event
    stream (and its resumption stream) is a GET, and session teardown is a
    DELETE. Only the SDK's single POST verb ever carries a JSON-RPC body, and
    that POST always sets Content-Length (verified independently during
    review — see tests/test_mcp_upload_guard.py's GET-exemption test for the
    same reasoning spelled out from the test side). If this guard is ever
    changed to apply to GET, a 411 on the SSE stream breaks EVERY MCP
    session, for every agent — do not widen this beyond POST.
    """
    path = request.url.path
    if request.method == "POST" and (path == "/mcp" or path.startswith("/mcp/")):
        # Stamp a BOUNDED path template into scope, same reasoning and same
        # scope key as _upload_body_guard above: routing never runs for a
        # guard-rejected request, so _http_metrics' route-less fallback would
        # otherwise key on the concrete /mcp/<junk> path, minting one unbounded
        # label series per distinct suffix an unauthenticated caller sends.
        request.scope["guard_path_template"] = "/mcp"

        content_length = request.headers.get("content-length")
        try:
            declared_size = int(content_length) if content_length is not None else None
        except ValueError:
            declared_size = None
        # Same reasoning as _upload_body_guard: int("-5") is neither None nor
        # > the ceiling, so a negative declared size must be rejected explicitly
        # rather than relying on the framing layer to have already caught it.
        if declared_size is None or declared_size < 0:
            return JSONResponse(
                status_code=411,
                content={"detail": "Content-Length header is required for /mcp requests"},
            )

        max_body_bytes = resolve_mcp_body_max_bytes()
        if declared_size > max_body_bytes:
            # Same counter/reason the web upload guard uses — both are
            # "an upload was refused before reaching S3", just via different
            # transports.
            upload_rejected_total.labels(reason="size_limit").inc()
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body exceeds maximum allowed size of {max_body_bytes} bytes"},
            )
    return await call_next(request)


# Exception handler to ensure all errors return JSON
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# HTTP metrics middleware — registered late so it sees the final response status
# (after exception handlers have run and converted exceptions to proper HTTP responses).
@app.middleware("http")
async def _http_metrics(request: Request, call_next):
    start = time.perf_counter()
    http_requests_in_flight.inc()
    try:
        response = await call_next(request)
    finally:
        # Decrement even if call_next raised, so an unhandled exception
        # never leaks the gauge upward.
        http_requests_in_flight.dec()
    duration = time.perf_counter() - start
    # path_template — bounded cardinality. Routed requests always use the route
    # pattern. When routing never ran (no-route 404, or a request rejected by
    # _upload_body_guard / _mcp_body_guard before call_next), prefer a
    # guard-stamped template over the concrete path — both guards stamp
    # request.scope["guard_path_template"] (bucket-upload and /mcp
    # respectively) so an attacker varying the bucket name or the /mcp
    # suffix can't mint unbounded label series. Falls back to the actual
    # path for a genuine no-route 404 (not guard-stamped).
    route = request.scope.get("route")
    if route is not None:
        path_template = route.path
    else:
        path_template = request.scope.get("guard_path_template") or request.url.path
    method = request.method
    status_code = str(response.status_code)
    http_requests_total.labels(method=method, path_template=path_template, status_code=status_code).inc()
    http_request_duration_seconds.labels(method=method, path_template=path_template).observe(duration)
    return response


# Canonical bare /mcp — registered BEFORE the kill-switch below, so Starlette's
# add_middleware() prepend order leaves the kill-switch OUTSIDE this one and it
# still evaluates the original, un-rewritten path (it matches both forms itself).
@app.middleware("http")
async def _mcp_canonical_path(request: Request, call_next):
    """Serve a bare /mcp directly instead of 307-redirecting it to /mcp/.

    Starlette's Mount matches with a regex equivalent to ^/mcp(?P<path>/.*)$,
    so a request to exactly /mcp never matches the mount; the router then falls
    through to redirect_slashes and answers 307 -> /mcp/. MCP clients that do
    not follow redirects cannot connect at all — and a bare /mcp is both how
    every other MCP server is addressed and what our own MCP_SERVER_INSTRUCTIONS
    text tells agents to use. Rewriting the path before routing makes the mount
    match directly, so both forms answer 200.

    Exact match only: /mcpfoo must still 404, so never use startswith("/mcp").
    """
    if request.scope["path"] == "/mcp":
        request.scope["path"] = "/mcp/"
        request.scope["raw_path"] = b"/mcp/"
    return await call_next(request)


# MCP kill-switch middleware — must be registered BEFORE the MCP sub-app is
# mounted so Starlette evaluates it on every /mcp/* request.
@app.middleware("http")
async def _mcp_kill_switch(request: Request, call_next):
    """Return 503 for all /mcp paths when mcp_enabled=False in config.

    Match both /mcp (without trailing slash — Starlette would 307-redirect
    this to /mcp/ unless we intercept first) and /mcp/* so the kill-switch
    can't be bypassed via the no-slash form.
    """
    path = request.url.path
    if path == "/mcp" or path.startswith("/mcp/"):
        cfg = config_module.load_config(force_reload=False)
        if not cfg.get("mcp_enabled", True):
            return JSONResponse(
                {"error": "MCP_DISABLED", "message": "MCP API is disabled"},
                status_code=503,
            )
    return await call_next(request)


def _check_metrics_auth(request: Request) -> None:
    """Enforce optional basic auth on /metrics. Open when METRICS_PASSWORD is unset."""
    expected = os.getenv("METRICS_PASSWORD")
    if not expected:
        return  # endpoint is open
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        raise HTTPException(
            status_code=401,
            detail="Basic auth required",
            headers={"WWW-Authenticate": 'Basic realm="metrics"'},
        )
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        username, password = decoded.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed basic auth")
    if username != "metrics" or not _secrets.compare_digest(password, expected):
        raise HTTPException(status_code=401, detail="Invalid credentials")


# Scrape-time callbacks. Computing at scrape time (rather than hooking every
# mutation) means the gauge can never drift out of sync with its source of truth
# (the database, or config.json for roles_gauge).
roles_gauge.set_function(lambda: float(len(load_config(force_reload=False).get("roles", []))))

# Pre-create fixed-enum counter series at 0 so the very first real increment
# is visible to Grafana's increase()/rate() panels (see metrics.py's
# _seed_zero_series docstring). Module-level, like the callbacks above, so it
# runs exactly once per process at import time -- doesn't depend on the ASGI
# server actually entering the `lifespan` async context manager.
_seed_zero_series()


@app.get("/metrics")
async def metrics_endpoint(request: Request):
    """Prometheus metrics exposition endpoint. Optional METRICS_PASSWORD basic auth."""
    _check_metrics_auth(request)
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


# Health endpoint (no auth required)
@app.get("/health")
async def health():
    return {"status": "ok", "version": APP_VERSION}


def _serialize_current_user_info(current_user: Dict[str, Any]) -> Dict[str, Any]:
    """Render the /api/me payload from the header-derived principal."""
    is_admin = current_user.get("is_admin", False)
    config = load_config()
    if is_admin:
        allowed_roles = [r["name"] for r in config.get("roles", []) if r.get("name")]
    else:
        allowed_roles = current_user.get("allowed_roles", [])
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)
    disable_deletion = disable_deletion_env or disable_deletion_config
    default_role = allowed_roles[0] if allowed_roles else None
    max_file_size_from_config = config.get("max_file_size")
    if max_file_size_from_config is None:
        max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
    else:
        max_file_size = int(max_file_size_from_config)
    return {
        "username": current_user.get("username"),
        "is_admin": is_admin,
        "csrf_token": current_user.get("csrf_token"),
        "theme": current_user.get("theme", "auto"),
        "allowed_roles": allowed_roles,
        "default_role": default_role,
        "must_change_password": False,
        "disable_deletion": disable_deletion,
        "max_file_size": max_file_size,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
    }


# ============================================================================
# Routes
# ============================================================================


@app.post("/api/login")
async def login_removed():
    """Local password login is gone — identity comes from the gateway."""
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


@app.post("/api/logout")
async def logout(response: Response):
    """Clear the CSRF cookie. Auth itself is the gateway session."""
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


@app.get("/api/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Return the gateway-derived principal and mint a CSRF cookie."""
    return _serialize_current_user_info(current_user)


@app.get("/api/app-info")
async def get_app_info():
    """Get application information (public endpoint)"""
    return {
        "app_name": APP_NAME,
        "app_description": APP_DESCRIPTION,
        "app_version": APP_VERSION,
    }


@app.put("/api/user/theme")
async def update_user_theme(
    theme: str = Form(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf_token),
):
    """Theme preference is not persisted without local users; accept and ignore."""
    if theme not in ("auto", "light", "dark"):
        raise HTTPException(status_code=400, detail="theme must be auto, light, or dark")
    return {"ok": True, "theme": theme}


async def _local_account_gone():
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


for _path, _methods in (
    ("/api/admin/users", ["GET", "POST"]),
    ("/api/admin/users/{username}", ["PUT", "DELETE"]),
    ("/api/admin/users/{username}/password", ["PUT"]),
    ("/api/admin/bans", ["GET"]),
    ("/api/admin/bans/{username}", ["DELETE"]),
    ("/api/me/password", ["PUT"]),
    ("/api/me/default-role", ["PUT"]),
    ("/api/me/tokens", ["GET", "POST"]),
    ("/api/me/tokens/{token_id}", ["DELETE", "PUT"]),
    ("/api/admin/tokens", ["GET", "POST"]),
    ("/api/admin/tokens/{token_id}", ["DELETE", "PUT"]),
):
    app.add_api_route(_path, _local_account_gone, methods=_methods, include_in_schema=False)


@app.get("/api/config")
async def get_config(
    force_reload: bool = Query(False, description="Force reload from file"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Get current configuration (filtered by user permissions)."""
    config = load_config(force_reload=force_reload)

    # Check if deletion is disabled (from environment variable or config)
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)
    disable_deletion = disable_deletion_env or disable_deletion_config

    # Get enable_lazy_loading from config file, fallback to environment variable, then default
    enable_lazy_loading = config.get("enable_lazy_loading")
    if enable_lazy_loading is None:
        enable_lazy_loading = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"
    else:
        enable_lazy_loading = bool(enable_lazy_loading)

    # Get max_file_size from config file, fallback to environment variable, then default
    max_file_size = config.get("max_file_size")
    if max_file_size is None:
        max_file_size = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))
    else:
        max_file_size = int(max_file_size)

    # Get max_client_load from config file, fallback to environment variable, then default
    max_client_load = config.get("max_client_load")
    if max_client_load is None:
        max_client_load = int(os.getenv("MAX_CLIENT_LOAD", "10000"))
    else:
        max_client_load = int(max_client_load)

    # Resolve presigned URL TTL bounds (config → env → hardcoded defaults).
    presigned_url_default_ttl, presigned_url_max_ttl = resolve_presigned_ttls(config)

    # Create a safe copy without secret credentials
    def sanitize_role(role: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive secret credentials from role (keep access_key_id as it's not secret)"""
        sanitized = role.copy()
        # Remove secret_access_key completely from API response (don't show it at all)
        if "secret_access_key" in sanitized:
            del sanitized["secret_access_key"]
        # Keep access_key_id, role_arn and profile_name as they're not sensitive
        return sanitized

    # If user is admin, return config but without credentials
    if current_user.get("is_admin", False):
        from another_s3_manager.config import is_config_writable
        from another_s3_manager.constants import get_data_dir

        # default_role removed from config in Phase 6a-4 (now per-user via /api/me).
        # effective_role falls back to the first configured role for the vanilla UI;
        # React UI reads per-user default_role from /api/me instead.
        roles_list = config.get("roles", [])
        effective_role = roles_list[0].get("name", "") if roles_list else ""

        safe_config = {
            "roles": [sanitize_role(role) for role in config.get("roles", [])],
            "current_role": effective_role,  # Computed value for frontend (not stored in config)
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size,
            "max_client_load": max_client_load,
            "presigned_url_default_ttl": presigned_url_default_ttl,
            "presigned_url_max_ttl": presigned_url_max_ttl,
            "preview_text_extensions": config.get("preview_text_extensions", []),
            "upload_inline_extensions": config.get("upload_inline_extensions", []),
            "data_dir": str(get_data_dir()),  # Return current DATA_DIR value (read-only)
            "is_read_only": not is_config_writable(),
            "password_min_length": config.get("password_min_length", 0),
            "password_min_uppercase": config.get("password_min_uppercase", 0),
            "password_min_lowercase": config.get("password_min_lowercase", 0),
            "password_min_digits": config.get("password_min_digits", 0),
            "password_min_special": config.get("password_min_special", 0),
            # MCP server fields (Phase 5)
            "mcp_enabled": config.get("mcp_enabled", True),
            "mcp_disable_writes": config.get("mcp_disable_writes", False),
            "mcp_text_extensions": config.get("mcp_text_extensions", []),
            "mcp_global_max_read_bytes": config.get("mcp_global_max_read_bytes", 10_485_760),
            "mcp_summary_max_keys": config.get("mcp_summary_max_keys", 50_000),
            "mcp_summary_prefix_scan_pages": config.get("mcp_summary_prefix_scan_pages", 20),
            "mcp_list_page_size": config.get("mcp_list_page_size", 1000),
            "mcp_list_max_page_size": config.get("mcp_list_max_page_size", 10_000),
        }
        return safe_config

    # For regular users, filter roles by gateway-derived permissions
    allowed_roles = current_user.get("allowed_roles", [])
    if not allowed_roles:
        # No roles allowed, return empty config with all required fields
        return {
            "roles": [],
            "current_role": "",
            "disable_deletion": disable_deletion,
            "enable_lazy_loading": enable_lazy_loading,
            "max_file_size": max_file_size,
            "max_client_load": max_client_load,
            "presigned_url_default_ttl": presigned_url_default_ttl,
            "presigned_url_max_ttl": presigned_url_max_ttl,
            "preview_text_extensions": config.get("preview_text_extensions", []),
            "upload_inline_extensions": config.get("upload_inline_extensions", []),
        }

    # Filter roles and sanitize
    filtered_roles = [sanitize_role(role) for role in config.get("roles", []) if role.get("name") in allowed_roles]

    # default_role removed from config in Phase 6a-4 (now per-user via /api/me).
    # React UI reads per-user default_role from /api/me; vanilla UI falls back to first allowed role.
    effective_role = allowed_roles[0] if allowed_roles else ""

    return {
        "roles": filtered_roles,
        "current_role": effective_role,
        "disable_deletion": disable_deletion,
        "enable_lazy_loading": enable_lazy_loading,
        "max_file_size": max_file_size,
        "max_client_load": max_client_load,
        "presigned_url_default_ttl": presigned_url_default_ttl,
        "presigned_url_max_ttl": presigned_url_max_ttl,
        "preview_text_extensions": config.get("preview_text_extensions", []),
        "upload_inline_extensions": config.get("upload_inline_extensions", []),
    }


@app.get("/api/config/export")
async def export_config(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Export full configuration as JSON (admin only)"""
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required to export configuration"
        )

    config = load_config(force_reload=True)

    # Return as JSON response with download headers
    from fastapi.responses import Response

    json_str = json.dumps(config, indent=2, ensure_ascii=False)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=config.json"},
    )


@app.post("/api/config")
async def update_config(
    request: Request,
    config: Dict[str, Any] = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Update configuration (admin only)"""
    # Only admins can update config
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required to update configuration"
        )

    # Check if config is read-only
    from another_s3_manager.config import is_config_writable

    if not is_config_writable():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The application does not have write access to the configuration file (e.g., mounted as read-only from Kubernetes ConfigMap). Configuration management must be handled externally.",
        )

    try:
        # Validate config structure
        if "roles" not in config:
            raise HTTPException(status_code=400, detail="Invalid config structure: 'roles' is required")

        # Handle enable_lazy_loading - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "enable_lazy_loading" in config:
            # Validate enable_lazy_loading (must be boolean)
            if not isinstance(config["enable_lazy_loading"], bool):
                raise HTTPException(status_code=400, detail="enable_lazy_loading must be a boolean")
        else:
            # Preserve enable_lazy_loading from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "enable_lazy_loading" in current_config:
                config["enable_lazy_loading"] = current_config["enable_lazy_loading"]
            else:
                # Use env var or default if not in config
                config["enable_lazy_loading"] = os.getenv("ENABLE_LAZY_LOADING", "true").lower() == "true"

        # Handle max_file_size - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "max_file_size" in config:
            # Validate max_file_size
            try:
                max_file_size_val = int(config["max_file_size"])
                if max_file_size_val < 1024:  # At least 1KB
                    raise HTTPException(status_code=400, detail="max_file_size must be at least 1024 bytes (1KB)")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="max_file_size must be a valid integer")
        else:
            # Preserve max_file_size from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "max_file_size" in current_config:
                config["max_file_size"] = current_config["max_file_size"]
            else:
                # Use env var or default if not in config
                config["max_file_size"] = int(os.getenv("MAX_FILE_SIZE", str(100 * 1024 * 1024)))

        # Handle max_client_load - if provided, validate and use it; otherwise preserve existing or use env var/default
        if "max_client_load" in config:
            # Validate max_client_load (1..200000, matching the s3_client clamp)
            try:
                max_client_load_val = int(config["max_client_load"])
                if max_client_load_val < 1 or max_client_load_val > 200000:
                    raise HTTPException(
                        status_code=400,
                        detail="max_client_load must be between 1 and 200000",
                    )
                config["max_client_load"] = max_client_load_val
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="max_client_load must be a valid integer")
        else:
            # Preserve max_client_load from current config if exists, otherwise use env var or default
            current_config = load_config(force_reload=False)
            if "max_client_load" in current_config:
                config["max_client_load"] = current_config["max_client_load"]
            else:
                # Use env var or default if not in config
                config["max_client_load"] = int(os.getenv("MAX_CLIENT_LOAD", "10000"))

        # Handle presigned URL TTLs — validate when provided, preserve when omitted.
        _current_for_ttl = load_config(force_reload=False)

        def _validate_ttl_field(field_name: str) -> None:
            if field_name in config:
                try:
                    val = int(config[field_name])
                except (ValueError, TypeError):
                    raise HTTPException(status_code=400, detail=f"{field_name} must be a valid integer")
                if val < PRESIGNED_URL_MIN_TTL or val > PRESIGNED_URL_HARD_CEILING:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"{field_name} must be between {PRESIGNED_URL_MIN_TTL} "
                            f"and {PRESIGNED_URL_HARD_CEILING} seconds"
                        ),
                    )
                config[field_name] = val
            else:
                preserved = _current_for_ttl.get(field_name)
                if preserved is not None:
                    config[field_name] = preserved

        _validate_ttl_field("presigned_url_default_ttl")
        _validate_ttl_field("presigned_url_max_ttl")

        # Cross-field invariant: default cannot exceed max (when both are known).
        _eff_default = config.get("presigned_url_default_ttl")
        _eff_max = config.get("presigned_url_max_ttl")
        if _eff_default is not None and _eff_max is not None and int(_eff_default) > int(_eff_max):
            raise HTTPException(
                status_code=400,
                detail="presigned_url_default_ttl cannot exceed presigned_url_max_ttl",
            )

        # Extension lists — validate (list of strings) when provided, preserve
        # when omitted. Two independent keys since the 1.0.3 split:
        #   preview_text_extensions → text-preview in the UI
        #   upload_inline_extensions → Content-Disposition: inline on upload
        current_config = load_config(force_reload=False)
        for ext_field in ("preview_text_extensions", "upload_inline_extensions"):
            if ext_field in config:
                if not isinstance(config[ext_field], list):
                    raise HTTPException(status_code=400, detail=f"{ext_field} must be a list")
                for ext in config[ext_field]:
                    if not isinstance(ext, str):
                        raise HTTPException(status_code=400, detail=f"{ext_field} must contain only strings")
                # Normalize: strip leading dots, lowercase, drop blanks.
                config[ext_field] = [ext.lstrip(".").lower() for ext in config[ext_field] if ext.strip()]
            elif ext_field in current_config:
                config[ext_field] = current_config[ext_field]
            else:
                config[ext_field] = []

        # Password policy fields: validate range when provided, preserve when omitted.
        for field in (
            "password_min_length",
            "password_min_uppercase",
            "password_min_lowercase",
            "password_min_digits",
            "password_min_special",
        ):
            if field in config:
                try:
                    val = int(config[field])
                except (ValueError, TypeError):
                    raise HTTPException(status_code=400, detail=f"{field} must be an integer")
                if val < 0 or val > 50:
                    raise HTTPException(status_code=400, detail=f"{field} must be between 0 and 50")
                config[field] = val
            else:
                preserved = load_config(force_reload=False).get(field)
                if preserved is not None:
                    config[field] = preserved

        # MCP server fields (Phase 5): validate types/ranges when provided, preserve when omitted.
        if "mcp_enabled" in config and not isinstance(config["mcp_enabled"], bool):
            raise HTTPException(status_code=422, detail="mcp_enabled must be boolean")
        if "mcp_disable_writes" in config and not isinstance(config["mcp_disable_writes"], bool):
            raise HTTPException(status_code=422, detail="mcp_disable_writes must be boolean")
        if "mcp_text_extensions" in config:
            ext = config["mcp_text_extensions"]
            if not isinstance(ext, list) or not all(isinstance(e, str) for e in ext):
                raise HTTPException(status_code=422, detail="mcp_text_extensions must be list of strings")
        if "mcp_global_max_read_bytes" in config:
            v = config["mcp_global_max_read_bytes"]
            # Explicitly reject booleans (bool is a subclass of int in Python)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1 or v > 10_485_760:
                raise HTTPException(status_code=422, detail="mcp_global_max_read_bytes must be 1..10485760")
        # MCP big-bucket ergonomics keys (2026-07-12): positive ints within UI
        # bounds. POST rejects garbage; the READ path additionally clamps
        # (floor 1 for the list keys, floor 1000 for the summary walk) so a
        # hand-edited config file cannot brick the tools.
        for int_field, lo, hi in (
            # Lower bound 1_000 matches the runtime floor
            # (s3_client._MIN_SUMMARY_MAX_KEYS) and the Settings NumberInput
            # min — a value accepted here that the walk silently re-floors
            # at call time would be a lie by the time it's echoed back.
            ("mcp_summary_max_keys", 1_000, 1_000_000),
            ("mcp_summary_prefix_scan_pages", 1, 200),
            ("mcp_list_page_size", 1, 10_000),
            ("mcp_list_max_page_size", 1, 10_000),
        ):
            if int_field in config:
                v = config[int_field]
                # Explicitly reject booleans (bool is a subclass of int in Python)
                if isinstance(v, bool) or not isinstance(v, int) or v < lo or v > hi:
                    raise HTTPException(status_code=422, detail=f"{int_field} must be {lo}..{hi}")
        # Preserve MCP fields from current config when omitted in request
        _current_cfg = load_config(force_reload=False)
        for k in (
            "mcp_enabled",
            "mcp_disable_writes",
            "mcp_text_extensions",
            "mcp_global_max_read_bytes",
            "mcp_summary_max_keys",
            "mcp_summary_prefix_scan_pages",
            "mcp_list_page_size",
            "mcp_list_max_page_size",
        ):
            if k not in config:
                config[k] = _current_cfg.get(k)

        # Validate roles and preserve existing secret_access_key if not provided
        current_config = load_config(force_reload=False)
        current_roles = {r.get("name"): r for r in current_config.get("roles", [])}

        for role in config.get("roles", []):
            if "name" not in role or "type" not in role:
                raise HTTPException(status_code=400, detail="Role must have 'name' and 'type'")

            role_type = role.get("type")
            if role_type == "assume_role" and "role_arn" not in role:
                raise HTTPException(status_code=400, detail="assume_role type requires 'role_arn'")
            elif role_type == "credentials":
                if "access_key_id" not in role:
                    raise HTTPException(status_code=400, detail="credentials type requires 'access_key_id'")

                # Validate and clean access_key_id
                access_key_id = role.get("access_key_id", "").strip()
                if not access_key_id:
                    raise HTTPException(status_code=400, detail="access_key_id cannot be empty")

                # Validate AWS format (should start with AKIA and be 20 characters)
                import re

                if not re.match(r"^AKIA[0-9A-Z]{16}$", access_key_id):
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid access_key_id format. AWS access keys should start with AKIA and be 20 characters long",
                    )

                role["access_key_id"] = access_key_id  # Save trimmed value

                # Handle secret_access_key: if not provided or is REDACTED, preserve existing from config
                secret_access_key = role.get("secret_access_key", "").strip() if role.get("secret_access_key") else ""
                role_name = role.get("name")

                if not secret_access_key or secret_access_key == "***REDACTED***":
                    # Preserve existing secret_access_key from current config (for editing existing role)
                    if role_name in current_roles:
                        existing_secret = current_roles[role_name].get("secret_access_key", "")
                        if existing_secret and existing_secret != "***REDACTED***":
                            role["secret_access_key"] = existing_secret
                        else:
                            raise HTTPException(
                                status_code=400,
                                detail=f"secret_access_key is required for role '{role_name}'. Please provide it.",
                            )
                    else:
                        # New role - secret_access_key is required
                        raise HTTPException(
                            status_code=400, detail="secret_access_key is required for new credentials role"
                        )
                else:
                    # New secret_access_key provided, use it
                    role["secret_access_key"] = secret_access_key

            elif role_type == "s3_compatible":
                if "access_key_id" not in role:
                    raise HTTPException(status_code=400, detail="s3_compatible type requires 'access_key_id'")
                if "endpoint_url" not in role:
                    raise HTTPException(status_code=400, detail="s3_compatible type requires 'endpoint_url'")

                # Validate and clean access_key_id (no format validation for S3-compatible services)
                access_key_id = role.get("access_key_id", "").strip()
                if not access_key_id:
                    raise HTTPException(status_code=400, detail="access_key_id cannot be empty")

                endpoint_url = role.get("endpoint_url", "").strip()
                if not endpoint_url:
                    raise HTTPException(status_code=400, detail="endpoint_url cannot be empty")

                role["access_key_id"] = access_key_id  # Save trimmed value
                role["endpoint_url"] = endpoint_url  # Save trimmed value

                # Handle secret_access_key: if not provided or is REDACTED, preserve existing from config
                secret_access_key = role.get("secret_access_key", "").strip() if role.get("secret_access_key") else ""
                role_name = role.get("name")

                if not secret_access_key or secret_access_key == "***REDACTED***":
                    # Preserve existing secret_access_key from current config (for editing existing role)
                    if role_name in current_roles:
                        existing_secret = current_roles[role_name].get("secret_access_key", "")
                        if existing_secret and existing_secret != "***REDACTED***":
                            role["secret_access_key"] = existing_secret
                        else:
                            raise HTTPException(
                                status_code=400,
                                detail=f"secret_access_key is required for role '{role_name}'. Please provide it.",
                            )
                    else:
                        # New role - secret_access_key is required
                        raise HTTPException(
                            status_code=400, detail="secret_access_key is required for new s3_compatible role"
                        )
                else:
                    # New secret_access_key provided, use it
                    role["secret_access_key"] = secret_access_key

            elif role_type == "profile":
                if "profile_name" not in role:
                    raise HTTPException(status_code=400, detail="profile type requires 'profile_name'")

        save_config(config)
        clear_s3_clients_cache()
        logger.info("S3 client cache cleared after config save")
        return {"message": "Configuration updated successfully"}
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in update_config")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Failed to update config — see server logs"},
        ) from e


def _s3_error_to_http(error: S3OperationError) -> HTTPException:
    """Map a typed S3 error to an HTTPException with structured detail.

    Detail shape: ``{"code": <boto code>, "message": <human-readable>}``.
    Frontend reads ``message`` for display and ``code`` for per-code UI hints
    (e.g. "Open admin to fix" when code == "InvalidRegion").
    """
    return HTTPException(
        status_code=error.http_status,
        detail={"code": error.code, "message": str(error)},
    )


def validate_role_access(role_name: Optional[str], current_user: Dict[str, Any]) -> Optional[str]:
    """Validate that user has access to the specified role"""
    if role_name is None:
        return None

    # Admins have access to all roles
    if current_user.get("is_admin", False):
        return role_name

    allowed_roles = current_user.get("allowed_roles", [])
    if role_name not in allowed_roles:
        raise HTTPException(
            status_code=403, detail=f"Access denied: You don't have permission to use role '{role_name}'"
        )

    return role_name


@app.get("/api/buckets")
async def list_buckets(
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List available S3 buckets - delegates to s3_client.list_buckets_for_role."""
    try:
        # list_buckets_for_role does blocking boto3 I/O (list_buckets, or nothing
        # at all if allowed_buckets is configured) — run off the event loop so a
        # slow/unreachable S3 endpoint doesn't stall every other request.
        return await run_in_threadpool(list_buckets_for_role, role, current_user)
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        # e.g. malformed allowed_buckets, missing credentials, assume_role failure
        logger.error(f"Configuration error when listing buckets: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))
    except (ClientError, BotoCoreError) as e:
        # Detect "credentials cannot list all buckets" — common for R2, MinIO scoped tokens,
        # AWS IAM with bucket-scoped policies. Return 403 with actionable guidance pointing
        # the user to the role's "Allowed Buckets" field instead of a raw S3 error.
        error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") and e.response else ""
        http_status = (
            e.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
            if hasattr(e, "response") and e.response
            else 0
        )
        if error_code in {"AccessDenied", "Forbidden"} or http_status == 403:
            # Generic message: this role's credentials cannot list all buckets.
            # Frontend layers the role-appropriate CTA on top — admins get an
            # "open admin to fix" button, non-admins get "contact administrator".
            raise HTTPException(
                status_code=403,
                detail=(
                    "Your credentials don't have permission to list all buckets. "
                    "This is normal for scoped tokens (R2, MinIO, AWS IAM with bucket-scoped policies)."
                ),
            )

        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list buckets: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in list_buckets")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Server error — see server logs"},
        ) from e


@app.get("/api/buckets/{bucket_name}/files")
async def list_files(
    bucket_name: str,
    path: str = Query("", description="Path prefix to list files from"),
    role: Optional[str] = Query(None, description="Role name to use"),
    max_keys: Optional[int] = Query(
        None,
        ge=1,
        le=1000,
        description=(
            "Page size (1..1000). When set, switches the response shape to the "
            "paginated envelope {directories, files, next_token, has_more}."
        ),
    ),
    continuation_token: Optional[str] = Query(
        None,
        max_length=1024,
        description=("Opaque S3 continuation token from a previous response's next_token. Requires max_keys."),
    ),
    client_load: bool = Query(
        False,
        description=(
            "When true, switch to client-load mode: aggregate S3 pages up to "
            "max_client_load (or max_keys if given) and return "
            "{directories, files, truncated, next_token} for the /v2 UI to "
            "paginate client-side."
        ),
    ),
    search: Optional[str] = Query(
        None,
        max_length=1024,
        description=(
            "Server-side name-prefix search (client_load mode only). Lists the "
            "current folder's immediate children whose name starts with this "
            "value. Case-sensitive. Requires client_load=1."
        ),
    ),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List files and directories.

    Three modes (response shape selected by the query params):
      * Legacy (no `max_keys`, no `client_load`): zip every S3 page into one
        flat envelope `{files, path, total_count}`. Used by the vanilla UI at
        `/` and any external HTTP caller that pre-dates the pagination work.
      * Paginated (`max_keys` set): one S3 call per HTTP request (plus one
        directory-discovery call on the first page). Directories return only
        on the first page (when no `continuation_token`); files paginate via
        S3's `NextContinuationToken`.
      * Client-load (`client_load=1`): aggregate S3 pages up to
        `max_client_load` (or `max_keys` as the chunk size if given) and return
        `{directories, files, truncated, next_token}` for the /v2 UI to hold in
        memory and paginate client-side. Directories only on the first chunk.
    """
    try:
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
            search_prefix = sanitize_search_prefix(search) if isinstance(search, str) and search else ""
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if continuation_token is not None and max_keys is None and not client_load:
            raise HTTPException(
                status_code=400,
                detail="continuation_token requires max_keys to be set as well",
            )

        if search_prefix and not client_load:
            raise HTTPException(
                status_code=400,
                detail="search requires client_load=1",
            )

        # All three branches below do blocking boto3 I/O (one or more
        # list_objects_v2 calls) — run off the event loop so a slow bucket
        # listing doesn't stall every other request.
        if client_load:
            cfg = load_config()
            chunk = max_keys if max_keys is not None else int(cfg.get("max_client_load", 10000))
            page = await run_in_threadpool(
                list_objects_client_load_for_role,
                role,
                bucket_name,
                path,
                current_user,
                chunk,
                continuation_token,
                name_prefix=search_prefix,
            )
            return page

        if max_keys is None:
            files = await run_in_threadpool(list_objects_for_role, role, bucket_name, path, current_user)
            return {"files": files, "path": path, "total_count": len(files)}

        page = await run_in_threadpool(
            list_objects_paginated_for_role,
            role,
            bucket_name,
            path,
            current_user,
            max_keys,
            continuation_token,
        )
        return page

    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        error_msg = str(e)
        logger.error(f"Configuration error when listing files: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
        if error_code == "NoSuchBucket":
            raise HTTPException(status_code=404, detail=f"Bucket '{bucket_name}' not found")
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to list files: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in list_files")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Server error — see server logs"},
        ) from e


@app.post("/api/buckets/{bucket_name}/upload")
async def upload_file(
    request: Request,
    bucket_name: str,
    file: UploadFile = File(...),
    key: str = Form(..., description="S3 object key (path)"),
    role: Optional[str] = Form(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Upload a file to S3 — streams the spooled body via
    s3_client.upload_fileobj_for_role (boto3 managed multipart).

    The _upload_body_guard middleware has already auth-gated this request and
    bounded its declared Content-Length. This handler re-checks the TRUE
    spooled size (defense-in-depth against under-reported Content-Length),
    applies the upload_inline_extensions content-disposition logic, and hands
    the multipart parser's SpooledTemporaryFile to the streaming helper — the
    body is never copied into a bytes object. The helper does role validation,
    bucket-access validation, and metric accounting."""
    size: Optional[int] = None
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            key = sanitize_path(key)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # config is still needed below for upload_inline_extensions; the size
        # limit itself comes from the shared resolver.
        config = load_config(force_reload=False)
        max_file_size = resolve_max_file_size()

        # The multipart parser already spooled the body into `file`
        # (SpooledTemporaryFile: memory under 1 MB, disk above). Starlette
        # populates UploadFile.size while parsing; fall back to seeking the
        # underlying sync file object (cheap — it's a local temp file).
        size = file.size
        if size is None:
            file.file.seek(0, os.SEEK_END)
            size = file.file.tell()
        file.file.seek(0)

        # Defense-in-depth: the middleware bounded the DECLARED Content-Length,
        # but a client can under-report it. Reject on the true spooled size.
        if size > max_file_size:
            upload_rejected_total.labels(reason="size_limit").inc()
            size_mb = max_file_size / (1024 * 1024)
            raise HTTPException(status_code=413, detail=f"File size exceeds maximum allowed size of {size_mb}MB")

        # Check if file extension should have Content-Disposition: inline so it
        # opens in the browser (instead of downloading) when served via CDN /
        # presigned URL. Driven by upload_inline_extensions (split from the old
        # auto_inline_extensions in 1.0.3 — preview is a separate concern now).
        upload_inline_extensions = config.get("upload_inline_extensions", [])
        content_disposition: Optional[str] = None
        if upload_inline_extensions:
            # Get file extension from key (path)
            file_ext = Path(key).suffix.lstrip(".").lower()
            if file_ext in upload_inline_extensions:
                content_disposition = "inline"

        # boto3's upload_fileobj is synchronous — run it off the event loop.
        # The helper increments s3_bytes_total (direction="upload") and
        # s3_objects_total (operation="upload") internally — do NOT also
        # increment them here, doing so would double-count.
        await run_in_threadpool(
            upload_fileobj_for_role,
            role,
            bucket_name,
            key,
            file.file,
            current_user,
            content_type=file.content_type or "application/octet-stream",
            content_disposition=content_disposition,
            size=size,
        )
        return {"message": "File uploaded successfully", "key": key}
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
        error_msg = str(e)
        logger.error(f"Configuration error when uploading file: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_message = format_boto_error(e)
        # Log error details for debugging (without credentials)
        error_code = ""
        error_msg = ""
        error_type = type(e).__name__
        http_status_code = None
        if hasattr(e, "response") and e.response:
            if isinstance(e.response, dict):
                error_code = e.response.get("Error", {}).get("Code", "")
                error_msg = e.response.get("Error", {}).get("Message", "")
                http_status_code = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            elif hasattr(e.response, "get"):
                error_code = (
                    e.response.get("Error", {}).get("Code", "") if hasattr(e.response.get("Error", {}), "get") else ""
                )

        # Special handling for 403/AccessDenied errors
        is_access_denied = error_code == "AccessDenied" or (http_status_code and http_status_code == 403)
        log_level = logger.warning if is_access_denied else logger.error

        log_extra = {
            "bucket": bucket_name,
            "key": key,
            "role": role,
            "error_type": error_type,
            "error_code": error_code,
            "file_size": size,
        }
        if error_msg:
            log_extra["error_message"] = error_msg
        if http_status_code:
            log_extra["http_status_code"] = http_status_code

        log_level(
            f"File upload failed (S3 error{' - Access Denied' if is_access_denied else ''})",
            extra=log_extra,
            exc_info=True,
        )

        # Return 403 status for access denied errors
        status_code = 403 if is_access_denied else 500
        raise HTTPException(status_code=status_code, detail=f"Failed to upload file: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        # Log error details for debugging (without credentials)
        logger.exception(
            "File upload failed (unexpected error)",
            extra={
                "bucket": bucket_name,
                "key": key,
                "role": role,
                "error_type": type(e).__name__,
                "file_size": size,
            },
        )
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Upload failed — see server logs"},
        ) from e


def get_user_for_download(request: Request, response: Response) -> Dict[str, Any]:
    """Downloads go through the gateway too — same header principal as everything else."""
    return get_current_user(request, response)


@app.get("/api/buckets/{bucket_name}/download")
async def download_file(
    bucket_name: str,
    path: str = Query(..., description="Path to file to download"),
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_user_for_download),
):
    """Download a file from S3 - delegates to s3_client.iter_object_for_role for true streaming."""
    try:
        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Stream the object via the helper. The helper increments the
        # s3_bytes_total metric (direction="download") exactly once at
        # metadata-fetch time and returns a lazy iterator — MUST NOT be
        # materialized to bytes here so 100MB downloads don't get buffered
        # in process memory.
        #
        # Only the INITIAL call (the blocking GetObject that fetches metadata
        # + the body handle) is offloaded here. The returned body_iter is a
        # plain sync generator handed to StreamingResponse below — Starlette's
        # StreamingResponse already wraps a non-async iterator with
        # iterate_in_threadpool (see starlette/responses.py), so every
        # subsequent body.read() chunk is ALREADY run in the threadpool, one
        # chunk at a time, during stream_response(). Wrapping the whole
        # generator here too would double-hop each chunk through the
        # threadpool for no benefit.
        metadata, body_iter = await run_in_threadpool(iter_object_for_role, role, bucket_name, path, current_user)
        filename = path.split("/")[-1]

        from fastapi.responses import StreamingResponse

        headers = {"Content-Disposition": format_content_disposition(filename)}
        content_length = metadata.get("content_length", 0)
        if content_length:
            headers["Content-Length"] = str(content_length)

        return StreamingResponse(
            body_iter,
            media_type=metadata["content_type"],
            headers=headers,
        )
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
        # Check if it's a configuration error (contains role_arn or assume role related text)
        error_msg = str(e)
        if "role" in error_msg.lower() or "assume" in error_msg.lower() or "credentials" in error_msg.lower():
            logger.error(f"Configuration error when downloading file: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_code = e.response.get("Error", {}).get("Code", "") if hasattr(e, "response") else ""
        if error_code in {"404", "NoSuchKey"}:
            raise HTTPException(status_code=404, detail=f"File '{path}' not found")
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to download file: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in download_file")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Download failed — see server logs"},
        ) from e


@app.get("/api/buckets/{bucket_name}/presigned")
async def get_presigned_url(
    bucket_name: str,
    path: str = Query(..., description="Object key to sign"),
    role: str = Query(..., description="Role name to use (required)"),
    op: str = Query("get", description="Presign operation; only 'get' is supported"),
    expires_in: Optional[int] = Query(
        None,
        description="Requested URL lifetime in seconds. Defaults to the configured "
        "default; must be between 60 and the configured maximum.",
    ),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Return a presigned URL for sharing or browser-side display.

    The signed URL embeds the role's credentials. Lifetime is the configured
    default unless `expires_in` is given, which must be between 60s and the
    configured maximum (out-of-range values are rejected with 400, not clamped).
    The response echoes the granted `expires_in` and, for
    STS-backed roles (assume_role / profile) asked for more than 1h, a `warning`
    that the link may expire when the role's session ends.

    `role` is required. The frontend always passes it explicitly. Direct API
    callers that omit it get 422 from FastAPI's query validation.
    """
    from datetime import datetime, timedelta, timezone

    if op != "get":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported op: {op!r} (only 'get' is supported)",
        )

    # Resolve configured TTL bounds (config → env → default, clamped to ceiling).
    # Validate expires_in before bucket/path sanitization so callers get a clean
    # INVALID_EXPIRES_IN error even when bucket name shorthand is used in tests.
    config = load_config(force_reload=False)
    default_ttl, max_ttl = resolve_presigned_ttls(config)

    if expires_in is None:
        granted_ttl = default_ttl
    else:
        if expires_in < PRESIGNED_URL_MIN_TTL or expires_in > max_ttl:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "INVALID_EXPIRES_IN",
                    "message": (f"expires_in must be between {PRESIGNED_URL_MIN_TTL} and {max_ttl} seconds"),
                },
            )
        granted_ttl = expires_in

    try:
        bucket_name = sanitize_bucket_name(bucket_name)
        path = sanitize_path(path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Validate the role belongs to the user; on success, validated_role is the
    # canonical role string the helper expects.
    validated_role = validate_role_access(role, current_user) or role

    try:
        # generate_presigned_url itself is local crypto (no I/O) — but
        # get_s3_client() underneath can do a blocking STS assume_role call or
        # refresh expired credentials for assume_role/profile-typed roles, so
        # the whole (retrying) call is offloaded, same as every other S3 op.
        url = await run_in_threadpool(
            s3_generate_presigned_url_for_role,
            validated_role,
            bucket_name,
            path,
            current_user,
            expires_in=granted_ttl,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except (ClientError, BotoCoreError) as e:
        raise HTTPException(status_code=500, detail=format_boto_error(e))
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in get_presigned_url")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Presigned URL generation failed — see server logs"},
        ) from e

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=granted_ttl)).isoformat()
    response: Dict[str, Any] = {
        "url": url,
        "expires_at": expires_at,
        "expires_in": granted_ttl,
    }
    if granted_ttl > PRESIGNED_STS_WARNING_THRESHOLD and role_uses_temporary_credentials(validated_role):
        response["warning"] = (
            "This role uses temporary credentials — the link may stop working earlier, when the role's session expires."
        )
    return response


@app.delete("/api/buckets/{bucket_name}/files")
async def delete_file(
    request: Request,
    bucket_name: str,
    path: str = Query(..., description="Path to file or directory to delete"),
    role: Optional[str] = Query(None, description="Role name to use"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    csrf_verified: bool = Depends(verify_csrf_token),
):
    """Delete a file or recursively delete a directory from S3"""
    # Check if deletion is disabled (from environment variable or config)
    config = load_config(force_reload=False)
    disable_deletion_env = os.getenv("DISABLE_DELETION", "").lower() == "true"
    disable_deletion_config = config.get("disable_deletion", False)

    if disable_deletion_env or disable_deletion_config:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="File deletion is disabled by administrator")
    try:
        # A trailing "/" is the directory-delete signal delete_object_for_role
        # relies on (recursive delete vs. exact single-key delete) — capture it
        # from the RAW query value before sanitize_path strips every leading
        # and trailing "/" for path-traversal safety.
        wants_recursive_delete = path.rstrip().endswith("/")

        # Validate and sanitize inputs
        try:
            bucket_name = sanitize_bucket_name(bucket_name)
            path = sanitize_path(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not path:
            raise HTTPException(status_code=400, detail="Cannot delete root path")

        # Restore the directory signal sanitize_path just stripped. Without
        # this, a folder delete would reach delete_object_for_role as a bare
        # key (no trailing slash) and either 404 (exact-key miss) or, pre-fix,
        # silently prefix-match and delete unrelated siblings. Guarded by
        # `not path.endswith("/")` so this stays a no-op if sanitize_path ever
        # stops stripping the trailing slash (e.g. under test monkeypatching).
        if wants_recursive_delete and not path.endswith("/"):
            path = path + "/"

        # Delegate to s3_client.delete_object_for_role. The helper does its own
        # role/bucket access validation, recursively deletes everything under
        # `path` when it ends with "/", otherwise deletes exactly that one key
        # (no prefix matching), and raises FileNotFoundError when nothing
        # matches. Returns {"message": ..., "count": N}. Blocking boto3 I/O
        # (list + delete_object(s)) — offloaded so a large recursive delete
        # doesn't stall the event loop.
        return await run_in_threadpool(delete_object_for_role, role, bucket_name, path, current_user)
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        # Handle errors from s3_client (e.g., assume_role failures, missing credentials)
        # Check if it's a configuration error (contains role_arn or assume role related text)
        error_msg = str(e)
        if "role" in error_msg.lower() or "assume" in error_msg.lower() or "credentials" in error_msg.lower():
            logger.error(f"Configuration error when deleting file: {error_msg}", exc_info=True)
        raise HTTPException(status_code=400, detail=error_msg)
    except (ClientError, BotoCoreError) as e:
        error_message = format_boto_error(e)
        raise HTTPException(status_code=500, detail=f"Failed to delete: {error_message}")
    except S3OperationError as e:
        raise _s3_error_to_http(e) from e
    except Exception as e:
        logger.exception("Unexpected error in delete_file")
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL", "message": "Delete failed — see server logs"},
        ) from e


# Mount MCP sub-app at /mcp — must come AFTER all @app.get/@app.post route
# registrations (so the middleware stack is complete) and BEFORE the SPA
# catch-all below: the catch-all is greedy, anything registered after it is
# unreachable. ROUTE ORDERING INVARIANT: API routes -> /mcp mount -> SPA
# catch-all LAST.
from another_s3_manager.mcp_server import get_mcp_app

app.mount("/mcp", get_mcp_app())


# Root React SPA (built by frontend/, bundled into static/app/ by the
# multi-stage Dockerfile). Phase 7 removed the vanilla UI — the SPA owns
# every path, including the old /v2/* URLs (they render the router's 404).
#
# Single catch-all: real files (assets, favicon) are served with the right
# content-type; everything else falls back to index.html so React Router
# handles the URL. Files are read fully into memory and returned via
# Response (not FileResponse) — SPA bundles are <1MB, the cost is
# negligible and it avoids Starlette mount-vs-route ordering bugs
# (https://github.com/encode/starlette/issues/437).
_SPA_DIR = STATIC_DIR / "app"

# Unknown paths under these prefixes 404 as JSON instead of serving
# index.html — an HTML 200 for a typo'd API call reads as success to
# clients and would mask MCP misroutes. (Known routes and the /mcp mount
# win by registration order; this guard covers the UNKNOWN remainder.)
_RESERVED_PREFIXES = ("api/", "mcp/")
_RESERVED_EXACT = {"api", "mcp", "metrics", "health", "login"}


# Pre-Phase-7, bare /mcp worked via Starlette's redirect_slashes (307 to
# /mcp/). The GET catch-all below shadows that mechanism (full match beats
# the redirect fallback; for POST the catch-all's partial match turns into
# a 405). Existing agent configs point at /mcp without a trailing slash, so
# keep the redirect explicit. Methods = MCP streamable-HTTP verbs.
@app.api_route("/mcp", methods=["GET", "POST", "DELETE"], include_in_schema=False)
async def mcp_no_slash_redirect():
    return RedirectResponse(url="/mcp/", status_code=307)


@app.get("/", response_class=HTMLResponse)
async def serve_spa_root():
    """Bare / → index.html."""
    return await serve_spa("")


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """SPA-aware static handler (see block comment above)."""
    import mimetypes

    from fastapi import Response

    if (
        full_path in _RESERVED_EXACT
        or full_path.startswith(_RESERVED_PREFIXES)
        or full_path == "login"
        or full_path.startswith("login/")
    ):
        raise HTTPException(status_code=404, detail="Not found")

    # Block path traversal at the route level (sanitize_path is for S3 keys)
    if ".." in full_path or full_path.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid path")

    if full_path:
        candidate = _SPA_DIR / full_path
        try:
            candidate_resolved = candidate.resolve()
            spa_resolved = _SPA_DIR.resolve()
            if spa_resolved in candidate_resolved.parents and candidate.is_file():
                content_type, _ = mimetypes.guess_type(str(candidate))
                if not content_type:
                    content_type = "application/octet-stream"
                return Response(content=candidate.read_bytes(), media_type=content_type)
        except (OSError, ValueError):
            pass  # fall through to index.html

    index_file = _SPA_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="React SPA not built yet")
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    port = int(os.getenv("PORT", "8080"))
    log_level = str(os.getenv("LOG_LEVEL", "info")).lower()
    host = str(os.getenv("UVICORN_HOST", "0.0.0.0"))
    uvicorn.run(app, host=host, port=port, log_level=log_level)
