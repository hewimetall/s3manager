import builtins
import copy
import importlib
import io
import os
import time
from datetime import datetime
from pathlib import Path

os.environ.setdefault("APP_VERSION", "0.1.0")

import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException, status

import another_s3_manager.constants as _constants_module


def reload_main():
    import another_s3_manager.main as main

    importlib.reload(main)
    return main


def reload_auth_module():
    import another_s3_manager.auth as auth

    importlib.reload(auth)
    return auth


def reload_users_module():
    import another_s3_manager.users as users

    importlib.reload(users)
    return users


def test_reload_helpers():
    assert hasattr(reload_main(), "app")
    assert reload_auth_module()
    assert reload_users_module()


def test_main_import_without_dotenv(monkeypatch):
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    module = importlib.reload(importlib.import_module("another_s3_manager.main"))
    try:
        assert hasattr(module, "app")
    finally:
        importlib.reload(module)


def test_main_exits_when_secret_missing(monkeypatch):
    module = importlib.import_module("another_s3_manager.main")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.setenv("JWT_SECRET_KEY", "")

    def fake_exit(code):
        raise SystemExit(code)

    monkeypatch.setattr("sys.exit", fake_exit)
    with pytest.raises(SystemExit) as exc:
        importlib.reload(module)
    assert exc.value.code == 1
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
    importlib.reload(module)


def login(client, username="admin", password="admin123", *, groups=None):
    """Authenticate the TestClient via gateway headers.

    Local password login is gone. ``password`` is ignored and kept only so
    older call sites that still pass it keep working. Identity and roles come
    from ``x-authentik-*`` on every request (including CSRF-bearing ones).
    """
    del password  # local passwords are not used
    if groups is None:
        groups = "admin" if username == "admin" else username
    if not isinstance(groups, str):
        groups = "|".join(groups)
    gateway = {
        "x-authentik-username": username,
        "x-authentik-groups": groups,
    }
    me_response = client.get("/api/me", headers=gateway)
    assert me_response.status_code == status.HTTP_200_OK, me_response.text
    body = me_response.json()
    headers = {
        "X-CSRF-Token": body["csrf_token"],
        **gateway,
    }
    # TestClient keeps cookies automatically; gateway identity is header-based,
    # so pin the trusted headers on the client for subsequent requests.
    client.headers.update(headers)
    return {"user": body}, headers


def _seed_spa_index():
    """Seed a fake SPA index.html; returns (index_file, created)."""
    from another_s3_manager.constants import STATIC_DIR

    spa_dir = STATIC_DIR / "app"
    spa_dir.mkdir(parents=True, exist_ok=True)
    index_file = spa_dir / "index.html"
    created = not index_file.exists()
    if created:
        index_file.write_text("<!DOCTYPE html><html><head></head><body><div id='root'></div></body></html>")
    return index_file, created


def test_root_serves_spa_index(app_client):
    """Phase 7: the React SPA owns / — vanilla index.html is gone."""
    index_file, created = _seed_spa_index()
    try:
        response = app_client.get("/")
        assert response.status_code == status.HTTP_200_OK
        assert "root" in response.text  # SPA mount div, not the vanilla page
    finally:
        if created:
            index_file.unlink()


def test_spa_fallback_serves_index_for_unknown_paths(app_client):
    """Deep links (/login, /r/.../b/...) and dead /v2 URLs all serve index.html
    so React Router renders the page (or its 404)."""
    index_file, created = _seed_spa_index()
    try:
        # /login is reserved after local-login removal — must not be SPA-swallowed.
        assert app_client.get("/login").status_code == 404
        for path in ("/r/aws-prod/b/images/p/2026/photos", "/v2/anything"):
            response = app_client.get(path)
            assert response.status_code == 200, f"{path} -> {response.status_code}"
            assert "root" in response.text
    finally:
        if created:
            index_file.unlink()


def test_spa_catchall_does_not_swallow_reserved_prefixes(app_client):
    """Unknown api/* paths must be JSON 404, not index.html with HTTP 200 —
    and /mcp must keep routing to the MCP mount (ordering invariant)."""
    index_file, created = _seed_spa_index()
    try:
        response = app_client.get("/api/definitely-not-a-route")
        assert response.status_code == 404
        assert "<!DOCTYPE" not in response.text

        response = app_client.get("/mcp/definitely-not-a-route")
        assert "<!DOCTYPE" not in response.text  # anything but the SPA page

        assert app_client.get("/health").status_code == 200
    finally:
        if created:
            index_file.unlink()














def test_get_current_user_info(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/me", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "admin"
    assert data["is_admin"] is True
    assert data["app_version"] == _constants_module.APP_VERSION


def test_get_current_user_info_requires_auth(app_client):
    response = app_client.get("/api/me")
    # Cookie-based auth: missing access_token cookie -> 401 Not authenticated
    assert response.status_code == status.HTTP_401_UNAUTHORIZED








def test_get_app_info(app_client):
    response = app_client.get("/api/app-info")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "app_name" in data
    assert data["app_version"] == _constants_module.APP_VERSION
























def test_get_config_admin(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "roles" in data
    assert "is_read_only" in data




def test_export_config_admin(app_client):
    _, headers = login(app_client)
    response = app_client.get("/api/config/export", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "roles" in data




def test_update_config(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Default",
                "type": "default",
                "description": "Use default credentials",
            }
        ],
        "enable_lazy_loading": False,
        "max_file_size": 1024 * 1024,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_200_OK, response.json()


def test_update_config_clears_s3_client_cache(app_client):
    """POST /api/config must clear the S3 client cache so subsequent requests
    re-create clients with the new config (region, endpoint, credentials).

    Regression: prior to this fix the monkey-patch on `config_module.save_config`
    was dead code (main.py imported `save_config` directly, bypassing the patch),
    so admin edits to a broken role's region required a container restart.
    """
    from another_s3_manager import s3_client

    _, headers = login(app_client)

    # Pre-fill cache: simulate that the role was used before the config save.
    s3_client._s3_clients_cache["Default"] = "fake-cached-client"
    assert "Default" in s3_client._s3_clients_cache

    payload = {
        "roles": [{"name": "Default", "type": "default", "description": "Use default credentials"}],
        "enable_lazy_loading": False,
        "max_file_size": 1024 * 1024,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == 200, response.json()

    assert "Default" not in s3_client._s3_clients_cache
    assert s3_client._s3_clients_cache == {}


def test_update_config_clears_boto3_credential_cache(app_client, monkeypatch):
    """POST /api/config must also flush boto3/botocore's credential cache.

    The bare _s3_clients_cache dict clear is insufficient for `assume_role` /
    `profile` role types: boto3 keeps an independent credential cache on the
    default session, so a fresh client would still pick up the OLD STS or
    profile credentials until natural expiry (~1h). Verifies that
    clear_s3_clients_cache calls _clear_boto3_cached_credentials.
    """
    from another_s3_manager import s3_client

    _, headers = login(app_client)

    called = {"count": 0}
    original_clear = s3_client._clear_boto3_cached_credentials

    def spy() -> None:
        called["count"] += 1
        original_clear()

    monkeypatch.setattr(s3_client, "_clear_boto3_cached_credentials", spy)

    payload = {
        "roles": [{"name": "Default", "type": "default", "description": "Use default credentials"}],
        "enable_lazy_loading": False,
        "max_file_size": 1024 * 1024,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == 200, response.json()
    assert called["count"] >= 1, "Expected _clear_boto3_cached_credentials to be invoked"


def test_list_buckets_with_allowed_list(app_client, monkeypatch):
    import another_s3_manager.config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data["roles"][0]["allowed_buckets"] = ["bucket-a", "bucket-b"]
    config_module.save_config(config_data)

    _, headers = login(app_client)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == ["bucket-a", "bucket-b"]


def test_list_buckets_uses_s3(app_client, moto_s3):
    """B1: route -> list_buckets_for_role -> boto3 -> moto returns real bucket names."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="bucket")

    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == ["bucket"]


def test_list_files(app_client, moto_s3):
    """B1: route -> list_objects_for_role -> moto. Verifies the delimiter='/'
    response surfaces top-level files + immediate subdirectories without
    leaking deeper keys, and that the route wraps the helper's list in the
    legacy {files, path, total_count} envelope the React frontend expects."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="files-bucket")
    moto_s3.put_object(Bucket="files-bucket", Key="root.txt", Body=b"hi")
    moto_s3.put_object(Bucket="files-bucket", Key="sub/inner.txt", Body=b"deep")

    response = app_client.get("/api/buckets/files-bucket/files?path=", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["path"] == ""
    assert data["total_count"] == 2
    names = {item["name"] for item in data["files"]}
    assert "root.txt" in names
    assert "sub" in names
    # delimiter='/' must scope to depth-1 — nested keys must not leak
    assert "inner.txt" not in names
    sub_entry = next(item for item in data["files"] if item["name"] == "sub")
    assert sub_entry["is_directory"] is True


def test_upload_file(app_client, moto_s3):
    """B1: route -> put_object_for_role -> boto3 -> moto stores the object."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="up-bucket")

    response = app_client.post(
        "/api/buckets/up-bucket/upload",
        data={"key": "hello.txt"},
        files={"file": ("hello.txt", b"world", "text/plain")},
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    stored = moto_s3.get_object(Bucket="up-bucket", Key="hello.txt")
    assert stored["Body"].read() == b"world"
    assert stored["ContentType"] == "text/plain"


def test_upload_sets_inline_disposition_for_configured_extension(app_client, moto_s3):
    """An extension in upload_inline_extensions gets Content-Disposition: inline
    on the stored object (so it opens in the browser via CDN/presigned)."""
    import another_s3_manager.config as config_module

    cfg = config_module.load_config(force_reload=True)
    cfg["upload_inline_extensions"] = ["pdf"]
    config_module.save_config(cfg)

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="inline-bucket")

    # .pdf → inline
    app_client.post(
        "/api/buckets/inline-bucket/upload",
        data={"key": "doc.pdf"},
        files={"file": ("doc.pdf", b"%PDF-1.4", "application/pdf")},
        headers=headers,
    )
    pdf = moto_s3.get_object(Bucket="inline-bucket", Key="doc.pdf")
    assert pdf.get("ContentDisposition") == "inline"

    # .txt → NOT inline (not in the list)
    app_client.post(
        "/api/buckets/inline-bucket/upload",
        data={"key": "note.txt"},
        files={"file": ("note.txt", b"hi", "text/plain")},
        headers=headers,
    )
    txt = moto_s3.get_object(Bucket="inline-bucket", Key="note.txt")
    assert txt.get("ContentDisposition") in (None, "")


def test_upload_increments_bytes_metric_once(app_client, moto_s3):
    """Regression: the route used to manually increment s3_bytes_total
    (direction="upload") AFTER calling the helper, which itself increments
    the metric internally. That double-counted the bytes. After this
    refactor only the helper bumps the metric — the route's manual
    increment was removed."""
    from another_s3_manager.metrics import s3_bytes_total

    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="metric-bucket")
    labels = {"role": "Default", "bucket": "metric-bucket", "direction": "upload"}
    before = s3_bytes_total.labels(**labels)._value.get()

    payload = b"a" * 100
    response = app_client.post(
        "/api/buckets/metric-bucket/upload",
        data={"key": "m.bin", "role": "Default"},
        files={"file": ("m.bin", payload, "application/octet-stream")},
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK

    after = s3_bytes_total.labels(**labels)._value.get()
    assert after - before == 100, f"metric must increment once, got {after - before}"


def test_upload_routes_through_streaming_helper(app_client, mocker):
    """The happy path calls upload_fileobj_for_role (streaming) with the
    spooled FILE OBJECT and exact size — NOT the bytes-based
    put_object_for_role (which stays MCP-only)."""
    _, headers = login(app_client)
    stream_spy = mocker.patch("another_s3_manager.main.upload_fileobj_for_role", return_value=None)
    legacy_spy = mocker.patch("another_s3_manager.s3_client.put_object_for_role")

    payload = b"stream body"
    response = app_client.post(
        "/api/buckets/stream-bucket/upload",
        data={"key": "s.txt", "role": "Default"},
        files={"file": ("s.txt", payload, "text/plain")},
        headers=headers,
    )

    assert response.status_code == status.HTTP_200_OK
    legacy_spy.assert_not_called()
    stream_spy.assert_called_once()
    args, kwargs = stream_spy.call_args
    assert args[0] == "Default"  # role
    assert args[1] == "stream-bucket"  # bucket
    assert args[2] == "s.txt"  # key
    assert not isinstance(args[3], (bytes, bytearray)) and hasattr(args[3], "read")  # fileobj
    assert args[4]["username"] == "admin"  # user dict
    assert kwargs["content_type"] == "text/plain"
    assert kwargs["content_disposition"] is None
    assert kwargs["size"] == len(payload)


async def test_upload_handler_rejects_oversize_spooled_body():
    """Defense-in-depth (G2): a client that under-reports Content-Length slips
    past the middleware guard; the handler must 413 on the TRUE spooled size
    and bump upload_rejected_total. Calls the handler directly because real
    multipart cannot under-report (Content-Length >= file bytes), so this
    branch is unreachable through TestClient."""
    import importlib

    from fastapi import UploadFile
    from starlette.datastructures import Headers

    import another_s3_manager.config as config_module
    import another_s3_manager.main as main
    from another_s3_manager.metrics import upload_rejected_total

    importlib.reload(main)
    cfg = config_module.load_config(force_reload=True)
    cfg["max_file_size"] = 1024
    config_module.save_config(cfg)

    payload = b"x" * 2048
    upload = UploadFile(
        file=io.BytesIO(payload),
        size=len(payload),
        filename="big.bin",
        headers=Headers({"content-type": "application/octet-stream"}),
    )
    before = upload_rejected_total.labels(reason="size_limit")._value.get()

    with pytest.raises(HTTPException) as exc_info:
        await main.upload_file(
            request=None,
            bucket_name="bucket",
            file=upload,
            key="big.bin",
            role=None,
            current_user={"username": "admin", "is_admin": True, "allowed_roles": []},
            csrf_verified=True,
        )

    assert exc_info.value.status_code == 413
    assert upload_rejected_total.labels(reason="size_limit")._value.get() - before == 1


def test_upload_file_too_large(app_client, mocker):
    """Oversize declared Content-Length is refused by the body-guard middleware
    with 413 (was a handler-level 400 before the guard existed)."""
    import another_s3_manager.config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data["max_file_size"] = 1
    config_module.save_config(config_data)
    _, headers = login(app_client)
    response = app_client.post(
        "/api/buckets/test-bucket/upload",
        data={"key": "file.txt"},
        files={"file": ("file.txt", io.BytesIO(b"toolarge"), "text/plain")},
        headers=headers,
    )
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


def test_download_file(app_client, moto_s3):
    """B1: route -> iter_object_for_role -> boto3 -> moto streams the stored body."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="dl-bucket")
    moto_s3.put_object(Bucket="dl-bucket", Key="file.txt", Body=b"data", ContentType="text/plain")

    response = app_client.get("/api/buckets/dl-bucket/download", params={"path": "file.txt"}, headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.content == b"data"
    # Streaming must preserve the upstream Content-Type
    assert response.headers["content-type"].startswith("text/plain")


def test_delete_file(app_client, moto_s3):
    """B1: route -> delete_object_for_role -> boto3 -> moto removes the object."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="test-bucket")
    moto_s3.put_object(Bucket="test-bucket", Key="path/file.txt", Body=b"data")

    response = app_client.delete("/api/buckets/test-bucket/files", params={"path": "path/file.txt"}, headers=headers)
    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["count"] == 1
    # Verify the file is actually gone from the moto-backed bucket
    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="test-bucket").get("Contents", [])}
    assert "path/file.txt" not in remaining


def test_delete_file_does_not_delete_prefix_siblings(app_client, moto_s3):
    """Data-loss regression: deleting 'notes.txt' via the web route must not
    also remove 'notes.txt.bak' / 'notes.txt.old' just because they share the
    same prefix."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="siblings-route-b")
    moto_s3.put_object(Bucket="siblings-route-b", Key="notes.txt", Body=b"a")
    moto_s3.put_object(Bucket="siblings-route-b", Key="notes.txt.bak", Body=b"b")
    moto_s3.put_object(Bucket="siblings-route-b", Key="notes.txt.old", Body=b"c")

    response = app_client.delete("/api/buckets/siblings-route-b/files", params={"path": "notes.txt"}, headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["count"] == 1

    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="siblings-route-b").get("Contents", [])}
    assert remaining == {"notes.txt.bak", "notes.txt.old"}


def test_delete_file_folder_delete_via_route_is_recursive(app_client, moto_s3):
    """A trailing '/' in the query param must survive sanitize_path and still
    trigger a recursive folder delete, while a lexically-similar sibling
    outside the folder survives."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="folder-route-b")
    moto_s3.put_object(Bucket="folder-route-b", Key="reports/2026/jan.csv", Body=b"f")
    moto_s3.put_object(Bucket="folder-route-b", Key="reports/2026/feb.csv", Body=b"g")
    moto_s3.put_object(Bucket="folder-route-b", Key="reports/2026-q1.csv", Body=b"e")

    response = app_client.delete("/api/buckets/folder-route-b/files", params={"path": "reports/2026/"}, headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["count"] == 2

    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="folder-route-b").get("Contents", [])}
    assert remaining == {"reports/2026-q1.csv"}


def test_delete_file_not_found_returns_404_via_moto(app_client, moto_s3):
    """A genuinely non-existent key returns 404, not a silent success — real
    S3's DeleteObject is idempotent and would not raise on its own."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="missing-route-b")
    moto_s3.put_object(Bucket="missing-route-b", Key="unrelated.txt", Body=b"z")

    response = app_client.delete("/api/buckets/missing-route-b/files", params={"path": "gone.txt"}, headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="missing-route-b").get("Contents", [])}
    assert remaining == {"unrelated.txt"}






















def test_me_admin_returns_all_config_roles(app_client, mocker):
    """Admins should see every role defined in config.json, regardless of
    the per-user `allowed_roles` field. The React sidebar relies on this
    to show admins the full role tree without an extra /api/config call."""
    config_data = {
        "roles": [
            {"name": "aws-prod", "type": "default"},
            {"name": "r2-cdn", "type": "credentials"},
            {"name": "wasabi-archive", "type": "profile"},
        ],
    }
    mocker.patch("another_s3_manager.main.load_config", return_value=config_data)

    _, _ = login(app_client)  # admin login (admin user has allowed_roles=[])

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    body = me_response.json()
    assert body["is_admin"] is True
    assert body["allowed_roles"] == ["aws-prod", "r2-cdn", "wasabi-archive"]


def test_me_admin_with_empty_config_returns_empty_roles(app_client, mocker):
    """Admin with no roles in config gets an empty list — must not crash."""
    mocker.patch("another_s3_manager.main.load_config", return_value={"roles": []})

    _, _ = login(app_client)

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    body = me_response.json()
    assert body["is_admin"] is True
    assert body["allowed_roles"] == []


def test_me_includes_disable_deletion_from_config(app_client, mocker):
    """/api/me must surface disable_deletion so the React UI can disable Delete controls."""
    mocker.patch(
        "another_s3_manager.main.load_config",
        return_value={"roles": [], "disable_deletion": True},
    )
    _, _ = login(app_client)

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    assert me_response.json()["disable_deletion"] is True


def test_me_includes_disable_deletion_from_env(app_client, mocker, monkeypatch):
    """DISABLE_DELETION env var should win over config (matches /api/config behaviour)."""
    mocker.patch(
        "another_s3_manager.main.load_config",
        return_value={"roles": [], "disable_deletion": False},
    )
    monkeypatch.setenv("DISABLE_DELETION", "true")
    _, _ = login(app_client)

    me_response = app_client.get("/api/me")
    assert me_response.status_code == status.HTTP_200_OK
    assert me_response.json()["disable_deletion"] is True


def test_me_disable_deletion_defaults_false(app_client, mocker, monkeypatch):
    """Neither env nor config set → disable_deletion is False."""
    mocker.patch("another_s3_manager.main.load_config", return_value={"roles": []})
    monkeypatch.delenv("DISABLE_DELETION", raising=False)
    _, _ = login(app_client)

    assert app_client.get("/api/me").json()["disable_deletion"] is False






def test_get_config_admin_read_only(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch("another_s3_manager.config.is_config_writable", return_value=False)
    response = app_client.get("/api/config", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["is_read_only"] is True




def test_list_buckets_access_denied_returns_friendly_403(app_client, mocker):
    """When ListBuckets fails with AccessDenied (e.g. R2 bucket-scoped tokens, AWS IAM
    bucket-scoped policies), the API must return 403 with a generic explanation —
    not a raw 500 boto error. The frontend layers role-appropriate CTAs on top."""
    mocker.patch(
        "another_s3_manager.main.list_buckets_for_role",
        side_effect=ClientError({"Error": {"Code": "AccessDenied", "Message": "Nope"}}, "ListBuckets"),
    )
    _, headers = login(app_client)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    detail = response.json()["detail"]
    assert "permission to list all buckets" in detail
    assert "scoped" in detail.lower()


def test_list_buckets_other_client_error_still_returns_500(app_client, mocker):
    """Non-403 boto errors should still surface as 500 — the friendly-error path
    is specifically for 'cannot list buckets' permission failures, not generic ones."""
    mocker.patch(
        "another_s3_manager.main.list_buckets_for_role",
        side_effect=ClientError({"Error": {"Code": "InternalError", "Message": "boom"}}, "ListBuckets"),
    )
    _, headers = login(app_client)
    response = app_client.get("/api/buckets", headers=headers)
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


def test_list_files_handles_error(app_client, mocker):
    """B2: helper raises ClientError(NoSuchBucket) -> route maps to 404."""
    _, headers = login(app_client)

    mocker.patch(
        "another_s3_manager.main.list_objects_for_role",
        side_effect=ClientError({"Error": {"Code": "NoSuchBucket", "Message": "Missing"}}, "ListObjectsV2"),
    )
    response = app_client.get("/api/buckets/test-bucket/files", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_upload_file_handles_exception(app_client, mocker):
    """B2: helper raises ValueError (e.g. assume_role failure) -> route returns 400."""
    _, headers = login(app_client)
    mocker.patch(
        "another_s3_manager.main.upload_fileobj_for_role",
        side_effect=ValueError("boom"),
    )
    response = app_client.post(
        "/api/buckets/test-bucket/upload",
        data={"key": "file.txt"},
        files={"file": ("file.txt", io.BytesIO(b"data"), "text/plain")},
        headers=headers,
    )
    # ValueError from s3_client now returns 400 (configuration error) instead of 500
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_download_file_not_found(app_client, mocker):
    """B2: helper raises FileNotFoundError -> route returns 404."""
    _, headers = login(app_client)
    mocker.patch(
        "another_s3_manager.main.iter_object_for_role",
        side_effect=FileNotFoundError("Object 'ghost.txt' not found in bucket 'test-bucket'"),
    )
    response = app_client.get("/api/buckets/test-bucket/download", params={"path": "ghost.txt"}, headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_delete_file_handles_error(app_client, mocker):
    """B2: helper raises ClientError -> route returns 500."""
    _, headers = login(app_client)
    mocker.patch(
        "another_s3_manager.main.delete_object_for_role",
        side_effect=ClientError({"Error": {"Code": "AccessDenied", "Message": "Nope"}}, "ListObjectsV2"),
    )
    response = app_client.delete("/api/buckets/test-bucket/files", params={"path": "path"}, headers=headers)
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR






def test_update_config_read_only(app_client, mocker):
    _, headers = login(app_client)
    mocker.patch("another_s3_manager.config.is_config_writable", return_value=False)
    response = app_client.post(
        "/api/config",
        json={"roles": []},
        headers=headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_update_config_invalid_structure(app_client):
    _, headers = login(app_client)
    response = app_client.post("/api/config", json={}, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_enable_lazy_loading_not_bool(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [],
        "enable_lazy_loading": "yes",
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_max_file_size_invalid(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [],
        "max_file_size": "big",
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_credentials_invalid_access_key(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Creds",
                "type": "credentials",
                "access_key_id": "BAD",
                "secret_access_key": "secret",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_credentials_missing_secret(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Creds",
                "type": "credentials",
                "access_key_id": "AKIA1234567890123456",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_profile_requires_name(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Profile",
                "type": "profile",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_assume_role_requires_arn(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "Assume",
                "type": "assume_role",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_update_config_s3_compatible_success(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
                "use_ssl": False,
                "verify_ssl": False,
                "addressing_style": "path",
            }
        ],
        "enable_lazy_loading": True,
        "max_file_size": 100 * 1024 * 1024,
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    if response.status_code != status.HTTP_200_OK:
        print(f"Response: {response.status_code}")
        print(f"Detail: {response.json()}")
    assert response.status_code == status.HTTP_200_OK


def test_update_config_s3_compatible_missing_endpoint_url(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "endpoint_url" in response.json()["detail"].lower()


def test_update_config_s3_compatible_missing_access_key_id(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "access_key_id" in response.json()["detail"].lower()


def test_update_config_s3_compatible_missing_secret(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "secret_access_key" in response.json()["detail"].lower()


def test_update_config_s3_compatible_empty_endpoint_url(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
                "endpoint_url": "   ",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "endpoint_url" in response.json()["detail"].lower()


def test_update_config_s3_compatible_empty_access_key_id(app_client):
    _, headers = login(app_client)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "   ",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "access_key_id" in response.json()["detail"].lower()


def test_update_config_s3_compatible_preserves_secret_on_edit(app_client):
    _, headers = login(app_client)
    # First, create a role with secret
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "minioadmin",
                "secret_access_key": "minioadmin",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_200_OK

    # Now edit without providing secret (should preserve existing)
    payload = {
        "roles": [
            {
                "name": "MinIO",
                "type": "s3_compatible",
                "access_key_id": "newkey",
                "endpoint_url": "http://minio:9000",
            }
        ],
    }
    response = app_client.post("/api/config", json=payload, headers=headers)
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_list_buckets_invalid_allowed_buckets(mocker):
    module = reload_main()
    import another_s3_manager.config as config_module

    config_data = copy.deepcopy(config_module.load_config(force_reload=True))
    config_data["roles"][0]["allowed_buckets"] = "not-a-list"
    mocker.patch("another_s3_manager.config.load_config", return_value=config_data)

    with pytest.raises(HTTPException) as exc:
        await module.list_buckets(None, {"username": "admin", "is_admin": True})
    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
async def test_list_files_invalid_path():
    module = reload_main()
    with pytest.raises(HTTPException) as exc:
        await module.list_files(
            "test-bucket",
            "../etc",
            None,
            {"username": "admin", "is_admin": True},
        )
    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST




@pytest.mark.parametrize("raw_path", ["", "/", "//", "  /  ", "../"])
def test_delete_file_root_path_forbidden(app_client, moto_s3, raw_path):
    """The root-delete guard (`if not path: raise 400`) in main.py fires
    BEFORE the trailing-slash restoration step that re-appends "/" after
    sanitize_path strips it — that ORDERING is the entire reason an input
    that sanitizes to "" can never be resurrected into "/", a bucket-root
    recursive-delete prefix. The previous version of this test only covered
    `path=""`, so a refactor that moved the restoration above the guard
    would have stayed green right up until it deleted a whole bucket.

    Parametrized over shapes that could plausibly collapse to "" or "/" —
    bare empty, one or more bare slashes, a whitespace-padded slash, and a
    traversal attempt — each seeded against a real (moto) bucket and
    asserted to leave every object untouched. Checking only the response
    status would still pass even if the delete had already happened; the
    survival assertion is what actually proves the guard held."""
    _, headers = login(app_client)
    moto_s3.create_bucket(Bucket="root-guard-bucket")
    moto_s3.put_object(Bucket="root-guard-bucket", Key="keep-me.txt", Body=b"data")
    moto_s3.put_object(Bucket="root-guard-bucket", Key="also-keep.txt", Body=b"data2")

    response = app_client.delete(
        "/api/buckets/root-guard-bucket/files",
        params={"path": raw_path},
        headers=headers,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    remaining = {obj["Key"] for obj in moto_s3.list_objects_v2(Bucket="root-guard-bucket").get("Contents", [])}
    assert remaining == {"keep-me.txt", "also-keep.txt"}


def test_delete_file_disabled(app_client, mocker):
    _, headers = login(app_client)
    import another_s3_manager.config as config_module

    config_data = config_module.load_config(force_reload=True)
    config_data["disable_deletion"] = True
    config_module.save_config(config_data)
    response = app_client.delete(
        "/api/buckets/test-bucket/files",
        params={"path": "path/file.txt"},
        headers=headers,
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN




def test_run_alembic_upgrade_preserves_the_alembic_ini_section(monkeypatch):
    """Regression test for the `_ = cfg.file_config` no-op in `_run_alembic_upgrade`.

    `Config.file_config` is a `@util.memoized_property`: its FIRST access parses alembic.ini
    (if `config_file_name` is still set) or falls back to a bare, section-less ConfigParser (if
    `config_file_name` is already None) -- and either way the result is cached forever. The whole
    `[alembic]` section (script_location, prepend_sys_path, ...) only survives nulling
    `config_file_name` because `_ = cfg.file_config` forces that first access, from the real ini,
    BEFORE the null happens. `script_location` alone would not catch a regression here (it is
    explicitly re-set with `cfg.set_main_option(...)` a few lines later regardless of ini
    parsing) -- `prepend_sys_path` is untouched by any explicit set, so it is proof the real ini
    was parsed. Deleting the no-op line, or hoisting `cfg.config_file_name = None` above it,
    raises nothing and silently drops this to None instead.
    """
    import another_s3_manager.main as main

    captured = {}

    def _fake_upgrade(cfg, revision):
        captured["cfg"] = cfg

    monkeypatch.setattr(main.command, "upgrade", _fake_upgrade)

    main._run_alembic_upgrade()

    cfg = captured.get("cfg")
    assert cfg is not None, "command.upgrade was never called"
    # Explicitly re-set by _run_alembic_upgrade -- would pass even with the bug, kept as a sanity check.
    script_location = cfg.get_main_option("script_location")
    assert script_location
    assert Path(script_location).is_dir()
    # NOT explicitly set anywhere -- only present if alembic.ini was actually parsed into
    # file_config before config_file_name was nulled. This is what the bug drops to None.
    assert cfg.get_main_option("prepend_sys_path") == ".", (
        "the [alembic] section of alembic.ini was not preserved -- "
        "cfg.file_config must be materialized before cfg.config_file_name is nulled"
    )


async def test_lifespan_runs_startup_tasks_then_enters_mcp(mocker):
    """The lifespan's two jobs: run the startup work, then enter FastMCP's session manager.

    All the actual startup BEHAVIOUR is tested by driving main.run_startup_tasks() directly
    (see tests/test_admin_password_sync.py) -- this test only pins the WIRING, i.e. that
    `lifespan` still calls it and still enters the MCP session manager, in that order.

    Both collaborators are mocked, deliberately: FastMCP's StreamableHTTPSessionManager.run()
    can be entered only ONCE per instance for the life of the process (a hard guard in the mcp
    SDK), and the FastMCP instance is a module-level singleton the suite never reloads. That
    one real entry is already spent by test_startup_runs_migrations_and_json_import above, so
    a second real lifespan boot anywhere in the suite would raise RuntimeError. Mocking the
    session manager keeps this test independent of that budget.
    """
    import contextlib

    from another_s3_manager import main

    calls = []

    mocker.patch.object(main, "run_startup_tasks", side_effect=lambda: calls.append("startup"))

    @contextlib.asynccontextmanager
    async def _fake_run():
        calls.append("mcp_enter")
        yield
        calls.append("mcp_exit")

    # Patch the module-level FastMCP reference rather than its `session_manager` attribute:
    # session_manager is a read-only property on FastMCP, so patch.object cannot restore it.
    mocker.patch.object(main, "_mcp_instance", mocker.Mock(session_manager=mocker.Mock(run=_fake_run)))

    async with main.lifespan(main.app):
        # Startup work must be done -- and MCP entered -- before the app serves anything.
        assert calls == ["startup", "mcp_enter"]

    assert calls == ["startup", "mcp_enter", "mcp_exit"]


def test_download_file_with_colon_in_key(app_client, moto_s3):
    """REGRESSION: files with `:` in S3 key (e.g. ISO timestamps) must be downloadable.
    Previously sanitize_path rejected `:` outright, breaking download/delete for these keys.
    B1: route -> iter_object_for_role -> moto."""
    key_with_colon = "logs/2026-04-30T15:00:00.log"
    file_content = b"hello from a colon-named file"

    moto_s3.create_bucket(Bucket="test-bucket")
    moto_s3.put_object(Bucket="test-bucket", Key=key_with_colon, Body=file_content, ContentType="text/plain")

    # Login to obtain session cookie + CSRF token
    _, headers = login(app_client)

    # Download via API — query param carries the literal key (TestClient handles URL encoding).
    # The key point of this test is that sanitize_path no longer rejects the `:` character.
    response = app_client.get(
        "/api/buckets/test-bucket/download",
        params={"path": key_with_colon},
        headers=headers,
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text[:200]}"
    assert response.content == file_content




# ---------------------------------------------------------------------------
# MCP config fields (Phase 5, Task 6)
# ---------------------------------------------------------------------------


def test_get_config_includes_mcp_fields(app_client):
    """GET /api/config must expose all 4 MCP fields to the admin."""
    _, headers = login(app_client)
    resp = app_client.get("/api/config", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "mcp_enabled" in body
    assert "mcp_disable_writes" in body
    assert "mcp_text_extensions" in body
    assert "mcp_global_max_read_bytes" in body


def test_post_config_persists_mcp_fields(app_client):
    """POST /api/config must accept and persist all 4 MCP fields."""
    _, headers = login(app_client)
    initial = app_client.get("/api/config", headers=headers).json()
    initial["mcp_enabled"] = False
    initial["mcp_disable_writes"] = True
    initial["mcp_text_extensions"] = ["custom"]
    initial["mcp_global_max_read_bytes"] = 2_097_152
    resp = app_client.post("/api/config", json=initial, headers=headers)
    assert resp.status_code == 200
    after = app_client.get("/api/config", headers=headers).json()
    assert after["mcp_enabled"] is False
    assert after["mcp_disable_writes"] is True
    assert after["mcp_text_extensions"] == ["custom"]
    assert after["mcp_global_max_read_bytes"] == 2_097_152


def test_post_config_validates_mcp_global_max_read_bytes_range(app_client):
    """POST /api/config must reject mcp_global_max_read_bytes > 10MB."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config", headers=headers).json()
    cfg["mcp_global_max_read_bytes"] = 999_999_999
    resp = app_client.post("/api/config", json=cfg, headers=headers)
    assert resp.status_code == 422


def test_post_config_preserves_mcp_fields_when_omitted(app_client):
    """POST /api/config without MCP fields must preserve previously saved values."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config", headers=headers).json()
    cfg["mcp_enabled"] = False
    app_client.post("/api/config", json=cfg, headers=headers)
    # Submit same payload but without mcp_enabled key
    minimal = {k: v for k, v in cfg.items() if k != "mcp_enabled"}
    resp = app_client.post("/api/config", json=minimal, headers=headers)
    assert resp.status_code == 200
    after = app_client.get("/api/config", headers=headers).json()
    assert after["mcp_enabled"] is False  # preserved from previous POST


# ---------------------------------------------------------------------------
# MCP big-bucket ergonomics config fields (2026-07-12 design)
# ---------------------------------------------------------------------------

_BIG_BUCKET_KEYS = (
    "mcp_summary_max_keys",
    "mcp_summary_prefix_scan_pages",
    "mcp_list_page_size",
    "mcp_list_max_page_size",
)


def test_get_config_includes_big_bucket_mcp_fields(app_client):
    """GET /api/config must expose all four summary/list-paging keys to the admin."""
    _, headers = login(app_client)
    body = app_client.get("/api/config", headers=headers).json()
    assert body["mcp_summary_max_keys"] == 50_000
    assert body["mcp_summary_prefix_scan_pages"] == 20
    assert body["mcp_list_page_size"] == 1000
    assert body["mcp_list_max_page_size"] == 10_000


def test_post_config_persists_big_bucket_mcp_fields(app_client):
    """POST /api/config must accept and persist all four keys."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config", headers=headers).json()
    cfg["mcp_summary_max_keys"] = 20_000
    cfg["mcp_summary_prefix_scan_pages"] = 5
    cfg["mcp_list_page_size"] = 200
    cfg["mcp_list_max_page_size"] = 2000
    resp = app_client.post("/api/config", json=cfg, headers=headers)
    assert resp.status_code == 200
    after = app_client.get("/api/config", headers=headers).json()
    assert after["mcp_summary_max_keys"] == 20_000
    assert after["mcp_summary_prefix_scan_pages"] == 5
    assert after["mcp_list_page_size"] == 200
    assert after["mcp_list_max_page_size"] == 2000


def test_post_config_rejects_invalid_big_bucket_mcp_fields(app_client):
    """Non-int, boolean, zero and over-ceiling values are rejected with 422."""
    _, headers = login(app_client)
    base = app_client.get("/api/config", headers=headers).json()

    for key, bad in (
        ("mcp_summary_max_keys", "abc"),
        ("mcp_summary_max_keys", 0),
        # 999 was accepted before the 2026-07-13 final-review fix (POST bound
        # was 1..1_000_000) even though the Settings NumberInput min and the
        # runtime floor (s3_client._MIN_SUMMARY_MAX_KEYS) were both already
        # 1000 — a value the walk would silently re-floor at call time. The
        # POST bound now agrees with the other two layers.
        ("mcp_summary_max_keys", 999),
        ("mcp_summary_max_keys", 1_000_001),
        ("mcp_summary_prefix_scan_pages", True),
        ("mcp_summary_prefix_scan_pages", 201),
        ("mcp_list_page_size", -5),
        ("mcp_list_page_size", 10_001),
        ("mcp_list_max_page_size", 0),
        ("mcp_list_max_page_size", 10_001),
    ):
        cfg = dict(base)
        cfg[key] = bad
        resp = app_client.post("/api/config", json=cfg, headers=headers)
        assert resp.status_code == 422, f"{key}={bad!r} should be rejected, got {resp.status_code}"


def test_post_config_preserves_big_bucket_mcp_fields_when_omitted(app_client):
    """POST without the four keys must preserve previously saved values."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config", headers=headers).json()
    cfg["mcp_summary_max_keys"] = 30_000
    app_client.post("/api/config", json=cfg, headers=headers)

    minimal = {k: v for k, v in cfg.items() if k not in _BIG_BUCKET_KEYS}
    resp = app_client.post("/api/config", json=minimal, headers=headers)
    assert resp.status_code == 200
    after = app_client.get("/api/config", headers=headers).json()
    assert after["mcp_summary_max_keys"] == 30_000
    assert after["mcp_list_page_size"] == 1000  # untouched default preserved too


# ---------------------------------------------------------------------------
# MCP kill-switch middleware
# ---------------------------------------------------------------------------


def test_mcp_kill_switch_blocks_when_disabled(app_client, monkeypatch):
    """When mcp_enabled=False in config, /mcp/* returns 503."""
    import another_s3_manager.config as config_module

    original_load = config_module.load_config

    def _disabled_config(force_reload=False):
        cfg = original_load(force_reload=force_reload)
        cfg["mcp_enabled"] = False
        return cfg

    monkeypatch.setattr(config_module, "load_config", _disabled_config)
    resp = app_client.get("/mcp/anything")
    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "MCP_DISABLED"


def test_mcp_kill_switch_allows_when_enabled(app_client):
    """Default is mcp_enabled=True. /mcp/* should NOT return 503 from kill-switch."""
    resp = app_client.get("/mcp/anything")
    # MCP routing may return 404/405/etc. — any status except 503 is acceptable.
    assert resp.status_code != 503


# --- /api/buckets/{b}/presigned ---


def test_presigned_endpoint_happy_path(app_client, mocker):
    """Allowed role + bucket + existing path returns 200 with url + expires_at."""
    _, _ = login(app_client)

    mocker.patch(
        "another_s3_manager.main.validate_role_access",
        return_value="default-role",
    )
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        return_value="https://bucket.s3.amazonaws.com/file.txt?X-Amz-Signature=abc",
    )

    response = app_client.get(
        "/api/buckets/my-bucket/presigned",
        params={"role": "default-role", "path": "file.txt"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["url"].startswith("https://")
    assert "X-Amz-Signature" in body["url"]
    assert "expires_at" in body
    # Parses as ISO8601 with timezone info
    from datetime import datetime

    datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))


def test_presigned_endpoint_permission_denied(app_client, mocker):
    """PermissionError from helper → 403."""
    _, _ = login(app_client)

    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        side_effect=PermissionError("Bucket not allowed for role"),
    )

    response = app_client.get(
        "/api/buckets/forbidden/presigned",
        params={"role": "r", "path": "x.txt"},
    )
    assert response.status_code == 403


def test_presigned_endpoint_not_found(app_client, mocker):
    """FileNotFoundError → 404."""
    _, _ = login(app_client)

    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        side_effect=FileNotFoundError("not there"),
    )

    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "missing.txt"},
    )
    assert response.status_code == 404


def test_presigned_endpoint_invalid_op(app_client):
    """Only op=get supported in v1."""
    _, _ = login(app_client)
    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "x.txt", "op": "put"},
    )
    assert response.status_code == 400


def test_presigned_endpoint_requires_auth(app_client):
    """Anonymous request → 401."""
    app_client.cookies.clear()
    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "x.txt"},
    )
    assert response.status_code == 401


def test_presigned_endpoint_requires_role_param(app_client):
    """Omitting `role` query param → 422 (FastAPI validation)."""
    _, _ = login(app_client)
    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"path": "x.txt"},
    )
    assert response.status_code == 422


def test_presigned_endpoint_boto_error_returns_500(app_client, mocker):
    """ClientError from helper (e.g. STS assume_role failure) → 500 with formatted message."""
    _, _ = login(app_client)

    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        side_effect=ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "STS token expired"}},
            "AssumeRole",
        ),
    )

    response = app_client.get(
        "/api/buckets/some-bucket/presigned",
        params={"role": "r", "path": "x.txt"},
    )
    assert response.status_code == 500
    # format_boto_error produces a user-friendly message rather than raw repr
    body = response.json()
    assert "detail" in body
    assert isinstance(body["detail"], str)


def test_presigned_endpoint_custom_expires_in_echoed(app_client, mocker):
    """A valid expires_in is granted and echoed; expires_at matches it."""
    login(app_client)
    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        return_value="https://my-bucket.s3.amazonaws.com/f?X-Amz-Signature=abc",
    )
    mocker.patch("another_s3_manager.main.role_uses_temporary_credentials", return_value=False)
    resp = app_client.get(
        "/api/buckets/my-bucket/presigned",
        params={"role": "r", "path": "f.txt", "expires_in": 21600},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["expires_in"] == 21600
    assert "warning" not in body


def test_presigned_endpoint_default_when_expires_in_omitted(app_client, mocker):
    """No expires_in → server default (3600) is granted and echoed."""
    login(app_client)
    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        return_value="https://my-bucket.s3.amazonaws.com/f?X-Amz-Signature=abc",
    )
    mocker.patch("another_s3_manager.main.role_uses_temporary_credentials", return_value=False)
    resp = app_client.get("/api/buckets/my-bucket/presigned", params={"role": "r", "path": "f.txt"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["expires_in"] == 3600


def test_presigned_endpoint_rejects_below_minimum(app_client, mocker):
    """expires_in < 60 → 400 with structured detail."""
    login(app_client)
    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    resp = app_client.get(
        "/api/buckets/b/presigned",
        params={"role": "r", "path": "f.txt", "expires_in": 30},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "INVALID_EXPIRES_IN"


def test_presigned_endpoint_rejects_above_max(app_client, mocker):
    """expires_in > configured max → 400 with structured detail."""
    login(app_client)
    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    resp = app_client.get(
        "/api/buckets/b/presigned",
        params={"role": "r", "path": "f.txt", "expires_in": 999_999_999},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "INVALID_EXPIRES_IN"


def test_presigned_endpoint_warns_for_sts_role_over_threshold(app_client, mocker):
    """STS role + TTL > 1h → response carries a warning string."""
    login(app_client)
    mocker.patch("another_s3_manager.main.validate_role_access", return_value="sts")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        return_value="https://my-bucket.s3.amazonaws.com/f?X-Amz-Signature=abc",
    )
    mocker.patch("another_s3_manager.main.role_uses_temporary_credentials", return_value=True)
    resp = app_client.get(
        "/api/buckets/my-bucket/presigned",
        params={"role": "sts", "path": "f.txt", "expires_in": 86400},
    )
    assert resp.status_code == 200, resp.text
    assert "warning" in resp.json()
    assert "temporary credentials" in resp.json()["warning"]


def test_presigned_endpoint_no_warning_for_sts_role_at_default(app_client, mocker):
    """STS role but TTL <= 1h → no warning (link fits inside a fresh session)."""
    login(app_client)
    mocker.patch("another_s3_manager.main.validate_role_access", return_value="sts")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        return_value="https://my-bucket.s3.amazonaws.com/f?X-Amz-Signature=abc",
    )
    mocker.patch("another_s3_manager.main.role_uses_temporary_credentials", return_value=True)
    resp = app_client.get(
        "/api/buckets/my-bucket/presigned",
        params={"role": "sts", "path": "f.txt", "expires_in": 3600},
    )
    assert resp.status_code == 200, resp.text
    assert "warning" not in resp.json()


def test_get_config_returns_presigned_ttl_fields(app_client):
    """GET /api/config exposes default + max presigned TTL for the frontend."""
    login(app_client)
    resp = app_client.get("/api/config")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "presigned_url_default_ttl" in body
    assert "presigned_url_max_ttl" in body
    assert body["presigned_url_default_ttl"] == 3600
    assert body["presigned_url_max_ttl"] == 604800


def test_update_config_persists_presigned_ttls(app_client):
    """Admin can save valid default + max presigned TTL."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config").json()
    cfg["presigned_url_default_ttl"] = 900
    cfg["presigned_url_max_ttl"] = 86400
    save = app_client.post("/api/config", json=cfg, headers=headers)
    assert save.status_code == 200, save.text
    after = app_client.get("/api/config").json()
    assert after["presigned_url_default_ttl"] == 900
    assert after["presigned_url_max_ttl"] == 86400


def test_update_config_rejects_default_over_max(app_client):
    """default > max → 400."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config").json()
    cfg["presigned_url_default_ttl"] = 86400
    cfg["presigned_url_max_ttl"] = 3600
    save = app_client.post("/api/config", json=cfg, headers=headers)
    assert save.status_code == 400


def test_update_config_rejects_max_over_ceiling(app_client):
    """max above the 7-day ceiling → 400."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config").json()
    cfg["presigned_url_max_ttl"] = 999_999_999
    save = app_client.post("/api/config", json=cfg, headers=headers)
    assert save.status_code == 400


def test_update_config_rejects_below_minimum_ttl(app_client):
    """default below the 60s floor → 400."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config").json()
    cfg["presigned_url_default_ttl"] = 10
    save = app_client.post("/api/config", json=cfg, headers=headers)
    assert save.status_code == 400


def test_presigned_endpoint_accepts_expires_in_exactly_max(app_client, mocker):
    """expires_in exactly equal to the configured max is accepted (inclusive bound)."""
    login(app_client)
    mocker.patch("another_s3_manager.main.validate_role_access", return_value="r")
    mocker.patch(
        "another_s3_manager.main.s3_generate_presigned_url_for_role",
        return_value="https://b.s3.amazonaws.com/f?X-Amz-Signature=abc",
    )
    mocker.patch("another_s3_manager.main.role_uses_temporary_credentials", return_value=False)
    resp = app_client.get(
        "/api/buckets/my-bucket/presigned",
        params={"role": "r", "path": "f.txt", "expires_in": 604800},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["expires_in"] == 604800


def test_update_config_preserves_omitted_ttl_field(app_client):
    """Saving only max_ttl preserves the existing default_ttl (preserve-on-omit)."""
    _, headers = login(app_client)
    cfg = app_client.get("/api/config").json()
    # First set a known default so we can prove it survives a later partial save.
    cfg["presigned_url_default_ttl"] = 900
    cfg["presigned_url_max_ttl"] = 86400
    first = app_client.post("/api/config", json=cfg, headers=headers)
    assert first.status_code == 200, first.text
    # Now save a config payload that omits presigned_url_default_ttl entirely.
    cfg2 = app_client.get("/api/config").json()
    del cfg2["presigned_url_default_ttl"]
    cfg2["presigned_url_max_ttl"] = 172800
    second = app_client.post("/api/config", json=cfg2, headers=headers)
    assert second.status_code == 200, second.text
    after = app_client.get("/api/config").json()
    assert after["presigned_url_default_ttl"] == 900  # preserved
    assert after["presigned_url_max_ttl"] == 172800  # updated


def test_to_http_exception_uses_typed_status_and_dict_detail():
    """_s3_error_to_http maps each typed S3 error to its http_status + structured detail."""
    from fastapi import HTTPException

    from another_s3_manager.errors import S3AccessDeniedError, S3NotFoundError
    from another_s3_manager.main import _s3_error_to_http

    err = S3AccessDeniedError("AccessDenied", "no perms")
    http = _s3_error_to_http(err)
    assert isinstance(http, HTTPException)
    assert http.status_code == 403
    assert http.detail == {"code": "AccessDenied", "message": "no perms"}

    nf = S3NotFoundError("NoSuchBucket", "missing")
    http2 = _s3_error_to_http(nf)
    assert http2.status_code == 404
    assert http2.detail == {"code": "NoSuchBucket", "message": "missing"}


def test_list_buckets_typed_access_denied_returns_403_with_dict_detail(app_client, mocker):
    """When the s3_client probe / op raises S3AccessDeniedError, /api/buckets
    returns 403 with detail={'code': 'AccessDenied', 'message': '...'}."""
    from another_s3_manager.errors import S3AccessDeniedError

    mocker.patch(
        "another_s3_manager.main.list_buckets_for_role",
        side_effect=S3AccessDeniedError("AccessDenied", "scoped token cannot list"),
    )
    _, headers = login(app_client)
    resp = app_client.get("/api/buckets", headers=headers)
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["code"] == "AccessDenied"
    assert "scoped token cannot list" in body["detail"]["message"]


def test_list_files_typed_no_such_bucket_returns_404_with_dict_detail(app_client, mocker):
    """list_files maps S3NotFoundError to 404 with structured detail."""
    from another_s3_manager.errors import S3NotFoundError

    mocker.patch(
        "another_s3_manager.main.list_objects_for_role",
        side_effect=S3NotFoundError("NoSuchBucket", "bucket missing"),
    )
    _, headers = login(app_client)
    resp = app_client.get("/api/buckets/missing-bucket/files", headers=headers)
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["code"] == "NoSuchBucket"
    assert body["detail"]["message"] == "bucket missing"


def test_list_files_generic_exception_logs_and_returns_500(app_client, mocker, caplog):
    """Generic uncaught Exception in list_files: response is 500 with INTERNAL,
    AND the server logs include the stack trace (was missing before)."""
    import logging

    mocker.patch(
        "another_s3_manager.main.list_objects_for_role",
        side_effect=RuntimeError("totally unexpected"),
    )
    _, headers = login(app_client)

    with caplog.at_level(logging.ERROR, logger="another_s3_manager.main"):
        resp = app_client.get("/api/buckets/some/files", headers=headers)

    assert resp.status_code == 500
    # Must contain the stack trace (logger.exception writes ERROR level + exc_info).
    assert any("totally unexpected" in record.message or record.exc_info is not None for record in caplog.records)


# Regression coverage for the S3OperationError ladder + structured `{"code":"INTERNAL", ...}`
# fallback on the three remaining routes (upload/download/delete). The Phase 6a-7 refactor
# moved the raise sites from `execute_with_s3_retry` (which the routes used to mock) into
# the s3_client._for_role helpers — coverage for these branches re-anchors via the helper
# mocks here.


def test_upload_typed_s3_error_returns_mapped_status_with_dict_detail(app_client, mocker):
    """upload_fileobj_for_role raises S3AccessDeniedError → 403 with structured detail."""
    from another_s3_manager.errors import S3AccessDeniedError

    mocker.patch(
        "another_s3_manager.main.upload_fileobj_for_role",
        side_effect=S3AccessDeniedError("AccessDenied", "scoped token rejected"),
    )
    _, headers = login(app_client)
    resp = app_client.post(
        "/api/buckets/any/upload",
        data={"key": "x.bin", "role": "Default"},
        files={"file": ("x.bin", b"abc", "application/octet-stream")},
        headers=headers,
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["code"] == "AccessDenied"


def test_upload_generic_exception_returns_structured_500(app_client, mocker):
    """A non-typed RuntimeError from the helper hits the structured INTERNAL fallback."""
    mocker.patch(
        "another_s3_manager.main.upload_fileobj_for_role",
        side_effect=RuntimeError("kaboom"),
    )
    _, headers = login(app_client)
    resp = app_client.post(
        "/api/buckets/any/upload",
        data={"key": "x.bin", "role": "Default"},
        files={"file": ("x.bin", b"abc", "application/octet-stream")},
        headers=headers,
    )
    assert resp.status_code == 500
    assert resp.json()["detail"] == {"code": "INTERNAL", "message": "Upload failed — see server logs"}


def test_download_typed_s3_error_returns_mapped_status_with_dict_detail(app_client, mocker):
    """iter_object_for_role raises S3NotFoundError → 404 with structured detail."""
    from another_s3_manager.errors import S3NotFoundError

    mocker.patch(
        "another_s3_manager.main.iter_object_for_role",
        side_effect=S3NotFoundError("NoSuchKey", "missing"),
    )
    _, headers = login(app_client)
    resp = app_client.get("/api/buckets/any/download?path=missing.txt&role=Default", headers=headers)
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["code"] == "NoSuchKey"


def test_download_generic_exception_returns_structured_500(app_client, mocker):
    """A non-typed RuntimeError from the streaming helper hits the structured INTERNAL fallback."""
    mocker.patch(
        "another_s3_manager.main.iter_object_for_role",
        side_effect=RuntimeError("kaboom"),
    )
    _, headers = login(app_client)
    resp = app_client.get("/api/buckets/any/download?path=x.bin&role=Default", headers=headers)
    assert resp.status_code == 500
    assert resp.json()["detail"] == {"code": "INTERNAL", "message": "Download failed — see server logs"}


def test_delete_typed_s3_error_returns_mapped_status_with_dict_detail(app_client, mocker):
    """delete_object_for_role raises S3AccessDeniedError → 403 with structured detail."""
    from another_s3_manager.errors import S3AccessDeniedError

    mocker.patch(
        "another_s3_manager.main.delete_object_for_role",
        side_effect=S3AccessDeniedError("AccessDenied", "denied"),
    )
    _, headers = login(app_client)
    resp = app_client.delete("/api/buckets/any/files?path=x.bin&role=Default", headers=headers)
    assert resp.status_code == 403
    body = resp.json()
    assert body["detail"]["code"] == "AccessDenied"


def test_delete_generic_exception_returns_structured_500(app_client, mocker):
    """A non-typed RuntimeError from the delete helper hits the structured INTERNAL fallback."""
    mocker.patch(
        "another_s3_manager.main.delete_object_for_role",
        side_effect=RuntimeError("kaboom"),
    )
    _, headers = login(app_client)
    resp = app_client.delete("/api/buckets/any/files?path=x.bin&role=Default", headers=headers)
    assert resp.status_code == 500
    assert resp.json()["detail"] == {"code": "INTERNAL", "message": "Delete failed — see server logs"}








def test_clearing_extension_lists_persists_across_reload(app_client):
    """End-to-end: admin clears both extension lists to [] via POST /api/config;
    the empty lists must stick across a reload (no re-seed) — key presence is the
    migrated marker now."""
    import another_s3_manager.config as config_module

    seeded = config_module.load_config(force_reload=True)
    assert seeded["preview_text_extensions"]  # defaults seeded in
    assert seeded["upload_inline_extensions"]

    _, headers = login(app_client)
    resp = app_client.post(
        "/api/config",
        json={
            "roles": seeded.get("roles", []),
            "preview_text_extensions": [],
            "upload_inline_extensions": [],
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.json()

    reloaded = config_module.load_config(force_reload=True)
    assert reloaded["preview_text_extensions"] == []
    assert reloaded["upload_inline_extensions"] == []
