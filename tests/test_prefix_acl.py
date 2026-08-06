"""One-bucket + prefixes: validate_storage_access is the single gate for REST and MCP."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("COOKIE_SECURE", "false")

SHARED = "13820aae-0a3c-463d-b672-d25f73eda26a"

_PREFIX_CONFIG = {
    "shared_bucket": SHARED,
    "roles": [
        {
            "name": "timeweb",
            "type": "s3_compatible",
            "allowed_buckets": [SHARED],
        },
        {
            "name": "dayana",
            "type": "s3_compatible",
            "allowed_buckets": [SHARED],
            "allowed_prefixes": ["stand-dayana/"],
        },
        {
            "name": "dayna",
            "type": "s3_compatible",
            "allowed_buckets": [SHARED],
            "allowed_prefixes": ["stand-dayna/"],
        },
        {
            "name": "legacy-stand",
            "type": "s3_compatible",
            "allowed_buckets": ["tw-stand-legacy-aaaaaaaaaaaaaaaa"],
        },
    ],
    "disable_deletion": True,
}


@pytest.fixture
def prefix_config(tmp_path, monkeypatch):
    """Runs after autouse isolated_environment — overwrites Default-only config."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_PREFIX_CONFIG))
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(config_path))
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from another_s3_manager.config import load_config

    load_config(force_reload=True)
    return config_path


DAYANA_HDR = {
    "x-authentik-username": "dayana-owner",
    "x-authentik-groups": "dayana",
}
ADMIN_HDR = {
    "x-authentik-username": "akadmin",
    "x-authentik-groups": "admin",
}
NO_GROUP_HDR = {
    "x-authentik-username": "lonely",
    "x-authentik-groups": "",
}


def test_unit_prefix_boundary_helpers():
    from another_s3_manager.s3_client import key_within_allowed_prefix, normalize_access_key

    assert key_within_allowed_prefix("stand-dayana/sprites/a.png", "stand-dayana/")
    assert key_within_allowed_prefix("stand-dayana", "stand-dayana/")
    assert not key_within_allowed_prefix("stand-dayana-evil/x", "stand-dayana/")
    assert not key_within_allowed_prefix("stand-dayna/x", "stand-dayana/")
    assert not key_within_allowed_prefix("", "stand-dayana/")

    with pytest.raises(PermissionError):
        normalize_access_key("../stand-dayana/x")
    with pytest.raises(PermissionError):
        normalize_access_key("/stand-dayana/x")
    with pytest.raises(PermissionError):
        normalize_access_key("s3://bucket/stand-dayana/x")


def test_validate_storage_access_allow_and_deny(prefix_config):
    from another_s3_manager.s3_client import validate_storage_access

    dayana = {"username": "u", "is_admin": False, "allowed_roles": ["dayana"]}
    admin = {"username": "a", "is_admin": True, "allowed_roles": ["timeweb", "dayana"]}
    nobody = {"username": "n", "is_admin": False, "allowed_roles": []}

    validate_storage_access("dayana", SHARED, dayana, object_key="stand-dayana/")
    validate_storage_access("dayana", SHARED, dayana, object_key="stand-dayana/sprites/a.png")

    for bad in ("stand-dayna/", "stand-dayana-evil/x", "", "../stand-dayana/x", "/stand-dayana/x"):
        with pytest.raises(PermissionError):
            validate_storage_access("dayana", SHARED, dayana, object_key=bad)

    with pytest.raises(PermissionError):
        validate_storage_access("dayana", SHARED, nobody, object_key="stand-dayana/")

    validate_storage_access("timeweb", SHARED, admin, object_key="")
    validate_storage_access("timeweb", SHARED, admin, object_key="stand-dayna/anything")

    legacy_user = {"username": "l", "is_admin": False, "allowed_roles": ["legacy-stand"]}
    validate_storage_access(
        "legacy-stand",
        "tw-stand-legacy-aaaaaaaaaaaaaaaa",
        legacy_user,
        object_key="anything/at/root",
    )
    with pytest.raises(PermissionError):
        validate_storage_access("legacy-stand", SHARED, legacy_user, object_key="stand-dayana/")


def test_rest_and_mcp_doors(prefix_config):
    """REST + MCP allow/deny in ONE TestClient (MCP session manager is one-shot)."""
    from another_s3_manager.main import app
    from another_s3_manager.mcp_server import McpError, _current_request, mcp

    with TestClient(app) as client:

        def files(path: str, headers=DAYANA_HDR, role="dayana"):
            return client.get(
                f"/api/buckets/{SHARED}/files",
                params={"role": role, "path": path},
                headers=headers,
            )

        with patch("another_s3_manager.s3_client.execute_with_s3_retry", return_value=[]):
            ok = files("stand-dayana")
            assert ok.status_code == 200, ok.text

        for path, label in [
            ("stand-dayna", "foreign"),
            ("stand-dayana-evil", "spoof"),
            ("", "root"),
            ("../stand-dayana", "traversal"),
            ("/stand-dayana", "absolute"),
        ]:
            denied = files(path)
            assert denied.status_code in (400, 403), (
                f"{label} path={path!r} -> {denied.status_code} {denied.text}"
            )

        no_groups = client.get("/api/me", headers=NO_GROUP_HDR)
        assert no_groups.status_code == 200
        assert no_groups.json()["allowed_roles"] == []
        assert files("stand-dayana", headers=NO_GROUP_HDR).status_code in (401, 403)

        with patch("another_s3_manager.s3_client.execute_with_s3_retry", return_value=[]):
            admin_root = files("", headers=ADMIN_HDR, role="timeweb")
            assert admin_root.status_code == 200, admin_root.text

    # MCP tools (no second TestClient lifespan)
    tool_registry = {tool.name: tool.fn for tool in mcp._tool_manager._tools.values()}

    class FakeToken:
        is_read_only = True
        max_read_bytes = None
        id = 1

    user = {"username": "dayana-owner", "is_admin": False, "allowed_roles": ["dayana"]}

    async def run_mcp():
        import another_s3_manager.mcp_server as mcp_mod

        async def fake_auth(_req):
            return FakeToken(), user

        original = mcp_mod.authenticate_mcp_request
        mcp_mod.authenticate_mcp_request = fake_auth
        token = _current_request.set(type("R", (), {"headers": {}})())
        try:
            with pytest.raises(McpError) as me:
                await tool_registry["list_files"](role="dayana", bucket=SHARED, path="stand-dayna/")
            assert me.value.code == "PREFIX_NOT_ALLOWED"

            with pytest.raises(McpError) as me2:
                await tool_registry["list_files"](role="dayana", bucket=SHARED, path="/stand-dayana/")
            assert me2.value.code == "PREFIX_NOT_ALLOWED"

            with pytest.raises(McpError) as me3:
                await tool_registry["list_files"](
                    role="dayana", bucket=SHARED, path="stand-dayana-evil/"
                )
            assert me3.value.code == "PREFIX_NOT_ALLOWED"

            with patch("another_s3_manager.s3_client.execute_with_s3_retry", return_value=[]):
                allowed = await tool_registry["list_files"](
                    role="dayana", bucket=SHARED, path="stand-dayana/"
                )
            assert "files" in allowed
        finally:
            _current_request.reset(token)
            mcp_mod.authenticate_mcp_request = original

    import asyncio

    asyncio.run(run_mcp())
