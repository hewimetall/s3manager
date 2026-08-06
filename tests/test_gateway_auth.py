"""Gateway-header auth: groups grant roles; /login is gone."""

import os

from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("COOKIE_SECURE", "false")


def test_gateway_header_auth(tmp_path, monkeypatch):
    """All gateway checks share one TestClient — MCP session manager is one-shot."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        """
{
  "roles": [
    {"name": "timeweb", "type": "s3_compatible", "allowed_buckets": ["13820aae-shared"]},
    {"name": "dayana", "type": "s3_compatible", "allowed_buckets": ["tw-stand-owner-dayana-ae91a9b6b21236ef"]}
  ],
  "disable_deletion": true
}
""".strip()
    )
    monkeypatch.setenv("S3_FILE_MANAGER_CONFIG", str(config_path))
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only")

    from another_s3_manager.config import load_config

    load_config(force_reload=True)

    from another_s3_manager.main import app

    with TestClient(app) as client:
        assert client.post("/api/login", data={"username": "x", "password": "y"}).status_code == 404
        assert client.get("/login").status_code == 404
        assert client.get("/api/me").status_code == 401

        response = client.get(
            "/api/me",
            headers={
                "x-authentik-username": "dayana-owner",
                "x-authentik-groups": "dayana",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["username"] == "dayana-owner"
        assert body["is_admin"] is False
        assert body["allowed_roles"] == ["dayana"]

        denied = client.get(
            "/api/buckets",
            params={"role": "timeweb"},
            headers={
                "x-authentik-username": "dayana-owner",
                "x-authentik-groups": "dayana",
            },
        )
        assert denied.status_code == 403

        admin = client.get(
            "/api/me",
            headers={
                "x-authentik-username": "akadmin",
                "x-authentik-groups": "admin|owners",
            },
        )
        assert admin.status_code == 200
        admin_body = admin.json()
        assert admin_body["is_admin"] is True
        assert "dayana" in admin_body["allowed_roles"]
        assert "timeweb" in admin_body["allowed_roles"]
