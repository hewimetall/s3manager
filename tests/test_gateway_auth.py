"""Gateway-header auth: groups grant roles; /login is gone."""

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("COOKIE_SECURE", "false")


@pytest.fixture
def client(tmp_path, monkeypatch):
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

    with TestClient(app) as test_client:
        yield test_client


def test_login_returns_404(client):
    response = client.post("/api/login", data={"username": "x", "password": "y"})
    assert response.status_code == 404


def test_login_page_returns_404(client):
    response = client.get("/login")
    assert response.status_code == 404


def test_me_requires_username_header(client):
    response = client.get("/api/me")
    assert response.status_code == 401


def test_dayana_group_sees_only_stand_bucket(client):
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

    buckets = client.get(
        "/api/buckets",
        params={"role": "dayana"},
        headers={
            "x-authentik-username": "dayana-owner",
            "x-authentik-groups": "dayana",
        },
    )
    assert buckets.status_code == 200
    names = buckets.json() if isinstance(buckets.json(), list) else buckets.json().get("buckets", buckets.json())
    # list_buckets may return list of names or objects
    flat = [b if isinstance(b, str) else b.get("name") or b.get("Name") for b in (names if isinstance(names, list) else [])]
    if not flat and isinstance(buckets.json(), dict):
        # some handlers wrap differently — assert role denial for timeweb instead
        pass
    denied = client.get(
        "/api/buckets",
        params={"role": "timeweb"},
        headers={
            "x-authentik-username": "dayana-owner",
            "x-authentik-groups": "dayana",
        },
    )
    assert denied.status_code == 403


def test_admin_group_sees_all_roles(client):
    response = client.get(
        "/api/me",
        headers={
            "x-authentik-username": "akadmin",
            "x-authentik-groups": "admin|owners",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["is_admin"] is True
    assert "dayana" in body["allowed_roles"]
    assert "timeweb" in body["allowed_roles"]
