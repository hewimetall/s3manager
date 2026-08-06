"""Gateway-header authentication.

Identity and bucket access come only from headers the gateway forwards after
authentik. There is no local password login. The app trusts these headers
completely — NetworkPolicy that admits only the gateway is load-bearing.
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence

from fastapi import Depends, HTTPException, Request, Response, status
from jose import JWTError, jwt

from another_s3_manager.constants import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    COOKIE_SECURE,
    JWT_ALGORITHM,
)

logger = logging.getLogger(__name__)

# kgateway/Envoy normalize upstream header names to lower-case before FastAPI
# sees them. Keep the trust anchors in the same form.
TRUSTED_USERNAME_HEADER = "x-authentik-username"
TRUSTED_GROUPS_HEADER = "x-authentik-groups"
ADMIN_GROUP = "admin"


def get_jwt_secret_key() -> str:
    """Get JWT secret key. Raises error if not set."""
    jwt_secret_key = os.getenv("JWT_SECRET_KEY", None)
    if not jwt_secret_key or jwt_secret_key.strip() == "" or jwt_secret_key == "your-secret-key-change-in-production":
        raise ValueError("JWT_SECRET_KEY environment variable is required and must be set")
    return jwt_secret_key


def generate_csrf_token() -> str:
    """Generate a secure CSRF token."""
    return secrets.token_urlsafe(32)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT that carries CSRF (identity still comes from headers)."""
    to_encode = data.copy()
    if "csrf_token" not in to_encode:
        to_encode["csrf_token"] = generate_csrf_token()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, get_jwt_secret_key(), algorithm=JWT_ALGORITHM)


def issue_session_cookie(response: Response, username: str) -> str:
    """Mint a CSRF-bearing cookie for the SPA. Identity remains header-based."""
    csrf_token = generate_csrf_token()
    access_token = create_access_token(data={"sub": username, "csrf_token": csrf_token})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    return csrf_token


def get_trusted_username(request: Request) -> Optional[str]:
    """Return the forwarded authentik username, if present and non-empty."""
    username = request.headers.get(TRUSTED_USERNAME_HEADER)
    if username is None:
        return None
    username = username.strip()
    return username or None


def parse_authentik_groups(raw: Optional[str]) -> List[str]:
    """Split authentik's groups header on the separators it actually uses."""
    if not raw:
        return []
    groups: List[str] = []
    for piece in raw.replace(";", "|").replace(",", "|").split("|"):
        name = piece.strip()
        if name and name not in groups:
            groups.append(name)
    return groups


def get_trusted_groups(request: Request) -> List[str]:
    return parse_authentik_groups(request.headers.get(TRUSTED_GROUPS_HEADER))


def role_names_from_config(roles: Sequence[Dict[str, Any]]) -> List[str]:
    return [role["name"] for role in roles if role.get("name")]


def resolve_allowed_roles(groups: Sequence[str], config_roles: Sequence[Dict[str, Any]]) -> List[str]:
    """Map authentik groups onto s3manager role names.

    - group `admin` → every configured role
    - otherwise → intersection of groups with role names (stand slug == role name)
    """
    names = role_names_from_config(config_roles)
    if ADMIN_GROUP in groups:
        return list(names)
    allowed = [name for name in names if name in groups]
    return allowed


def build_principal(username: str, groups: Sequence[str], config_roles: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Ephemeral principal — never persisted."""
    is_admin = ADMIN_GROUP in groups
    allowed_roles = resolve_allowed_roles(groups, config_roles)
    return {
        "username": username,
        "is_admin": is_admin,
        "allowed_roles": allowed_roles,
        "theme": "auto",
        "default_role": allowed_roles[0] if allowed_roles else None,
        "must_change_password": False,
        "groups": list(groups),
    }


def _decode_session_payload(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        return jwt.decode(token, get_jwt_secret_key(), algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


def has_valid_session(request: Request) -> bool:
    """Upload body-guard: require a gateway-forwarded username."""
    return get_trusted_username(request) is not None


def get_current_user(request: Request, response: Response) -> Dict[str, Any]:
    """Build the principal from trusted gateway headers. Fail closed if absent."""
    from another_s3_manager.config import load_config

    username = get_trusted_username(request)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    groups = get_trusted_groups(request)
    config = load_config(force_reload=False)
    user = build_principal(username, groups, config.get("roles", []))

    payload = _decode_session_payload(request)
    csrf_token = None
    if payload is not None and payload.get("sub") == username:
        csrf_token = payload.get("csrf_token")
    if not csrf_token:
        csrf_token = issue_session_cookie(response, username)
    user["csrf_token"] = csrf_token
    return user


def verify_csrf_token(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> bool:
    """Verify CSRF token from request header."""
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing")

    expected_token = current_user.get("csrf_token")
    if not expected_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token not found in session")

    if not secrets.compare_digest(csrf_token, expected_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")

    return True


def get_current_admin_user(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Require the authentik `admin` group."""
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user
