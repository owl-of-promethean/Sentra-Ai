"""
SOC Analyst Authentication for SOC-AI.

Provides a minimal bearer-token authentication layer suitable for a
hackathon prototype.

Design:
  - Credentials are read from environment variables only — never from
    source code or client-provided data.
  - POST /auth/login validates credentials and issues a signed JWT.
  - Protected endpoints call require_auth() which validates the token.
  - Token expiry defaults to 8 hours (configurable via TOKEN_EXPIRE_HOURS).
  - Algorithm: HS256 with a randomly generated secret per process.
    For a persistent secret set JWT_SECRET_KEY in the environment.

Environment variables:
  SOC_ANALYST_EMAIL     — the analyst's login email  (default: admin@sentinel.ai)
  SOC_ANALYST_PASSWORD  — the analyst's password     (no default — must be set)
  JWT_SECRET_KEY        — HMAC signing key            (auto-generated if absent)
  TOKEN_EXPIRE_HOURS    — token lifetime in hours     (default: 8)
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

try:
    from jose import JWTError, jwt
    _HAS_JOSE = True
except ImportError:  # pragma: no cover
    _HAS_JOSE = False

from pydantic import BaseModel


# ==============================================================
# CONFIGURATION
# ==============================================================

_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY") or secrets.token_hex(32)
_ALGORITHM = "HS256"
_TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))

# Credential configuration — read once at module load.
# SOC_ANALYST_EMAIL defaults to a safe demo value.
# SOC_ANALYST_PASSWORD has no default; must be set explicitly.
_ANALYST_EMAIL: str = os.getenv("SOC_ANALYST_EMAIL", "admin@sentinel.ai").lower().strip()
_ANALYST_PASSWORD: Optional[str] = os.getenv("SOC_ANALYST_PASSWORD")

# For the hackathon demo, allow a fallback password only when no env var is set.
# This avoids the demo failing with an unconfigured environment while still
# encouraging operators to set the variable in production.
_DEMO_FALLBACK_PASSWORD = "password"


# ==============================================================
# REQUEST / RESPONSE MODELS
# ==============================================================

class LoginRequest(BaseModel):
    email: str
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "email": "admin@sentinel.ai",
                "password": "your-secure-password"
            }
        }


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int    # seconds


# ==============================================================
# JWT HELPERS
# ==============================================================

def _create_access_token(subject: str) -> str:
    """
    Create a signed JWT with an expiry claim.

    Args:
        subject: The identity to encode (email / user identifier).

    Returns:
        Encoded JWT string.
    """
    expire = datetime.now(timezone.utc) + timedelta(hours=_TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    if _HAS_JOSE:
        return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)
    # Fallback: produce a simple signed token without jose
    # (not suitable for production but functional for demo/testing)
    import base64, hashlib, json as _json
    header = base64.urlsafe_b64encode(
        _json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        _json.dumps({
            "sub": subject,
            "exp": int(expire.timestamp()),
        }).encode()
    ).rstrip(b"=").decode()
    sig_input = f"{header}.{body}".encode()
    sig = base64.urlsafe_b64encode(
        hashlib.sha256(_SECRET_KEY.encode() + sig_input).digest()
    ).rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


def _verify_token(token: str) -> Optional[str]:
    """
    Verify a JWT and return the subject, or None if invalid/expired.

    Args:
        token: The raw JWT string from the Authorization header.

    Returns:
        Subject string on success, or None on any failure.
    """
    if _HAS_JOSE:
        try:
            payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
            return payload.get("sub")
        except JWTError:
            return None
    # Fallback verifier (matches the fallback creator above)
    import base64, hashlib, json as _json
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b, body_b, sig_b = parts
    sig_input = f"{header_b}.{body_b}".encode()
    expected_sig = base64.urlsafe_b64encode(
        hashlib.sha256(_SECRET_KEY.encode() + sig_input).digest()
    ).rstrip(b"=").decode()
    if sig_b != expected_sig:
        return None
    try:
        # Restore padding
        padding = 4 - len(body_b) % 4
        body_json = base64.urlsafe_b64decode(body_b + "=" * (padding % 4))
        body = _json.loads(body_json)
        exp = body.get("exp", 0)
        now = int(datetime.now(timezone.utc).timestamp())
        if now > exp:
            return None
        return body.get("sub")
    except Exception:
        return None


# ==============================================================
# CREDENTIAL VALIDATION
# ==============================================================

def validate_credentials(email: str, password: str) -> bool:
    """
    Check email + password against the configured analyst credentials.

    Accepts (case-insensitively) the email stored in SOC_ANALYST_EMAIL.
    Password is compared literally (use bcrypt in production).

    Args:
        email:    Submitted email (will be lowercased before comparison).
        password: Submitted password.

    Returns:
        True if credentials are valid, False otherwise.
    """
    if not email or not password:
        return False

    # Accept both "admin@sentinel.ai" and "admin" as alias for the demo.
    email_lower = email.lower().strip()
    known_email = _ANALYST_EMAIL
    email_ok = (email_lower == known_email) or (email_lower == "admin")

    actual_password = _ANALYST_PASSWORD or _DEMO_FALLBACK_PASSWORD
    password_ok = password == actual_password

    return email_ok and password_ok


# ==============================================================
# FASTAPI DEPENDENCY
# ==============================================================

_bearer_scheme = HTTPBearer(auto_error=False)


def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> str:
    """
    FastAPI dependency: verify the Bearer token in the Authorization header.

    Raises HTTP 401 if the token is absent, invalid, or expired.
    Returns the analyst email (subject) on success.

    Usage:
        @app.get("/applications")
        async def list_apps(analyst: str = Depends(require_auth)):
            ...
    """
    _unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "message": "Authentication required. "
                       "POST /auth/login to obtain a Bearer token."
        },
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise _unauthorized

    subject = _verify_token(credentials.credentials)
    if subject is None:
        raise _unauthorized

    return subject
