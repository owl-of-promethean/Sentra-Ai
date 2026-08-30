"""
Authorized Application Registry for SOC-AI.

This module is the SINGLE source of truth for which customer applications
are permitted to be audited by the SOC system.

Security model:
  - The registry lives entirely on the server side.
  - The frontend sends an app_id; the backend resolves it to a
    trusted source_path / configuration.
  - Internal filesystem paths are NEVER sent to the frontend.
  - Unknown or inactive applications are rejected before the audit engine
    is ever invoked.

For the prototype the registry is a static in-process dict.
In production this would be backed by a database or secrets manager.
"""

from __future__ import annotations

import os
from typing import List, Optional, Dict, Any

from pydantic import BaseModel


# ==============================================================
# MODELS
# ==============================================================

class AuthorizedScope(BaseModel):
    """One permitted scan scope for an application."""

    scope_id: str
    name: str
    # For scope_id=="endpoint" this list constrains which paths are allowed.
    paths: List[str] = []


class AuthorizedApp(BaseModel):
    """
    A registered, authorized customer application.

    source_path is the INTERNAL trusted path used by the audit engine.
    It is NEVER serialized in normal frontend-facing responses.
    """

    app_id: str
    name: str
    website: str
    environment: str
    status: str            # "active" | "inactive" | "archived"
    stack: List[str]
    # Internal — never forwarded to the client
    source_path: str
    allowed_scopes: List[AuthorizedScope]

    # Advanced AI [BETA] — sandbox security validation approval.
    # Only apps explicitly approved here may be used as Advanced AI
    # validation targets.
    advanced_ai_approved: bool = False
    # Internal sandbox base URL — resolved server-side and never
    # serialized to the frontend.
    base_url: Optional[str] = None

    def to_frontend_dict(self) -> Dict[str, Any]:
        """
        Return a safe frontend-facing representation.
        source_path is intentionally excluded.
        """
        return {
            "app_id":         self.app_id,
            "name":           self.name,
            "website":        self.website,
            "environment":    self.environment,
            "status":         self.status,
            "stack":          self.stack,
            "allowed_scopes": [s.model_dump() for s in self.allowed_scopes],
            # Approval flag is safe to expose; base_url is NOT.
            "advanced_ai_approved": self.advanced_ai_approved,
        }


# ==============================================================
# REGISTRY
# ==============================================================

# The source_path values point at the backend's own codebase directories
# as illustrative stand-ins for real customer codebases.
# In a real deployment each entry would point to a checked-out
# copy of that customer's repository on the audit server.

_REGISTRY: List[AuthorizedApp] = [
    AuthorizedApp(
        app_id="app_demoshop",
        name="DemoShop",
        website="https://demo-shop.local",
        environment="sandbox",
        status="active",
        stack=["Flask", "Python 3.11"],
        source_path="app",          # internal path — points at our own app dir
        allowed_scopes=[
            AuthorizedScope(
                scope_id="application",
                name="Entire Application",
                paths=[],
            ),
            AuthorizedScope(
                scope_id="endpoint",
                name="Specific Endpoint / Path",
                paths=[
                    "/login",
                    "/register",
                    "/api/users",
                    "/api/orders",
                    "/api/products",
                    "/admin",
                    "/src/auth/",
                ],
            ),
        ],
    ),
    AuthorizedApp(
        app_id="app_portal",
        name="Customer Portal",
        website="https://portal.example.local",
        environment="staging",
        status="active",
        stack=["Django", "Python 3.10"],
        source_path="app",
        allowed_scopes=[
            AuthorizedScope(
                scope_id="application",
                name="Entire Application",
                paths=[],
            ),
            AuthorizedScope(
                scope_id="endpoint",
                name="Specific Endpoint / Path",
                paths=[
                    "/login",
                    "/dashboard",
                    "/api/accounts",
                    "/api/transactions",
                    "/admin/",
                    "/src/views/",
                ],
            ),
        ],
    ),
    AuthorizedApp(
        app_id="app_inventory",
        name="Inventory API",
        website="https://inventory.example.local",
        environment="sandbox",
        status="active",
        stack=["Express", "Node.js 18"],
        source_path="app",
        allowed_scopes=[
            AuthorizedScope(
                scope_id="application",
                name="Entire Application",
                paths=[],
            ),
            AuthorizedScope(
                scope_id="endpoint",
                name="Specific Endpoint / Path",
                paths=[
                    "/api/items",
                    "/api/stock",
                    "/api/suppliers",
                    "/auth/token",
                    "/src/middleware/auth.js",
                ],
            ),
        ],
    ),
    AuthorizedApp(
        app_id="app_auth",
        name="Auth Service",
        website="https://auth.example.local",
        environment="sandbox",
        status="active",
        stack=["React", "TypeScript"],
        source_path="app",
        allowed_scopes=[
            AuthorizedScope(
                scope_id="application",
                name="Entire Application",
                paths=[],
            ),
            AuthorizedScope(
                scope_id="endpoint",
                name="Specific Endpoint / Path",
                paths=[
                    "/oauth/authorize",
                    "/oauth/token",
                    "/oauth/revoke",
                    "/api/users",
                    "/api/sessions",
                    "/src/components/",
                ],
            ),
        ],
    ),
    # Demo target for Advanced AI [BETA] — Meridian Analytics.
    # Registered and explicitly approved for sandbox security
    # validation. source_path points at the local Meridian codebase
    # (used by the source audit crawler); base_url is the INTERNAL
    # sandbox target and is never sent to the frontend.
    AuthorizedApp(
        app_id="app_meridian",
        name="Meridian Analytics",
        website="http://localhost:5001",
        environment="sandbox",
        status="active",
        stack=["Flask", "Python 3", "SQLite"],
        source_path=os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..", "dummy website"
        )),
        allowed_scopes=[
            AuthorizedScope(
                scope_id="application",
                name="Entire Application",
                paths=[],
            ),
            AuthorizedScope(
                scope_id="endpoint",
                name="Specific Endpoint / Path",
                paths=[
                    "/login",
                    "/search",
                    "/dashboard",
                    "/profile",
                    "/api/login",
                    "/api/search",
                    "/api/users",
                    "/api/profile",
                    "/api/metrics",
                    "/api/admin/users",
                ],
            ),
        ],
        advanced_ai_approved=True,
        base_url="http://127.0.0.1:5001",
    ),
    # Inactive app — should be rejected by get_authorized_app()
    AuthorizedApp(
        app_id="app_legacy",
        name="Legacy System",
        website="https://legacy.example.local",
        environment="production",
        status="inactive",
        stack=["PHP"],
        source_path="app",
        allowed_scopes=[
            AuthorizedScope(scope_id="application", name="Entire Application"),
        ],
    ),
]

# Keyed index for O(1) lookup
_INDEX: Dict[str, AuthorizedApp] = {a.app_id: a for a in _REGISTRY}


# ==============================================================
# PUBLIC API
# ==============================================================

def list_authorized_apps() -> List[AuthorizedApp]:
    """
    Return all applications with status='active'.

    Only active apps are visible to SOC analysts.
    """
    return [a for a in _REGISTRY if a.status == "active"]


def get_authorized_app(app_id: str) -> Optional[AuthorizedApp]:
    """
    Return an active application by app_id.

    Returns None if:
      - app_id is not in the registry (unknown application)
      - the application is not active (inactive / archived)

    The caller MUST reject None — never fall back to accepting
    an unregistered or inactive application.
    """
    app = _INDEX.get(app_id)
    if app is None:
        return None
    if app.status != "active":
        return None
    return app


def validate_scope(
    app: AuthorizedApp,
    scope_id: str,
    endpoint: Optional[str],
) -> Optional[str]:
    """
    Validate the requested scope against the app's allowed_scopes.

    Returns an error string if validation fails, or None on success.

    Rules:
      - scope_id must be in app.allowed_scopes.
      - For scope_id == "endpoint":
            endpoint must be provided AND must be in the allowed paths list.
      - For scope_id == "application":
            endpoint must be None (or empty).
      - endpoint is treated strictly as a named path, NEVER as a filesystem path.
    """
    # Find the scope definition
    scope_def = next(
        (s for s in app.allowed_scopes if s.scope_id == scope_id),
        None,
    )
    if scope_def is None:
        return (
            f"scope_id '{scope_id}' is not permitted for application "
            f"'{app.app_id}'. Allowed: "
            + str([s.scope_id for s in app.allowed_scopes])
        )

    if scope_id == "application":
        if endpoint:
            return (
                "endpoint must be null when scope_id is 'application'. "
                "Use scope_id='endpoint' to target a specific path."
            )
        return None  # OK

    if scope_id == "endpoint":
        if not endpoint:
            return (
                "endpoint is required when scope_id is 'endpoint'. "
                "Provide one of the allowed paths for this application."
            )
        if endpoint not in scope_def.paths:
            return (
                f"endpoint '{endpoint}' is not in the allowed paths for "
                f"application '{app.app_id}'. "
                "Allowed: " + str(scope_def.paths)
            )
        return None  # OK

    # Unknown scope_id format — deny by default
    return f"Unknown scope_id '{scope_id}'."


def get_advanced_ai_target(app_id: str) -> Optional[AuthorizedApp]:
    """
    Return an application approved for Advanced AI [BETA] validation.

    Stricter than get_authorized_app(): the application must be
      - active,
      - explicitly flagged advanced_ai_approved=True,
      - configured with an internal base_url for the sandbox.

    Returns None otherwise. Callers MUST reject None.
    """
    app = get_authorized_app(app_id)
    if app is None:
        return None
    if not app.advanced_ai_approved:
        return None
    if not app.base_url:
        return None
    return app
