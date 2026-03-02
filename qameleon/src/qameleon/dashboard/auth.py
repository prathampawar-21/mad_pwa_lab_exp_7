"""API key authentication for dashboard."""

import hashlib
import os
import secrets
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class APIKeyStore:
    """Stores API keys as SHA-256 hashes."""

    def __init__(self) -> None:
        self._hashed_keys: dict[str, str] = {}  # name -> hash

    def generate_key(self, name: str) -> str:
        """Generate a new API key."""
        key = secrets.token_hex(32)
        self._hashed_keys[name] = hashlib.sha256(key.encode()).hexdigest()
        return key

    def validate(self, key: str) -> bool:
        """Validate an API key."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return key_hash in self._hashed_keys.values()

    def revoke(self, name: str) -> bool:
        """Revoke an API key by name."""
        if name in self._hashed_keys:
            del self._hashed_keys[name]
            return True
        return False


_PUBLIC_PATHS = {"/", "/health", "/docs", "/openapi.json", "/favicon.ico"}


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Bearer token authentication middleware."""

    def __init__(self, app, key_store: APIKeyStore, enabled: bool = True) -> None:
        super().__init__(app)
        self._store = key_store
        self._enabled = enabled

    async def dispatch(self, request: Request, call_next):
        if not self._enabled or request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Missing or invalid Authorization header"},
            )

        token = auth_header[7:]
        if not self._store.validate(token):
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid API key"},
            )

        return await call_next(request)
