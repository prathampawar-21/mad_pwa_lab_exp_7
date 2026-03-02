"""Token bucket rate limiter middleware."""

import time
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, capacity: float = 60.0, refill_rate: float = 10.0) -> None:
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._tokens = capacity
        self._last_refill = time.time()

    def consume(self, tokens: float = 1.0) -> bool:
        """Try to consume tokens. Returns True if allowed."""
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
        self._last_refill = now

        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """Per-client rate limiting middleware."""

    def __init__(
        self,
        app,
        capacity: float = 60.0,
        refill_rate: float = 10.0,
    ) -> None:
        super().__init__(app)
        self._buckets: dict[str, TokenBucket] = {}
        self._capacity = capacity
        self._refill_rate = refill_rate

    def _get_client_id(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        client_id = self._get_client_id(request)

        if client_id not in self._buckets:
            self._buckets[client_id] = TokenBucket(self._capacity, self._refill_rate)

        if not self._buckets[client_id].consume():
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"},
                headers={"Retry-After": "1"},
            )

        return await call_next(request)
