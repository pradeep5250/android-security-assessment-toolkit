"""
Rate Limiting Middleware.

Token bucket rate limiter per IP address.
"""

import time
from collections import defaultdict
from typing import Callable, Dict, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple token bucket rate limiter per IP address."""

    def __init__(self, app, max_requests: int | None = None, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests or settings.rate_limit_per_minute
        self.window_seconds = window_seconds
        # IP -> (token_count, last_refill_time)
        self._buckets: Dict[str, Tuple[float, float]] = defaultdict(
            lambda: (float(self.max_requests), time.time())
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only rate limit API calls
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        tokens, last_refill = self._buckets[client_ip]

        # Refill tokens based on elapsed time
        now = time.time()
        elapsed = now - last_refill
        refill = elapsed * (self.max_requests / self.window_seconds)
        tokens = min(self.max_requests, tokens + refill)

        if tokens < 1:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please slow down.",
                    "retry_after": self.window_seconds,
                },
                headers={"Retry-After": str(self.window_seconds)},
            )

        # Consume a token
        self._buckets[client_ip] = (tokens - 1, now)

        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(int(tokens - 1))

        return response
