"""
Audit Logging Middleware.

Logs every API request with user info, endpoint, method, IP, and response status.
"""

import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import async_session_factory
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all API requests to the audit_logs table."""

    # Paths to skip logging (health checks, static files, etc.)
    SKIP_PATHS = {"/health", "/favicon.ico", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip non-API paths and static files
        path = request.url.path
        if any(path.startswith(skip) for skip in self.SKIP_PATHS):
            return await call_next(request)
        if path.startswith("/css/") or path.startswith("/js/") or path.startswith("/assets/"):
            return await call_next(request)

        start_time = time.time()
        response = await call_next(request)
        duration_ms = int((time.time() - start_time) * 1000)

        # Only log API calls
        if not path.startswith("/api/"):
            return response

        # Extract user info from request state (set by auth dependency)
        user_id = None
        username = None

        # Try to get user from authorization header context
        try:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                from jose import jwt
                from app.config import settings
                token = auth_header[7:]
                payload = jwt.decode(
                    token, settings.jwt_secret_key,
                    algorithms=[settings.jwt_algorithm],
                )
                user_id = int(payload.get("sub", 0))
                username = payload.get("username")
        except Exception:
            pass

        # Log asynchronously (fire-and-forget)
        try:
            async with async_session_factory() as session:
                log_entry = AuditLog(
                    user_id=user_id,
                    username=username,
                    action=f"{request.method} {path}",
                    resource=path,
                    method=request.method,
                    status_code=response.status_code,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent", "")[:500],
                    details=f"Duration: {duration_ms}ms",
                )
                session.add(log_entry)
                await session.commit()
        except Exception as e:
            logger.warning(f"Failed to write audit log: {e}")

        return response
