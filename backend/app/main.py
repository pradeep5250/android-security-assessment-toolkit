"""
Android Security Assessment Toolkit — FastAPI Application Entry Point.

Initializes the app, registers routes, middleware, and serves the frontend.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db, close_db
from app.middleware.audit import AuditMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("asat")


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle events."""
    logger.info("=" * 60)
    logger.info("  🛡️  Android Security Assessment Toolkit")
    logger.info(f"  Version: {settings.app_version}")
    logger.info(f"  Database: {'SQLite' if settings.is_sqlite else 'PostgreSQL'}")
    logger.info("=" * 60)

    # Import all models so Base.metadata knows about them
    import app.models  # noqa: F401

    # Create tables
    await init_db()
    logger.info("✅ Database initialized")

    # Ensure upload/report dirs exist
    settings.upload_path.mkdir(parents=True, exist_ok=True)
    settings.reports_path.mkdir(parents=True, exist_ok=True)

    # Check ADB availability
    from app.core.adb_manager import adb_manager
    adb_available = await adb_manager.check_adb()
    if adb_available:
        logger.info("✅ ADB is available")
    else:
        logger.warning("⚠️  ADB not found — ADB features will be disabled")

    logger.info(f"🚀 Server ready at http://localhost:{settings.port}")

    yield

    # Shutdown
    await close_db()
    logger.info("🛑 Server stopped")


# ── App Factory ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Professional Android Security Assessment Toolkit for educational purposes "
        "and authorized penetration testing. Requires explicit user authorization."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditMiddleware)

# ── API Routes ───────────────────────────────────────────────────────────────

from app.api.auth import router as auth_router
from app.api.adb import router as adb_router
from app.api.scanner import router as scanner_router
from app.api.apk import router as apk_router
from app.api.devices import router as devices_router
from app.api.reports import router as reports_router
from app.api.websocket import router as ws_router

app.include_router(auth_router)
app.include_router(adb_router)
app.include_router(scanner_router)
app.include_router(apk_router)
app.include_router(devices_router)
app.include_router(reports_router)
app.include_router(ws_router)


# ── Health Check ─────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/api/v1/stats", tags=["System"])
async def get_stats():
    """Get dashboard statistics."""
    from sqlalchemy import select, func
    from app.database import async_session_factory
    from app.models.device import Device, DeviceStatus
    from app.models.scan_result import ScanResult
    from app.models.report import Report
    from app.models.audit_log import AuditLog

    async with async_session_factory() as db:
        devices_total = (await db.execute(select(func.count()).select_from(Device))).scalar() or 0
        devices_online = (await db.execute(
            select(func.count()).select_from(Device).where(Device.status == DeviceStatus.ONLINE)
        )).scalar() or 0
        scans_total = (await db.execute(select(func.count()).select_from(ScanResult))).scalar() or 0
        reports_total = (await db.execute(select(func.count()).select_from(Report))).scalar() or 0
        recent_logs = (await db.execute(
            select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10)
        )).scalars().all()

        return {
            "devices": {"total": devices_total, "online": devices_online},
            "scans": {"total": scans_total},
            "reports": {"total": reports_total},
            "recent_activity": [
                {
                    "action": log.action,
                    "username": log.username,
                    "timestamp": str(log.timestamp),
                    "ip": log.ip_address,
                }
                for log in recent_logs
            ],
        }


# ── Frontend Static Files ───────────────────────────────────────────────────

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

if FRONTEND_DIR.exists():
    app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
    app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")
    if (FRONTEND_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="assets")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def serve_frontend():
        """Serve the frontend SPA."""
        index_path = FRONTEND_DIR / "index.html"
        if index_path.exists():
            return HTMLResponse(index_path.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Frontend not found</h1>", status_code=404)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa_routes(full_path: str):
        """Catch-all for SPA routing — serve index.html for non-API paths."""
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("ws"):
            return None

        # Try to serve a static file first
        static_path = FRONTEND_DIR / full_path
        if static_path.exists() and static_path.is_file():
            return FileResponse(str(static_path))

        # Otherwise serve index.html for SPA routing
        index_path = FRONTEND_DIR / "index.html"
        if index_path.exists():
            return HTMLResponse(index_path.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Not found</h1>", status_code=404)


# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
