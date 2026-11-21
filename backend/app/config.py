"""
ASAT Configuration Module.

Loads settings from environment variables / .env file using Pydantic Settings.
"""

from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────────────────────
    app_name: str = "Android Security Assessment Toolkit"
    app_version: str = "1.0.0"
    debug: bool = True

    # ── Server ───────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    allowed_origins: str = "http://localhost:8000,http://127.0.0.1:8000"

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",")]

    # ── Database ─────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./asat.db"

    @property
    def is_sqlite(self) -> bool:
        return "sqlite" in self.database_url

    # ── JWT ───────────────────────────────────────────────────────────────
    jwt_secret_key: str = "change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # ── ADB ───────────────────────────────────────────────────────────────
    adb_path: str = "adb"
    adb_timeout: int = 30

    # ── File Handling ─────────────────────────────────────────────────────
    max_upload_size_mb: int = 500
    upload_dir: str = "./uploads"
    reports_dir: str = "./reports"

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def upload_path(self) -> Path:
        path = Path(self.upload_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def reports_path(self) -> Path:
        path = Path(self.reports_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ── Rate Limiting ─────────────────────────────────────────────────────
    rate_limit_per_minute: int = 60


# Singleton settings instance
settings = Settings()
