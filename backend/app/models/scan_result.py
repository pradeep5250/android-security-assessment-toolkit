"""ScanResult ORM model."""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ScanType(str, enum.Enum):
    """Type of security scan."""
    PORT_SCAN = "port_scan"
    DNS_LOOKUP = "dns_lookup"
    SSL_CHECK = "ssl_check"
    HTTP_HEADERS = "http_headers"
    WHOIS = "whois"
    APK_ANALYSIS = "apk_analysis"
    DEVICE_AUDIT = "device_audit"
    PERMISSION_CHECK = "permission_check"
    NETWORK_CONFIG = "network_config"
    PING = "ping"
    TRACEROUTE = "traceroute"


class SeverityLevel(str, enum.Enum):
    """Finding severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanResult(Base):
    """Security scan result with findings."""

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    device_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), default="completed", nullable=False)
    findings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    highest_severity: Mapped[SeverityLevel | None] = mapped_column(
        Enum(SeverityLevel), nullable=True
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<ScanResult(id={self.id}, type='{self.scan_type.value}', target='{self.target}')>"
