"""Device ORM model."""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class DeviceStatus(str, enum.Enum):
    """Device connection status."""
    ONLINE = "online"
    OFFLINE = "offline"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN = "unknown"


class Device(Base):
    """Registered Android device."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    serial: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(100), nullable=True)
    android_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    sdk_version: Mapped[str | None] = mapped_column(String(10), nullable=True)
    security_patch: Mapped[str | None] = mapped_column(String(20), nullable=True)
    build_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_abi: Mapped[str | None] = mapped_column(String(50), nullable=True)
    display_resolution: Mapped[str | None] = mapped_column(String(30), nullable=True)
    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus), default=DeviceStatus.UNKNOWN, nullable=False
    )
    nickname: Mapped[str | None] = mapped_column(String(100), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Device(serial='{self.serial}', model='{self.model}', status='{self.status.value}')>"
