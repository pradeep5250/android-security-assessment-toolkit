"""Device Pydantic schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.device import DeviceStatus


class DeviceResponse(BaseModel):
    """Device information response."""
    id: int
    serial: str
    model: Optional[str]
    manufacturer: Optional[str]
    android_version: Optional[str]
    sdk_version: Optional[str]
    security_patch: Optional[str]
    build_fingerprint: Optional[str]
    cpu_abi: Optional[str]
    display_resolution: Optional[str]
    status: DeviceStatus
    nickname: Optional[str]
    notes: Optional[str]
    metadata_json: Optional[Dict[str, Any]]
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class DeviceUpdate(BaseModel):
    """Update device metadata."""
    nickname: Optional[str] = Field(None, max_length=100)
    notes: Optional[str] = None


class DeviceInfoResponse(BaseModel):
    """Detailed device information from ADB."""
    serial: str
    model: str
    manufacturer: str
    android_version: str
    sdk_version: str
    security_patch: str
    build_fingerprint: str
    cpu_abi: str
    cpu_hardware: Optional[str] = None
    total_ram: Optional[str] = None
    available_storage: Optional[str] = None
    display_resolution: Optional[str] = None
    display_density: Optional[str] = None
    battery_level: Optional[str] = None
    is_rooted: Optional[bool] = None
    is_encrypted: Optional[bool] = None
    developer_options: Optional[bool] = None
    usb_debugging: Optional[bool] = None


class PackageInfo(BaseModel):
    """Installed package information."""
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    installer: Optional[str] = None
    is_system: bool = False
    permissions: List[str] = []


class DevicePackagesResponse(BaseModel):
    """List of packages on a device."""
    serial: str
    total: int
    system_apps: int
    user_apps: int
    packages: List[PackageInfo]
