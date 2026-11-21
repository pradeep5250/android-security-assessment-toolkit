"""
Device Management API Routes.

CRUD operations for tracked devices and full security audits.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.adb_manager import ADBCommandError, adb_manager
from app.core.device_auditor import device_auditor
from app.core.security import get_current_user, require_analyst_or_above
from app.database import get_db
from app.models.device import Device, DeviceStatus
from app.models.scan_result import ScanResult, ScanType
from app.models.user import User
from app.schemas.device import DeviceResponse, DeviceUpdate
from app.core.risk_scorer import calculate_risk_score

router = APIRouter(
    prefix="/api/v1/devices",
    tags=["Device Management"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/")
async def list_devices(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: DeviceStatus | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List all tracked devices with pagination."""
    query = select(Device).order_by(Device.last_seen.desc())
    if status:
        query = query.where(Device.status == status)

    # Count
    count_query = select(func.count()).select_from(Device)
    if status:
        count_query = count_query.where(Device.status == status)
    total = (await db.execute(count_query)).scalar()

    # Paginate
    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    devices = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "devices": [DeviceResponse.model_validate(d) for d in devices],
    }


@router.post("/sync")
async def sync_devices(
    user: User = Depends(require_analyst_or_above()),
    db: AsyncSession = Depends(get_db),
):
    """
    Sync ADB-connected devices with the database.
    
    Discovers devices via ADB and creates/updates database records.
    """
    try:
        adb_devices = await adb_manager.list_devices()
    except ADBCommandError as e:
        raise HTTPException(status_code=503, detail=str(e))

    synced = []
    for adb_dev in adb_devices:
        serial = adb_dev["serial"]
        adb_status = adb_dev["status"]

        # Map ADB status to our enum
        status_map = {
            "device": DeviceStatus.ONLINE,
            "offline": DeviceStatus.OFFLINE,
            "unauthorized": DeviceStatus.UNAUTHORIZED,
        }
        dev_status = status_map.get(adb_status, DeviceStatus.UNKNOWN)

        # Check if device exists
        result = await db.execute(select(Device).where(Device.serial == serial))
        device = result.scalar_one_or_none()

        if device:
            device.status = dev_status
            device.last_seen = datetime.now(timezone.utc)
        else:
            device = Device(serial=serial, status=dev_status)
            db.add(device)

        # Fetch device info if online
        if dev_status == DeviceStatus.ONLINE:
            try:
                info = await adb_manager.get_device_info(serial)
                device.model = info.get("model")
                device.manufacturer = info.get("manufacturer")
                device.android_version = info.get("android_version")
                device.sdk_version = info.get("sdk_version")
                device.security_patch = info.get("security_patch")
                device.build_fingerprint = info.get("build_fingerprint")
                device.cpu_abi = info.get("cpu_abi")
                device.display_resolution = info.get("display_resolution")
                device.metadata_json = {
                    k: v for k, v in info.items()
                    if k not in ("serial", "model", "manufacturer")
                }
            except ADBCommandError:
                pass

        await db.flush()
        await db.refresh(device)
        synced.append(DeviceResponse.model_validate(device))

    # Mark devices not in ADB list as offline
    adb_serials = {d["serial"] for d in adb_devices}
    all_devices = await db.execute(
        select(Device).where(Device.status == DeviceStatus.ONLINE)
    )
    for device in all_devices.scalars():
        if device.serial not in adb_serials:
            device.status = DeviceStatus.OFFLINE

    return {
        "synced": len(synced),
        "devices": synced,
    }


@router.get("/{device_id}")
async def get_device(device_id: int, db: AsyncSession = Depends(get_db)):
    """Get device details by ID."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceResponse.model_validate(device)


@router.patch("/{device_id}")
async def update_device(
    device_id: int,
    updates: DeviceUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update device metadata (nickname, notes)."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if updates.nickname is not None:
        device.nickname = updates.nickname
    if updates.notes is not None:
        device.notes = updates.notes

    await db.flush()
    await db.refresh(device)
    return DeviceResponse.model_validate(device)


@router.delete("/{device_id}")
async def delete_device(
    device_id: int,
    user: User = Depends(require_analyst_or_above()),
    db: AsyncSession = Depends(get_db),
):
    """Delete a tracked device."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await db.delete(device)
    return {"message": f"Device {device.serial} deleted"}


@router.post("/{device_id}/audit")
async def audit_device(
    device_id: int,
    user: User = Depends(require_analyst_or_above()),
    db: AsyncSession = Depends(get_db),
):
    """
    Perform a full security audit on a device.
    
    Checks root status, patch level, developer options,
    installed apps, and running services.
    """
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if device.status != DeviceStatus.ONLINE:
        raise HTTPException(
            status_code=400,
            detail=f"Device is {device.status.value}. Must be online for audit.",
        )

    try:
        audit_result = await device_auditor.full_audit(device.serial)

        # Save as scan result
        findings = audit_result.get("findings", [])
        risk_score = calculate_risk_score(findings)

        scan = ScanResult(
            scan_type=ScanType.DEVICE_AUDIT,
            target=device.serial,
            device_id=device.id,
            user_id=user.id,
            status="completed",
            findings=audit_result,
            summary=f"{len(findings)} findings - Risk: {audit_result.get('risk_level', 'Unknown')}",
            risk_score=risk_score,
            highest_severity=audit_result.get("findings", [{}])[0].get("severity") if findings else None,
        )
        db.add(scan)
        await db.flush()

        audit_result["scan_id"] = scan.id
        return audit_result

    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))
