"""
ADB API Routes.

Device management, package operations, logcat, screenshots, and file transfer
endpoints — all requiring user authentication.
"""

import io
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from fastapi.responses import StreamingResponse

from app.core.adb_manager import ADBCommandError, adb_manager
from app.core.security import get_current_user, require_analyst_or_above
from app.models.user import User
from app.config import settings

router = APIRouter(
    prefix="/api/v1/adb",
    tags=["ADB Automation"],
    dependencies=[Depends(get_current_user)],
)


async def _ensure_adb():
    """Ensure ADB is available before processing requests."""
    if adb_manager.is_available is None:
        await adb_manager.check_adb()
    if not adb_manager.is_available:
        raise HTTPException(
            status_code=503,
            detail="ADB is not available. Install Android SDK Platform Tools and add to PATH.",
        )


@router.get("/status")
async def adb_status():
    """Check ADB availability status."""
    available = await adb_manager.check_adb()
    return {
        "available": available,
        "adb_path": settings.adb_path,
    }


@router.get("/devices")
async def list_devices():
    """List all connected ADB devices."""
    await _ensure_adb()
    try:
        devices = await adb_manager.list_devices()
        return {"devices": devices, "count": len(devices)}
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/device/{serial}/info")
async def get_device_info(serial: str):
    """Get detailed device information."""
    await _ensure_adb()
    try:
        info = await adb_manager.get_device_info(serial)
        return info
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/device/{serial}/packages")
async def list_packages(
    serial: str,
    include_system: bool = Query(False, description="Include system packages"),
):
    """List installed packages on a device."""
    await _ensure_adb()
    try:
        packages = await adb_manager.list_packages(serial, include_system)
        return {
            "serial": serial,
            "total": len(packages),
            "packages": packages,
        }
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/device/{serial}/install")
async def install_apk(
    serial: str,
    apk: UploadFile = File(...),
    user: User = Depends(require_analyst_or_above()),
):
    """Install an APK on a device (analyst+ only)."""
    await _ensure_adb()

    if not apk.filename or not apk.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an APK")

    # Save uploaded APK temporarily
    upload_path = settings.upload_path / f"install_{serial}_{apk.filename}"
    try:
        content = await apk.read()
        upload_path.write_bytes(content)

        result = await adb_manager.install_apk(serial, str(upload_path))
        return {"message": "APK installed successfully", "output": result}
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        upload_path.unlink(missing_ok=True)


@router.delete("/device/{serial}/package/{package_name}")
async def uninstall_package(
    serial: str,
    package_name: str,
    user: User = Depends(require_analyst_or_above()),
):
    """Uninstall a package from a device (analyst+ only)."""
    await _ensure_adb()
    try:
        result = await adb_manager.uninstall_package(serial, package_name)
        return {"message": f"Package '{package_name}' uninstalled", "output": result}
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/device/{serial}/screenshot")
async def take_screenshot(serial: str):
    """Capture a screenshot from the device."""
    await _ensure_adb()
    try:
        png_data = await adb_manager.take_screenshot(serial)
        return StreamingResponse(
            io.BytesIO(png_data),
            media_type="image/png",
            headers={"Content-Disposition": f"inline; filename=screenshot_{serial}.png"},
        )
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/device/{serial}/screenrecord")
async def start_screen_recording(
    serial: str,
    duration: int = Query(10, ge=1, le=180, description="Recording duration in seconds"),
    user: User = Depends(require_analyst_or_above()),
):
    """Start screen recording on a device (analyst+ only)."""
    await _ensure_adb()
    try:
        remote_path = await adb_manager.start_recording(serial, duration)
        return {
            "message": f"Recording started for {duration}s",
            "remote_path": remote_path,
        }
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/device/{serial}/logcat")
async def get_logcat(
    serial: str,
    lines: int = Query(500, ge=10, le=5000),
):
    """Get recent logcat entries."""
    await _ensure_adb()
    try:
        log = await adb_manager.get_logcat_dump(serial, lines)
        return {
            "serial": serial,
            "lines": log.count("\n") + 1,
            "content": log,
        }
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/device/{serial}/push")
async def push_file(
    serial: str,
    file: UploadFile = File(...),
    remote_path: str = Query(..., description="Destination path on device"),
    user: User = Depends(require_analyst_or_above()),
):
    """Push a file to the device (analyst+ only)."""
    await _ensure_adb()

    local_path = settings.upload_path / f"push_{serial}_{file.filename}"
    try:
        content = await file.read()
        local_path.write_bytes(content)
        result = await adb_manager.push_file(serial, str(local_path), remote_path)
        return {"message": "File pushed successfully", "output": result}
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        local_path.unlink(missing_ok=True)


@router.get("/device/{serial}/pull")
async def pull_file(
    serial: str,
    remote_path: str = Query(..., description="File path on device"),
):
    """Pull a file from the device."""
    await _ensure_adb()

    filename = Path(remote_path).name
    local_path = settings.upload_path / f"pull_{serial}_{filename}"

    try:
        await adb_manager.pull_file(serial, remote_path, str(local_path))
        data = local_path.read_bytes()
        return StreamingResponse(
            io.BytesIO(data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        local_path.unlink(missing_ok=True)


@router.get("/device/{serial}/services")
async def get_running_services(serial: str):
    """Get running services on a device."""
    await _ensure_adb()
    try:
        services = await adb_manager.get_running_services(serial)
        return {"serial": serial, "count": len(services), "services": services}
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/device/{serial}/security")
async def quick_security_check(serial: str):
    """Quick security posture check of a device."""
    await _ensure_adb()
    try:
        is_rooted = await adb_manager.check_root(serial)
        dev_options = await adb_manager.check_developer_options(serial)
        info = await adb_manager.get_device_info(serial)

        findings = []
        if is_rooted:
            findings.append({
                "severity": "critical",
                "title": "Device is rooted",
                "description": "Root access detected — device integrity may be compromised.",
            })
        if dev_options:
            findings.append({
                "severity": "medium",
                "title": "Developer options enabled",
                "description": "Developer options are enabled, increasing attack surface.",
            })

        return {
            "serial": serial,
            "is_rooted": is_rooted,
            "developer_options_enabled": dev_options,
            "android_version": info.get("android_version", "unknown"),
            "security_patch": info.get("security_patch", "unknown"),
            "findings": findings,
        }
    except ADBCommandError as e:
        raise HTTPException(status_code=500, detail=str(e))
