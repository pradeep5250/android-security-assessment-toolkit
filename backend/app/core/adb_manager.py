"""
ADB Manager.

Async wrapper around ADB commands for device management,
package operations, logcat, screenshots, and file transfers.
"""

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, List, Optional, Tuple

from app.config import settings
from app.utils.adb_commands import (
    ADBCommandError,
    build_command,
    build_dumpsys_command,
    build_getprop_command,
    build_logcat_command,
    build_pm_command,
    build_screencap_command,
    build_screenrecord_command,
)

logger = logging.getLogger(__name__)


class ADBManager:
    """Manages ADB interactions with connected Android devices."""

    def __init__(self):
        self._adb_available: Optional[bool] = None

    async def _run(
        self, cmd: List[str], timeout: Optional[int] = None
    ) -> Tuple[int, str, str]:
        """
        Execute a command asynchronously.
        
        Returns (return_code, stdout, stderr).
        """
        timeout = timeout or settings.adb_timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return (
                proc.returncode or 0,
                stdout.decode("utf-8", errors="replace").strip(),
                stderr.decode("utf-8", errors="replace").strip(),
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise ADBCommandError(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        except FileNotFoundError:
            raise ADBCommandError(
                f"ADB not found at '{settings.adb_path}'. "
                "Install Android SDK Platform Tools and add to PATH."
            )

    async def check_adb(self) -> bool:
        """Check if ADB is available and responsive."""
        try:
            code, out, _ = await self._run(build_command("version"))
            self._adb_available = code == 0 and "Android Debug Bridge" in out
            return self._adb_available
        except ADBCommandError:
            self._adb_available = False
            return False

    @property
    def is_available(self) -> Optional[bool]:
        return self._adb_available

    # ── Device Discovery ─────────────────────────────────────────────────

    async def list_devices(self) -> List[Dict[str, str]]:
        """List connected ADB devices with their status."""
        code, out, err = await self._run(build_command("devices"))
        devices = []
        for line in out.splitlines()[1:]:  # Skip header
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                devices.append({
                    "serial": parts[0],
                    "status": parts[1],
                })
        return devices

    # ── Device Properties ────────────────────────────────────────────────

    async def get_device_info(self, serial: str) -> Dict[str, str]:
        """Get comprehensive device information via getprop."""
        props_to_fetch = {
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
            "android_version": "ro.build.version.release",
            "sdk_version": "ro.build.version.sdk",
            "security_patch": "ro.build.version.security_patch",
            "build_fingerprint": "ro.build.fingerprint",
            "cpu_abi": "ro.product.cpu.abi",
            "hardware": "ro.hardware",
            "brand": "ro.product.brand",
            "device": "ro.product.device",
            "build_type": "ro.build.type",
            "build_id": "ro.build.display.id",
        }

        info = {"serial": serial}
        for key, prop in props_to_fetch.items():
            try:
                code, out, _ = await self._run(
                    build_getprop_command(serial, prop)
                )
                info[key] = out if code == 0 else "unknown"
            except ADBCommandError:
                info[key] = "error"

        # Get RAM info
        try:
            code, out, _ = await self._run(
                build_dumpsys_command(serial, "meminfo")
            )
            if code == 0:
                match = re.search(r"Total RAM:\s*([\d,]+)", out)
                if match:
                    info["total_ram"] = match.group(1).replace(",", "")
        except ADBCommandError:
            pass

        # Get display info
        try:
            code, out, _ = await self._run(
                build_command("shell", ["wm", "size"], serial)
            )
            if code == 0 and "Physical size:" in out:
                info["display_resolution"] = out.split(":")[-1].strip()
        except ADBCommandError:
            pass

        # Get battery level
        try:
            code, out, _ = await self._run(
                build_dumpsys_command(serial, "battery")
            )
            if code == 0:
                match = re.search(r"level:\s*(\d+)", out)
                if match:
                    info["battery_level"] = match.group(1)
        except ADBCommandError:
            pass

        # Get storage
        try:
            code, out, _ = await self._run(
                build_command("shell", ["df", "/data"], serial)
            )
            if code == 0:
                info["storage_info"] = out
        except ADBCommandError:
            pass

        return info

    # ── Package Management ───────────────────────────────────────────────

    async def list_packages(
        self, serial: str, include_system: bool = False
    ) -> List[Dict[str, str]]:
        """List installed packages on a device."""
        args = ["list", "packages", "-f"]
        if not include_system:
            args.append("-3")  # Third-party only

        code, out, _ = await self._run(build_pm_command(serial, args))
        packages = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                # Format: package:/path/to/apk=com.example.app
                match = re.match(r"package:(.+?)=(.+)", line)
                if match:
                    packages.append({
                        "apk_path": match.group(1),
                        "package_name": match.group(2),
                        "is_system": include_system,
                    })
        return packages

    async def install_apk(self, serial: str, apk_path: str) -> str:
        """Install an APK on a device."""
        code, out, err = await self._run(
            build_command("install", ["-r", apk_path], serial),
            timeout=120,
        )
        if code != 0 or "Failure" in out:
            raise ADBCommandError(f"APK installation failed: {out} {err}")
        return out

    async def uninstall_package(self, serial: str, package_name: str) -> str:
        """Uninstall a package from a device."""
        code, out, err = await self._run(
            build_pm_command(serial, ["uninstall", package_name])
        )
        if code != 0:
            raise ADBCommandError(f"Uninstall failed: {out} {err}")
        return out

    # ── Logcat ───────────────────────────────────────────────────────────

    async def get_logcat_dump(
        self, serial: str, lines: int = 500
    ) -> str:
        """Get a dump of recent logcat entries."""
        code, out, _ = await self._run(
            build_logcat_command(serial, dump=True),
            timeout=15,
        )
        # Return last N lines
        log_lines = out.splitlines()
        return "\n".join(log_lines[-lines:])

    async def stream_logcat(
        self, serial: str, filters: Optional[List[str]] = None
    ) -> AsyncGenerator[str, None]:
        """Stream logcat output line by line (async generator)."""
        cmd = build_logcat_command(serial, filters=filters)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            while True:
                line = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=30
                )
                if not line:
                    break
                yield line.decode("utf-8", errors="replace").rstrip()
        except asyncio.TimeoutError:
            pass
        finally:
            proc.kill()
            await proc.wait()

    # ── Screenshot ───────────────────────────────────────────────────────

    async def take_screenshot(self, serial: str) -> bytes:
        """Capture a screenshot and return raw PNG bytes."""
        cmd = build_screencap_command(serial)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode != 0:
            raise ADBCommandError(f"Screenshot failed: {stderr.decode()}")
        return stdout

    # ── Screen Recording ─────────────────────────────────────────────────

    async def start_recording(
        self, serial: str, duration: int = 10
    ) -> str:
        """Start screen recording on device. Returns the remote file path."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        remote_path = f"/sdcard/asat_recording_{timestamp}.mp4"
        cmd = build_screenrecord_command(serial, remote_path, duration)

        # Run in background — don't await completion
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"Screen recording started on {serial}: {remote_path}")
        return remote_path

    # ── File Transfer ────────────────────────────────────────────────────

    async def push_file(
        self, serial: str, local_path: str, remote_path: str
    ) -> str:
        """Push a file to the device."""
        code, out, err = await self._run(
            build_command("push", [local_path, remote_path], serial),
            timeout=120,
        )
        if code != 0:
            raise ADBCommandError(f"Push failed: {err}")
        return out

    async def pull_file(
        self, serial: str, remote_path: str, local_path: str
    ) -> str:
        """Pull a file from the device."""
        code, out, err = await self._run(
            build_command("pull", [remote_path, local_path], serial),
            timeout=120,
        )
        if code != 0:
            raise ADBCommandError(f"Pull failed: {err}")
        return out

    # ── Security Checks ──────────────────────────────────────────────────

    async def check_root(self, serial: str) -> bool:
        """Check if device appears to be rooted."""
        try:
            code, out, _ = await self._run(
                build_command("shell", ["id"], serial)
            )
            if "uid=0" in out:
                return True
            # Check for su binary
            code2, out2, _ = await self._run(
                build_command("shell", ["ls", "/system/xbin/su"], serial)
            )
            return code2 == 0 and "No such file" not in out2
        except ADBCommandError:
            return False

    async def check_developer_options(self, serial: str) -> bool:
        """Check if developer options are enabled."""
        try:
            code, out, _ = await self._run(
                build_command(
                    "shell",
                    ["settings", "get", "global", "development_settings_enabled"],
                    serial,
                )
            )
            return out.strip() == "1"
        except ADBCommandError:
            return False

    async def get_running_services(self, serial: str) -> List[str]:
        """Get list of running services."""
        code, out, _ = await self._run(
            build_dumpsys_command(serial, "activity services")
        )
        services = []
        for line in out.splitlines():
            match = re.search(r"ServiceRecord\{.*?\s+(.+?)\}", line)
            if match:
                services.append(match.group(1))
        return services[:100]  # Limit output


# Singleton instance
adb_manager = ADBManager()
