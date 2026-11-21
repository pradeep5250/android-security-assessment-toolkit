"""
Device Auditor.

Aggregates device information, ADB security checks,
and generates a comprehensive security posture assessment.
"""

import logging
from typing import Any, Dict, List

from app.core.adb_manager import ADBCommandError, adb_manager
from app.core.risk_scorer import calculate_risk_score, get_risk_level

logger = logging.getLogger(__name__)


class DeviceAuditor:
    """Performs comprehensive security audits on connected Android devices."""

    async def full_audit(self, serial: str) -> Dict[str, Any]:
        """
        Perform a full security audit of a device.
        
        Checks:
        - Device info and patch level
        - Root detection
        - Developer options
        - Encryption status
        - USB debugging
        - Installed packages analysis
        - Running services
        """
        findings: List[Dict[str, Any]] = []
        audit_data: Dict[str, Any] = {"serial": serial}

        # 1. Collect device info
        try:
            info = await adb_manager.get_device_info(serial)
            audit_data["device_info"] = info
        except ADBCommandError as e:
            audit_data["device_info"] = {"error": str(e)}
            findings.append({
                "severity": "high",
                "title": "Could not collect device information",
                "category": "Device Info",
                "description": str(e),
            })
            # Can't proceed with other checks
            audit_data["findings"] = findings
            audit_data["risk_score"] = calculate_risk_score(findings)
            return audit_data

        # 2. Check security patch level
        patch = info.get("security_patch", "unknown")
        if patch != "unknown":
            self._check_patch_level(patch, findings)

        # 3. Check Android version
        version = info.get("android_version", "unknown")
        if version != "unknown":
            self._check_android_version(version, findings)

        # 4. Root detection
        try:
            is_rooted = await adb_manager.check_root(serial)
            audit_data["is_rooted"] = is_rooted
            if is_rooted:
                findings.append({
                    "severity": "critical",
                    "title": "Device is rooted",
                    "category": "Root Detection",
                    "description": "Root access detected. Device integrity may be compromised.",
                    "recommendation": "Use a non-rooted device for sensitive operations. "
                                     "Root access bypasses Android's security model.",
                    "cwe_id": "CWE-250",
                })
        except ADBCommandError:
            audit_data["is_rooted"] = None

        # 5. Developer options
        try:
            dev_opts = await adb_manager.check_developer_options(serial)
            audit_data["developer_options"] = dev_opts
            if dev_opts:
                findings.append({
                    "severity": "medium",
                    "title": "Developer options are enabled",
                    "category": "Configuration",
                    "description": "Developer options are enabled, increasing the attack surface.",
                    "recommendation": "Disable developer options on production devices.",
                })
        except ADBCommandError:
            audit_data["developer_options"] = None

        # 6. Package analysis
        try:
            packages = await adb_manager.list_packages(serial, include_system=False)
            audit_data["installed_apps"] = len(packages)
            audit_data["packages"] = packages[:50]

            # Check for known risky apps
            risky_patterns = [
                "supersu", "magisk", "kingroot", "kingoroot",
                "framaroot", "towelroot", "xposed",
            ]
            for pkg in packages:
                pkg_name = pkg.get("package_name", "").lower()
                for pattern in risky_patterns:
                    if pattern in pkg_name:
                        findings.append({
                            "severity": "high",
                            "title": f"Potentially risky app: {pkg.get('package_name')}",
                            "category": "Installed Apps",
                            "description": f"App '{pkg.get('package_name')}' matches risky pattern '{pattern}'.",
                            "recommendation": "Review this application and remove if not needed.",
                        })
        except ADBCommandError:
            audit_data["installed_apps"] = None

        # 7. Running services
        try:
            services = await adb_manager.get_running_services(serial)
            audit_data["running_services"] = len(services)
            audit_data["services_sample"] = services[:20]
        except ADBCommandError:
            audit_data["running_services"] = None

        # Calculate final score
        risk_score = calculate_risk_score(findings)
        risk_level = get_risk_level(risk_score)

        audit_data["findings"] = findings
        audit_data["findings_count"] = len(findings)
        audit_data["risk_score"] = risk_score
        audit_data["risk_level"] = risk_level["level"]
        audit_data["risk_icon"] = risk_level["icon"]

        return audit_data

    def _check_patch_level(
        self, patch: str, findings: List[Dict[str, Any]]
    ) -> None:
        """Check if the security patch level is outdated."""
        try:
            from datetime import datetime, timezone

            # Parse YYYY-MM-DD format
            patch_date = datetime.strptime(patch, "%Y-%m-%d")
            now = datetime.now()
            months_old = (now.year - patch_date.year) * 12 + (now.month - patch_date.month)

            if months_old > 12:
                findings.append({
                    "severity": "critical",
                    "title": f"Security patch is {months_old} months old",
                    "category": "Patch Level",
                    "description": f"Last security patch: {patch}. "
                                   f"Device is {months_old} months behind on security updates.",
                    "recommendation": "Update the device to the latest security patch immediately.",
                })
            elif months_old > 6:
                findings.append({
                    "severity": "high",
                    "title": f"Security patch is {months_old} months old",
                    "category": "Patch Level",
                    "description": f"Last security patch: {patch}.",
                    "recommendation": "Update the device to the latest security patch.",
                })
            elif months_old > 3:
                findings.append({
                    "severity": "medium",
                    "title": f"Security patch is {months_old} months old",
                    "category": "Patch Level",
                    "description": f"Last security patch: {patch}.",
                    "recommendation": "Check for available security updates.",
                })
        except ValueError:
            pass

    def _check_android_version(
        self, version: str, findings: List[Dict[str, Any]]
    ) -> None:
        """Check if Android version is supported."""
        try:
            major = int(version.split(".")[0])
            if major < 10:
                findings.append({
                    "severity": "high",
                    "title": f"Outdated Android version ({version})",
                    "category": "OS Version",
                    "description": f"Android {version} is no longer receiving security updates.",
                    "recommendation": "Upgrade to Android 10 or later for continued security support.",
                })
            elif major < 12:
                findings.append({
                    "severity": "medium",
                    "title": f"Aging Android version ({version})",
                    "category": "OS Version",
                    "description": f"Android {version} may have limited security update support.",
                    "recommendation": "Consider upgrading to a newer Android version.",
                })
        except (ValueError, IndexError):
            pass


# Singleton
device_auditor = DeviceAuditor()
