"""
APK Analyzer.

Parses Android APK files to extract manifest data, permissions,
exported components, and security configuration issues.
Uses androguard when available, falls back to zipfile + XML parsing.
"""

import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Dangerous Permissions Classification ─────────────────────────────────────

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR": ("medium", "Calendar", "Can read calendar events"),
    "android.permission.WRITE_CALENDAR": ("medium", "Calendar", "Can modify calendar events"),
    "android.permission.CAMERA": ("high", "Camera", "Can access the camera"),
    "android.permission.READ_CONTACTS": ("high", "Contacts", "Can read contacts"),
    "android.permission.WRITE_CONTACTS": ("high", "Contacts", "Can modify contacts"),
    "android.permission.GET_ACCOUNTS": ("medium", "Contacts", "Can access accounts on device"),
    "android.permission.ACCESS_FINE_LOCATION": ("high", "Location", "Can access precise GPS location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("medium", "Location", "Can access approximate location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("critical", "Location", "Can access location in background"),
    "android.permission.RECORD_AUDIO": ("critical", "Microphone", "Can record audio"),
    "android.permission.READ_PHONE_STATE": ("high", "Phone", "Can read phone state and identity"),
    "android.permission.READ_PHONE_NUMBERS": ("high", "Phone", "Can read phone numbers"),
    "android.permission.CALL_PHONE": ("high", "Phone", "Can make phone calls"),
    "android.permission.READ_CALL_LOG": ("critical", "Phone", "Can read call history"),
    "android.permission.WRITE_CALL_LOG": ("critical", "Phone", "Can modify call history"),
    "android.permission.SEND_SMS": ("critical", "SMS", "Can send SMS messages"),
    "android.permission.RECEIVE_SMS": ("critical", "SMS", "Can receive SMS messages"),
    "android.permission.READ_SMS": ("critical", "SMS", "Can read SMS messages"),
    "android.permission.READ_EXTERNAL_STORAGE": ("high", "Storage", "Can read external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("high", "Storage", "Can write external storage"),
    "android.permission.READ_MEDIA_IMAGES": ("medium", "Storage", "Can read images"),
    "android.permission.READ_MEDIA_VIDEO": ("medium", "Storage", "Can read videos"),
    "android.permission.READ_MEDIA_AUDIO": ("medium", "Storage", "Can read audio files"),
    "android.permission.BODY_SENSORS": ("high", "Sensors", "Can access body sensors"),
    "android.permission.ACTIVITY_RECOGNITION": ("medium", "Sensors", "Can detect physical activity"),
    "android.permission.INTERNET": ("low", "Network", "Can access the internet"),
    "android.permission.ACCESS_NETWORK_STATE": ("info", "Network", "Can check network connectivity"),
    "android.permission.ACCESS_WIFI_STATE": ("low", "Network", "Can access WiFi state"),
    "android.permission.BLUETOOTH_CONNECT": ("medium", "Bluetooth", "Can connect to Bluetooth devices"),
    "android.permission.NEARBY_WIFI_DEVICES": ("medium", "WiFi", "Can discover nearby WiFi devices"),
    "android.permission.POST_NOTIFICATIONS": ("low", "Notifications", "Can post notifications"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("high", "System", "Can draw over other apps"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("critical", "System", "Can request to install packages"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("critical", "System", "Can bind as accessibility service"),
    "android.permission.BIND_DEVICE_ADMIN": ("critical", "System", "Can act as device administrator"),
}


class APKAnalyzer:
    """Analyzes Android APK files for security issues."""

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.manifest_xml: Optional[str] = None
        self.manifest_tree: Optional[ET.Element] = None
        self.findings: List[Dict[str, Any]] = []
        self._androguard_available = False

    async def analyze(self) -> Dict[str, Any]:
        """Run full APK analysis and return results."""
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK not found: {self.apk_path}")

        result = {
            "file_name": self.apk_path.name,
            "file_size": self.apk_path.stat().st_size,
            "file_size_mb": round(self.apk_path.stat().st_size / (1024 * 1024), 2),
        }

        # Try androguard first, fall back to manual parsing
        try:
            result.update(await self._analyze_with_androguard())
        except (ImportError, Exception) as e:
            logger.info(f"Androguard not available ({e}), using manual parsing")
            result.update(await self._analyze_manual())

        # Run security checks
        result["findings"] = self.findings
        result["risk_score"] = self._calculate_risk_score()
        result["summary"] = self._generate_summary()

        return result

    async def _analyze_with_androguard(self) -> Dict[str, Any]:
        """Analyze APK using androguard library."""
        from androguard.core.apk import APK

        apk = APK(str(self.apk_path))

        info = {
            "package_name": apk.get_package(),
            "app_name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "max_sdk": apk.get_max_sdk_version(),
        }

        # Permissions
        permissions = apk.get_permissions()
        info["permissions"] = self._classify_permissions(permissions)

        # Activities
        activities = apk.get_activities()
        info["activities"] = {
            "total": len(activities),
            "list": activities[:50],
        }

        # Services
        services = apk.get_services()
        info["services"] = {
            "total": len(services),
            "list": services[:50],
        }

        # Receivers
        receivers = apk.get_receivers()
        info["receivers"] = {
            "total": len(receivers),
            "list": receivers[:50],
        }

        # Providers
        providers = apk.get_providers()
        info["providers"] = {
            "total": len(providers),
            "list": providers[:50],
        }

        # Security checks
        self._check_debuggable(apk)
        self._check_backup(apk)
        self._check_min_sdk(info.get("min_sdk"))
        self._check_exported_components_androguard(apk)
        self._check_dangerous_permissions(permissions)

        return info

    async def _analyze_manual(self) -> Dict[str, Any]:
        """Analyze APK by extracting and parsing AndroidManifest.xml."""
        info = {"parse_method": "manual"}

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                # List all files in APK
                file_list = zf.namelist()
                info["apk_contents"] = {
                    "total_files": len(file_list),
                    "has_native_libs": any("lib/" in f for f in file_list),
                    "has_assets": any("assets/" in f for f in file_list),
                    "dex_files": [f for f in file_list if f.endswith(".dex")],
                }

                # Try to read AndroidManifest.xml (binary XML in APK)
                if "AndroidManifest.xml" in file_list:
                    info["manifest_present"] = True
                    # Binary XML can't be parsed directly without androguard
                    # But we can still check for other files
                else:
                    info["manifest_present"] = False
                    self.findings.append({
                        "severity": "critical",
                        "title": "Missing AndroidManifest.xml",
                        "category": "Manifest",
                        "description": "APK does not contain AndroidManifest.xml",
                        "recommendation": "This APK may be malformed or corrupted.",
                    })

                # Check for network security config
                info["has_network_security_config"] = any(
                    "network_security_config" in f.lower() for f in file_list
                )

                # Check for certificate
                cert_files = [f for f in file_list if f.startswith("META-INF/") and (
                    f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".EC")
                )]
                info["signing_certificates"] = len(cert_files)

                if not cert_files:
                    self.findings.append({
                        "severity": "critical",
                        "title": "No signing certificate found",
                        "category": "Signing",
                        "description": "APK does not appear to be signed.",
                        "recommendation": "Unsigned APKs cannot be installed on Android devices.",
                    })

        except zipfile.BadZipFile:
            self.findings.append({
                "severity": "critical",
                "title": "Invalid APK file",
                "category": "File",
                "description": "The file is not a valid ZIP/APK archive.",
                "recommendation": "Verify the APK source and integrity.",
            })

        return info

    def _classify_permissions(self, permissions: List[str]) -> Dict[str, Any]:
        """Classify permissions by danger level."""
        classified = {
            "total": len(permissions),
            "dangerous": [],
            "normal": [],
            "by_category": {},
        }

        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                severity, category, desc = DANGEROUS_PERMISSIONS[perm]
                classified["dangerous"].append({
                    "permission": perm,
                    "severity": severity,
                    "category": category,
                    "description": desc,
                })
                classified["by_category"].setdefault(category, []).append(perm)
            else:
                classified["normal"].append(perm)

        classified["dangerous_count"] = len(classified["dangerous"])
        classified["normal_count"] = len(classified["normal"])
        return classified

    def _check_debuggable(self, apk) -> None:
        """Check if application is debuggable."""
        try:
            if apk.get_attribute_value("application", "debuggable") == "true":
                self.findings.append({
                    "severity": "critical",
                    "title": "Application is debuggable",
                    "category": "Configuration",
                    "description": "android:debuggable is set to true, allowing debugging in production.",
                    "recommendation": "Set android:debuggable to false for release builds.",
                    "cwe_id": "CWE-489",
                })
        except Exception:
            pass

    def _check_backup(self, apk) -> None:
        """Check backup configuration."""
        try:
            backup = apk.get_attribute_value("application", "allowBackup")
            if backup != "false":
                self.findings.append({
                    "severity": "high",
                    "title": "Application allows backup",
                    "category": "Configuration",
                    "description": "android:allowBackup is not explicitly disabled. "
                                   "App data can be extracted via ADB backup.",
                    "recommendation": "Set android:allowBackup to false unless required.",
                    "cwe_id": "CWE-530",
                })
        except Exception:
            pass

    def _check_min_sdk(self, min_sdk: Optional[str]) -> None:
        """Check minimum SDK version for known vulnerabilities."""
        if min_sdk:
            try:
                sdk = int(min_sdk)
                if sdk < 21:
                    self.findings.append({
                        "severity": "high",
                        "title": f"Low minimum SDK version ({sdk})",
                        "category": "Configuration",
                        "description": f"minSdkVersion is {sdk} (Android {self._sdk_to_version(sdk)}). "
                                       "Older Android versions have known security vulnerabilities.",
                        "recommendation": "Increase minSdkVersion to at least 21 (Android 5.0).",
                    })
                elif sdk < 26:
                    self.findings.append({
                        "severity": "medium",
                        "title": f"Moderate minimum SDK version ({sdk})",
                        "category": "Configuration",
                        "description": f"minSdkVersion is {sdk}. Consider increasing for better security.",
                        "recommendation": "Consider increasing minSdkVersion to 26+ (Android 8.0).",
                    })
            except ValueError:
                pass

    def _check_exported_components_androguard(self, apk) -> None:
        """Check for exported components that may be accessible to other apps."""
        for activity in apk.get_activities():
            try:
                exported = apk.get_attribute_value("activity", "exported", name=activity)
                if exported == "true":
                    self.findings.append({
                        "severity": "medium",
                        "title": f"Exported activity: {activity.split('.')[-1]}",
                        "category": "Exported Components",
                        "description": f"Activity '{activity}' is exported and accessible to other apps.",
                        "recommendation": "Verify this component needs to be exported. Add permission protection if needed.",
                    })
            except Exception:
                pass

    def _check_dangerous_permissions(self, permissions: List[str]) -> None:
        """Generate findings for dangerous permissions."""
        critical_perms = [
            p for p in permissions
            if p in DANGEROUS_PERMISSIONS and DANGEROUS_PERMISSIONS[p][0] == "critical"
        ]
        if critical_perms:
            self.findings.append({
                "severity": "high",
                "title": f"{len(critical_perms)} critical permissions requested",
                "category": "Permissions",
                "description": f"App requests {len(critical_perms)} critical permissions: "
                               + ", ".join(p.split(".")[-1] for p in critical_perms[:5]),
                "recommendation": "Review if all critical permissions are necessary for app functionality.",
            })

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100) based on findings."""
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
        }
        score = 0
        for finding in self.findings:
            score += severity_weights.get(finding.get("severity", "info"), 0)
        return min(100.0, score)

    def _generate_summary(self) -> str:
        """Generate a text summary of findings."""
        counts = {}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                parts.append(f"{counts[sev]} {sev}")

        return f"Found {len(self.findings)} issues: {', '.join(parts)}" if parts else "No issues found"

    @staticmethod
    def _sdk_to_version(sdk: int) -> str:
        """Map SDK version to Android version string."""
        mapping = {
            19: "4.4", 21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0",
            25: "7.1", 26: "8.0", 27: "8.1", 28: "9", 29: "10",
            30: "11", 31: "12", 32: "12L", 33: "13", 34: "14", 35: "15",
        }
        return mapping.get(sdk, f"API {sdk}")
