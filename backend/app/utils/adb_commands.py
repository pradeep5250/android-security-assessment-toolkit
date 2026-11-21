"""
ADB Command Builder.

Safe command construction with injection prevention.
Only whitelisted ADB commands are permitted.
"""

import re
import shlex
from typing import List, Optional

from app.config import settings


# ── Whitelist of allowed ADB sub-commands ────────────────────────────────────

ALLOWED_COMMANDS = {
    "devices", "get-state", "get-serialno", "version",
    "shell", "push", "pull", "install", "uninstall",
    "logcat", "bugreport", "forward", "reverse",
    "exec-out", "reboot",
}

# Shell sub-commands that are allowed
ALLOWED_SHELL_COMMANDS = {
    "getprop", "dumpsys", "pm", "am", "settings", "wm", "input",
    "cat", "ls", "df", "free", "uname", "id", "whoami",
    "screencap", "screenrecord", "service", "cmd",
    "top", "ps", "netstat", "ip",
}

# Characters that are NEVER allowed in ADB arguments (injection prevention)
DANGEROUS_CHARS = re.compile(r"[;&|`$\(\)\{\}<>!]")


class ADBCommandError(Exception):
    """Raised when a command fails safety validation."""
    pass


def sanitize_argument(arg: str) -> str:
    """
    Sanitize a single command argument.
    
    Raises ADBCommandError if dangerous characters are detected.
    """
    if DANGEROUS_CHARS.search(arg):
        raise ADBCommandError(
            f"Dangerous characters detected in argument: {arg!r}"
        )
    return arg


def build_command(
    sub_command: str,
    args: Optional[List[str]] = None,
    serial: Optional[str] = None,
) -> List[str]:
    """
    Build a safe ADB command list.

    Args:
        sub_command: The ADB sub-command (e.g., 'shell', 'install')
        args: Additional arguments
        serial: Device serial number (-s flag)

    Returns:
        List of command parts ready for subprocess.

    Raises:
        ADBCommandError: If command is not whitelisted or args are unsafe.
    """
    if sub_command not in ALLOWED_COMMANDS:
        raise ADBCommandError(
            f"ADB command '{sub_command}' is not in the whitelist. "
            f"Allowed: {', '.join(sorted(ALLOWED_COMMANDS))}"
        )

    cmd = [settings.adb_path]

    if serial:
        sanitize_argument(serial)
        cmd.extend(["-s", serial])

    cmd.append(sub_command)

    if args:
        # Special validation for shell commands
        if sub_command == "shell" and args:
            shell_cmd = args[0]
            if shell_cmd not in ALLOWED_SHELL_COMMANDS:
                raise ADBCommandError(
                    f"Shell command '{shell_cmd}' is not allowed. "
                    f"Allowed: {', '.join(sorted(ALLOWED_SHELL_COMMANDS))}"
                )

        for arg in args:
            sanitize_argument(arg)
            cmd.append(arg)

    return cmd


def build_getprop_command(serial: str, prop: Optional[str] = None) -> List[str]:
    """Build an ADB getprop command."""
    args = ["getprop"]
    if prop:
        args.append(prop)
    return build_command("shell", args, serial)


def build_dumpsys_command(serial: str, service: str) -> List[str]:
    """Build an ADB dumpsys command."""
    sanitize_argument(service)
    return build_command("shell", ["dumpsys", service], serial)


def build_pm_command(serial: str, pm_args: List[str]) -> List[str]:
    """Build an ADB package manager command."""
    return build_command("shell", ["pm"] + pm_args, serial)


def build_screencap_command(serial: str) -> List[str]:
    """Build an ADB screenshot capture command (raw PNG to stdout)."""
    return build_command("exec-out", ["screencap", "-p"], serial)


def build_screenrecord_command(
    serial: str, output_path: str, time_limit: int = 10
) -> List[str]:
    """Build an ADB screen recording command."""
    sanitize_argument(output_path)
    return build_command(
        "shell",
        ["screenrecord", "--time-limit", str(time_limit), output_path],
        serial,
    )


def build_logcat_command(
    serial: str,
    filters: Optional[List[str]] = None,
    dump: bool = False,
) -> List[str]:
    """Build an ADB logcat command."""
    args = ["logcat"]
    if dump:
        args.append("-d")
    if filters:
        for f in filters:
            sanitize_argument(f)
            args.append(f)
    return build_command("shell", args, serial)
