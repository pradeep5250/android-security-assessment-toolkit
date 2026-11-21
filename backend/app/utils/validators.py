"""Input validation utilities."""

import re
from typing import Optional


def validate_ip_address(ip: str) -> bool:
    """Validate an IPv4 address."""
    pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$"
    )
    return bool(pattern.match(ip))


def validate_hostname(hostname: str) -> bool:
    """Validate a hostname or domain name."""
    if len(hostname) > 253:
        return False
    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    )
    return bool(pattern.match(hostname))


def validate_port(port: int) -> bool:
    """Validate a port number."""
    return 1 <= port <= 65535


def validate_port_range(port_range: str) -> Optional[list[int]]:
    """
    Parse and validate a port range string.
    
    Supports formats:
    - "80" → [80]
    - "80,443,8080" → [80, 443, 8080]
    - "1-1024" → [1, 2, ..., 1024]
    - "common" → common ports list
    
    Returns list of valid port numbers, or None if invalid.
    """
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888,
    ]

    port_range = port_range.strip().lower()

    if port_range == "common":
        return COMMON_PORTS

    ports = []

    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if not (validate_port(start) and validate_port(end) and start <= end):
                    return None
                if end - start > 10000:
                    return None  # Prevent scanning too many ports
                ports.extend(range(start, end + 1))
            except ValueError:
                return None
        else:
            try:
                p = int(part)
                if not validate_port(p):
                    return None
                ports.append(p)
            except ValueError:
                return None

    return sorted(set(ports)) if ports else None


def validate_package_name(package: str) -> bool:
    """Validate an Android package name."""
    pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
    return bool(pattern.match(package))


def sanitize_filename(filename: str) -> str:
    """Remove potentially dangerous characters from a filename."""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)
