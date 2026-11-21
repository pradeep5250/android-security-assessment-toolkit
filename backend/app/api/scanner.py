"""
Network Security Scanner API Routes.

Port scanning, DNS lookup, SSL inspection, HTTP headers,
WHOIS, ping, and traceroute endpoints.
"""

import time

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.network_scanner import network_scanner
from app.core.risk_scorer import calculate_risk_score, get_risk_level
from app.core.security import get_current_user
from app.database import get_db
from app.models.scan_result import ScanResult, ScanType
from app.models.user import User
from app.schemas.scan import (
    DnsLookupRequest,
    HttpHeadersRequest,
    PingRequest,
    PortScanRequest,
    SslCheckRequest,
    TracerouteRequest,
    WhoisRequest,
)
from app.utils.validators import validate_port_range

router = APIRouter(
    prefix="/api/v1/scanner",
    tags=["Network Security"],
    dependencies=[Depends(get_current_user)],
)


async def _save_scan(
    db: AsyncSession,
    scan_type: ScanType,
    target: str,
    user: User,
    result: dict,
    findings: list,
    duration_ms: int,
) -> int:
    """Save scan result to database and return the ID."""
    risk_score = calculate_risk_score(findings)
    highest = None
    if findings:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        highest = min(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))
        highest = highest.get("severity")

    scan = ScanResult(
        scan_type=scan_type,
        target=target,
        user_id=user.id,
        status="completed",
        findings={"results": result, "findings": findings},
        summary=f"{len(findings)} findings",
        risk_score=risk_score,
        highest_severity=highest,
        duration_ms=duration_ms,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    return scan.id


@router.post("/port-scan")
async def port_scan(
    request: PortScanRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Perform a TCP port scan on a target."""
    ports = validate_port_range(request.ports)
    if ports is None:
        return {"error": "Invalid port range. Use formats: '80', '1-1024', '80,443', or 'common'"}

    start = time.time()
    result = await network_scanner.port_scan(request.target, ports, request.timeout)
    duration_ms = int((time.time() - start) * 1000)

    scan_id = await _save_scan(
        db, ScanType.PORT_SCAN, request.target, user,
        result, result.get("findings", []), duration_ms,
    )

    result["scan_id"] = scan_id
    result["risk_level"] = get_risk_level(calculate_risk_score(result.get("findings", [])))
    return result


@router.post("/dns-lookup")
async def dns_lookup(
    request: DnsLookupRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Perform DNS record lookups."""
    start = time.time()
    result = await network_scanner.dns_lookup(request.domain, request.record_types)
    duration_ms = int((time.time() - start) * 1000)

    scan_id = await _save_scan(
        db, ScanType.DNS_LOOKUP, request.domain, user,
        result, result.get("findings", []), duration_ms,
    )

    result["scan_id"] = scan_id
    return result


@router.post("/ssl-check")
async def ssl_check(
    request: SslCheckRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Inspect SSL/TLS certificate and configuration."""
    start = time.time()
    result = await network_scanner.ssl_check(request.host, request.port)
    duration_ms = int((time.time() - start) * 1000)

    scan_id = await _save_scan(
        db, ScanType.SSL_CHECK, request.host, user,
        result, result.get("findings", []), duration_ms,
    )

    result["scan_id"] = scan_id
    return result


@router.post("/http-headers")
async def http_headers(
    request: HttpHeadersRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze HTTP security headers."""
    start = time.time()
    result = await network_scanner.check_http_headers(request.url)
    duration_ms = int((time.time() - start) * 1000)

    scan_id = await _save_scan(
        db, ScanType.HTTP_HEADERS, request.url, user,
        result, result.get("findings", []), duration_ms,
    )

    result["scan_id"] = scan_id
    return result


@router.post("/whois")
async def whois_lookup(
    request: WhoisRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Perform WHOIS domain lookup."""
    start = time.time()
    result = await network_scanner.whois_lookup(request.domain)
    duration_ms = int((time.time() - start) * 1000)

    scan_id = await _save_scan(
        db, ScanType.WHOIS, request.domain, user,
        result, [], duration_ms,
    )

    result["scan_id"] = scan_id
    return result


@router.post("/ping")
async def ping(
    request: PingRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ping a target host."""
    start = time.time()
    result = await network_scanner.ping(request.target, request.count)
    duration_ms = int((time.time() - start) * 1000)

    scan_id = await _save_scan(
        db, ScanType.PING, request.target, user,
        result, [], duration_ms,
    )

    result["scan_id"] = scan_id
    return result


@router.post("/traceroute")
async def traceroute(
    request: TracerouteRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run traceroute to a target."""
    start = time.time()
    result = await network_scanner.traceroute(request.target, request.max_hops)
    duration_ms = int((time.time() - start) * 1000)

    scan_id = await _save_scan(
        db, ScanType.TRACEROUTE, request.target, user,
        result, [], duration_ms,
    )

    result["scan_id"] = scan_id
    return result
