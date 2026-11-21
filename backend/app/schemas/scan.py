"""Scan Pydantic schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.scan_result import ScanType, SeverityLevel


# ── Request Schemas ──────────────────────────────────────────────────────────

class PortScanRequest(BaseModel):
    """Port scan request."""
    target: str = Field(..., description="IP address or hostname")
    ports: Optional[str] = Field(
        "1-1024",
        description="Port range (e.g., '1-1024', '80,443,8080', 'common')",
    )
    timeout: float = Field(2.0, ge=0.1, le=10.0)


class DnsLookupRequest(BaseModel):
    """DNS lookup request."""
    domain: str
    record_types: List[str] = Field(
        default=["A", "AAAA", "MX", "NS", "TXT"],
        description="DNS record types to query",
    )


class SslCheckRequest(BaseModel):
    """SSL certificate check request."""
    host: str
    port: int = 443


class HttpHeadersRequest(BaseModel):
    """HTTP security headers check request."""
    url: str


class WhoisRequest(BaseModel):
    """WHOIS lookup request."""
    domain: str


class PingRequest(BaseModel):
    """Ping request."""
    target: str
    count: int = Field(4, ge=1, le=20)


class TracerouteRequest(BaseModel):
    """Traceroute request."""
    target: str
    max_hops: int = Field(30, ge=1, le=64)


# ── Finding Schema ───────────────────────────────────────────────────────────

class Finding(BaseModel):
    """Individual security finding."""
    title: str
    severity: SeverityLevel
    category: str
    description: str
    recommendation: Optional[str] = None
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None


# ── Response Schemas ─────────────────────────────────────────────────────────

class ScanResultResponse(BaseModel):
    """Scan result response."""
    id: int
    scan_type: ScanType
    target: str
    device_id: Optional[int]
    status: str
    findings: Optional[Dict[str, Any]]
    summary: Optional[str]
    risk_score: Optional[float]
    highest_severity: Optional[SeverityLevel]
    duration_ms: Optional[int]
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    """Paginated scan results list."""
    total: int
    page: int
    per_page: int
    results: List[ScanResultResponse]


class PortScanResult(BaseModel):
    """Port scan detailed results."""
    target: str
    open_ports: List[Dict[str, Any]]
    closed_ports_count: int
    filtered_ports_count: int
    scan_duration_ms: int


class DnsResult(BaseModel):
    """DNS lookup results."""
    domain: str
    records: Dict[str, List[str]]


class SslCertResult(BaseModel):
    """SSL certificate analysis results."""
    host: str
    port: int
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: str
    not_before: str
    not_after: str
    days_remaining: int
    is_expired: bool
    signature_algorithm: Optional[str] = None
    san: List[str] = []
    protocol_version: Optional[str] = None
    cipher: Optional[str] = None
    findings: List[Finding] = []
