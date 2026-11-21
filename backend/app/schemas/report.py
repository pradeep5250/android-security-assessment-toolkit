"""Report Pydantic schemas."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from app.models.report import ReportFormat


class ReportGenerateRequest(BaseModel):
    """Request to generate a report."""
    title: str = Field(..., max_length=255)
    description: Optional[str] = None
    report_format: ReportFormat = ReportFormat.PDF
    scan_ids: List[int] = Field(..., min_length=1, description="Scan result IDs to include")
    device_id: Optional[int] = None


class ReportResponse(BaseModel):
    """Report metadata response."""
    id: int
    title: str
    description: Optional[str]
    report_format: ReportFormat
    file_path: str
    file_size: Optional[int]
    scan_ids: Optional[str]
    device_id: Optional[int]
    created_by: Optional[int]
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportListResponse(BaseModel):
    """List of reports."""
    total: int
    reports: List[ReportResponse]
