"""
Report API Routes.

Generate, list, download, and delete security assessment reports.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.report_generator import report_generator
from app.core.security import get_current_user, require_analyst_or_above
from app.database import get_db
from app.models.report import Report, ReportFormat
from app.models.scan_result import ScanResult
from app.models.user import User
from app.schemas.report import ReportGenerateRequest, ReportListResponse, ReportResponse

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"],
    dependencies=[Depends(get_current_user)],
)


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    request: ReportGenerateRequest,
    user: User = Depends(require_analyst_or_above()),
    db: AsyncSession = Depends(get_db),
):
    """Generate a security assessment report from scan results."""
    # Fetch scan results
    result = await db.execute(
        select(ScanResult).where(ScanResult.id.in_(request.scan_ids))
    )
    scans = result.scalars().all()

    if not scans:
        raise HTTPException(status_code=404, detail="No scan results found for the given IDs")

    # Convert to dicts for the generator
    scan_dicts = []
    for scan in scans:
        scan_dicts.append({
            "id": scan.id,
            "scan_type": scan.scan_type.value,
            "target": scan.target,
            "findings": scan.findings,
            "risk_score": scan.risk_score,
            "created_at": str(scan.created_at),
        })

    # Get device info if available
    device_info = None
    if request.device_id:
        from app.models.device import Device
        dev_result = await db.execute(select(Device).where(Device.id == request.device_id))
        device = dev_result.scalar_one_or_none()
        if device:
            device_info = {
                "serial": device.serial,
                "model": device.model,
                "manufacturer": device.manufacturer,
                "android_version": device.android_version,
                "security_patch": device.security_patch,
            }

    # Generate report
    if request.report_format == ReportFormat.PDF:
        filepath = await report_generator.generate_pdf(request.title, scan_dicts, device_info)
    elif request.report_format == ReportFormat.HTML:
        filepath = await report_generator.generate_html(request.title, scan_dicts, device_info)
    elif request.report_format == ReportFormat.CSV:
        filepath = await report_generator.generate_csv(request.title, scan_dicts)
    else:
        raise HTTPException(status_code=400, detail="Invalid report format")

    # Save report record
    file_size = filepath.stat().st_size
    report = Report(
        title=request.title,
        description=request.description,
        report_format=request.report_format,
        file_path=str(filepath),
        file_size=file_size,
        scan_ids=",".join(str(sid) for sid in request.scan_ids),
        device_id=request.device_id,
        created_by=user.id,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return report


@router.get("/", response_model=ReportListResponse)
async def list_reports(db: AsyncSession = Depends(get_db)):
    """List all generated reports."""
    total = (await db.execute(select(func.count()).select_from(Report))).scalar()
    result = await db.execute(select(Report).order_by(Report.created_at.desc()))
    reports = result.scalars().all()
    return ReportListResponse(
        total=total,
        reports=[ReportResponse.model_validate(r) for r in reports],
    )


@router.get("/{report_id}/download")
async def download_report(report_id: int, db: AsyncSession = Depends(get_db)):
    """Download a generated report file."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    from pathlib import Path
    filepath = Path(report.file_path)
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    media_types = {
        ReportFormat.PDF: "application/pdf",
        ReportFormat.HTML: "text/html",
        ReportFormat.CSV: "text/csv",
    }

    return FileResponse(
        str(filepath),
        media_type=media_types.get(report.report_format, "application/octet-stream"),
        filename=filepath.name,
    )


@router.delete("/{report_id}")
async def delete_report(
    report_id: int,
    user: User = Depends(require_analyst_or_above()),
    db: AsyncSession = Depends(get_db),
):
    """Delete a report and its file."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Delete file
    from pathlib import Path
    filepath = Path(report.file_path)
    filepath.unlink(missing_ok=True)

    # Delete record
    await db.delete(report)
    return {"message": f"Report '{report.title}' deleted"}
