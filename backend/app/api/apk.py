"""
APK Analysis API Routes.

Upload and analyze Android APK files for security issues.
"""

import time

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.apk_analyzer import APKAnalyzer
from app.core.security import get_current_user, require_analyst_or_above
from app.database import get_db
from app.models.scan_result import ScanResult, ScanType
from app.models.user import User
from app.core.risk_scorer import calculate_risk_score

router = APIRouter(
    prefix="/api/v1/apk",
    tags=["APK Analysis"],
    dependencies=[Depends(get_current_user)],
)


@router.post("/analyze")
async def analyze_apk(
    apk: UploadFile = File(...),
    user: User = Depends(require_analyst_or_above()),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload and analyze an APK file.
    
    Extracts manifest data, permissions, exported components,
    and identifies security issues.
    """
    if not apk.filename or not apk.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an APK")

    # Check file size
    content = await apk.read()
    if len(content) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size: {settings.max_upload_size_mb}MB",
        )

    # Save to disk for analysis
    apk_path = settings.upload_path / f"analyze_{apk.filename}"
    try:
        apk_path.write_bytes(content)

        start = time.time()
        analyzer = APKAnalyzer(str(apk_path))
        result = await analyzer.analyze()
        duration_ms = int((time.time() - start) * 1000)

        # Save to database
        findings = result.get("findings", [])
        risk_score = calculate_risk_score(findings)

        highest = None
        if findings:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            highest = min(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))
            highest = highest.get("severity")

        scan = ScanResult(
            scan_type=ScanType.APK_ANALYSIS,
            target=apk.filename,
            user_id=user.id,
            status="completed",
            findings=result,
            summary=result.get("summary", ""),
            risk_score=risk_score,
            highest_severity=highest,
            duration_ms=duration_ms,
        )
        db.add(scan)
        await db.flush()
        await db.refresh(scan)

        result["scan_id"] = scan.id
        result["duration_ms"] = duration_ms
        return result

    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        apk_path.unlink(missing_ok=True)
