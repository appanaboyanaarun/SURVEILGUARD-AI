"""
API routes for Security Reporting and Compliance Exports.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, Response, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.report_service import report_service
from app.services.auth_service import get_current_user_optional
from app.services.audit_service import AuditService
from app.models.schema import User

router = APIRouter(prefix="/reports", tags=["Reporting & Compliance"])


@router.get("/activity")
def get_activity_report(
    period: str = Query("daily", description="Timeframe: daily, weekly, monthly, custom"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    camera_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Generates structured activity summary report for dashboard and analytics views.
    """
    return report_service.generate_activity_report(
        db=db,
        period=period,
        start_date=start_date,
        end_date=end_date,
        camera_id=camera_id,
        status=status,
    )


@router.get("/activity/csv")
@router.get("/activity.csv")
def export_activity_csv(
    request: Request,
    period: str = Query("daily"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    camera_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Exports surveillance activity ledger as a downloadable CSV spreadsheet.
    """
    csv_data = report_service.generate_csv_report(
        db=db,
        period=period,
        start_date=start_date,
        end_date=end_date,
        camera_id=camera_id,
    )

    admin_name = current_user.full_name if current_user else "Admin"
    admin_id = current_user.user_id if current_user else None

    # Audit export
    AuditService.log(
        db=db,
        action="REPORT_EXPORT_CSV",
        actor_name=admin_name,
        actor_id=admin_id,
        entity_type="report",
        details=f"Exported CSV activity report for period '{period}'",
    )

    filename = f"surveilguard_report_{period}_{start_date or 'latest'}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
