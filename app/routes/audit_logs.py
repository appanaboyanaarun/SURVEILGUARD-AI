"""
API routes for Security Audit Ledger.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.dto import AuditLogResponse
from app.services.audit_service import AuditService
from app.services.auth_service import get_current_user_optional, require_admin
from app.models.schema import User

router = APIRouter(prefix="/audit", tags=["Audit & Compliance"])


@router.get("/logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = Query(None),
    actor_name: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Returns security audit log entries.
    """
    logs = AuditService.get_logs(
        db=db,
        skip=skip,
        limit=limit,
        action=action,
        actor_name=actor_name,
        entity_type=entity_type,
    )
    return [AuditLogResponse.model_validate(l) for l in logs]
