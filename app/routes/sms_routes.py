"""
API routes for SMS Notification Gateway, Delivery Logs, and Status Webhooks.

Endpoints:
    GET    /api/sms/status               — Provider configuration readiness (no secrets)
    POST   /api/sms/test                 — Send test SMS (admin-only, rate-limited)
    GET    /api/sms/logs                 — SMS dispatch log history
    POST   /api/sms/{sms_log_id}/retry   — Retry a failed SMS
    POST   /api/sms/webhooks/twilio      — Twilio delivery status callback
"""

import hmac
import hashlib
import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Form
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.config import settings
from app.database.connection import get_db
from app.models.schema import SMSLog, User
from app.services.sms_service import sms_service, mask_phone
from app.services.auth_service import get_current_user_optional, require_admin

logger = logging.getLogger("sms_routes")

router = APIRouter(prefix="/sms", tags=["SMS Notification Gateway"])


class TestSMSRequest(BaseModel):
    phone_number: Optional[str] = Field(None, description="Recipient phone number (E.164 format, e.g. +14155551234)")


class AlertSMSRequest(BaseModel):
    phone_number: Optional[str] = Field(None, description="Target recipient phone (or leave empty to send to all configured admin recipients)")
    activity_type: Optional[str] = Field("Suspicious Activity", description="Type of suspicious activity detected")
    camera_id: Optional[str] = Field("CAM-01", description="Camera identifier")
    location: Optional[str] = Field("Main Entrance", description="Location where activity occurred")
    risk_priority: Optional[str] = Field("HIGH", description="Risk priority level (LOW, MEDIUM, HIGH, CRITICAL)")
    event_id: Optional[str] = Field(None, description="Optional incident Event ID")


class SMSLogResponse(BaseModel):
    id: int
    event_id: Optional[str]
    recipient_phone: str
    provider: str
    provider_message_id: Optional[str]
    message_body: str
    video_link: Optional[str]
    status: str
    delivery_status: Optional[str]
    error_message: Optional[str]
    retry_count: int = 0
    is_test: bool = False
    sent_at: Optional[str] = None
    provider_accepted_at: Optional[str] = None
    delivered_at: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True


@router.get("/status")
def get_sms_status():
    """
    Returns SMS provider configuration readiness.
    Does NOT reveal secrets — only shows readiness, masked phone numbers, and issues.
    """
    return sms_service.get_provider_status()


@router.post("/test")
def send_test_sms(
    payload: Optional[TestSMSRequest] = None,
    current_user: User = Depends(require_admin),
):
    """
    Sends a test SMS to verify carrier gateway delivery.
    Requires admin authentication.
    Rate-limited: one test per 10 seconds.
    """
    # Rate limiting
    rate_key = f"user_{current_user.user_id}"
    if not sms_service.check_test_rate_limit(rate_key, min_interval=10.0):
        raise HTTPException(
            status_code=429,
            detail="Rate limited: wait at least 10 seconds between test SMS requests."
        )

    phone = payload.phone_number if payload else None
    result = sms_service.send_test_sms(phone)
    return result


@router.post("/alert")
def send_alert_sms(
    payload: Optional[AlertSMSRequest] = None,
    current_user: User = Depends(require_admin),
):
    """
    Dispatches a high-priority Suspicious Activity Alert SMS to configured Admin numbers.
    Can be used to test the alert template or dispatch alerts on demand.
    Requires admin authentication.
    """
    # Rate limiting
    rate_key = f"alert_user_{current_user.user_id}"
    if not sms_service.check_test_rate_limit(rate_key, min_interval=5.0):
        raise HTTPException(
            status_code=429,
            detail="Rate limited: wait at least 5 seconds between alert SMS requests."
        )

    p = payload or AlertSMSRequest()
    result = sms_service.send_alert_sms(
        phone=p.phone_number,
        activity_type=p.activity_type or "Suspicious Activity",
        camera_id=p.camera_id or "CAM-01",
        location=p.location or "Main Entrance",
        risk_priority=p.risk_priority or "HIGH",
        event_id=p.event_id,
    )
    return result


@router.get("/logs")
def get_sms_logs(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    failed_only: bool = False,
    db: Session = Depends(get_db),
):
    """
    Returns recent SMS dispatch logs.
    Masks phone numbers for security.
    """
    q = db.query(SMSLog)
    if status:
        q = q.filter(SMSLog.status == status.upper())
    if failed_only:
        q = q.filter(SMSLog.status.in_(["FAILED", "NOT_CONFIGURED"]))
    logs = q.order_by(desc(SMSLog.created_at)).offset(skip).limit(limit).all()
    return [
        {
            "id": l.id,
            "event_id": l.event_id,
            "recipient_phone": mask_phone(l.recipient_phone),
            "provider": l.provider,
            "provider_message_id": l.provider_message_id,
            "message_body": l.message_body,
            "video_link": l.video_link,
            "status": l.status,
            "delivery_status": getattr(l, "delivery_status", None),
            "error_message": l.error_message,
            "retry_count": getattr(l, "retry_count", 0) or 0,
            "is_test": getattr(l, "is_test", False) or False,
            "sent_at": l.sent_at.isoformat() if l.sent_at else None,
            "provider_accepted_at": l.provider_accepted_at.isoformat() if getattr(l, "provider_accepted_at", None) else None,
            "delivered_at": l.delivered_at.isoformat() if getattr(l, "delivered_at", None) else None,
            "created_at": l.created_at.isoformat() if l.created_at else None,
        }
        for l in logs
    ]


@router.post("/{sms_log_id}/retry")
def retry_failed_sms(
    sms_log_id: int,
    current_user: User = Depends(require_admin),
):
    """
    Retry a failed SMS notification.
    Requires admin authentication.
    """
    result = sms_service.retry_failed_sms(sms_log_id)
    if not result["success"] and "not found" in result.get("error", "").lower():
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/webhooks/twilio")
async def twilio_status_callback(request: Request):
    """
    Twilio delivery status webhook endpoint.
    Validates the callback and updates SMS log delivery status.
    Idempotent — safe to receive duplicate callbacks.
    """
    # Parse form data (Twilio sends application/x-www-form-urlencoded)
    form_data = await request.form()
    data = dict(form_data)

    # Validate Twilio signature if auth token is configured
    auth_token = settings.TWILIO_AUTH_TOKEN
    if auth_token:
        twilio_signature = request.headers.get("X-Twilio-Signature", "")
        if twilio_signature:
            try:
                from twilio.request_validator import RequestValidator
                validator = RequestValidator(auth_token)
                request_url = str(request.url)
                if not validator.validate(request_url, data, twilio_signature):
                    logger.warning("Twilio webhook signature validation failed")
                    raise HTTPException(status_code=403, detail="Invalid Twilio signature")
            except ImportError:
                # If twilio SDK not available, skip validation but log warning
                logger.warning("Twilio SDK not available for signature validation")
            except HTTPException:
                raise
            except Exception as e:
                logger.warning(f"Twilio signature validation error: {e}")

    success = sms_service.handle_twilio_status_callback(data)
    return {"received": True, "processed": success}


# ============================================================
# RECIPIENT MANAGEMENT ENDPOINTS
# ============================================================

class RecipientCreateRequest(BaseModel):
    name: str = Field("Admin Recipient", description="Display name for this recipient")
    phone_number: str = Field(..., description="Phone number in E.164 format (e.g. +14155551234)")


class RecipientUpdateRequest(BaseModel):
    name: Optional[str] = None
    phone_number: Optional[str] = None
    is_active: Optional[bool] = None


@router.get("/recipients")
def get_recipients(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Returns all configured SMS notification recipients from all sources
    (database, environment variables, admin users with phone numbers).
    """
    recipients = sms_service.get_all_recipients(db)
    return {
        "recipients": recipients,
        "count": len(recipients),
    }


@router.post("/recipients")
def add_recipient(
    payload: RecipientCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Adds a new notification recipient phone number.
    Validates E.164 format and checks for duplicates.
    """
    try:
        result = sms_service.add_recipient(
            name=payload.name,
            phone=payload.phone_number,
            db=db,
        )
        return {"success": True, "recipient": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/recipients/{recipient_id}")
def update_recipient(
    recipient_id: int,
    payload: RecipientUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Updates an existing notification recipient.
    Only database-managed recipients can be updated (not env/user-sourced).
    """
    try:
        result = sms_service.update_recipient(
            recipient_id=recipient_id,
            name=payload.name,
            phone=payload.phone_number,
            is_active=payload.is_active,
            db=db,
        )
        return {"success": True, "recipient": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/recipients/{recipient_id}")
def delete_recipient(
    recipient_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Permanently removes a notification recipient.
    Only database-managed recipients can be deleted.
    """
    deleted = sms_service.delete_recipient(recipient_id, db)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Recipient #{recipient_id} not found.")
    return {"success": True, "message": f"Recipient #{recipient_id} deleted."}
