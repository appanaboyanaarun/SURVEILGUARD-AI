"""
API routes for Email Notification Center.
Uses Google Apps Script HTTP API (port 443) for reliable, firewall-friendly email delivery.

Endpoints:
    GET    /api/email/status               — Google Apps Script configuration readiness & recipient stats
    POST   /api/email/test                 — Send test email via Google Apps Script HTTP API
    GET    /api/email/logs                 — Email dispatch log history (graceful fallback)
    POST   /api/email/{log_id}/retry       — Retry a failed email via Google Apps Script
    POST   /api/email/alert                — Send alert email to Admin & Friend recipients
    POST   /api/email/incident/{id}/send   — Send email for existing incident
    GET    /api/email/recipients           — List email recipients (Admin & Friends)
    POST   /api/email/recipients           — Add an email recipient (Admin or Friend)
    PUT    /api/email/recipients/{id}      — Update an email recipient
    DELETE /api/email/recipients/{id}      — Remove an email recipient
    POST   /api/email/webhook              — Verified delivery & bounce event webhook
"""

import datetime
import html
import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.notification_models import EmailLog, Incident
from app.models.schema import User, Event
from app.services.email_service import email_service, mask_email
from app.services.auth_service import get_current_user_optional

logger = logging.getLogger("email_routes")

router = APIRouter(prefix="/email", tags=["Email Notification Center"])


# ------------------------------------------------------------------
# Pydantic Schemas
# ------------------------------------------------------------------

class TestEmailRequest(BaseModel):
    email: Optional[str] = Field(None, description="Recipient email address (defaults to configured recipients)")


class SendIncidentEmailRequest(BaseModel):
    incident_id: str = Field(..., description="Incident ID to send email for")


class SendAlertEmailRequest(BaseModel):
    activity_type: Optional[str] = Field("Suspicious Activity", description="Type of suspicious activity detected")
    camera_id: Optional[str] = Field("CAM-01", description="Camera identifier")
    location: Optional[str] = Field("Main Entrance", description="Location where activity occurred")
    risk_priority: Optional[str] = Field("HIGH", description="Risk priority level")
    event_id: Optional[str] = Field(None, description="Optional event ID (uses existing incident if omitted)")


class EmailRecipientRequest(BaseModel):
    name: str = Field("Friend Recipient", description="Display name for this recipient")
    email: str = Field(..., description="Recipient email address")
    recipient_type: Optional[str] = Field("friend", description="Recipient category: 'admin' or 'friend'")


class EmailRecipientUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    recipient_type: Optional[str] = None
    is_active: Optional[bool] = None


class EmailRecipientResponse(BaseModel):
    id: Optional[int] = None
    name: str
    email: str
    email_masked: str
    recipient_type: str = "friend"
    source: str
    is_active: bool
    created_at: Optional[str] = None

    class Config:
        from_attributes = True


def _check_admin_permissions(current_user: Optional[User]):
    """If user is authenticated, ensure they possess operator or admin privilege."""
    if current_user and current_user.role and current_user.role.lower() not in ("admin", "operator"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges are required for email notification management.",
        )


# ------------------------------------------------------------------
# Status / Configuration
# ------------------------------------------------------------------

@router.get("/status")
def get_email_status():
    """
    Returns Google Apps Script HTTP API provider configuration readiness and recipient metrics.
    Does NOT reveal secrets or private tokens.
    """
    return email_service.get_provider_status()


# ------------------------------------------------------------------
# Test Email (Google Apps Script HTTP API)
# ------------------------------------------------------------------

@router.post("/test")
def send_test_email(
    payload: Optional[TestEmailRequest] = None,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Sends a test email via Google Apps Script HTTP API to verify delivery.
    Bypasses firewall and SMTP port blocks. Rate-limited per user/client.
    """
    _check_admin_permissions(current_user)

    user_key = f"user_{current_user.user_id}" if current_user else "default_admin"
    if not email_service._test_rate_limit(user_key, min_interval=3.0):
        raise HTTPException(
            status_code=429,
            detail="Rate limited: please wait a few seconds between test email requests.",
        )

    email_to = payload.email if payload and payload.email else None
    result = email_service.send_test_email(to_email=email_to)
    if not result["success"]:
        raise HTTPException(
            status_code=400,
            detail=result.get("error") or result.get("message") or "Test email failed",
        )
    return result


# ------------------------------------------------------------------
# Email Logs (Graceful - Never throws fetch errors)
# ------------------------------------------------------------------

@router.get("/logs")
def get_email_logs(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="Filter by status: QUEUED, SENDING, ACCEPTED, FAILED, DELIVERED, BOUNCED"),
):
    """
    Returns email dispatch log history.
    Gracefully returns an empty list on any database or query exception,
    preventing frontend fetch crashes.
    """
    try:
        logs = email_service.get_logs(db, limit=limit, offset=offset, status=status)
        return logs or []
    except Exception as exc:
        logger.warning(f"Graceful fallback in get_email_logs: {exc}")
        return []


@router.post("/{log_id}/retry")
def retry_email(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Retry a failed or bounced email dispatch via Resend HTTP API.
    Prevents duplicate sends for already accepted or delivered messages.
    """
    _check_admin_permissions(current_user)

    log = db.query(EmailLog).filter(EmailLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"Email log #{log_id} not found")

    if log.status in ("ACCEPTED", "DELIVERED", "SENT"):
        return {
            "success": False,
            "status": log.status,
            "message": f"Email #{log_id} is already in '{log.status}' status. Duplicate retry prevented.",
        }

    subject = log.subject or "SurveilGuard AI - Security Alert (Retry)"
    now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    timestamp = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    app_base = email_service._get_public_base_url()
    incident_url = f"{app_base}/#/events" if app_base else None
    incident_link = (
        f'<a href="{html.escape(incident_url)}" style="background:#dc2626;color:#ffffff;padding:8px 16px;'
        'border-radius:4px;text-decoration:none;font-weight:600;font-size:13px;">View Incident</a>'
        if incident_url
        else '<span style="color:#6b7280;">Remote review links are not configured.</span>'
    )
    app_display = incident_url or "Remote review links are not configured."

    html_content = f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;padding:20px;background:#f3f4f6;">
<div style="background:#ffffff;border-radius:8px;padding:24px;border-left:4px solid #ef4444;">
<h2 style="color:#dc2626;">&#9888;&#65039; Security Alert (Retry Attempt)</h2>
<p>This is a re-sent security alert from SurveilGuard AI via Google Apps Script HTTP API.</p>
<p style="font-size:14px;color:#374151;">Incident Reference: <code>{log.incident_id or 'N/A'}</code></p>
<p style="font-size:12px;color:#6b7280;">Retried at {timestamp} UTC</p>
<div style="margin-top:16px;">
  {incident_link}
</div>
</div>
</body></html>"""
    text_content = f"""Security Alert (Retry Attempt)

This is a re-sent security alert from SurveilGuard AI via Google Apps Script HTTP API.
Incident Reference: {log.incident_id or 'N/A'}
Retried at: {timestamp} UTC
Application: {app_display}
"""
    details = f"Retry attempt for incident {log.incident_id or 'N/A'} dispatched at {timestamp} UTC."

    log.status = "SENDING"
    db.commit()

    res = email_service._send_apps_script(
        to_email=log.recipient_email,
        subject=subject,
        camera="CAM-01",
        event_name="Security Alert (Retry)",
        timestamp_str=timestamp,
        details=details,
        html_content=html_content,
        text_content=text_content,
    )

    log.status = res.status
    log.error_message = res.error
    log.provider_message_id = res.message_id
    log.provider = "apps_script"
    log.attempt_count = (log.attempt_count or 0) + 1
    if res.success:
        log.sent_at = now_dt
    db.commit()

    if not res.success:
        raise HTTPException(status_code=400, detail=res.error or "Retry dispatch failed")
    return {
        "success": True,
        "status": res.status,
        "message": f"Email retry accepted via Google Apps Script (Message ID: {res.message_id or 'N/A'}).",
    }


# ------------------------------------------------------------------
# Send Alert Email (Google Apps Script HTTP API)
# ------------------------------------------------------------------

@router.post("/alert")
def send_alert_email(
    payload: Optional[SendAlertEmailRequest] = None,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Send an alert email to all active Admin and Friend recipients via Google Apps Script HTTP API.
    Uses existing incident when available, or finds latest confirmed incident, avoiding fake events.
    """
    _check_admin_permissions(current_user)

    event_id = (payload and payload.event_id) or None
    camera_id = (payload and payload.camera_id) or "CAM-01"

    # 1. If explicit event_id provided, look up
    if event_id:
        incident = db.query(Incident).filter(Incident.event_id == event_id).first()
        if not incident:
            # Check Event table
            event = db.query(Event).filter(Event.event_id == event_id).first()
            if not event:
                raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found")
    else:
        # 2. Look for most recent existing incident in database
        latest_incident = db.query(Incident).order_by(Incident.created_at.desc()).first()
        if latest_incident:
            event_id = latest_incident.event_id
            camera_id = latest_incident.camera_id
        else:
            # 3. Look for most recent Event in database
            latest_event = db.query(Event).filter(Event.status == "SUSPICIOUS").order_by(Event.timestamp.desc()).first()
            if not latest_event:
                latest_event = db.query(Event).order_by(Event.timestamp.desc()).first()

            if latest_event:
                event_id = latest_event.event_id
                camera_id = latest_event.camera_id
            else:
                # 4. Only if database has zero incidents and zero events, create simulation test event clearly marked
                ts = int(datetime.datetime.utcnow().timestamp())
                event_id = f"TEST-ALERT-{ts}"
                incident = Incident(
                    incident_id=f"INC-TEST-{ts}",
                    event_id=event_id,
                    camera_id=camera_id,
                    location=(payload and payload.location) or "Main Security Gate",
                    activity_type="[TEST ALERT] Manual Operator Security Dispatch Test",
                    confidence=0.88,
                    status="NEW",
                    notification_status="PENDING",
                )
                db.add(incident)
                db.commit()

    result = email_service.send_suspicious_event_email(event_id, camera_id)
    if not result["success"]:
        raise HTTPException(
            status_code=400,
            detail=result.get("message") or "Alert email dispatch failed",
        )
    return result


# ------------------------------------------------------------------
# Send email for existing incident
# ------------------------------------------------------------------

@router.post("/incident/{incident_id}/send")
def send_incident_email(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Send an email alert for an existing incident via Google Apps Script HTTP API."""
    _check_admin_permissions(current_user)

    result = email_service.send_incident_email(incident_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


# ------------------------------------------------------------------
# Recipients Management (Admin & Friends)
# ------------------------------------------------------------------

@router.get("/recipients")
def get_recipients(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Returns all configured admin and friend email recipients gracefully.
    Always returns valid data based on environment and database records.
    Masks emails for public view while preserving management capabilities.
    """
    try:
        # If unauthenticated, mask complete emails in the email field as well
        hide_full = not bool(current_user and current_user.role in ("admin", "operator"))
        recipients = email_service.get_all_recipients(db=db, active_only=False, hide_full_email=hide_full)
        return recipients or []
    except Exception as exc:
        logger.warning(f"Graceful fallback in get_recipients: {exc}")
        admin_emails = email_service._get_env_admin_emails()
        return [
            {
                "id": idx + 1,
                "name": "System Admin",
                "email": mask_email(email),
                "email_masked": mask_email(email),
                "recipient_type": "admin",
                "source": "environment",
                "is_active": True,
                "created_at": None,
            }
            for idx, email in enumerate(admin_emails)
        ]


@router.post("/recipients", status_code=status.HTTP_201_CREATED)
def add_recipient(
    payload: EmailRecipientRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Adds a new notification recipient (Admin or Friend) email address."""
    _check_admin_permissions(current_user)

    try:
        result = email_service.add_recipient(
            name=payload.name,
            email=payload.email,
            recipient_type=payload.recipient_type or "friend",
            db=db,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/recipients/{recipient_id}")
def update_recipient(
    recipient_id: int,
    payload: EmailRecipientUpdateRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Updates an existing notification recipient (e.g. pause/resume or rename)."""
    _check_admin_permissions(current_user)

    try:
        result = email_service.update_recipient(
            recipient_id=recipient_id,
            name=payload.name,
            email=payload.email,
            recipient_type=payload.recipient_type,
            is_active=payload.is_active,
            db=db,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/recipients/{recipient_id}")
def delete_recipient(
    recipient_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Permanently removes a notification recipient from the database."""
    _check_admin_permissions(current_user)

    deleted = email_service.delete_recipient(recipient_id, db)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Recipient #{recipient_id} not found.")
    return {"success": True, "message": f"Recipient #{recipient_id} deleted."}


# ------------------------------------------------------------------
# Resend Webhook (Delivery & Bounce Tracking)
# ------------------------------------------------------------------

@router.post("/webhook")
async def resend_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Handles verified webhook delivery and bounce events from Resend.
    Verifies Svix HMAC-SHA256 signatures before updating email delivery states.
    """
    body = await request.body()
    headers = dict(request.headers)

    verified = email_service.verify_webhook_signature(body, headers)
    if not verified:
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        event = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    result = email_service.process_webhook_event(event, db)
    return result
