"""
API routes for the incident & device management system.

Endpoints:
    POST   /api/admin/devices/register          — Register an FCM device token
    GET    /api/admin/devices                    — List registered devices
    DELETE /api/admin/devices/{device_id}        — Unregister a device

    GET    /api/admin/incidents                  — List incidents
    GET    /api/admin/incidents/{incident_id}    — Get incident detail
    POST   /api/admin/incidents/{incident_id}/acknowledge
    POST   /api/admin/incidents/{incident_id}/resolve

    POST   /api/admin/notifications/test         — Send a test notification
"""

import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.connection import get_db
from app.models.notification_models import AdminDevice, Incident, NotificationLog
from app.models.schema import User
from app.services.notification_service import notification_service

router = APIRouter(prefix="/admin", tags=["Admin — Incidents & Notifications"])


# ------------------------------------------------------------------
# Pydantic Schemas (kept co-located for this feature module)
# ------------------------------------------------------------------


class DeviceRegisterRequest(BaseModel):
    fcm_token: str = Field(..., min_length=10, description="Firebase Cloud Messaging device token")
    device_name: Optional[str] = Field(None, description="Human-readable device name")
    platform: str = Field("android", description="Device platform: android, ios, web")
    user_id: Optional[int] = Field(None, description="Admin user ID (defaults to 1 for demo)")


class DeviceResponse(BaseModel):
    id: int
    user_id: int
    fcm_token: str
    device_name: Optional[str]
    platform: str
    is_active: bool
    created_at: datetime.datetime
    last_seen: datetime.datetime

    class Config:
        from_attributes = True


class NotificationLogResponse(BaseModel):
    id: int
    incident_id: str
    admin_device_id: Optional[int]
    notification_type: str
    status: str
    sent_at: Optional[datetime.datetime]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class IncidentResponse(BaseModel):
    id: int
    incident_id: str
    event_id: str
    camera_id: str
    location: Optional[str]
    activity_type: Optional[str]
    confidence: float
    status: str
    notification_status: str
    screenshot_path: Optional[str]
    video_clip_path: Optional[str]
    created_at: datetime.datetime
    acknowledged_at: Optional[datetime.datetime]
    resolved_at: Optional[datetime.datetime]
    notification_logs: List[NotificationLogResponse] = []

    class Config:
        from_attributes = True


class TestNotificationRequest(BaseModel):
    user_id: Optional[int] = Field(None, description="Admin user ID (defaults to 1)")


# ------------------------------------------------------------------
# Device Registration Endpoints
# ------------------------------------------------------------------


@router.post("/devices/register", response_model=DeviceResponse)
def register_device(payload: DeviceRegisterRequest, db: Session = Depends(get_db)):
    """Register a mobile device's FCM token for push notifications."""
    user_id = payload.user_id or 1  # default admin

    # Verify user exists and is admin
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only admins can register devices for notifications",
        )

    device = notification_service.register_device(
        user_id=user_id,
        fcm_token=payload.fcm_token,
        device_name=payload.device_name,
        platform=payload.platform,
    )
    return DeviceResponse.model_validate(device)


@router.get("/devices", response_model=List[DeviceResponse])
def list_devices(active_only: bool = True, db: Session = Depends(get_db)):
    """List all registered admin devices."""
    q = db.query(AdminDevice)
    if active_only:
        q = q.filter(AdminDevice.is_active == True)
    return [DeviceResponse.model_validate(d) for d in q.order_by(desc(AdminDevice.created_at)).all()]


@router.delete("/devices/{device_id}", status_code=204)
def unregister_device(device_id: int):
    """Deactivate a registered device."""
    success = notification_service.unregister_device(device_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    return None


# ------------------------------------------------------------------
# Incident Endpoints
# ------------------------------------------------------------------


@router.get("/incidents", response_model=List[IncidentResponse])
def list_incidents(
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = Query(None, description="Filter by status: NEW, ACKNOWLEDGED, RESOLVED"),
    camera_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List incidents with optional filtering."""
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status.upper())
    if camera_id:
        q = q.filter(Incident.camera_id == camera_id)
    incidents = q.order_by(desc(Incident.created_at)).offset(skip).limit(limit).all()
    return [IncidentResponse.model_validate(i) for i in incidents]


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    """Get full incident details including notification logs."""
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return IncidentResponse.model_validate(incident)


@router.post("/incidents/{incident_id}/acknowledge", response_model=IncidentResponse)
def acknowledge_incident(incident_id: str, db: Session = Depends(get_db)):
    """Mark an incident as ACKNOWLEDGED."""
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    if incident.status == "RESOLVED":
        raise HTTPException(status_code=400, detail="Cannot acknowledge a resolved incident")

    incident.status = "ACKNOWLEDGED"
    incident.acknowledged_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(incident)
    return IncidentResponse.model_validate(incident)


@router.post("/incidents/{incident_id}/resolve", response_model=IncidentResponse)
def resolve_incident(incident_id: str, db: Session = Depends(get_db)):
    """Mark an incident as RESOLVED."""
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    incident.status = "RESOLVED"
    incident.resolved_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(incident)
    return IncidentResponse.model_validate(incident)


# ------------------------------------------------------------------
# Test Notification
# ------------------------------------------------------------------


@router.post("/notifications/test")
def send_test_notification(payload: TestNotificationRequest = None):
    """
    Send a test push notification to all active devices of the admin.
    Does NOT create a fake incident — purely for connectivity testing.
    """
    user_id = (payload.user_id if payload else None) or 1
    result = notification_service.send_test_notification(user_id)
    return result
