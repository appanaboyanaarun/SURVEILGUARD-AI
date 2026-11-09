import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field


# --- Camera Schemas ---
class CameraBase(BaseModel):
    camera_id: str
    name: str
    location: str
    description: Optional[str] = None
    camera_type: Optional[str] = "CCTV"
    stream_url: Optional[str] = None
    status: Optional[str] = "OFFLINE"
    restricted_zone_coords: Optional[str] = None
    is_active: Optional[bool] = True


class CameraCreate(CameraBase):
    pass


class CameraUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    camera_type: Optional[str] = None
    stream_url: Optional[str] = None
    status: Optional[str] = None
    restricted_zone_coords: Optional[str] = None
    is_active: Optional[bool] = None


class CameraResponse(CameraBase):
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# --- Review Schemas ---
class ReviewCreate(BaseModel):
    event_id: str
    review_status: str  # CONFIRMED_SUSPICIOUS, FALSE_ALARM, UNDER_REVIEW
    annotation: Optional[str] = ""
    reviewed_by: Optional[str] = "Operator"


class ReviewResponse(BaseModel):
    review_id: int
    event_id: str
    review_status: str
    annotation: Optional[str]
    reviewed_by: str
    reviewed_at: datetime.datetime

    class Config:
        from_attributes = True


# --- Event Schemas ---
class EventBase(BaseModel):
    camera_id: str
    timestamp: datetime.datetime
    location: str
    person_count: int = 1
    object_type: str = "person"
    motion_level: str = "Medium"
    activity_type: str = "Normal Movement"
    event_duration: int = 0
    event_duration_formatted: str = "00:00"
    restricted_area: int = 0


class EventCreate(EventBase):
    event_id: Optional[str] = None
    session_id: Optional[str] = None
    admin_id: Optional[int] = None
    admin_name: Optional[str] = "Admin"
    anomaly_score: Optional[float] = 0.0
    status: Optional[str] = "NORMAL"
    risk_priority: Optional[str] = "LOW"
    anomaly_reasons: Optional[str] = None
    video_filename: Optional[str] = None
    thumbnail_path: Optional[str] = None
    evidence_video_id: Optional[str] = None
    sms_status: Optional[str] = "NONE"


class EventResponse(EventBase):
    event_id: str
    session_id: Optional[str] = None
    admin_name: Optional[str] = "Admin"
    anomaly_score: float
    status: str
    risk_priority: str
    anomaly_reasons: Optional[str] = None
    video_filename: Optional[str] = None
    thumbnail_path: Optional[str] = None
    evidence_video_id: Optional[str] = None
    source: Optional[str] = None
    sms_status: Optional[str] = "NONE"
    sms_sent_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime
    reviews: List[ReviewResponse] = []

    class Config:
        from_attributes = True


# --- Detection Session Schemas ---
class DetectionSessionStart(BaseModel):
    camera_id: str = Field(..., description="Target camera ID")
    device_info: Optional[str] = Field(None, description="Browser or device user-agent")


class DetectionSessionStop(BaseModel):
    session_id: str = Field(..., description="ID of session to terminate")


class DetectionSessionResponse(BaseModel):
    session_id: str
    user_id: Optional[int]
    admin_name: str
    camera_id: str
    location: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    device_info: Optional[str] = None
    detection_result: str
    suspicious_event_count: int
    is_active: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# --- Evidence Video Schemas ---
class EvidenceVideoResponse(BaseModel):
    video_id: str
    event_id: Optional[str]
    session_id: Optional[str]
    filename: str
    storage_provider: str
    storage_path: str
    file_size: int
    duration_seconds: float
    mime_type: str
    thumbnail_path: Optional[str]
    secure_url: Optional[str] = None
    created_at: datetime.datetime

    class Config:
        from_attributes = True


# --- Audit Log Schemas ---
class AuditLogResponse(BaseModel):
    id: int
    actor_id: Optional[int]
    actor_name: str
    action: str
    entity_type: Optional[str]
    entity_id: Optional[str]
    details: Optional[str]
    ip_address: Optional[str]
    timestamp: datetime.datetime

    class Config:
        from_attributes = True


# --- Analytics & Summary Schemas ---
class DashboardSummary(BaseModel):
    total_events: int
    normal_events: int
    suspicious_events: int
    high_priority_alerts: int
    reviewed_events: int
    cameras_active: int
    active_detection_sessions: int = 0
    sms_alerts_sent: int = 0


class ChartDataset(BaseModel):
    labels: List[str]
    values: List[Any]


class DashboardCharts(BaseModel):
    events_by_camera: ChartDataset
    status_distribution: ChartDataset
    events_by_hour: ChartDataset
    suspicious_by_location: ChartDataset
    recent_activity_trend: ChartDataset


# --- User & Auth Schemas ---
class UserLogin(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    role: str = "operator"  # admin, operator, viewer
    phone_number: Optional[str] = None


class UserResponse(BaseModel):
    user_id: int
    username: str
    full_name: str
    role: str
    phone_number: Optional[str] = None
    is_active: bool
    last_login: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# --- Live Detection Schemas ---
class DetectionROI(BaseModel):
    """A named region-of-interest for restricted zone detection."""
    name: str = Field(..., description="Human-readable zone name, e.g. 'Server Room Perimeter'")
    coordinates: List[List[float]] = Field(
        ...,
        description="Polygon vertices as [[x1,y1],[x2,y2],...] in normalized 0-1 or pixel coords",
    )


class LiveDetectionSettings(BaseModel):
    """Current live detection configuration."""
    sensitivity: float = Field(0.35, ge=0.0, le=1.0, description="Detection sensitivity (0=most sensitive, 1=least)")
    confidence_threshold: float = Field(0.60, ge=0.0, le=1.0)
    confirmation_seconds: float = Field(1.5, ge=0.0, le=10.0)
    recording_duration_seconds: float = Field(
        15.0, ge=10.0, le=20.0, description="Automatic video recording clip duration in seconds (10 to 20s, default 15s)"
    )
    roi_zones: List[DetectionROI] = Field(default_factory=list, description="Active restricted zones")
    enabled_categories: List[str] = Field(
        default_factory=lambda: [
            "intrusion", "loitering", "suspicious_package",
            "rapid_motion", "unauthorized_access", "group_gathering",
        ],
        description="Anomaly event categories to watch for",
    )
    motion_threshold: float = Field(0.05, ge=0.0, le=1.0)
    person_count_threshold: int = Field(3, ge=1)


class LiveDetectionSettingsUpdate(BaseModel):
    """Partial update payload for detection settings."""
    sensitivity: Optional[float] = Field(None, ge=0.0, le=1.0)
    confidence_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    confirmation_seconds: Optional[float] = Field(None, ge=0.0, le=10.0)
    recording_duration_seconds: Optional[float] = Field(None, ge=10.0, le=20.0)
    roi_zones: Optional[List[DetectionROI]] = None
    enabled_categories: Optional[List[str]] = None
    motion_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    person_count_threshold: Optional[int] = Field(None, ge=1)


class SuspiciousActivityAlert(BaseModel):
    """Payload pushed to admin clients when a suspicious event fires."""
    event_id: str
    session_id: Optional[str] = None
    camera_id: str
    timestamp: str
    anomaly_score: float
    status: str
    risk_priority: str
    activity_type: str
    triggered_categories: List[str] = []
    breached_zones: List[str] = []
    anomaly_reasons: Optional[str] = None
    thumbnail_url: Optional[str] = None
    sms_dispatched: bool = False


class LiveFrameAnalysisResponse(BaseModel):
    """Result of analysing a single video frame."""
    detected: bool
    status: str
    activity_type: str
    confidence: float
    risk_level: str
    risk_priority: str
    timestamp: str
    camera_id: str
    location: str
    person_count: int
    motion_score: float
    motion_level: str
    anomaly_score: float
    is_confirmed: bool = False
    triggered_categories: List[str] = []
    breached_zones: List[str] = []
    anomaly_reasons: Optional[str] = None
    boxes: List[List[Any]] = []
    normalized_boxes: List[List[float]] = []
    confidences: List[float] = []
    person_confidence: Optional[float] = None
    alert: Optional[SuspiciousActivityAlert] = None
