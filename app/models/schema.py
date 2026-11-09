import datetime
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from app.database.connection import Base


class Camera(Base):
    __tablename__ = "cameras"

    camera_id = Column(String(50), primary_key=True, index=True)  # e.g., CAM-01
    name = Column(String(100), nullable=False)
    location = Column(String(150), nullable=False)
    description = Column(String(255), nullable=True)
    camera_type = Column(String(50), default="CCTV")
    stream_url = Column(String(255), nullable=True)
    status = Column(String(50), default="OFFLINE")
    # Coordinates for restricted zone (JSON string e.g. [[x1, y1], [x2, y2], ...] or [x, y, w, h])
    restricted_zone_coords = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    events = relationship("Event", back_populates="camera", cascade="all, delete-orphan")
    detection_sessions = relationship("DetectionSession", back_populates="camera", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(50), default="operator")  # admin, operator, viewer
    phone_number = Column(String(50), nullable=True)
    email_address = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    detection_sessions = relationship("DetectionSession", back_populates="user")


class DetectionSession(Base):
    """
    Tracks every live detection session initiated by an Admin or Operator.
    Associates the monitoring admin with the camera, timeframe, and generated events.
    """
    __tablename__ = "detection_sessions"

    session_id = Column(String(50), primary_key=True, index=True)  # e.g. SES-0001
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=True, index=True)
    admin_name = Column(String(100), nullable=False, default="Admin")
    camera_id = Column(String(50), ForeignKey("cameras.camera_id"), nullable=False, index=True)
    location = Column(String(150), nullable=False)
    start_time = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    device_info = Column(Text, nullable=True)  # Browser user-agent / mobile device info
    detection_result = Column(String(50), default="NORMAL")  # NORMAL, SUSPICIOUS
    suspicious_event_count = Column(Integer, default=0)
    recording_references = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    camera = relationship("Camera", back_populates="detection_sessions")
    user = relationship("User", back_populates="detection_sessions")
    events = relationship("Event", back_populates="session")
    evidence_videos = relationship("EvidenceVideo", back_populates="session")


class Event(Base):
    __tablename__ = "events"

    event_id = Column(String(50), primary_key=True, index=True)  # e.g., EVT-0001
    camera_id = Column(String(50), ForeignKey("cameras.camera_id"), nullable=False, index=True)
    session_id = Column(String(50), ForeignKey("detection_sessions.session_id"), nullable=True, index=True)
    admin_id = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    admin_name = Column(String(100), nullable=True, default="Admin")

    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow, index=True)
    location = Column(String(150), nullable=False)
    person_count = Column(Integer, default=1)
    object_type = Column(String(50), default="person")
    motion_level = Column(String(50), default="Medium")  # Low, Medium, High
    activity_type = Column(String(100), default="Normal Movement")  # Normal Movement, Person Entry, Loitering, Restricted Intrusion
    event_duration = Column(Integer, default=0)  # In seconds
    event_duration_formatted = Column(String(50), default="00:00")  # e.g. "04:37"
    restricted_area = Column(Integer, default=0)  # 0: NO, 1: YES

    # Anomaly / Risk scoring
    anomaly_score = Column(Float, default=0.0)  # Normalized 0.0 - 1.0 (higher = more anomalous)
    status = Column(String(50), default="NORMAL")  # NORMAL or SUSPICIOUS
    risk_priority = Column(String(50), default="LOW")  # LOW, MEDIUM, HIGH
    anomaly_reasons = Column(Text, nullable=True)  # Explanation of reasons

    # Media & Storage references
    video_filename = Column(String(255), nullable=True)
    thumbnail_path = Column(String(255), nullable=True)
    evidence_video_id = Column(String(50), nullable=True)

    # SMS notification tracking
    sms_status = Column(String(50), default="NONE")  # NONE, SENT, FAILED, PENDING
    sms_sent_at = Column(DateTime, nullable=True)
    sms_phone = Column(String(50), nullable=True)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    camera = relationship("Camera", back_populates="events")
    session = relationship("DetectionSession", back_populates="events")
    reviews = relationship("Review", back_populates="event", cascade="all, delete-orphan")
    evidence_videos = relationship("EvidenceVideo", back_populates="event", cascade="all, delete-orphan")
    sms_logs = relationship("SMSLog", back_populates="event", cascade="all, delete-orphan")

    @property
    def source(self) -> str:
        if self.camera_id and "MOBILE" in str(self.camera_id).upper():
            return "Mobile Camera"
        if self.camera and getattr(self.camera, "camera_type", None) and str(self.camera.camera_type).upper() == "MOBILE":
            return "Mobile Camera"
        return "CCTV Camera"


class EvidenceVideo(Base):
    """
    Secure evidence recording metadata.
    Supports local storage and cloud/object storage with signed URL access.
    """
    __tablename__ = "evidence_videos"

    video_id = Column(String(50), primary_key=True, index=True)  # e.g. VID-0001
    event_id = Column(String(50), ForeignKey("events.event_id"), nullable=True, index=True)
    session_id = Column(String(50), ForeignKey("detection_sessions.session_id"), nullable=True, index=True)
    filename = Column(String(255), nullable=False)
    storage_provider = Column(String(50), default="local")  # local, s3
    storage_path = Column(String(500), nullable=False)
    file_size = Column(Integer, default=0)  # in bytes
    duration_seconds = Column(Float, default=0.0)
    mime_type = Column(String(50), default="video/mp4")
    thumbnail_path = Column(String(255), nullable=True)
    is_secure = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    event = relationship("Event", back_populates="evidence_videos")
    session = relationship("DetectionSession", back_populates="evidence_videos")


class Review(Base):
    __tablename__ = "reviews"

    review_id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(50), ForeignKey("events.event_id"), nullable=False, index=True)
    review_status = Column(String(50), nullable=False)  # CONFIRMED_SUSPICIOUS, FALSE_ALARM, UNDER_REVIEW
    annotation = Column(Text, nullable=True)
    reviewed_by = Column(String(100), default="Security Operator")
    reviewed_at = Column(DateTime, default=datetime.datetime.utcnow)

    event = relationship("Event", back_populates="reviews")


class AuditLog(Base):
    """
    Immutable audit ledger for security compliance.
    Records every security-relevant operator / admin activity.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor_id = Column(Integer, nullable=True)
    actor_name = Column(String(100), default="System")
    action = Column(String(100), nullable=False, index=True)  # LOGIN, LOGOUT, DETECTION_START, etc.
    entity_type = Column(String(50), nullable=True)  # user, session, camera, event, video, report
    entity_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)


class SMSLog(Base):
    """
    Audit record for every SMS alert dispatched.
    Tracks provider response, message IDs, and delivery status.
    """
    __tablename__ = "sms_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(50), ForeignKey("events.event_id"), nullable=True, index=True)
    recipient_phone = Column(String(50), nullable=False)
    provider = Column(String(50), default="mock")
    provider_message_id = Column(String(255), nullable=True)  # Twilio SID, Vonage ID, etc.
    message_body = Column(Text, nullable=False)
    video_link = Column(String(500), nullable=True)
    status = Column(String(50), default="PENDING")  # NOT_CONFIGURED, QUEUED, SENT, DELIVERED, FAILED
    delivery_status = Column(String(50), nullable=True)  # Provider delivery status
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    is_test = Column(Boolean, default=False)  # True for test SMS dispatches
    sent_at = Column(DateTime, nullable=True)
    provider_accepted_at = Column(DateTime, nullable=True)  # When provider accepted the message
    delivered_at = Column(DateTime, nullable=True)  # When delivery was confirmed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    event = relationship("Event", back_populates="sms_logs")


class NotificationRecipient(Base):
    """
    Configured recipient phone numbers for SMS incident dispatches.
    Allows authorized Admin users to add, edit, and remove recipients safely.
    """
    __tablename__ = "notification_recipients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), default="Admin Recipient", nullable=False)
    phone_number = Column(String(50), unique=True, index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
