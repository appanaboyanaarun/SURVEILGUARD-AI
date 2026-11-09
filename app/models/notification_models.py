"""
Database models for the FCM notification system.

New tables added alongside existing Camera, Event, Review, User tables.
No existing tables are modified or dropped.
"""

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


class AdminDevice(Base):
    """Registered admin mobile devices for receiving FCM push notifications."""

    __tablename__ = "admin_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False, index=True)
    fcm_token = Column(String(500), nullable=False, unique=True)
    device_name = Column(String(100), nullable=True)
    platform = Column(String(50), default="android")  # android, ios, web
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    user = relationship("User", backref="devices")
    notification_logs = relationship(
        "NotificationLog", back_populates="device", cascade="all, delete-orphan"
    )


class Incident(Base):
    """
    Incident record created when suspicious activity is detected.
    Links to the underlying Event and tracks incident lifecycle + notification status.
    """

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(
        String(50), unique=True, nullable=False, index=True
    )  # e.g., INC-000001
    event_id = Column(
        String(50), ForeignKey("events.event_id"), nullable=False, index=True
    )
    camera_id = Column(
        String(50), ForeignKey("cameras.camera_id"), nullable=False, index=True
    )
    location = Column(String(150), nullable=True)
    activity_type = Column(String(100), nullable=True)
    confidence = Column(Float, default=0.0)  # anomaly_score (0.0 – 1.0)
    status = Column(String(50), default="NEW")  # NEW, ACKNOWLEDGED, RESOLVED
    notification_status = Column(
        String(50), default="PENDING"
    )  # PENDING, SENT, FAILED
    screenshot_path = Column(String(255), nullable=True)
    video_clip_path = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    # Relationships
    event = relationship("Event", backref="incidents")
    camera = relationship("Camera", backref="incidents")
    notification_logs = relationship(
        "NotificationLog", back_populates="incident", cascade="all, delete-orphan"
    )


class NotificationLog(Base):
    """Audit log for every notification delivery attempt."""

    __tablename__ = "notification_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(
        String(50), ForeignKey("incidents.incident_id"), nullable=False, index=True
    )
    admin_device_id = Column(
        Integer, ForeignKey("admin_devices.id"), nullable=True
    )
    notification_type = Column(
        String(50), default="SUSPICIOUS_ACTIVITY"
    )  # SUSPICIOUS_ACTIVITY, TEST
    status = Column(String(50), default="PENDING")  # PENDING, SENT, FAILED
    sent_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="notification_logs")
    device = relationship("AdminDevice", back_populates="notification_logs")


class EmailRecipient(Base):
    """Configured recipient email addresses for email incident dispatches.
    Allows authorized Admin users to add, edit, and remove recipients safely.
    Supports both 'admin' and 'friend' recipient categories.
    """

    __tablename__ = "email_recipients"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), default="Admin Recipient", nullable=False)
    email_address = Column(String(255), unique=True, index=True, nullable=False)
    recipient_type = Column(String(50), default="admin", nullable=False)  # admin, friend
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class EmailLog(Base):
    """Audit record for every email alert dispatched.
    Tracks Google Apps Script HTTP API acceptance status, errors, and retry attempts.
    """

    __tablename__ = "email_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(50), ForeignKey("incidents.incident_id"), nullable=True, index=True)
    recipient_email = Column(String(255), nullable=False)
    recipient_email_masked = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=False)
    provider = Column(String(50), default="apps_script")
    provider_message_id = Column(String(255), nullable=True, index=True)
    status = Column(String(50), default="QUEUED", index=True)  # QUEUED, SENDING, ACCEPTED, FAILED, DELIVERED, BOUNCED
    error_message = Column(Text, nullable=True)
    attempt_count = Column(Integer, default=0)
    is_test = Column(Boolean, default=False)
    sent_at = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    incident = relationship("Incident", backref="email_logs")
