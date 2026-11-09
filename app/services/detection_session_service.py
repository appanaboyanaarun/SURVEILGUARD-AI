"""
Detection Session Management Service.
Manages Admin/Operator live detection sessions, session lifecycle,
and associates all generated events, evidence clips, and audits with the monitoring admin.
"""

import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.models.schema import DetectionSession, Camera, User, Event
from app.services.audit_service import AuditService


class DetectionSessionService:
    @staticmethod
    def generate_session_id(db: Session) -> str:
        """Generates sequential ID like SES-0001."""
        count = db.query(func.count(DetectionSession.session_id)).scalar() or 0
        return f"SES-{(count + 1):04d}"

    @staticmethod
    def start_session(
        db: Session,
        camera_id: str,
        user: Optional[User] = None,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> DetectionSession:
        """
        Creates and starts a new live detection session.
        """
        camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
        location = camera.location if camera else "Live Monitoring Station"
        admin_name = user.full_name if user else "Admin"
        user_id = user.user_id if user else None

        # Deactivate any previous active sessions for this camera & user
        active_previous = (
            db.query(DetectionSession)
            .filter(
                DetectionSession.camera_id == camera_id,
                DetectionSession.is_active == True,
            )
            .all()
        )
        for s in active_previous:
            s.is_active = False
            s.end_time = datetime.datetime.utcnow()

        session_id = DetectionSessionService.generate_session_id(db)
        session = DetectionSession(
            session_id=session_id,
            user_id=user_id,
            admin_name=admin_name,
            camera_id=camera_id,
            location=location,
            start_time=datetime.datetime.utcnow(),
            device_info=device_info,
            detection_result="NORMAL",
            suspicious_event_count=0,
            is_active=True,
            created_at=datetime.datetime.utcnow(),
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        # Audit log
        AuditService.log(
            db=db,
            action="DETECTION_START",
            actor_name=admin_name,
            actor_id=user_id,
            entity_type="session",
            entity_id=session_id,
            details=f"Live detection started on camera '{camera_id}' ({location})",
            ip_address=ip_address,
            user_agent=device_info,
        )

        return session

    @staticmethod
    def stop_session(
        db: Session,
        session_id: str,
        user: Optional[User] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[DetectionSession]:
        """
        Stops an active detection session and updates final statistics.
        """
        session = db.query(DetectionSession).filter(DetectionSession.session_id == session_id).first()
        if not session:
            return None

        session.is_active = False
        session.end_time = datetime.datetime.utcnow()
        db.commit()
        db.refresh(session)

        actor_name = user.full_name if user else session.admin_name
        actor_id = user.user_id if user else session.user_id

        # Audit log
        AuditService.log(
            db=db,
            action="DETECTION_STOP",
            actor_name=actor_name,
            actor_id=actor_id,
            entity_type="session",
            entity_id=session_id,
            details=f"Live detection stopped on session '{session_id}'. Result: {session.detection_result}, Suspicious Events: {session.suspicious_event_count}",
            ip_address=ip_address,
        )

        return session

    @staticmethod
    def get_session(db: Session, session_id: str) -> Optional[DetectionSession]:
        return db.query(DetectionSession).filter(DetectionSession.session_id == session_id).first()

    @staticmethod
    def list_sessions(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        camera_id: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[DetectionSession]:
        q = db.query(DetectionSession)
        if camera_id:
            q = q.filter(DetectionSession.camera_id == camera_id)
        if is_active is not None:
            q = q.filter(DetectionSession.is_active == is_active)
        return q.order_by(desc(DetectionSession.start_time)).offset(skip).limit(limit).all()

    @staticmethod
    def record_suspicious_event(db: Session, session_id: str, event_id: str):
        """
        Links a suspicious event to the active session and increments suspicious count.
        """
        session = db.query(DetectionSession).filter(DetectionSession.session_id == session_id).first()
        if session:
            session.suspicious_event_count += 1
            session.detection_result = "SUSPICIOUS"
            db.commit()


detection_session_service = DetectionSessionService()
