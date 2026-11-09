"""
Audit Logging Service.
Provides tamper-resistant logging of critical security operations.
"""

import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.schema import AuditLog


class AuditService:
    @staticmethod
    def log(
        db: Session,
        action: str,
        actor_name: str = "System",
        actor_id: Optional[int] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        """
        Records a security-sensitive event in the immutable audit log table.
        """
        try:
            entry = AuditLog(
                actor_id=actor_id,
                actor_name=actor_name,
                action=action,
                entity_type=entity_type,
                entity_id=str(entity_id) if entity_id is not None else None,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=datetime.datetime.utcnow(),
            )
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return entry
        except Exception:
            db.rollback()
            return None

    @staticmethod
    def get_logs(
        db: Session,
        skip: int = 0,
        limit: int = 100,
        action: Optional[str] = None,
        actor_name: Optional[str] = None,
        entity_type: Optional[str] = None,
    ) -> List[AuditLog]:
        q = db.query(AuditLog)
        if action:
            q = q.filter(AuditLog.action.ilike(f"%{action}%"))
        if actor_name:
            q = q.filter(AuditLog.actor_name.ilike(f"%{actor_name}%"))
        if entity_type:
            q = q.filter(AuditLog.entity_type == entity_type)
        return q.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()
