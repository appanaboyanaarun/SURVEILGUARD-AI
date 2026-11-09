from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from app.database.connection import get_db
from app.schemas.dto import EventResponse
from app.services.event_service import EventService

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get("", response_model=List[EventResponse])
def get_active_alerts(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    """Fetches high-risk and suspicious events requiring human security operator review."""
    return EventService.get_alerts(db, skip=skip, limit=limit)
