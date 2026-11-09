from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database.connection import get_db
from app.schemas.dto import EventResponse, EventCreate
from app.services.event_service import EventService

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=List[EventResponse])
def list_events(
    skip: int = 0,
    limit: int = 100,
    camera_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    risk_priority: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    return EventService.get_events(
        db,
        skip=skip,
        limit=limit,
        camera_id=camera_id,
        status=status,
        risk_priority=risk_priority,
        search=search,
    )


@router.get("/{event_id}", response_model=EventResponse)
def get_event(event_id: str, db: Session = Depends(get_db)):
    event = EventService.get_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")
    return event


@router.post("", response_model=EventResponse)
def create_manual_event(event_data: EventCreate, db: Session = Depends(get_db)):
    """API to register an event record directly (used in automated simulations/benchmarking)."""
    return EventService.create_event(db, event_data)
