from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.dto import DashboardSummary, DashboardCharts
from app.services.event_service import EventService

router = APIRouter(prefix="/analytics", tags=["Dashboard & Analytics"])


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    return EventService.get_summary(db)


@router.get("/charts", response_model=DashboardCharts)
def get_dashboard_charts(db: Session = Depends(get_db)):
    return EventService.get_charts(db)
