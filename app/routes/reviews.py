from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database.connection import get_db
from app.schemas.dto import ReviewCreate, ReviewResponse
from app.services.review_service import ReviewService

router = APIRouter(prefix="/reviews", tags=["Human Review"])


@router.post("", response_model=ReviewResponse, status_code=status.HTTP_201_CREATED)
def submit_review(review_data: ReviewCreate, db: Session = Depends(get_db)):
    """Submits human verification (Confirmed Suspicious / False Alarm / Under Review) with annotations."""
    try:
        return ReviewService.create_review(db, review_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/event/{event_id}", response_model=List[ReviewResponse])
def get_event_reviews(event_id: str, db: Session = Depends(get_db)):
    return ReviewService.get_by_event(db, event_id)
