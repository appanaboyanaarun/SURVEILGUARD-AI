import datetime
from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.schema import Review, Event
from app.schemas.dto import ReviewCreate


class ReviewService:
    @staticmethod
    def create_review(db: Session, review_data: ReviewCreate) -> Review:
        # Check event exists
        event = db.query(Event).filter(Event.event_id == review_data.event_id).first()
        if not event:
            raise ValueError(f"Event '{review_data.event_id}' does not exist.")

        # Create review entry
        review = Review(
            event_id=review_data.event_id,
            review_status=review_data.review_status,
            annotation=review_data.annotation or "",
            reviewed_by=review_data.reviewed_by or "Security Operator",
            reviewed_at=datetime.datetime.utcnow(),
        )
        db.add(review)

        # If confirmed as FALSE_ALARM, optionally update event display status or leave audit history
        # (Preserving original ML output while attaching review)
        db.commit()
        db.refresh(review)
        return review

    @staticmethod
    def get_by_event(db: Session, event_id: str) -> List[Review]:
        return db.query(Review).filter(Review.event_id == event_id).order_by(Review.reviewed_at.desc()).all()
