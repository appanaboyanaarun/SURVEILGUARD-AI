import os
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.database.connection import get_db, DATA_DIR
from app.models.schema import Event
from app.routes.videos import detector
from ml.sample_training_data import generate_baseline_normal_events

router = APIRouter(prefix="/ml", tags=["Machine Learning Operations"])


@router.get("/status")
def get_model_status():
    return {
        "algorithm": detector.algorithm,
        "is_fitted": detector.is_fitted,
        "contamination": detector.contamination,
        "model_file_exists": os.path.exists(detector.model_path),
    }


@router.post("/retrain")
def retrain_model(algorithm: str = "isolation_forest", contamination: float = 0.08, db: Session = Depends(get_db)):
    """Retrains the anomaly detection model using existing historical normal events and baseline data."""
    if algorithm not in ["isolation_forest", "one_class_svm"]:
        raise HTTPException(status_code=400, detail="Unsupported algorithm. Use 'isolation_forest' or 'one_class_svm'.")

    # Gather normal events from database
    db_events = db.query(Event).filter(Event.status == "NORMAL").all()
    events_data = []
    for e in db_events:
        events_data.append({
            "camera_id": e.camera_id,
            "timestamp": e.timestamp,
            "location": e.location,
            "person_count": e.person_count,
            "motion_level": e.motion_level,
            "activity_type": e.activity_type,
            "event_duration": e.event_duration,
            "restricted_area": e.restricted_area,
        })

    # Supplement with baseline generator
    baseline = generate_baseline_normal_events(500)
    combined = events_data + baseline

    detector.algorithm = algorithm
    detector.contamination = contamination
    detector.train(combined)

    return {
        "message": f"Successfully retrained anomaly detection model with {len(combined)} training samples.",
        "algorithm": algorithm,
        "total_samples": len(combined),
    }
