import os
import shutil
import uuid
import datetime
import mimetypes
from typing import Optional, Dict, Any, List

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Query,
    Request,
    status,
)
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.database.connection import get_db, DATA_DIR
from app.models.schema import Camera, Event, EvidenceVideo, User
from app.schemas.dto import EventResponse, EventCreate, EvidenceVideoResponse
from app.services.event_service import EventService
from app.services.auth_service import get_current_user_optional, verify_signed_video_token, create_signed_video_token
from app.services.storage_service import storage_service, ALLOWED_VIDEO_EXTENSIONS, MAX_VIDEO_FILE_SIZE
from app.services.audit_service import AuditService
from app.services.email_service import email_service
from video_processing.event_generator import VideoProcessingPipeline
from ml.anomaly_detection import AnomalyDetector
from ml.prediction import evaluate_event_anomaly

router = APIRouter(prefix="/videos", tags=["Video Ingestion & Storage"])

THUMBNAILS_DIR = os.path.join(DATA_DIR, "thumbnails")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
MODELS_DIR = os.path.join(DATA_DIR, "models")

pipeline = VideoProcessingPipeline(thumbnails_dir=THUMBNAILS_DIR)
detector = AnomalyDetector(model_dir=MODELS_DIR)


@router.post("/upload-and-process", response_model=EventResponse)
async def upload_and_process_video(
    request: Request,
    camera_id: str = Form(...),
    video_file: Optional[UploadFile] = File(None),
    sample_video_name: Optional[str] = Form(None),
    custom_timestamp: Optional[str] = Form(None),
    session_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Automated Video Ingestion Pipeline:
    1. Validates and saves video file with security checks
    2. Runs computer-vision person detection and tracking
    3. Extracts metadata (person count, duration, restricted entry, motion)
    4. Evaluates metadata with ML Anomaly Detector
    5. Stores event in DB with admin and session association.
    """
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail=f"Camera '{camera_id}' is not configured.")

    target_video_path = None
    original_filename = ""

    if video_file and (video_file.filename or video_file.size or video_file.file):
        raw_name = video_file.filename or f"upload_{camera_id}.mp4"
        file_ext = os.path.splitext(raw_name)[1].lower()
        if not file_ext or file_ext not in ALLOWED_VIDEO_EXTENSIONS:
            if video_file.content_type and "webm" in video_file.content_type:
                file_ext = ".webm"
            elif video_file.content_type and "quicktime" in video_file.content_type:
                file_ext = ".mov"
            else:
                file_ext = ".mp4"

        # Safe server-side randomized filename
        saved_filename = f"{camera_id}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}{file_ext}"
        target_video_path = os.path.join(UPLOADS_DIR, saved_filename)
        original_filename = os.path.basename(target_video_path)

        with open(target_video_path, "wb") as buffer:
            shutil.copyfileobj(video_file.file, buffer)
    elif sample_video_name:
        # Sanitize sample video name
        clean_sample = os.path.basename(sample_video_name)
        sample_path = os.path.join(DATA_DIR, "sample_videos", clean_sample)
        if not os.path.exists(sample_path):
            raise HTTPException(status_code=404, detail=f"Sample video '{sample_video_name}' not found.")
        target_video_path = sample_path
        original_filename = clean_sample
    else:
        raise HTTPException(status_code=400, detail="Either 'video_file' or 'sample_video_name' must be provided.")

    parsed_time = None
    if custom_timestamp:
        try:
            parsed_time = datetime.datetime.fromisoformat(custom_timestamp.replace("Z", "+00:00"))
        except Exception:
            parsed_time = datetime.datetime.utcnow()

    # Step 1: Automatic Video Processing & Metadata Extraction
    try:
        extracted_meta = pipeline.process_video(
            video_path=target_video_path,
            camera_id=camera.camera_id,
            camera_location=camera.location,
            restricted_zone_coords=camera.restricted_zone_coords,
            custom_timestamp=parsed_time,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Video processing failed: {str(e)}")

    # Step 2: ML Anomaly Evaluation
    ml_eval = evaluate_event_anomaly(extracted_meta, detector=detector)

    # Step 3: Persist Event to Database
    admin_name = current_user.full_name if current_user else "Admin"
    admin_id = current_user.user_id if current_user else None

    event_create_data = EventCreate(
        camera_id=extracted_meta["camera_id"],
        session_id=session_id,
        admin_id=admin_id,
        admin_name=admin_name,
        timestamp=extracted_meta["timestamp"],
        location=extracted_meta["location"],
        person_count=extracted_meta["person_count"],
        object_type=extracted_meta["object_type"],
        motion_level=extracted_meta["motion_level"],
        activity_type=extracted_meta["activity_type"],
        event_duration=extracted_meta["event_duration"],
        event_duration_formatted=extracted_meta["event_duration_formatted"],
        restricted_area=extracted_meta["restricted_area"],
        anomaly_score=ml_eval["anomaly_score"],
        status=ml_eval["status"],
        risk_priority=ml_eval["risk_priority"],
        anomaly_reasons=ml_eval["anomaly_reasons"],
        video_filename=original_filename,
        thumbnail_path=extracted_meta.get("thumbnail_path"),
    )

    created_event = EventService.create_event(db, event_create_data)

    # Dispatch SMS notification to Admin if suspicious activity detected
    if created_event.status == "SUSPICIOUS" or created_event.risk_priority in ["HIGH", "CRITICAL"]:
        try:
            email_service.dispatch_suspicious_event_email(
                event_id=created_event.event_id,
                camera_id=camera_id,
            )
        except Exception as _email_err:
            pass  # Email failure must not disrupt video response

    # Security Audit Log
    AuditService.log(
        db=db,
        action="VIDEO_PROCESSED",
        actor_name=admin_name,
        actor_id=admin_id,
        entity_type="event",
        entity_id=created_event.event_id,
        details=f"Processed video on {camera_id}. Result: {created_event.status} ({created_event.activity_type})",
    )

    return created_event


@router.get("/secure-stream/{video_id}")
def stream_secure_video(
    video_id: str,
    token: Optional[str] = Query(None, description="Signed playback JWT token"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Secure video streaming endpoint with time-bounded signed token validation.
    Protects surveillance evidence footage from unauthorized public access.
    """
    # 1. Validate Access: Check signed token OR authenticated user session
    has_valid_token = token and verify_signed_video_token(token, video_id)
    has_valid_user = current_user is not None

    if not has_valid_token and not has_valid_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Valid signed token or active Admin session required.",
        )

    # 2. Look up Video in EvidenceVideos or Events
    evidence = db.query(EvidenceVideo).filter(EvidenceVideo.video_id == video_id).first()
    abs_path = None
    mime_type = "video/mp4"

    if evidence:
        abs_path = storage_service.get_video_file_path(evidence.storage_path)
        mime_type = evidence.mime_type
    else:
        # Fallback: check if video_id matches an event_id or filename
        event = db.query(Event).filter(
            (Event.event_id == video_id) | (Event.evidence_video_id == video_id)
        ).first()
        if event and event.video_filename:
            # Check uploads, sample_videos, or evidence
            for sub in ["evidence", "uploads", "sample_videos"]:
                candidate = os.path.join(DATA_DIR, sub, event.video_filename)
                if os.path.exists(candidate):
                    abs_path = candidate
                    break

    if not abs_path or not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail="Video media file not found.")

    guessed_mime, _ = mimetypes.guess_type(abs_path)
    return FileResponse(abs_path, media_type=guessed_mime or mime_type)


@router.get("/{video_id}/secure-url")
def get_secure_video_url(
    video_id: str,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """
    Generates a time-bounded signed URL for playing the evidence video.
    Verifies that the underlying video file actually exists on storage before returning the URL.
    """
    # Check if video exists in EvidenceVideo
    evidence = db.query(EvidenceVideo).filter(EvidenceVideo.video_id == video_id).first()
    abs_path = None

    if evidence:
        abs_path = storage_service.get_video_file_path(evidence.storage_path)
    else:
        # Check by event_id or evidence_video_id
        event = db.query(Event).filter(
            (Event.event_id == video_id) | (Event.evidence_video_id == video_id)
        ).first()
        if event and event.evidence_video_id and event.evidence_video_id != video_id:
            ev_rec = db.query(EvidenceVideo).filter(EvidenceVideo.video_id == event.evidence_video_id).first()
            if ev_rec:
                abs_path = storage_service.get_video_file_path(ev_rec.storage_path)
        if not abs_path and event and event.video_filename:
            for sub in ["evidence", "uploads", "sample_videos"]:
                candidate = os.path.join(DATA_DIR, sub, event.video_filename)
                if os.path.exists(candidate):
                    abs_path = candidate
                    break

    has_file = abs_path is not None and os.path.exists(abs_path)
    if not has_file:
        return {
            "video_id": video_id,
            "available": False,
            "secure_url": None,
            "message": "Evidence video file is not yet uploaded or unavailable.",
        }

    user_id = current_user.user_id if current_user else None
    url = storage_service.generate_secure_video_url(video_id=video_id, user_id=user_id)
    return {
        "video_id": video_id,
        "available": True,
        "secure_url": url,
    }
