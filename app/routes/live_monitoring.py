"""
API routes for Live Surveillance Monitoring, Detection Sessions, and Evidence Management.

Endpoints:
    POST  /api/v1/live/detect           — Submit a frame for genuine real-time anomaly detection.
    POST  /api/v1/live/session/start    — Start a live detection session with Admin association.
    POST  /api/v1/live/session/stop     — Stop an active detection session.
    GET   /api/v1/live/sessions         — List historical detection sessions.
    GET   /api/v1/live/sessions/{id}    — Get details of a detection session.
    POST  /api/v1/live/evidence/save    — Upload and store a recorded evidence video clip.
    GET   /api/v1/live/settings         — Retrieve detection parameters.
    POST  /api/v1/live/settings         — Update detection sensitivity & ROI zones.
    WS    /ws/live-detection            — WebSocket for live frame analysis & alert streaming.
"""

import asyncio
import json
import uuid
from typing import Optional, List

from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    UploadFile,
    File,
    Form,
    Depends,
    HTTPException,
    Request,
    status,
)
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.schema import User, DetectionSession, Event, EvidenceVideo
from app.schemas.dto import (
    LiveDetectionSettings,
    LiveDetectionSettingsUpdate,
    LiveFrameAnalysisResponse,
    DetectionSessionStart,
    DetectionSessionStop,
    DetectionSessionResponse,
    EvidenceVideoResponse,
)
from app.services.auth_service import get_current_user_optional, get_current_user
from app.services.live_detection_service import live_detection_service
from app.services.detection_session_service import detection_session_service
from app.services.storage_service import storage_service
from app.services.audit_service import AuditService

router = APIRouter(prefix="/v1/live", tags=["Live Monitoring & Detection"])


# ---------------------------------------------------------------
# Frame Detection REST Endpoint
# ---------------------------------------------------------------

@router.post("/detect", response_model=LiveFrameAnalysisResponse)
async def detect_frame(
    request: Request,
    frame: UploadFile = File(..., description="Image frame (JPEG/PNG) from camera feed"),
    camera_id: str = Form("CAM-01"),
    location: str = Form("Live Station"),
    session_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Accepts a single live video frame from the browser or camera feed,
    executes genuine OpenCV person detection + ML anomaly scoring,
    and returns detection diagnostics, bounding boxes, and alert payloads.
    """
    raw_bytes = await frame.read()
    result = live_detection_service.analyse_frame(
        frame_bytes=raw_bytes,
        camera_id=camera_id,
        location=location,
        session_id=session_id,
        admin_user=current_user,
    )

    # If alert was confirmed, broadcast to WebSocket clients
    if result.get("alert"):
        await _broadcast_alert(result["alert"])

    return result


# ---------------------------------------------------------------
# Detection Session Lifecycle Endpoints
# ---------------------------------------------------------------

@router.post("/session/start", response_model=DetectionSessionResponse)
def start_detection_session(
    payload: DetectionSessionStart,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Starts a new live detection session. Associates Admin identity,
    camera ID, and starts session timer for auditing.
    """
    ip = request.client.host if request.client else None
    ua = payload.device_info or request.headers.get("user-agent")

    session = detection_session_service.start_session(
        db=db,
        camera_id=payload.camera_id,
        user=current_user,
        device_info=ua,
        ip_address=ip,
    )
    return DetectionSessionResponse.model_validate(session)


@router.post("/session/stop", response_model=DetectionSessionResponse)
def stop_detection_session(
    payload: DetectionSessionStop,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Stops an active detection session and updates final metrics.
    """
    ip = request.client.host if request.client else None
    session = detection_session_service.stop_session(
        db=db,
        session_id=payload.session_id,
        user=current_user,
        ip_address=ip,
    )
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{payload.session_id}' not found.")
    return DetectionSessionResponse.model_validate(session)


@router.get("/sessions", response_model=List[DetectionSessionResponse])
def list_detection_sessions(
    skip: int = 0,
    limit: int = 50,
    camera_id: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    """Lists detection sessions with optional filtering."""
    sessions = detection_session_service.list_sessions(
        db=db, skip=skip, limit=limit, camera_id=camera_id, is_active=is_active
    )
    return [DetectionSessionResponse.model_validate(s) for s in sessions]


@router.get("/sessions/{session_id}", response_model=DetectionSessionResponse)
def get_detection_session(session_id: str, db: Session = Depends(get_db)):
    """Retrieves full details of a specific detection session."""
    session = detection_session_service.get_session(db=db, session_id=session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return DetectionSessionResponse.model_validate(session)


# ---------------------------------------------------------------
# Evidence Video Recording Endpoint
# ---------------------------------------------------------------

@router.post("/evidence/save", response_model=EvidenceVideoResponse)
async def save_evidence_clip(
    request: Request,
    video_file: UploadFile = File(...),
    event_id: Optional[str] = Form(None),
    session_id: Optional[str] = Form(None),
    duration_seconds: float = Form(8.0),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Saves a short evidence video clip captured by the browser MediaRecorder
    when suspicious activity is detected. Stores the clip securely and links
    it with the Event and Detection Session.
    """
    video_bytes = await video_file.read()
    orig_name = video_file.filename or f"evidence_{event_id or uuid.uuid4().hex[:6]}.webm"
    mime = video_file.content_type or "video/webm"

    try:
        saved_meta = storage_service.save_evidence_video(
            video_bytes=video_bytes,
            filename=orig_name,
            mime_type=mime,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    video_id = f"VID-{uuid.uuid4().hex[:6].upper()}"
    evidence = EvidenceVideo(
        video_id=video_id,
        event_id=event_id,
        session_id=session_id,
        filename=saved_meta["filename"],
        storage_provider=saved_meta["storage_provider"],
        storage_path=saved_meta["storage_path"],
        file_size=saved_meta["file_size"],
        duration_seconds=duration_seconds,
        mime_type=mime,
        is_secure=True,
    )
    db.add(evidence)

    # Link to event if provided
    if event_id:
        event = db.query(Event).filter(Event.event_id == event_id).first()
        if event:
            event.evidence_video_id = video_id
            event.video_filename = saved_meta["filename"]

    db.commit()
    db.refresh(evidence)

    # Generate secure signed playback URL
    secure_url = storage_service.generate_secure_video_url(
        video_id=video_id,
        user_id=current_user.user_id if current_user else None,
    )

    resp = EvidenceVideoResponse.model_validate(evidence)
    resp.secure_url = secure_url
    return resp


# ---------------------------------------------------------------
# Detection Settings
# ---------------------------------------------------------------

@router.get("/settings", response_model=LiveDetectionSettings)
def get_detection_settings():
    """Return the current live detection configuration."""
    return live_detection_service.get_settings()


@router.post("/settings", response_model=LiveDetectionSettings)
def update_detection_settings(payload: LiveDetectionSettingsUpdate):
    """Update live detection parameters (sensitivity, ROI zones, categories)."""
    updated = live_detection_service.update_settings(payload.model_dump(exclude_unset=True))
    return updated


# ---------------------------------------------------------------
# WebSocket Alert Streaming Endpoint
# ---------------------------------------------------------------

async def live_detection_ws(websocket: WebSocket):
    """
    WebSocket endpoint at /ws/live-detection.
    - Streams live detection alerts in real-time.
    - Accepts inline frame analysis messages: { "frame_b64": "...", "camera_id": "CAM-01" }
    """
    await websocket.accept()
    live_detection_service.ws_clients.append(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON payload"})
                continue

            if "frame_b64" in msg:
                result = live_detection_service.analyse_frame(
                    frame_b64=msg["frame_b64"],
                    camera_id=msg.get("camera_id", "CAM-WS"),
                    location=msg.get("location", "Live Stream"),
                    session_id=msg.get("session_id"),
                )
                await websocket.send_json(result)

                if result.get("alert"):
                    await _broadcast_alert(result["alert"], exclude=websocket)
            elif msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            else:
                await websocket.send_json({"error": "Unknown message type"})

    except WebSocketDisconnect:
        pass
    finally:
        if websocket in live_detection_service.ws_clients:
            live_detection_service.ws_clients.remove(websocket)


async def _broadcast_alert(alert: dict, exclude: Optional[WebSocket] = None):
    """Push an alert to all connected WebSocket clients."""
    payload = json.dumps({"type": "alert", "data": alert}, default=str)
    disconnected = []
    for ws in live_detection_service.ws_clients:
        if ws is exclude:
            continue
        try:
            await ws.send_text(payload)
        except Exception:
            disconnected.append(ws)

    for ws in disconnected:
        if ws in live_detection_service.ws_clients:
            live_detection_service.ws_clients.remove(ws)
