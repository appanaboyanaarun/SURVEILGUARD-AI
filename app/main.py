import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.config import settings
from app.database.connection import Base, engine, SessionLocal, DATA_DIR, BASE_DIR
from app.models.schema import (
    Camera,
    User,
    DetectionSession,
    Event,
    EvidenceVideo,
    AuditLog,
    SMSLog,
    Review,
)
from app.models.notification_models import AdminDevice, Incident, NotificationLog
from app.services.auth_service import hash_password
from app.services.stream_manager import stream_manager
from app.routes import (
    auth_router,
    cameras_router,
    videos_router,
    events_router,
    alerts_router,
    reviews_router,
    analytics_router,
    live_monitoring_router,
    live_detection_ws,
    incidents_router,
    reports_router,
    email_router,
)

# Initialize database schema tables & run incremental migrations
Base.metadata.create_all(bind=engine)
from app.database.connection import run_migrations
run_migrations()

app = FastAPI(
    title="ArgusEye - Real-Time Suspicious Activity Detection & Monitoring System",
    description="Enterprise-grade browser-based real-time surveillance anomaly detection, email alert dispatch, and Admin monitoring platform.",
    version="3.0.0",
)

# CORS configuration — driven by CORS_ORIGINS env var
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(auth_router, prefix="/api")
app.include_router(cameras_router, prefix="/api")
app.include_router(videos_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(reviews_router, prefix="/api")
app.include_router(analytics_router, prefix="/api")
app.include_router(live_monitoring_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(email_router, prefix="/api")

# WebSocket endpoint for real-time live detection streaming
app.websocket("/ws/live-detection")(live_detection_ws)

# Static files mounts
EVIDENCE_DIR = os.path.join(DATA_DIR, "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

app.mount("/thumbnails", StaticFiles(directory=os.path.join(DATA_DIR, "thumbnails")), name="thumbnails")
app.mount("/uploads", StaticFiles(directory=os.path.join(DATA_DIR, "uploads")), name="uploads")
app.mount("/sample_videos", StaticFiles(directory=os.path.join(DATA_DIR, "sample_videos")), name="sample_videos")
# Evidence videos are strictly served via authenticated / signed-token streaming at /api/videos/secure-stream/{id}

FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")
    assets_dir = os.path.join(FRONTEND_DIR, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/favicon.ico", include_in_schema=False)
def serve_favicon():
    favicon_path = os.path.join(FRONTEND_DIR, "favicon.ico")
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path)
    return FileResponse(os.path.join(FRONTEND_DIR, "assets", "saj-logo.jpg"))


@app.get("/")
def serve_frontend_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "ArgusEye AI Security Monitoring API is running. Visit /docs for Swagger UI."}


def seed_initial_defaults():
    """Seeds default cameras and admin user on first run if database is fresh."""
    db = SessionLocal()
    try:
        # Check users
        if db.query(User).count() == 0:
            admin_user = User(
                username="admin",
                password_hash=hash_password("admin123"),
                full_name="System Administrator",
                role="admin",
                phone_number=settings.ADMIN_PHONE_NUMBER,
                is_active=True,
            )
            op_user = User(
                username="operator",
                password_hash=hash_password("operator123"),
                full_name="Duty Security Operator",
                role="operator",
                phone_number="+1987654321",
                is_active=True,
            )
            db.add_all([admin_user, op_user])
            db.commit()

        # Check default cameras
        if db.query(Camera).count() == 0:
            cams = [
                Camera(
                    camera_id="CAM-01",
                    name="Main Gate Camera",
                    location="Main Entrance Gate",
                    description="Monitors primary facility entrance and turnstiles",
                    camera_type="CCTV",
                    restricted_zone_coords="[[0.6, 0.2], [0.95, 0.2], [0.95, 0.85], [0.6, 0.85]]",
                    is_active=True,
                ),
                Camera(
                    camera_id="CAM-02",
                    name="Parking Lot West",
                    location="Parking Area",
                    description="Monitors outdoor parking and employee vehicle bays",
                    camera_type="CCTV",
                    restricted_zone_coords="[[0.7, 0.3], [0.98, 0.3], [0.98, 0.9], [0.7, 0.9]]",
                    is_active=True,
                ),
                Camera(
                    camera_id="CAM-03",
                    name="Storage Room Vault",
                    location="Storage Area",
                    description="High security vault and equipment storage room",
                    camera_type="CCTV",
                    restricted_zone_coords="[[0.45, 0.15], [0.95, 0.15], [0.95, 0.85], [0.45, 0.85]]",
                    is_active=True,
                ),
                Camera(
                    camera_id="CAM-04",
                    name="Server Room Corridor",
                    location="IT Infrastructure",
                    description="Strictly restricted access corridor to main server racks",
                    camera_type="CCTV",
                    restricted_zone_coords="[[0.5, 0.2], [0.95, 0.2], [0.95, 0.85], [0.5, 0.85]]",
                    is_active=True,
                ),
            ]
            db.add_all(cams)
            db.commit()

        # Ensure Mobile Security Camera is always configured
        mobile_cam = db.query(Camera).filter(Camera.camera_id == "CAM-MOBILE").first()
        if not mobile_cam:
            db.add(
                Camera(
                    camera_id="CAM-MOBILE",
                    name="Mobile Security Camera",
                    location="Mobile Field Station",
                    description="Mobile phone camera feed with real-time AI person detection and auto-evidence capture",
                    camera_type="MOBILE",
                    restricted_zone_coords="[[0.55, 0.20], [0.95, 0.20], [0.95, 0.85], [0.55, 0.85]]",
                    is_active=True,
                )
            )
            db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    seed_initial_defaults()

    # Start stream manager for active cameras
    db = SessionLocal()
    try:
        active_cameras = db.query(Camera).filter(Camera.is_active == True).all()
        for cam in active_cameras:
            if cam.stream_url:
                stream_manager.start_camera(cam)
    finally:
        db.close()
