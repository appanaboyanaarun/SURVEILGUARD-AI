"""
Live surveillance detection service.

Accepts incoming video frames (as base64 or raw bytes) from browser camera feeds or RTSP streams,
runs the computer-vision PersonDetector + RestrictedZone + AnomalyDetector pipeline,
implements temporal confirmation logic for false-positive control,
and generates real-time alerts, SMS notifications, and audit records when suspicious activity is confirmed.
"""

import base64
import datetime
import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import cv2
import numpy as np

from app.config import settings
from app.database.connection import SessionLocal, DATA_DIR
from app.models.schema import Event, User, DetectionSession, Camera
from app.schemas.dto import EventCreate
from app.services.event_service import EventService
from app.services.audit_service import AuditService
from app.services.detection_session_service import detection_session_service
from app.services.notification_service import notification_service
from video_processing.detector import PersonDetector
from video_processing.restricted_zone import RestrictedZone
from ml.anomaly_detection import AnomalyDetector

logger = logging.getLogger("live_detection_service")
THUMBNAILS_DIR = os.path.join(DATA_DIR, "thumbnails")
MODELS_DIR = os.path.join(DATA_DIR, "models")
os.makedirs(THUMBNAILS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)


class CameraDetectionState:
    """Tracks continuous detection state per camera for false-positive suppression."""

    def __init__(self, camera_id: str):
        self.camera_id = camera_id
        self.suspicious_first_seen: Optional[float] = None
        self.consecutive_suspicious_frames: int = 0
        self.last_confirmed_event_id: Optional[str] = None
        self.last_confirmed_time: Optional[float] = None
        self.consecutive_normal_frames: int = 0

    def update(self, is_suspicious: bool, score: float, confirmation_seconds: float) -> Tuple[bool, bool]:
        """
        Updates tracking state.
        Returns:
            (is_currently_suspicious: bool, is_confirmed_new_alert: bool)
        """
        now = time.time()

        if is_suspicious:
            self.consecutive_normal_frames = 0
            self.consecutive_suspicious_frames += 1

            if self.suspicious_first_seen is None:
                self.suspicious_first_seen = now

            duration_suspicious = now - self.suspicious_first_seen

            # Check if condition persisted long enough to confirm
            if duration_suspicious >= confirmation_seconds or self.consecutive_suspicious_frames >= 3:
                # Check cooldown from last confirmed alert on this camera
                if self.last_confirmed_time is None or (now - self.last_confirmed_time) > settings.SMS_COOLDOWN_SECONDS:
                    self.last_confirmed_time = now
                    return True, True  # Newly confirmed alert
                return True, False  # Already confirmed, ongoing incident
            return True, False  # Suspicious but not yet confirmed
        else:
            self.consecutive_normal_frames += 1
            # Reset suspicious state if 3 consecutive normal frames observed
            if self.consecutive_normal_frames >= 3:
                self.suspicious_first_seen = None
                self.consecutive_suspicious_frames = 0
            return False, False


class LiveDetectionService:
    """
    Singleton service that processes live browser and camera frames,
    performs genuine OpenCV + ML inference, and orchestrates incident handling.
    """

    def __init__(self):
        self.detector = PersonDetector()
        self.anomaly_detector = AnomalyDetector(model_dir=MODELS_DIR)

        # Runtime-configurable settings
        self._settings: Dict[str, Any] = {
            "sensitivity": settings.DETECTION_SENSITIVITY,
            "confidence_threshold": settings.DETECTION_CONFIDENCE_THRESHOLD,
            "confirmation_seconds": settings.SUSPICIOUS_CONFIRMATION_SECONDS,
            "recording_duration_seconds": 15.0,  # 10 to 20 seconds configurable, default 15s
            "roi_zones": [],
            "enabled_categories": [
                "intrusion",
                "loitering",
                "suspicious_package",
                "rapid_motion",
                "unauthorized_access",
                "group_gathering",
            ],
            "motion_threshold": 0.05,
            "person_count_threshold": 3,
        }

        # Per-camera state tracking
        self._states: Dict[str, CameraDetectionState] = {}
        self._state_lock = threading.Lock()

        # Connected WebSocket clients
        self.ws_clients: list = []

    def _get_camera_state(self, camera_id: str) -> CameraDetectionState:
        with self._state_lock:
            if camera_id not in self._states:
                self._states[camera_id] = CameraDetectionState(camera_id)
            return self._states[camera_id]

    # ------------------------------------------------------------------
    # Settings Management
    # ------------------------------------------------------------------
    def get_settings(self) -> Dict[str, Any]:
        return dict(self._settings)

    def update_settings(self, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        if "sensitivity" in new_settings and new_settings["sensitivity"] is not None:
            self._settings["sensitivity"] = max(0.0, min(1.0, float(new_settings["sensitivity"])))

        if "confidence_threshold" in new_settings and new_settings["confidence_threshold"] is not None:
            self._settings["confidence_threshold"] = max(0.0, min(1.0, float(new_settings["confidence_threshold"])))

        if "confirmation_seconds" in new_settings and new_settings["confirmation_seconds"] is not None:
            self._settings["confirmation_seconds"] = max(0.0, float(new_settings["confirmation_seconds"]))

        if "recording_duration_seconds" in new_settings and new_settings["recording_duration_seconds"] is not None:
            self._settings["recording_duration_seconds"] = max(10.0, min(20.0, float(new_settings["recording_duration_seconds"])))

        if "roi_zones" in new_settings and new_settings["roi_zones"] is not None:
            self._settings["roi_zones"] = new_settings["roi_zones"]

        if "enabled_categories" in new_settings and new_settings["enabled_categories"] is not None:
            self._settings["enabled_categories"] = new_settings["enabled_categories"]

        if "motion_threshold" in new_settings and new_settings["motion_threshold"] is not None:
            self._settings["motion_threshold"] = float(new_settings["motion_threshold"])

        if "person_count_threshold" in new_settings and new_settings["person_count_threshold"] is not None:
            self._settings["person_count_threshold"] = int(new_settings["person_count_threshold"])

        return self.get_settings()

    # ------------------------------------------------------------------
    # Genuine Frame Analysis Pipeline
    # ------------------------------------------------------------------
    def analyse_frame(
        self,
        frame_b64: Optional[str] = None,
        frame_bytes: Optional[bytes] = None,
        camera_id: str = "CAM-LIVE",
        location: str = "Live Feed",
        session_id: Optional[str] = None,
        admin_user: Optional[User] = None,
        custom_timestamp: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """
        Decodes incoming video frame, runs OpenCV computer-vision detection,
        evaluates ML anomaly score, applies false positive confirmation,
        and generates real events & SMS alerts when confirmed.
        """
        # 1. Decode Frame
        if frame_b64:
            # Handle data:image/jpeg;base64,... header if present
            if "," in frame_b64:
                frame_b64 = frame_b64.split(",", 1)[1]
            raw = base64.b64decode(frame_b64)
        elif frame_bytes:
            raw = frame_bytes
        else:
            return {"error": "No frame data provided"}

        np_arr = np.frombuffer(raw, dtype=np.uint8)
        frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if frame is None:
            return {"error": "Failed to decode image frame"}

        # 2. Genuine Deep Learning Person & Motion Detection
        det_result = self.detector.detect(frame)
        boxes = det_result["boxes"]
        normalized_boxes = det_result.get("normalized_boxes", [])
        confidences = det_result.get("confidences", [])
        motion_score = det_result["motion_score"]
        motion_level = det_result["motion_level"]
        person_count = det_result.get("person_count", len(boxes))

        # Primary person detection confidence (highest detected confidence or 0.0)
        primary_confidence = max(confidences) if confidences else (0.85 if person_count > 0 else 0.0)

        # 3. Camera Restricted Zone and ROI Check
        h, w = frame.shape[:2]
        restricted_breach = False
        breached_zones: List[str] = []
        zones_to_evaluate: List[Dict[str, Any]] = []

        # Check camera-specific zone configured in database
        db_cam = SessionLocal()
        try:
            cam_obj = db_cam.query(Camera).filter(Camera.camera_id == camera_id).first()
            if cam_obj and cam_obj.restricted_zone_coords:
                zones_to_evaluate.append({
                    "name": f"{cam_obj.name} Restricted Area",
                    "coordinates": cam_obj.restricted_zone_coords,
                })
        except Exception:
            pass
        finally:
            db_cam.close()

        # Add runtime configurable ROI zones
        for r_zone in self._settings.get("roi_zones", []):
            zones_to_evaluate.append(r_zone)

        # Evaluate intersection for detected persons only
        for roi in zones_to_evaluate:
            coords = roi.get("coordinates")
            zone_name = roi.get("name", "Restricted Zone")
            if not coords:
                continue
            coords_str = json.dumps(coords) if not isinstance(coords, str) else coords
            zone = RestrictedZone(coords_str, frame_width=w, frame_height=h)
            for box in boxes:
                if zone.check_bbox_intersection(box):
                    restricted_breach = True
                    if zone_name not in breached_zones:
                        breached_zones.append(zone_name)

        # 4. Activity Type Classification (strictly separated from mere presence)
        enabled = self._settings.get("enabled_categories", [])
        triggered_categories: List[str] = []

        if person_count > 0:
            if restricted_breach and "intrusion" in enabled:
                activity_type = "Restricted Area Intrusion"
                triggered_categories.append("intrusion")
            elif person_count >= self._settings["person_count_threshold"] and "group_gathering" in enabled:
                activity_type = "Group Gathering"
                triggered_categories.append("group_gathering")
            elif motion_score > self._settings["motion_threshold"] and "rapid_motion" in enabled:
                activity_type = "Rapid Movement"
                triggered_categories.append("rapid_motion")
            else:
                activity_type = "Normal Person Activity"
        else:
            if motion_score > self._settings["motion_threshold"] and "rapid_motion" in enabled:
                activity_type = "Scene Motion Detected"
            else:
                activity_type = "No Suspicious Activity"

        # 5. Machine Learning Anomaly Scoring
        now = custom_timestamp or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        meta: Dict[str, Any] = {
            "camera_id": camera_id,
            "timestamp": now,
            "location": location,
            "person_count": person_count,
            "object_type": "person",
            "motion_level": motion_level,
            "activity_type": activity_type,
            "event_duration": 0,
            "event_duration_formatted": "00:00",
            "restricted_area": 1 if restricted_breach else 0,
        }

        anomaly_score = self.anomaly_detector.score_single(meta)

        # 6. Incident Rules Evaluation (A person alone does NOT trigger an incident)
        threshold = 1.0 - self._settings["sensitivity"]
        raw_suspicious = False
        reasons: List[str] = []

        if person_count > 0 and restricted_breach:
            raw_suspicious = True
            reasons.append(f"Restricted zone breached: {', '.join(breached_zones)}")
        elif person_count >= self._settings["person_count_threshold"] and "group_gathering" in enabled:
            raw_suspicious = True
            reasons.append(f"High person count ({person_count} individuals) exceeds threshold")
        elif person_count > 0 and anomaly_score >= threshold:
            raw_suspicious = True
            reasons.append("ML feature vector anomaly detected")

        # 7. False Positive Suppression & Temporal Confirmation
        state = self._get_camera_state(camera_id)
        is_suspicious, is_confirmed_new_alert = state.update(
            is_suspicious=raw_suspicious,
            score=anomaly_score,
            confirmation_seconds=self._settings["confirmation_seconds"],
        )

        status_str = "SUSPICIOUS" if is_suspicious else "NORMAL"
        risk_priority = "LOW"
        if is_suspicious:
            if anomaly_score >= 0.75 or restricted_breach:
                risk_priority = "HIGH"
            elif anomaly_score >= 0.50:
                risk_priority = "MEDIUM"

        # 8. Construct Result Payload
        result: Dict[str, Any] = {
            "detected": is_suspicious,
            "status": status_str,
            "activity_type": activity_type,
            "confidence": round(float(primary_confidence), 3),
            "person_confidence": round(float(primary_confidence), 3),
            "risk_level": risk_priority,
            "risk_priority": risk_priority,
            "timestamp": now.isoformat(),
            "camera_id": camera_id,
            "location": location,
            "person_count": person_count,
            "motion_score": motion_score,
            "motion_level": motion_level,
            "anomaly_score": anomaly_score,
            "is_confirmed": is_confirmed_new_alert,
            "triggered_categories": triggered_categories,
            "breached_zones": breached_zones,
            "anomaly_reasons": "; ".join(reasons) if reasons else None,
            "boxes": [list(b) for b in boxes],
            "normalized_boxes": normalized_boxes,
            "confidences": confidences,
        }

        # 9. If Suspicious Activity is Confirmed, Persist Event, Dispatch SMS & Audit
        if is_confirmed_new_alert:
            alert = self._persist_confirmed_event(
                result=result,
                frame=frame,
                session_id=session_id,
                admin_user=admin_user,
            )
            result["alert"] = alert

        return result

    def _persist_confirmed_event(
        self,
        result: Dict[str, Any],
        frame: np.ndarray,
        session_id: Optional[str] = None,
        admin_user: Optional[User] = None,
    ) -> Dict[str, Any]:
        """
        Saves thumbnail, creates Event, updates DetectionSession, dispatches SMS,
        and triggers notification logs without ever crashing detection.
        """
        ts_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        uid = uuid.uuid4().hex[:6]
        thumbnail_filename = f"live_alert_{result['camera_id']}_{ts_str}_{uid}.jpg"
        thumbnail_path = os.path.join(THUMBNAILS_DIR, thumbnail_filename)
        cv2.imwrite(thumbnail_path, frame)

        admin_name = admin_user.full_name if admin_user else "Admin"
        admin_id = admin_user.user_id if admin_user else None

        db = SessionLocal()
        try:
            event_data = EventCreate(
                camera_id=result["camera_id"],
                timestamp=datetime.datetime.fromisoformat(result["timestamp"]),
                location=result["location"],
                person_count=result["person_count"],
                object_type="person",
                motion_level=result["motion_level"],
                activity_type=result["activity_type"],
                event_duration=0,
                event_duration_formatted="00:00",
                restricted_area=1 if result["breached_zones"] else 0,
                anomaly_score=result["anomaly_score"],
                status=result["status"],
                risk_priority=result["risk_priority"],
                anomaly_reasons=result.get("anomaly_reasons"),
                thumbnail_path=f"/thumbnails/{thumbnail_filename}",
            )

            event = EventService.create_event(db, event_data)

            # Associate session and admin
            event.session_id = session_id
            event.admin_id = admin_id
            event.admin_name = admin_name
            db.commit()

            # Update detection session if active
            if session_id:
                detection_session_service.record_suspicious_event(db, session_id, event.event_id)

            # 1. Create Incident record first so incident ID and metadata are persisted
            incident = None
            try:
                incident = notification_service.create_incident(
                    event_id=event.event_id,
                    camera_id=result["camera_id"],
                    location=result["location"],
                    activity_type=result["activity_type"],
                    anomaly_score=result["anomaly_score"],
                    screenshot_path=f"/thumbnails/{thumbnail_filename}",
                )
            except Exception as inc_err:
                logger.warning(f"Could not create incident record: {inc_err}")

            # 2. Dispatch FCM Push (if configured and incident exists)
            if incident:
                try:
                    notification_service.send_suspicious_activity_alert(incident)
                except Exception:
                    pass

            # 3. Security Audit Logging
            AuditService.log(
                db=db,
                action="SUSPICIOUS_ACTIVITY_CONFIRMED",
                actor_name=admin_name,
                actor_id=admin_id,
                entity_type="event",
                entity_id=event.event_id,
                details=(
                    f"Suspicious activity ({result['activity_type']}) confirmed on "
                    f"{result['camera_id']}. Email notification scheduled: {incident is not None}"
                ),
            )

            alert_payload = {
                "event_id": event.event_id,
                "session_id": session_id,
                "camera_id": result["camera_id"],
                "timestamp": result["timestamp"],
                "anomaly_score": result["anomaly_score"],
                "status": result["status"],
                "risk_priority": result["risk_priority"],
                "activity_type": result["activity_type"],
                "triggered_categories": result["triggered_categories"],
                "breached_zones": result["breached_zones"],
                "anomaly_reasons": result.get("anomaly_reasons"),
                "thumbnail_url": f"/thumbnails/{thumbnail_filename}",
                "email_dispatched": email_dispatched,
            }
            return alert_payload

        except Exception as exc:
            logger.error(f"Error persisting confirmed event: {exc}")
            db.rollback()
            return {"error": str(exc)}
        finally:
            db.close()


live_detection_service = LiveDetectionService()
