"""
Firebase Cloud Messaging notification service.

Sends real-time push notifications to registered admin devices when
suspicious activity is detected.  Implements:
  - Lazy Firebase SDK initialization
  - Per-camera notification cooldown / deduplication
  - Async (background-thread) notification delivery
  - Graceful error handling — never crashes the detection pipeline
"""

import datetime
import logging
import threading
import time
from typing import Optional, Dict

from app.config import settings
from app.database.connection import SessionLocal
from app.models.notification_models import AdminDevice, Incident, NotificationLog
from app.models.schema import User

logger = logging.getLogger("notification_service")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)


class NotificationService:
    """Singleton service for Firebase Cloud Messaging notifications."""

    def __init__(self):
        self._firebase_initialized = False
        self._firebase_app = None
        self._cooldown_tracker: Dict[str, float] = {}  # camera_id → epoch
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Firebase Initialization (lazy)
    # ------------------------------------------------------------------

    def _init_firebase(self) -> bool:
        """
        Lazy Firebase initialisation.  Returns True if Firebase is ready.
        Safe to call repeatedly — initialises only once.
        """
        if self._firebase_initialized:
            return self._firebase_app is not None

        try:
            import firebase_admin
            from firebase_admin import credentials as fb_credentials

            cred_path = settings.FIREBASE_CREDENTIALS_PATH

            if not cred_path and not settings.FIREBASE_PROJECT_ID:
                logger.warning(
                    "[NOTIFICATION] Firebase not configured. "
                    "Set FIREBASE_CREDENTIALS_PATH or FIREBASE_PROJECT_ID in .env"
                )
                self._firebase_initialized = True
                return False

            # Prefer a service-account JSON file if provided
            if cred_path:
                cred = fb_credentials.Certificate(cred_path)
            else:
                # Build credentials dict from individual env vars
                private_key = settings.FIREBASE_PRIVATE_KEY
                if private_key:
                    private_key = private_key.replace("\\n", "\n")
                cred = fb_credentials.Certificate(
                    {
                        "type": "service_account",
                        "project_id": settings.FIREBASE_PROJECT_ID,
                        "client_email": settings.FIREBASE_CLIENT_EMAIL,
                        "private_key": private_key or "",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                )

            self._firebase_app = firebase_admin.initialize_app(cred)
            self._firebase_initialized = True
            logger.info("[NOTIFICATION] Firebase initialized successfully")
            return True

        except Exception as exc:
            logger.error(f"[NOTIFICATION] Firebase initialization failed: {exc}")
            self._firebase_initialized = True  # avoid retrying on every frame
            return False

    # ------------------------------------------------------------------
    # Cooldown / Deduplication
    # ------------------------------------------------------------------

    def _is_cooldown_active(self, camera_id: str) -> bool:
        with self._lock:
            last_sent = self._cooldown_tracker.get(camera_id)
            if last_sent is None:
                return False
            return (time.time() - last_sent) < settings.NOTIFICATION_COOLDOWN_SECONDS

    def _update_cooldown(self, camera_id: str):
        with self._lock:
            self._cooldown_tracker[camera_id] = time.time()

    # ------------------------------------------------------------------
    # Incident Creation
    # ------------------------------------------------------------------

    def generate_incident_id(self, db) -> str:
        """Generate sequential incident ID like INC-000001."""
        from sqlalchemy import func

        count = db.query(func.count(Incident.id)).scalar() or 0
        return f"INC-{(count + 1):06d}"

    def create_incident(
        self,
        event_id: str,
        camera_id: str,
        location: str,
        activity_type: str,
        anomaly_score: float,
        screenshot_path: Optional[str] = None,
        video_clip_path: Optional[str] = None,
    ) -> Optional[Incident]:
        """
        Persist an Incident to the database.
        Returns the Incident ORM object, or None on error.
        """
        db = SessionLocal()
        incident = None
        try:
            incident_id = self.generate_incident_id(db)
            incident = Incident(
                incident_id=incident_id,
                event_id=event_id,
                camera_id=camera_id,
                location=location,
                activity_type=activity_type,
                confidence=round(anomaly_score, 4),
                status="NEW",
                notification_status="PENDING",
                screenshot_path=screenshot_path,
                video_clip_path=video_clip_path,
            )
            db.add(incident)
            db.commit()
            db.refresh(incident)
            logger.info(
                f"[SUSPICIOUS] Incident {incident_id} created for event {event_id}"
            )
        except Exception as exc:
            logger.error(f"[INCIDENT] Failed to create incident: {exc}")
            db.rollback()
            incident = None
        finally:
            db.close()

        if incident:
            try:
                from app.services.email_service import email_service

                email_service.dispatch_suspicious_event_email(
                    event_id=event_id,
                    camera_id=camera_id,
                )
            except Exception:
                logger.exception(
                    f"[INCIDENT] Email dispatch could not be scheduled for {incident.incident_id}"
                )
        return incident

    # ------------------------------------------------------------------
    # Alert Dispatch (entry-point called by detection code)
    # ------------------------------------------------------------------

    def send_suspicious_activity_alert(self, incident: Incident):
        """
        Fire-and-forget FCM alert.  Checks cooldown, then dispatches
        the actual send to a background daemon thread so the camera
        processing loop is never blocked.
        """
        if incident is None:
            return

        if self._is_cooldown_active(incident.camera_id):
            logger.info(
                f"[NOTIFICATION] Cooldown active for {incident.camera_id}, "
                f"skipping notification for {incident.incident_id}"
            )
            return

        thread = threading.Thread(
            target=self._send_notification_worker,
            kwargs={
                "incident_id": incident.incident_id,
                "camera_id": incident.camera_id,
                "location": incident.location or "",
                "activity_type": incident.activity_type or "",
                "confidence": incident.confidence,
                "event_id": incident.event_id,
            },
            daemon=True,
        )
        thread.start()

    # ------------------------------------------------------------------
    # Background Worker
    # ------------------------------------------------------------------

    def _send_notification_worker(
        self,
        incident_id: str,
        camera_id: str,
        location: str,
        activity_type: str,
        confidence: float,
        event_id: str,
    ):
        """Runs in a daemon thread.  Sends FCM to all active admin devices."""
        try:
            db = SessionLocal()
            try:
                # Fetch active admin devices
                admin_devices = (
                    db.query(AdminDevice)
                    .join(User, AdminDevice.user_id == User.user_id)
                    .filter(
                        AdminDevice.is_active == True,
                        User.role == "admin",
                        User.is_active == True,
                    )
                    .all()
                )

                if not admin_devices:
                    logger.info(
                        f"[NOTIFICATION] No active admin devices registered, "
                        f"skipping FCM for {incident_id}"
                    )
                    inc = (
                        db.query(Incident)
                        .filter(Incident.incident_id == incident_id)
                        .first()
                    )
                    if inc:
                        inc.notification_status = "NO_DEVICES"
                        db.commit()
                    return

                logger.info(
                    f"[NOTIFICATION] Sending alert to {len(admin_devices)} "
                    f"admin device(s) for {incident_id}"
                )

                confidence_pct = int(confidence * 100)
                now_str = datetime.datetime.utcnow().strftime("%I:%M:%S %p")

                title = "\U0001f6a8 Suspicious Activity Detected"
                body = (
                    f"Camera: {camera_id}\n"
                    f"Location: {location}\n"
                    f"Activity: {activity_type}\n"
                    f"Confidence: {confidence_pct}%\n"
                    f"Time: {now_str}"
                )
                data_payload = {
                    "type": "SUSPICIOUS_ACTIVITY",
                    "incident_id": incident_id,
                    "event_id": event_id,
                    "camera_id": camera_id,
                    "activity_type": activity_type,
                    "confidence": str(confidence),
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                }

                success_count = 0
                for device in admin_devices:
                    if self._send_to_device(
                        device, title, body, data_payload, incident_id, db
                    ):
                        success_count += 1

                # Update incident record
                inc = (
                    db.query(Incident)
                    .filter(Incident.incident_id == incident_id)
                    .first()
                )
                if inc:
                    if success_count > 0:
                        inc.notification_status = "SENT"
                        self._update_cooldown(camera_id)
                        logger.info(
                            f"[NOTIFICATION] Alert sent successfully for "
                            f"{incident_id} ({success_count} device(s))"
                        )
                    else:
                        inc.notification_status = "FAILED"
                        logger.warning(
                            f"[NOTIFICATION] Failed to send alert for {incident_id}"
                        )
                    db.commit()

            finally:
                db.close()
        except Exception as exc:
            logger.error(
                f"[NOTIFICATION] Unexpected error in notification worker: {exc}"
            )

    # ------------------------------------------------------------------
    # Single-device FCM send
    # ------------------------------------------------------------------

    def _send_to_device(
        self,
        device: AdminDevice,
        title: str,
        body: str,
        data: dict,
        incident_id: str,
        db,
    ) -> bool:
        """Send one FCM message.  Returns True on success."""
        try:
            if not self._init_firebase():
                log_entry = NotificationLog(
                    incident_id=incident_id,
                    admin_device_id=device.id,
                    notification_type="SUSPICIOUS_ACTIVITY",
                    status="FAILED",
                    sent_at=datetime.datetime.utcnow(),
                    error_message="Firebase not configured",
                )
                db.add(log_entry)
                db.commit()
                return False

            from firebase_admin import messaging

            message = messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                data=data,
                token=device.fcm_token,
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        click_action="OPEN_INCIDENT",
                        channel_id="suspicious_activity_alerts",
                    ),
                ),
            )
            messaging.send(message)

            db.add(
                NotificationLog(
                    incident_id=incident_id,
                    admin_device_id=device.id,
                    notification_type="SUSPICIOUS_ACTIVITY",
                    status="SENT",
                    sent_at=datetime.datetime.utcnow(),
                )
            )
            device.last_seen = datetime.datetime.utcnow()
            db.commit()
            return True

        except Exception as exc:
            error_msg = str(exc)[:500]
            logger.error(
                f"[NOTIFICATION] Failed to send to device {device.id}: {error_msg}"
            )

            # Deactivate stale tokens automatically
            if any(
                kw in error_msg.lower()
                for kw in ("not-registered", "invalid-registration", "unregistered")
            ):
                logger.warning(
                    f"[NOTIFICATION] Invalid FCM token — deactivating device {device.id}"
                )
                device.is_active = False

            db.add(
                NotificationLog(
                    incident_id=incident_id,
                    admin_device_id=device.id,
                    notification_type="SUSPICIOUS_ACTIVITY",
                    status="FAILED",
                    sent_at=datetime.datetime.utcnow(),
                    error_message=error_msg,
                )
            )
            db.commit()
            return False

    # ------------------------------------------------------------------
    # Device Registration
    # ------------------------------------------------------------------

    def register_device(
        self,
        user_id: int,
        fcm_token: str,
        device_name: Optional[str] = None,
        platform: str = "android",
    ) -> AdminDevice:
        """Register or update an admin device for push notifications."""
        db = SessionLocal()
        try:
            existing = (
                db.query(AdminDevice)
                .filter(AdminDevice.fcm_token == fcm_token)
                .first()
            )
            if existing:
                existing.user_id = user_id
                existing.device_name = device_name or existing.device_name
                existing.platform = platform
                existing.is_active = True
                existing.last_seen = datetime.datetime.utcnow()
                db.commit()
                db.refresh(existing)
                logger.info(
                    f"[DEVICE] Updated device {existing.id} for user {user_id}"
                )
                return existing

            device = AdminDevice(
                user_id=user_id,
                fcm_token=fcm_token,
                device_name=device_name,
                platform=platform,
                is_active=True,
            )
            db.add(device)
            db.commit()
            db.refresh(device)
            logger.info(
                f"[DEVICE] Registered device {device.id} for user {user_id}: "
                f"{device_name}"
            )
            return device
        finally:
            db.close()

    def unregister_device(self, device_id: int) -> bool:
        """Deactivate a registered device."""
        db = SessionLocal()
        try:
            device = (
                db.query(AdminDevice).filter(AdminDevice.id == device_id).first()
            )
            if not device:
                return False
            device.is_active = False
            db.commit()
            logger.info(f"[DEVICE] Unregistered device {device_id}")
            return True
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Test Notification
    # ------------------------------------------------------------------

    def send_test_notification(self, user_id: int) -> dict:
        """
        Send a harmless test notification to all active devices of an admin.
        Does NOT create a fake incident.
        """
        db = SessionLocal()
        try:
            devices = (
                db.query(AdminDevice)
                .filter(
                    AdminDevice.user_id == user_id,
                    AdminDevice.is_active == True,
                )
                .all()
            )

            if not devices:
                return {
                    "status": "no_devices",
                    "message": "No active devices registered for this admin",
                }

            if not self._init_firebase():
                return {
                    "status": "firebase_not_configured",
                    "message": "Firebase credentials not configured",
                }

            from firebase_admin import messaging

            success_count = 0
            for device in devices:
                try:
                    message = messaging.Message(
                        notification=messaging.Notification(
                            title="\u2705 Test Notification",
                            body=(
                                "SurveilGuard AI notification system is "
                                "working correctly!"
                            ),
                        ),
                        data={
                            "type": "TEST",
                            "timestamp": datetime.datetime.utcnow().isoformat(),
                        },
                        token=device.fcm_token,
                    )
                    messaging.send(message)
                    success_count += 1
                except Exception as exc:
                    logger.error(
                        f"[NOTIFICATION] Test notification failed for "
                        f"device {device.id}: {exc}"
                    )
                    if "not-registered" in str(exc).lower():
                        device.is_active = False
                        db.commit()

            return {
                "status": "sent",
                "message": (
                    f"Test notification sent to "
                    f"{success_count}/{len(devices)} device(s)"
                ),
                "devices_total": len(devices),
                "devices_reached": success_count,
            }
        finally:
            db.close()


# Module-level singleton
notification_service = NotificationService()
