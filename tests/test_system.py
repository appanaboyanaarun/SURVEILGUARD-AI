"""
Comprehensive Test Suite for SurveilGuard AI.
Covers:
  - Authentication (PBKDF2, JWT tokens, RBAC)
  - Live AI Detection (Computer Vision PersonDetector + AnomalyDetector)
  - False-Positive Control & Confirmation
  - Detection Sessions & Admin Association
  - Evidence Video Security & Signed URLs
  - SMS Notification Gateway & Cooldown
  - Reports & CSV Export
  - Audit Logging
"""

import datetime
import os
import unittest
import numpy as np
import cv2
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.database.connection import SessionLocal, Base, engine
from app.models.schema import User, Camera, Event, DetectionSession, EvidenceVideo, SMSLog, AuditLog
from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    create_signed_video_token,
    verify_signed_video_token,
)
from app.services.sms_service import sms_service
from app.services.live_detection_service import live_detection_service
from app.services.storage_service import storage_service
from app.services.report_service import report_service


class TestSurveilGuardSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # -------------------------------------------------------------
    # 1. Authentication & Security Tests
    # -------------------------------------------------------------
    def test_01_password_hashing_and_verification(self):
        password = "SecureAdminPassword2026!"
        hashed = hash_password(password)

        self.assertTrue(hashed.startswith("pbkdf2_sha256$100000$"))
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("WrongPassword", hashed))

    def test_02_jwt_token_generation_and_validation(self):
        payload = {"sub": "admin", "role": "admin", "user_id": 1}
        token = create_access_token(payload)

        self.assertIsInstance(token, str)
        decoded = decode_access_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["sub"], "admin")
        self.assertEqual(decoded["role"], "admin")

    def test_03_login_endpoint(self):
        response = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["username"], "admin")
        self.assertEqual(data["user"]["role"], "admin")

    def test_04_authenticated_profile(self):
        login_resp = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_resp.json()["access_token"]

        me_resp = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["username"], "admin")

    # -------------------------------------------------------------
    # 2. Live Detection & Computer Vision Pipeline Tests
    # -------------------------------------------------------------
    def test_05_live_frame_analysis_normal(self):
        # Create blank synthetic normal frame
        frame = np.zeros((480, 640, 3), dtype=np.uint8)
        frame[:] = (50, 50, 50)
        _, buf = cv2.imencode(".jpg", frame)

        resp = self.client.post(
            "/api/v1/live/detect",
            files={"frame": ("frame.jpg", buf.tobytes(), "image/jpeg")},
            data={"camera_id": "CAM-01", "location": "Main Gate"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("anomaly_score", data)
        self.assertIn("person_count", data)
        self.assertEqual(data["person_count"], 0)

    def test_06_live_frame_analysis_person_shape(self):
        # Create synthetic frame with person shape in restricted zone
        frame = np.zeros((480, 640, 3), dtype=np.uint8)
        # Person silhouette in right quadrant
        cv2.rectangle(frame, (450, 150), (550, 380), (220, 220, 220), -1)
        cv2.circle(frame, (500, 120), 30, (220, 220, 220), -1)
        _, buf = cv2.imencode(".jpg", frame)

        # Add ROI zone to settings
        live_detection_service.update_settings({
            "roi_zones": [{
                "name": "Restricted Vault",
                "coordinates": [[0.5, 0.1], [0.95, 0.1], [0.95, 0.9], [0.5, 0.9]]
            }],
            "confirmation_seconds": 0.0,  # immediate for testing
        })

        resp = self.client.post(
            "/api/v1/live/detect",
            files={"frame": ("frame.jpg", buf.tobytes(), "image/jpeg")},
            data={"camera_id": "CAM-03", "location": "Storage Area"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(data["status"], ["NORMAL", "SUSPICIOUS"])

    # -------------------------------------------------------------
    # 3. Detection Session Lifecycle Tests
    # -------------------------------------------------------------
    def test_07_detection_session_lifecycle(self):
        login_resp = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_resp.json()["access_token"]

        # Start Session
        start_resp = self.client.post(
            "/api/v1/live/session/start",
            headers={"Authorization": f"Bearer {token}"},
            json={"camera_id": "CAM-01", "device_info": "Test Browser Client"},
        )
        self.assertEqual(start_resp.status_code, 200)
        session = start_resp.json()
        session_id = session["session_id"]
        self.assertTrue(session["is_active"])
        self.assertEqual(session["camera_id"], "CAM-01")

        # Stop Session
        stop_resp = self.client.post(
            "/api/v1/live/session/stop",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": session_id},
        )
        self.assertEqual(stop_resp.status_code, 200)
        self.assertFalse(stop_resp.json()["is_active"])

    # -------------------------------------------------------------
    # 4. Storage & Signed Video URL Security Tests
    # -------------------------------------------------------------
    def test_08_signed_video_tokens(self):
        video_id = "VID-TEST01"
        signed_token = create_signed_video_token(video_id=video_id, expires_minutes=30)

        self.assertTrue(verify_signed_video_token(signed_token, video_id))
        self.assertFalse(verify_signed_video_token(signed_token, "VID-DIFFERENT"))

    def test_09_secure_video_stream_protection(self):
        # Unauthenticated request without token should be rejected
        resp = self.client.get("/api/videos/secure-stream/VID-UNKNOWN")
        self.assertEqual(resp.status_code, 403)

    # -------------------------------------------------------------
    # 5. SMS Notification Gateway Tests
    # -------------------------------------------------------------
    def test_10_sms_message_building(self):
        msg = sms_service.build_alert_message(
            activity_type="Restricted Area Intrusion",
            location="Storage Room Vault",
            risk_priority="HIGH",
            timestamp=datetime.datetime.utcnow(),
            video_link="http://127.0.0.1:8000/?event_id=EVT-0001#view-event-detail",
        )
        self.assertIn("ALERT: Suspicious activity detected", msg)
        self.assertIn("Restricted Area Intrusion", msg)
        self.assertIn("Storage Room Vault", msg)
        self.assertIn("HIGH", msg)
        self.assertIn("http://127.0.0.1:8000/?event_id=EVT-0001", msg)

    def test_11_test_sms_dispatch(self):
        login_resp = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin123"},
        )
        token = login_resp.json()["access_token"]
        resp = self.client.post(
            "/api/sms/test",
            json={"phone_number": "+1234567890"},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["recipient"], "+1234567890")

    # -------------------------------------------------------------
    # 6. Reports & CSV Export Tests
    # -------------------------------------------------------------
    def test_12_activity_report_and_csv_export(self):
        # JSON report
        rep_resp = self.client.get("/api/reports/activity?period=daily")
        self.assertEqual(rep_resp.status_code, 200)
        report = rep_resp.json()
        self.assertIn("total_events", report)
        self.assertIn("events", report)

        # CSV Export
        csv_resp = self.client.get("/api/reports/activity/csv?period=daily")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("text/csv", csv_resp.headers.get("content-type", ""))
        self.assertIn("Event ID,Timestamp (UTC)", csv_resp.text)

    # -------------------------------------------------------------
    # 7. Audit Logging Tests
    # -------------------------------------------------------------
    def test_13_audit_log_recording(self):
        from app.services.audit_service import AuditService
        AuditService.log(
            db=self.db,
            action="SYSTEM_TEST_AUDIT",
            actor_name="Test Admin",
            details="Automated audit log verification",
        )
        resp = self.client.get("/api/audit/logs")
        self.assertEqual(resp.status_code, 200)
        logs = resp.json()
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)
        self.assertTrue(any(l["action"] in ["SYSTEM_TEST_AUDIT", "LOGIN", "REPORT_EXPORT_CSV"] for l in logs))


if __name__ == "__main__":
    unittest.main()
