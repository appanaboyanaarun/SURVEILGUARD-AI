"""
Verification script for Admin Mobile Alert and Incident Management feature.
Tests DB models, API endpoints, and notification dispatch lifecycle.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.main import app
from app.database.connection import SessionLocal, Base, engine
from app.models.schema import User, Camera, Event
from app.models.notification_models import AdminDevice, Incident, NotificationLog
from app.services.notification_service import notification_service

client = TestClient(app)

class TestAdminMobileNotificationFeature(unittest.TestCase):

    def setUp(self):
        # Ensure schema tables exist
        Base.metadata.create_all(bind=engine)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def test_01_device_registration_and_list(self):
        """Test registering an admin FCM device and listing active devices."""
        # 1. Register a test FCM token
        payload = {
            "fcm_token": "test_fcm_token_sample_abc123456789_xyz",
            "device_name": "Admin Test Phone",
            "platform": "android",
            "user_id": 1
        }
        res = client.post("/api/admin/devices/register", json=payload)
        self.assertEqual(res.status_code, 200, f"Register failed: {res.text}")
        data = res.json()
        self.assertEqual(data["fcm_token"], payload["fcm_token"])
        self.assertEqual(data["device_name"], payload["device_name"])
        self.assertTrue(data["is_active"])

        # 2. List devices
        list_res = client.get("/api/admin/devices")
        self.assertEqual(list_res.status_code, 200)
        devices = list_res.json()
        self.assertTrue(any(d["fcm_token"] == payload["fcm_token"] for d in devices))

    def test_02_test_notification_endpoint(self):
        """Test sending a test alert (handles missing firebase credentials gracefully)."""
        res = client.post("/api/admin/notifications/test", json={"user_id": 1})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("status", data)
        print(f"\n[Test Notification Response]: {data}")

    def test_03_incident_creation_and_lifecycle(self):
        """Test creating an incident, acknowledging it, and resolving it."""
        incident_id = f"INC-TEST-{os.urandom(3).hex().upper()}"
        inc = Incident(
            incident_id=incident_id,
            event_id="EVT-TEST-001",
            camera_id="CAM-01",
            location="Main Entrance Gate",
            activity_type="Restricted Area Breach",
            confidence=0.92,
            status="NEW",
            notification_status="PENDING",
            screenshot_path="/thumbnails/sample.jpg"
        )
        self.db.add(inc)
        self.db.commit()

        # 1. Fetch incident via API
        res = client.get(f"/api/admin/incidents/{incident_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "NEW")
        self.assertEqual(data["camera_id"], "CAM-01")

        # 2. Acknowledge incident
        ack_res = client.post(f"/api/admin/incidents/{incident_id}/acknowledge")
        self.assertEqual(ack_res.status_code, 200)
        self.assertEqual(ack_res.json()["status"], "ACKNOWLEDGED")

        # 3. Resolve incident
        res_res = client.post(f"/api/admin/incidents/{incident_id}/resolve")
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.json()["status"], "RESOLVED")

    def test_04_cooldown_deduplication(self):
        """Test that rapid consecutive alerts for the same camera trigger cooldown deduplication."""
        cam_id = "CAM-01"
        self.assertFalse(notification_service._is_cooldown_active(cam_id))
        # Record a notification timestamp
        notification_service._update_cooldown(cam_id)
        # Should now be in cooldown
        self.assertTrue(notification_service._is_cooldown_active(cam_id))

if __name__ == "__main__":
    unittest.main()
