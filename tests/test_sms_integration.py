"""
Comprehensive Integration Tests for Real SMS Delivery, Provider Modes,
Twilio SDK Integration, Webhooks, and Evidence Linking.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.database.connection import SessionLocal, Base, engine
from app.models.schema import User, Event, SMSLog, EvidenceVideo
from app.services.sms_service import sms_service, validate_e164, mask_phone
from app.services.auth_service import hash_password


class TestSMSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)
        
        # Ensure test admin user exists
        db = SessionLocal()
        admin = db.query(User).filter(User.username == "test_sms_admin").first()
        if not admin:
            admin = User(
                username="test_sms_admin",
                password_hash=hash_password("SmsTestPass123!"),
                full_name="SMS Test Admin",
                role="admin",
                phone_number="+14155552671",
                is_active=True,
            )
            db.add(admin)
            db.commit()
        db.close()

    def setUp(self):
        self.db = SessionLocal()
        # Obtain auth token
        login_resp = self.client.post(
            "/api/auth/login",
            json={"username": "test_sms_admin", "password": "SmsTestPass123!"},
        )
        self.assertEqual(login_resp.status_code, 200)
        self.token = login_resp.json()["access_token"]
        self.auth_headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        self.db.close()

    # ------------------------------------------------------------------
    # 1. Phone validation & masking
    # ------------------------------------------------------------------
    def test_e164_validation_and_masking(self):
        # Valid E.164 formats
        self.assertTrue(validate_e164("+14155552671"))
        self.assertTrue(validate_e164("+447911123456"))
        self.assertTrue(validate_e164("+919876543210"))
        
        # Invalid phone formats
        self.assertFalse(validate_e164("14155552671"))  # missing +
        self.assertFalse(validate_e164("+1"))            # too short
        self.assertFalse(validate_e164("invalid_phone"))
        self.assertFalse(validate_e164(""))

        # Phone masking for security
        self.assertEqual(mask_phone("+14155552671"), "+1***671")
        self.assertEqual(mask_phone(None), "")

    # ------------------------------------------------------------------
    # 2. Provider Readiness Endpoint
    # ------------------------------------------------------------------
    def test_provider_status_endpoint(self):
        resp = self.client.get("/api/sms/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        
        self.assertIn("provider", data)
        self.assertIn("mode", data)
        self.assertIn("status", data)
        self.assertIn("admin_phone_masked", data)
        self.assertIn("issues", data)

    # ------------------------------------------------------------------
    # 3. Truthful Mock SMS Behavior
    # ------------------------------------------------------------------
    def test_mock_sms_records_mock_status(self):
        with patch.object(settings, "SMS_PROVIDER", "mock"):
            result = sms_service.send_test_sms("+14155552671")
            
            # Must truthfully identify as MOCK, not masquerade as REAL
            self.assertTrue(result["success"])
            self.assertEqual(result["status"], "MOCK")
            self.assertEqual(result["provider"], "mock")
            self.assertTrue(result["is_mock"])

            # Verify saved log in database
            log = self.db.query(SMSLog).filter(SMSLog.recipient_phone == "+14155552671").order_by(SMSLog.id.desc()).first()
            self.assertIsNotNone(log)
            self.assertEqual(log.status, "MOCK")
            self.assertTrue(log.is_test)

    # ------------------------------------------------------------------
    # 4. Twilio SDK Dispatch (Mocked Provider Responses)
    # ------------------------------------------------------------------
    @patch("app.services.sms_service.Client")
    def test_twilio_successful_dispatch(self, mock_twilio_client_class):
        mock_client = MagicMock()
        mock_twilio_client_class.return_value = mock_client
        
        # Mock Twilio message instance returned by client.messages.create()
        mock_message = MagicMock()
        mock_message.sid = "SM1234567890abcdef1234567890abcdef"
        mock_message.status = "queued"
        mock_message.date_created = datetime.now(timezone.utc)
        mock_message.error_code = None
        mock_client.messages.create.return_value = mock_message

        with patch.object(settings, "SMS_PROVIDER", "twilio"), \
             patch.object(settings, "TWILIO_ACCOUNT_SID", "ACmockaccount0000000000000000000"), \
             patch.object(settings, "TWILIO_AUTH_TOKEN", "mockauthtoken0000000000000000000"), \
             patch.object(settings, "TWILIO_FROM_NUMBER", "+15005550006"):
            
            dispatch_result = sms_service._dispatch_provider_sms("+14155552671", "Test Twilio Alert")
            
            self.assertTrue(dispatch_result.success)
            self.assertEqual(dispatch_result.provider, "twilio")
            self.assertEqual(dispatch_result.provider_message_id, "SM1234567890abcdef1234567890abcdef")
            self.assertIn(dispatch_result.status, ["QUEUED", "SENT"])

    @patch("app.services.sms_service.Client")
    def test_twilio_api_error_handling(self, mock_twilio_client_class):
        from twilio.base.exceptions import TwilioRestException
        mock_client = MagicMock()
        mock_twilio_client_class.return_value = mock_client
        
        # Simulate TwilioRestException (e.g. unverified destination number)
        mock_client.messages.create.side_effect = TwilioRestException(
            status=400,
            uri="/2010-04-01/Accounts/ACxxx/Messages.json",
            msg="The number +14155550000 is unverified.",
            code=21608,
        )

        with patch.object(settings, "SMS_PROVIDER", "twilio"), \
             patch.object(settings, "TWILIO_ACCOUNT_SID", "ACmockaccount0000000000000000000"), \
             patch.object(settings, "TWILIO_AUTH_TOKEN", "mockauthtoken0000000000000000000"), \
             patch.object(settings, "TWILIO_FROM_NUMBER", "+15005550006"):
            
            dispatch_result = sms_service._dispatch_provider_sms("+14155550000", "Test Alert")
            
            self.assertFalse(dispatch_result.success)
            self.assertEqual(dispatch_result.status, "FAILED")
            self.assertIn("unverified", dispatch_result.error.lower())

    # ------------------------------------------------------------------
    # 5. Twilio Delivery Status Webhook
    # ------------------------------------------------------------------
    def test_twilio_status_callback_webhook(self):
        # Create an existing SMS log record with a Message SID
        sid = "SMwebhooktest1234567890abcdef"
        log = SMSLog(
            recipient_phone="+14155552671",
            provider="twilio",
            provider_message_id=sid,
            message_body="Webhook test message",
            status="SENT",
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        self.db.add(log)
        self.db.commit()

        # Send webhook status update
        webhook_data = {
            "MessageSid": sid,
            "MessageStatus": "delivered",
            "To": "+14155552671",
            "From": "+15005550006",
        }
        resp = self.client.post("/api/sms/webhooks/twilio", data=webhook_data)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["processed"])

        # Check that DB record updated
        updated_log = self.db.query(SMSLog).filter(SMSLog.provider_message_id == sid).first()
        self.assertEqual(updated_log.delivery_status, "delivered")
        self.assertEqual(updated_log.status, "DELIVERED")
        self.assertIsNotNone(updated_log.delivered_at)

    # ------------------------------------------------------------------
    # 6. Retry Failed SMS Logic
    # ------------------------------------------------------------------
    def test_retry_failed_sms(self):
        log = SMSLog(
            recipient_phone="+14155552671",
            provider="mock",
            message_body="Failed alert to retry",
            status="FAILED",
            retry_count=0,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        self.db.add(log)
        self.db.commit()

        with patch.object(settings, "SMS_PROVIDER", "mock"):
            resp = self.client.post(
                f"/api/sms/{log.id}/retry",
                headers=self.auth_headers,
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertTrue(data["success"])

            self.db.expire_all()
            updated_log = self.db.query(SMSLog).filter(SMSLog.id == log.id).first()
            self.assertEqual(updated_log.retry_count, 1)

    # ------------------------------------------------------------------
    # 7. Rate Limiting on Test SMS
    # ------------------------------------------------------------------
    def test_rate_limiting_test_sms(self):
        rate_key = "test_rate_limit_user"
        # First call passes
        self.assertTrue(sms_service.check_test_rate_limit(rate_key, min_interval=5.0))
        # Immediate second call is rejected
        self.assertFalse(sms_service.check_test_rate_limit(rate_key, min_interval=5.0))

    # ------------------------------------------------------------------
    # 8. Evidence Video Available Flag (0:00 Video Player Fix)
    # ------------------------------------------------------------------
    def test_secure_url_checks_video_file_presence(self):
        import uuid
        # Create an event without a physical video file on disk
        evt_id = f"EVT-TEST-{uuid.uuid4().hex[:6]}"
        event = Event(
            event_id=evt_id,
            camera_id="CAM-01",
            location="Lobby",
            person_count=1,
            activity_type="Suspicious Loitering",
            motion_level="MEDIUM",
            anomaly_score=0.85,
            status="SUSPICIOUS",
            risk_priority="HIGH",
            sms_status="NONE",
            video_filename="non_existent_file.mp4",
        )
        self.db.add(event)
        self.db.commit()

        # Request secure URL
        resp = self.client.get(
            f"/api/videos/{evt_id}/secure-url",
            headers=self.auth_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        
        # Must return available: False so frontend doesn't render broken 0:00 video element
        self.assertFalse(data["available"])
        self.assertIsNone(data["secure_url"])
        self.assertIn("unavailable", data.get("message", "").lower())

    # ------------------------------------------------------------------
    # 9. Suspicious Activity Alert SMS Dispatch
    # ------------------------------------------------------------------
    def test_send_suspicious_activity_alert_sms(self):
        resp = self.client.post(
            "/api/sms/alert",
            headers=self.auth_headers,
            json={
                "phone_number": "+14155552671",
                "activity_type": "Night Restricted Intrusion",
                "camera_id": "CAM-01",
                "location": "Warehouse Perimeter",
                "risk_priority": "CRITICAL",
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertIn("Night Restricted Intrusion", data["message_body"])
        self.assertIn("CRITICAL", data["message_body"])

        # Check SMS log in DB
        log = self.db.query(SMSLog).filter(
            SMSLog.recipient_phone == "+14155552671",
            SMSLog.is_test == False,
        ).order_by(SMSLog.id.desc()).first()
        self.assertIsNotNone(log)
        self.assertIn("Night Restricted Intrusion", log.message_body)


if __name__ == "__main__":
    unittest.main()

