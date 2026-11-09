"""
Comprehensive Automated Tests for Email Notification System (Google Apps Script HTTP API).

Covers all required testing areas using mocked Google Apps Script responses:
1.  Valid provider request (success & message_id)
2.  Missing Web App URL or Webhook Secret (NOT_CONFIGURED)
3.  Placeholder configuration detection
4.  Invalid webhook secret rejection & secret scrubbing
5.  HTTP error responses (e.g. 403, 500)
6.  HTTP request timeout handling
7.  HTTP connection failure handling
8.  Invalid non-JSON response handling
9.  Invalid recipient address preflight rejection
10. Multiple active recipients dispatch
11. Five administrator emails support
12. Duplicate recipient address deduplication
13. Combination of environment and database recipients
14. Partial recipient failure handling
15. Database audit logging (EmailLog fields & apps_script provider)
16. Retry failed email handling & duplicate retry prevention
17. In-memory and database deduplication
18. Incident creation and automatic notification integration
19. Unauthorized access prevention (RBAC 403)
20. Historical Resend logs preservation
21. Email API routes integration (status, test, logs, retry, recipients)
"""

import datetime
import json
import os
import sys;'`1   ----------------------'
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.config import settings
from app.database.connection import SessionLocal, engine, Base, run_migrations
from app.models.notification_models import EmailRecipient, EmailLog, Incident
from app.models.schema import User, Camera, Event
from app.routes.email_routes import _check_admin_permissions
from app.services.email_service import (
    EmailService,
    email_service,
    validate_email,
    mask_email,
    EmailDispatchResult,
)

# Run migrations to ensure all columns exist
run_migrations()
Base.metadata.create_all(bind=engine)


def _mock_response(status_code=200, json_data=None, text=""):
    """Helper to construct a mocked requests.Response object."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    if json_data is not None:
        resp.json.return_value = json_data
        resp.text = json.dumps(json_data)
    else:
        resp.json.side_effect = ValueError("No JSON object could be decoded")
        resp.text = text
    return resp


def _configure_apps_script_settings():
    """Helper to configure test environment with mocked Apps Script settings."""
    patcher_enabled = patch.object(settings, "EMAIL_ENABLED", True)
    patcher_provider = patch.object(settings, "EMAIL_PROVIDER", "apps_script")
    patcher_url = patch.object(
        settings,
        "APPS_SCRIPT_WEB_APP_URL",
        "https://script.google.com/macros/s/test_deployment_123/exec",
    )
    patcher_secret = patch.object(
        settings, "APPS_SCRIPT_WEBHOOK_SECRET", "whsec_test_secret_abc123"
    )
    patcher_timeout = patch.object(settings, "APPS_SCRIPT_TIMEOUT_SECONDS", 5)
    patcher_name = patch.object(
        settings, "ALERT_FROM_NAME", "Suspicious Activity Detection"
    )
    patcher_base = patch.object(
        settings, "APP_BASE_URL", "https://surveilguard.example.com"
    )
    patcher_admin = patch.object(settings, "ADMIN_EMAIL", "")
    patcher_admins = patch.object(settings, "ADMIN_EMAILS", "")
    patcher_env = patch.dict(
        os.environ,
        {
            "EMAIL_ENABLED": "true",
            "EMAIL_PROVIDER": "apps_script",
            "APPS_SCRIPT_WEB_APP_URL": "https://script.google.com/macros/s/test_deployment_123/exec",
            "APPS_SCRIPT_WEBHOOK_SECRET": "whsec_test_secret_abc123",
            "APPS_SCRIPT_TIMEOUT_SECONDS": "5",
            "ADMIN_EMAIL": "",
            "ADMIN_EMAILS": "",
        },
        clear=False,
    )

    patcher_enabled.start()
    patcher_provider.start()
    patcher_url.start()
    patcher_secret.start()
    patcher_timeout.start()
    patcher_name.start()
    patcher_base.start()
    patcher_admin.start()
    patcher_admins.start()
    patcher_env.start()
    return [
        patcher_enabled,
        patcher_provider,
        patcher_url,
        patcher_secret,
        patcher_timeout,
        patcher_name,
        patcher_base,
        patcher_admin,
        patcher_admins,
        patcher_env,
    ]


def _clear_dedup():
    """Clear in-memory deduplication tracker."""
    email_service._dedup_tracker.clear()


class TestEmailWorkflow(unittest.TestCase):
    """Complete test suite for Google Apps Script HTTP API email alert system."""

    def setUp(self):
        self.db = SessionLocal()
        self.db.rollback()
        self.db.query(EmailLog).delete()
        self.db.query(EmailRecipient).delete()
        self.db.query(Incident).delete()
        self.db.query(Event).delete()
        self.db.commit()
        _clear_dedup()

    def tearDown(self):
        self.db.rollback()
        self.db.query(EmailLog).delete()
        self.db.query(EmailRecipient).delete()
        self.db.query(Incident).delete()
        self.db.query(Event).delete()
        self.db.commit()
        self.db.close()
        _clear_dedup()

    def _add_recipient(
        self, email: str, name: str = "Test Recipient", recipient_type: str = "friend"
    ):
        r = EmailRecipient(
            name=name,
            email_address=email,
            recipient_type=recipient_type,
            is_active=True,
        )
        self.db.add(r)
        self.db.commit()
        self.db.refresh(r)
        return r

    # ------------------------------------------------------------------
    # 1. Valid provider request
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_valid_provider_request(self, mock_post):
        """Test valid provider request succeeds and captures Apps Script message ID."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email sent", "message_id": "gas_valid_001"},
        )
        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_test_email(to_email="admin@company.com")
            self.assertTrue(result["success"])
            self.assertEqual(result["status"], "ACCEPTED")
            self.assertEqual(result["provider"], "apps_script")
            self.assertEqual(result["message_id"], "gas_valid_001")
            mock_post.assert_called_once()

            # Verify request payload format matches Apps Script requirements
            call_kwargs = mock_post.call_args[1]
            payload = call_kwargs["json"]
            self.assertEqual(payload["token"], "whsec_test_secret_abc123")
            self.assertEqual(payload["recipient"], "admin@company.com")
            self.assertIn("subject", payload)
            self.assertIn("camera", payload)
            self.assertIn("event", payload)
            self.assertIn("timestamp", payload)
            self.assertIn("details", payload)
            self.assertTrue(call_kwargs.get("allow_redirects", False))
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 2. Missing configuration
    # ------------------------------------------------------------------
    def test_missing_web_app_url(self):
        """Test missing Web App URL reports NOT_CONFIGURED without making HTTP call."""
        patchers = _configure_apps_script_settings()
        try:
            with patch.object(settings, "APPS_SCRIPT_WEB_APP_URL", ""), \
                 patch.dict(os.environ, {"APPS_SCRIPT_WEB_APP_URL": ""}, clear=False):
                self.assertFalse(email_service.is_configured())
                result = email_service.send_test_email(to_email="test@example.com")
                self.assertFalse(result["success"])
                self.assertEqual(result["status"], "NOT_CONFIGURED")
                self.assertIn("APPS_SCRIPT_WEB_APP_URL", result["error"])
        finally:
            for p in patchers:
                p.stop()

    def test_missing_webhook_secret(self):
        """Test missing webhook secret reports NOT_CONFIGURED without making HTTP call."""
        patchers = _configure_apps_script_settings()
        try:
            with patch.object(settings, "APPS_SCRIPT_WEBHOOK_SECRET", ""), \
                 patch.dict(os.environ, {"APPS_SCRIPT_WEBHOOK_SECRET": ""}, clear=False):
                self.assertFalse(email_service.is_configured())
                result = email_service.send_test_email(to_email="test@example.com")
                self.assertFalse(result["success"])
                self.assertEqual(result["status"], "NOT_CONFIGURED")
                self.assertIn("APPS_SCRIPT_WEBHOOK_SECRET", result["error"])
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 3. Placeholder configuration detection
    # ------------------------------------------------------------------
    def test_placeholder_secret_detection(self):
        """Placeholder secret template values are detected as unconfigured."""
        patchers = _configure_apps_script_settings()
        try:
            with patch.object(settings, "APPS_SCRIPT_WEBHOOK_SECRET", "YOUR_WEBHOOK_SECRET"), \
                 patch.dict(os.environ, {"APPS_SCRIPT_WEBHOOK_SECRET": "YOUR_WEBHOOK_SECRET"}, clear=False):
                self.assertFalse(email_service.is_configured())
                status = email_service.get_provider_status()
                self.assertFalse(status["configured"])
                self.assertEqual(status["mode"], "UNCONFIGURED")
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 4. Invalid webhook secret rejection & secret scrubbing
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_invalid_webhook_secret_rejected(self, mock_post):
        """Apps Script rejecting an invalid token is handled safely without leaking the secret."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "error", "message": "Unauthorized: Invalid or missing token"},
        )
        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_test_email(to_email="admin@example.com")
            self.assertFalse(result["success"])
            self.assertEqual(result["status"], "FAILED")
            self.assertIn("rejected dispatch", result["error"].lower())
            self.assertNotIn("whsec_test_secret_abc123", result["error"])
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 5. HTTP Error Status (e.g. 403 / 500)
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_http_error_status(self, mock_post):
        """Non-200 HTTP responses from Google Apps Script are handled gracefully."""
        mock_post.return_value = _mock_response(
            status_code=500,
            text="Internal Server Error in Google Script Runtime",
        )
        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_test_email(to_email="admin@example.com")
            self.assertFalse(result["success"])
            self.assertEqual(result["status"], "FAILED")
            self.assertIn("500", result["error"])
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 6. HTTP Timeout Handling
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_http_timeout(self, mock_post):
        """Network timeouts to Apps Script are caught and reported cleanly."""
        mock_post.side_effect = requests.exceptions.Timeout("HTTPS connection read timed out")
        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_test_email(to_email="admin@example.com")
            self.assertFalse(result["success"])
            self.assertEqual(result["status"], "FAILED")
            self.assertIn("timed out", result["error"].lower())
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 7. Connection Failure Handling
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_connection_failure(self, mock_post):
        """Network connectivity failures are reported with clear actionable messages."""
        mock_post.side_effect = requests.exceptions.ConnectionError("Failed to establish a new connection")
        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_test_email(to_email="admin@example.com")
            self.assertFalse(result["success"])
            self.assertEqual(result["status"], "FAILED")
            self.assertIn("Failed to connect", result["error"])
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 8. Invalid non-JSON HTTP response
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_invalid_non_json_response(self, mock_post):
        """Non-JSON responses (HTML error page, proxy redirect) are caught cleanly."""
        mock_post.return_value = _mock_response(
            status_code=200,
            text="<!DOCTYPE html><html><body>Google Service Temporary Error</body></html>",
        )
        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_test_email(to_email="admin@example.com")
            self.assertFalse(result["success"])
            self.assertEqual(result["status"], "FAILED")
            self.assertIn("non-JSON", result["error"])
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 9. Invalid recipient address preflight rejection
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_invalid_recipient_address(self, mock_post):
        """Malformed email addresses are rejected before sending an HTTP request."""
        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_test_email(to_email="not-an-email-address")
            self.assertFalse(result["success"])
            self.assertEqual(result["status"], "FAILED")
            self.assertIn("Invalid recipient", result["error"])
            mock_post.assert_not_called()
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 10. Multiple recipients dispatch
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_multiple_recipients_dispatch(self, mock_post):
        """Each active recipient receives a separate Apps Script dispatch and log entry."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email sent", "message_id": "gas_multi_101"},
        )
        self._add_recipient("admin@company.com", "Chief Admin", "admin")
        self._add_recipient("friend1@example.com", "Friend One", "friend")
        self._add_recipient("friend2@example.com", "Friend Two", "friend")

        incident = Incident(
            incident_id="INC-MULTI-001",
            event_id="EVT-MULTI-001",
            camera_id="CAM-01",
            location="Main Gate",
            activity_type="Restricted Intrusion",
            confidence=0.89,
            status="NEW",
            notification_status="PENDING",
        )
        self.db.add(incident)
        self.db.commit()

        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_suspicious_event_email("EVT-MULTI-001", "CAM-01")
            self.assertTrue(result["success"])
            self.assertEqual(len(result["dispatches"]), 3)
            self.assertEqual(mock_post.call_count, 3)

            logs = self.db.query(EmailLog).filter(EmailLog.incident_id == "INC-MULTI-001").all()
            self.assertEqual(len(logs), 3)
            for log in logs:
                self.assertEqual(log.status, "ACCEPTED")
                self.assertEqual(log.provider, "apps_script")
                self.assertEqual(log.provider_message_id, "gas_multi_101")
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 11. Five administrator emails support
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_five_admin_email_recipients(self, mock_post):
        """ADMIN_EMAILS dispatches to each of five normalized addresses via Apps Script."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email sent", "message_id": "gas_five_001"},
        )
        incident = Incident(
            incident_id="INC-FIVE-001",
            event_id="EVT-FIVE-001",
            camera_id="CAM-01",
            status="NEW",
            notification_status="PENDING",
        )
        self.db.add(incident)
        self.db.commit()
        addresses = [f"admin{i}@example.com" for i in range(1, 6)]

        patchers = _configure_apps_script_settings()
        try:
            with patch.dict(
                os.environ,
                {"ADMIN_EMAILS": ", ".join([f" {a.upper()} " for a in addresses] + ["bad-address"])},
                clear=False,
            ):
                result = email_service.send_suspicious_event_email("EVT-FIVE-001", "CAM-01")
                self.assertTrue(result["success"])
                self.assertEqual(mock_post.call_count, 5)
                persisted = {log.recipient_email for log in self.db.query(EmailLog).all()}
                self.assertEqual(persisted, set(addresses))
                for log in self.db.query(EmailLog).all():
                    self.assertEqual(log.provider, "apps_script")
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 12. Duplicate recipient address deduplication
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_duplicate_recipients_are_sent_once(self, mock_post):
        """Case/whitespace duplicates across environment and database are collapsed."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email sent", "message_id": "gas_dup_001"},
        )
        self._add_recipient("  ADMIN1@example.com ", "Duplicate Admin", "admin")
        incident = Incident(
            incident_id="INC-UNIQUE-001",
            event_id="EVT-UNIQUE-001",
            camera_id="CAM-01",
            status="NEW",
            notification_status="PENDING",
        )
        self.db.add(incident)
        self.db.commit()

        patchers = _configure_apps_script_settings()
        try:
            with patch.dict(
                os.environ,
                {"ADMIN_EMAILS": "Admin1@example.com, admin2@example.com"},
                clear=False,
            ):
                result = email_service.send_suspicious_event_email("EVT-UNIQUE-001", "CAM-01")
                self.assertTrue(result["success"])
                self.assertEqual(mock_post.call_count, 2)
                self.assertEqual(len(result["dispatches"]), 2)
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 13. Combination of environment and database recipients
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_legacy_and_database_recipients_are_combined(self, mock_post):
        """ADMIN_EMAIL and active database recipients remain additive to ADMIN_EMAILS."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email sent", "message_id": "gas_combo_001"},
        )
        self._add_recipient("db-admin@example.com", "Database Admin", "admin")
        incident = Incident(
            incident_id="INC-COMBINED-001",
            event_id="EVT-COMBINED-001",
            camera_id="CAM-01",
            status="NEW",
            notification_status="PENDING",
        )
        self.db.add(incident)
        self.db.commit()

        patchers = _configure_apps_script_settings()
        try:
            with patch.dict(
                os.environ,
                {
                    "ADMIN_EMAILS": "list-admin@example.com",
                    "ADMIN_EMAIL": "legacy-admin@example.com",
                },
                clear=False,
            ):
                result = email_service.send_suspicious_event_email("EVT-COMBINED-001", "CAM-01")
                self.assertTrue(result["success"])
                self.assertEqual(mock_post.call_count, 3)
                self.assertEqual(
                    {log.recipient_email for log in self.db.query(EmailLog).all()},
                    {"list-admin@example.com", "legacy-admin@example.com", "db-admin@example.com"},
                )
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 14. Partial recipient failure handling
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_partial_recipient_failure(self, mock_post):
        """When one recipient call fails, remaining recipients still receive alert."""
        # First call succeeds, second call fails with timeout
        mock_post.side_effect = [
            _mock_response(status_code=200, json_data={"status": "success", "message_id": "gas_part_1"}),
            requests.exceptions.Timeout("Connection timed out"),
        ]

        self._add_recipient("admin@company.com", "Account Owner", "admin")
        self._add_recipient("friend@example.com", "External Friend", "friend")

        incident = Incident(
            incident_id="INC-PARTIAL-001",
            event_id="EVT-PARTIAL-001",
            camera_id="CAM-01",
            location="Vault Corridor",
            activity_type="Loitering",
            confidence=0.75,
            status="NEW",
            notification_status="PENDING",
        )
        self.db.add(incident)
        self.db.commit()

        patchers = _configure_apps_script_settings()
        try:
            result = email_service.send_suspicious_event_email("EVT-PARTIAL-001", "CAM-01")
            self.assertTrue(result["success"])
            self.assertEqual(len(result["dispatches"]), 2)

            statuses = [d["status"] for d in result["dispatches"]]
            self.assertIn("ACCEPTED", statuses)
            self.assertIn("FAILED", statuses)

            inc_db = self.db.query(Incident).filter(Incident.incident_id == "INC-PARTIAL-001").first()
            self.assertEqual(inc_db.notification_status, "PARTIAL")

            logs = self.db.query(EmailLog).filter(EmailLog.incident_id == "INC-PARTIAL-001").all()
            self.assertEqual(sorted(l.status for l in logs), ["ACCEPTED", "FAILED"])
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 15. Database audit logging
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_database_logging(self, mock_post):
        """Email log persists all required fields with apps_script provider name."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Accepted", "message_id": "gas_log_888"},
        )
        self._add_recipient("security.officer@domain.com", "Security Officer", "admin")

        incident = Incident(
            incident_id="INC-LOG-001",
            event_id="EVT-LOG-001",
            camera_id="CAM-02",
            location="Server Room",
            activity_type="Unauthorized Boundary Entry",
            confidence=0.92,
            status="NEW",
            notification_status="PENDING",
        )
        self.db.add(incident)
        self.db.commit()

        patchers = _configure_apps_script_settings()
        try:
            email_service.send_suspicious_event_email("EVT-LOG-001", "CAM-02")
            log = self.db.query(EmailLog).filter(EmailLog.incident_id == "INC-LOG-001").first()
            self.assertIsNotNone(log)
            self.assertEqual(log.recipient_email, "security.officer@domain.com")
            self.assertEqual(log.recipient_email_masked, "s***r@domain.com")
            self.assertEqual(log.provider, "apps_script")
            self.assertEqual(log.provider_message_id, "gas_log_888")
            self.assertEqual(log.status, "ACCEPTED")
            self.assertIsNotNone(log.sent_at)
            self.assertIn("SECURITY ALERT: HIGH", log.subject)
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 16. Retry handling
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_retry_handling(self, mock_post):
        """Retry only retries failed logs via Apps Script and blocks retrying successful logs."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email sent", "message_id": "gas_retry_001"},
        )

        failed_log = EmailLog(
            incident_id="INC-RETRY-001",
            recipient_email="retry.recipient@example.com",
            recipient_email_masked="r***t@example.com",
            subject="Security Alert - Retry Test",
            provider="apps_script",
            status="FAILED",
            error_message="Simulated temporary timeout",
            attempt_count=1,
            is_test=False,
        )
        success_log = EmailLog(
            incident_id="INC-RETRY-002",
            recipient_email="already.sent@example.com",
            recipient_email_masked="a***t@example.com",
            subject="Security Alert - Already Sent",
            provider="apps_script",
            status="ACCEPTED",
            attempt_count=1,
            is_test=False,
        )
        self.db.add_all([failed_log, success_log])
        self.db.commit()
        self.db.refresh(failed_log)
        self.db.refresh(success_log)

        patchers = _configure_apps_script_settings()
        try:
            from app.routes.email_routes import retry_email

            mock_admin = User(user_id=1, username="admin", role="admin", is_active=True)

            # 1. Retry failed log
            retry_res = retry_email(log_id=failed_log.id, db=self.db, current_user=mock_admin)
            self.assertTrue(retry_res["success"])

            self.db.refresh(failed_log)
            self.assertEqual(failed_log.status, "ACCEPTED")
            self.assertEqual(failed_log.attempt_count, 2)
            self.assertEqual(failed_log.provider, "apps_script")
            self.assertEqual(failed_log.provider_message_id, "gas_retry_001")

            # 2. Duplicate retry on already successful log must be blocked
            dup_res = retry_email(log_id=success_log.id, db=self.db, current_user=mock_admin)
            self.assertFalse(dup_res["success"])
            self.assertIn("already", dup_res["message"].lower())
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 17. Duplicate-notification prevention
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_duplicate_notification_prevention(self, mock_post):
        """Subsequent notifications for same incident and recipient are prevented."""
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email sent", "message_id": "gas_dedup_001"},
        )
        self._add_recipient("dedup@example.com", "Dedup User", "friend")
        incident = Incident(
            incident_id="INC-DEDUP-001",
            event_id="EVT-DEDUP-001",
            camera_id="CAM-01",
            location="Perimeter Fence",
            activity_type="Lingering",
            confidence=0.81,
            status="NEW",
            notification_status="PENDING",
        )
        self.db.add(incident)
        self.db.commit()

        patchers = _configure_apps_script_settings()
        try:
            # First dispatch succeeds
            res1 = email_service.send_suspicious_event_email("EVT-DEDUP-001", "CAM-01")
            self.assertTrue(res1["success"])
            self.assertEqual(mock_post.call_count, 1)

            # Second dispatch for identical incident & recipient must be skipped
            res2 = email_service.send_suspicious_event_email("EVT-DEDUP-001", "CAM-01")
            self.assertEqual(mock_post.call_count, 1)
            self.assertEqual(res2["dispatches"][0]["status"], "DUPLICATE_SKIPPED")
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 18. Incident creation and automatic notification integration
    # ------------------------------------------------------------------
    def test_incident_creation_and_auto_notification(self):
        """Saving a new incident automatically sends and logs its Apps Script email alert."""
        from app.services.notification_service import notification_service

        class ImmediateThread:
            def __init__(self, target, args=(), kwargs=None, **_):
                self.target = target
                self.args = args
                self.kwargs = kwargs or {}

            def start(self):
                self.target(*self.args, **self.kwargs)

        camera = self.db.query(Camera).filter(Camera.camera_id == "CAM-AUTO-01").first()
        if not camera:
            camera = Camera(
                camera_id="CAM-AUTO-01",
                name="West Wing Camera",
                location="West Wing Sector B",
            )
            self.db.add(camera)
            self.db.commit()

        self.db.add(
            Event(
                event_id="EVT-AUTO-001",
                camera_id="CAM-AUTO-01",
                location="West Wing Sector B",
                activity_type="Restricted Intrusion",
                anomaly_score=0.91,
                anomaly_reasons="Intruder breached perimeter during off-hours",
                status="SUSPICIOUS",
                risk_priority="HIGH",
            )
        )
        self.db.commit()
        self._add_recipient("auto.friend@example.com", "Auto Friend", "friend")

        patchers = _configure_apps_script_settings()
        try:
            with patch("requests.post", return_value=_mock_response(
                status_code=200,
                json_data={"status": "success", "message": "Sent", "message_id": "gas_auto_001"},
            )) as mock_post, \
                 patch.object(notification_service, "generate_incident_id", return_value="INC-AUTO-001"), \
                 patch("app.services.email_service.threading.Thread", ImmediateThread):
                created = notification_service.create_incident(
                    event_id="EVT-AUTO-001",
                    camera_id="CAM-AUTO-01",
                    location="West Wing Sector B",
                    activity_type="Restricted Intrusion",
                    anomaly_score=0.91,
                )
            self.assertIsNotNone(created)
            mock_post.assert_called_once()
            email_log = (
                self.db.query(EmailLog)
                .filter(EmailLog.incident_id == "INC-AUTO-001")
                .one()
            )
            self.assertEqual(email_log.status, "ACCEPTED")
            self.assertEqual(email_log.provider, "apps_script")
            self.assertEqual(email_log.recipient_email, "auto.friend@example.com")
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 19. Unauthorized access prevention (RBAC 403)
    # ------------------------------------------------------------------
    def test_unauthorized_access_prevention(self):
        """Non-admin users (e.g. viewer) are rejected with HTTP 403."""
        viewer_user = User(user_id=99, username="viewer", role="viewer", is_active=True)
        with self.assertRaises(HTTPException) as ctx:
            _check_admin_permissions(viewer_user)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Administrative privileges", ctx.exception.detail)

        admin_user = User(user_id=1, username="admin", role="admin", is_active=True)
        _check_admin_permissions(admin_user)

        operator_user = User(user_id=2, username="operator", role="operator", is_active=True)
        _check_admin_permissions(operator_user)

    # ------------------------------------------------------------------
    # 20. Historical Resend records preservation
    # ------------------------------------------------------------------
    def test_historical_resend_records_preserved(self):
        """Existing historical logs created under Resend retain their provider name."""
        historical_log = EmailLog(
            incident_id="INC-HISTORICAL-001",
            recipient_email="history@example.com",
            recipient_email_masked="h***y@example.com",
            subject="Historical Resend Email",
            provider="resend",
            provider_message_id="resend_old_msg_123",
            status="ACCEPTED",
            attempt_count=1,
            is_test=False,
            sent_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
        )
        self.db.add(historical_log)
        self.db.commit()

        logs = email_service.get_logs(self.db)
        matched = next((l for l in logs if l["incident_id"] == "INC-HISTORICAL-001"), None)
        self.assertIsNotNone(matched)
        self.assertEqual(matched["provider"], "resend")
        self.assertEqual(matched["provider_message_id"], "resend_old_msg_123")

    # ------------------------------------------------------------------
    # 21. Webhook Secret Redaction in Errors
    # ------------------------------------------------------------------
    def test_webhook_secret_never_leaked_in_errors(self):
        """Secret is stripped from error logs and diagnostic strings."""
        patchers = _configure_apps_script_settings()
        try:
            secret = "whsec_test_secret_abc123"
            err_with_secret = f"Endpoint https://script.google.com failed with token={secret}"
            sanitized = email_service._sanitize_error(err_with_secret)
            self.assertNotIn(secret, sanitized)
            self.assertIn("[REDACTED]", sanitized)
        finally:
            for p in patchers:
                p.stop()

    # ------------------------------------------------------------------
    # 22. Email API Endpoints Integration
    # ------------------------------------------------------------------
    @patch("requests.post")
    def test_email_api_routes(self, mock_post):
        """All email API endpoints function correctly with Apps Script provider."""
        from app.main import app
        client = TestClient(app)
        mock_post.return_value = _mock_response(
            status_code=200,
            json_data={"status": "success", "message": "Email dispatched", "message_id": "gas_api_001"},
        )

        patchers = _configure_apps_script_settings()
        try:
            # 1. GET /api/email/status
            status_resp = client.get("/api/email/status")
            self.assertEqual(status_resp.status_code, 200)
            data = status_resp.json()
            self.assertEqual(data["provider"], "apps_script")
            self.assertTrue(data["configured"])
            self.assertEqual(data["mode"], "ACTIVE")
            self.assertNotIn("whsec_test_secret_abc123", json.dumps(data))

            # 2. POST /api/email/test
            test_resp = client.post("/api/email/test", json={"email": "test@domain.com"})
            self.assertEqual(test_resp.status_code, 200)
            test_data = test_resp.json()
            self.assertTrue(test_data["success"])
            self.assertEqual(test_data["provider"], "apps_script")

            # 3. GET /api/email/logs
            logs_resp = client.get("/api/email/logs")
            self.assertEqual(logs_resp.status_code, 200)
            self.assertIsInstance(logs_resp.json(), list)

            # 4. Recipients CRUD
            add_resp = client.post(
                "/api/email/recipients",
                json={"name": "API Admin", "email": "api.admin@domain.com", "recipient_type": "admin"},
            )
            self.assertEqual(add_resp.status_code, 201)
            rec_id = add_resp.json()["id"]

            list_resp = client.get("/api/email/recipients")
            self.assertEqual(list_resp.status_code, 200)

            put_resp = client.put(f"/api/email/recipients/{rec_id}", json={"is_active": False})
            self.assertEqual(put_resp.status_code, 200)
            self.assertFalse(put_resp.json()["is_active"])

            del_resp = client.delete(f"/api/email/recipients/{rec_id}")
            self.assertEqual(del_resp.status_code, 200)
        finally:
            for p in patchers:
                p.stop()


if __name__ == "__main__":
    unittest.main()
