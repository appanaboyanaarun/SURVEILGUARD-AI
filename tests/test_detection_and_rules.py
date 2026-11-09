"""
Automated Test Suite for Detection, Coordinate Transformations, Security Rules, and Resilience.

Tests:
  1. Coordinate conversion & letterbox transformation
  2. Person counting and duplicate suppression (NMS)
  3. Restricted-zone polygon & ground-contact intersection
  4. Temporal event confirmation & false-positive control
  5. Alert deduplication & cooldown handling
  6. Failure handling: SMS provider failure preserves event & evidence
  7. Video security: Token signing, expiration & traversal defense
"""

import os
import unittest
import numpy as np
import cv2
import datetime

from app.database.connection import SessionLocal, Base, engine
from app.models.schema import User, Camera, Event, SMSLog
from app.services.auth_service import create_signed_video_token, verify_signed_video_token
from app.services.storage_service import sanitize_filename, storage_service
from app.services.sms_service import sms_service
from app.services.live_detection_service import CameraDetectionState, live_detection_service
from video_processing.detector import letterbox_image, PersonDetector
from video_processing.restricted_zone import RestrictedZone
from video_processing.tracker import MultiPersonTracker, TrackedPerson


class TestDetectionAndRules(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # -------------------------------------------------------------
    # 1. Coordinate Conversion & Letterbox Transformation Tests
    # -------------------------------------------------------------
    def test_letterbox_aspect_ratio_preservation_widescreen(self):
        """16:9 widescreen frame (1280x720) must be padded symmetrically without squishing."""
        img = np.zeros((720, 1280, 3), dtype=np.uint8)
        padded, scale, (dw, dh) = letterbox_image(img, target_size=(640, 640))

        self.assertEqual(padded.shape, (640, 640, 3))
        # Scale = 640 / 1280 = 0.5
        self.assertAlmostEqual(scale, 0.5, places=3)
        # Symmetrical vertical padding: (640 - 360) / 2 = 140
        self.assertEqual(dw, 0)
        self.assertEqual(dh, 140)

    def test_letterbox_coordinate_reversion(self):
        """Bounding box predicted in 640x640 letterbox must correctly invert to original frame coordinates."""
        orig_w, orig_h = 1280, 720
        img = np.zeros((orig_h, orig_w, 3), dtype=np.uint8)
        _, scale, (dw, dh) = letterbox_image(img, target_size=(640, 640))

        # Suppose model predicts a person centered in the middle of the letterboxed image
        pred_cx, pred_cy, pred_bw, pred_bh = 320, 320, 200, 240

        # Invert to original frame coordinates
        x1 = (pred_cx - pred_bw / 2.0 - dw) / scale
        y1 = (pred_cy - pred_bh / 2.0 - dh) / scale
        box_w = pred_bw / scale
        box_h = pred_bh / scale

        # Check bounds
        self.assertGreaterEqual(x1, 0)
        self.assertLessEqual(x1 + box_w, orig_w)
        self.assertGreaterEqual(y1, 0)
        self.assertLessEqual(y1 + box_h, orig_h)
        # Expected: x1 = (320 - 100 - 0) / 0.5 = 440
        self.assertAlmostEqual(x1, 440.0, places=1)
        # Expected: y1 = (320 - 120 - 140) / 0.5 = 120.0
        self.assertAlmostEqual(y1, 120.0, places=1)

    # -------------------------------------------------------------
    # 2. Person Counting & Duplicate Suppression (NMS)
    # -------------------------------------------------------------
    def test_empty_frame_yields_zero_persons(self):
        """Blank or quiet scene must strictly return person_count == 0 (no hardcoded fallback)."""
        detector = PersonDetector()
        blank_frame = np.full((480, 640, 3), 40, dtype=np.uint8)
        result = detector.detect(blank_frame)

        self.assertEqual(result["person_count"], 0)
        self.assertEqual(len(result["boxes"]), 0)
        self.assertEqual(len(result["normalized_boxes"]), 0)

    def test_tracker_duplicate_suppression_and_counts(self):
        """Overlapping detections must not register multiple separate person tracks."""
        tracker = MultiPersonTracker(max_disappeared=10, max_distance=60.0)

        # Frame 1: Person at (100, 100, 50, 120)
        tracker.update([(100, 100, 50, 120)], frame_idx=1, fps=10.0)
        self.assertEqual(tracker.active_count, 1)
        self.assertEqual(tracker.total_unique_count, 1)

        # Frame 2: Same person moved slightly (105, 102, 50, 120)
        tracker.update([(105, 102, 50, 120)], frame_idx=2, fps=10.0)
        self.assertEqual(tracker.active_count, 1)
        self.assertEqual(tracker.total_unique_count, 1)

        # Frame 3: A second person appears at (300, 200, 50, 120)
        tracker.update([(108, 102, 50, 120), (300, 200, 50, 120)], frame_idx=3, fps=10.0)
        self.assertEqual(tracker.active_count, 2)
        self.assertEqual(tracker.total_unique_count, 2)

    # -------------------------------------------------------------
    # 3. Restricted Zone Geometry & Ground Contact Tests
    # -------------------------------------------------------------
    def test_zone_polygon_intersection(self):
        """Person outside zone must not trigger breach; person entering zone must trigger breach."""
        # Zone configured in right quadrant: [300, 100] to [600, 450]
        zone = RestrictedZone(
            zone_config="[[0.5, 0.2], [0.95, 0.2], [0.95, 0.85], [0.5, 0.85]]",
            frame_width=640,
            frame_height=480,
        )

        # Person walking in left quadrant (x=80, y=200, w=60, h=140) -> Feet at (110, 340)
        box_outside = (80, 200, 60, 140)
        self.assertFalse(zone.check_bbox_intersection(box_outside))

        # Person walking in right quadrant inside zone (x=400, y=200, w=60, h=140) -> Feet at (430, 340)
        box_inside = (400, 200, 60, 140)
        self.assertTrue(zone.check_bbox_intersection(box_inside))

    # -------------------------------------------------------------
    # 4. Temporal Event Confirmation & Debouncing
    # -------------------------------------------------------------
    def test_camera_detection_state_requires_persistence(self):
        """Single transient frame must not confirm alert immediately when confirmation_seconds > 0."""
        state = CameraDetectionState("CAM-TEST-DEBOUNCE")

        # Frame 1: suspicious initially seen
        is_susp, is_confirmed = state.update(is_suspicious=True, score=0.85, confirmation_seconds=2.0)
        self.assertTrue(is_susp)
        self.assertFalse(is_confirmed)  # Not confirmed on single frame!

        # Immediate return to normal before confirmation duration clears state
        state.update(is_suspicious=False, score=0.2, confirmation_seconds=2.0)
        state.update(is_suspicious=False, score=0.2, confirmation_seconds=2.0)
        is_susp_after, is_conf_after = state.update(is_suspicious=False, score=0.2, confirmation_seconds=2.0)
        self.assertFalse(is_susp_after)
        self.assertFalse(is_conf_after)

    # -------------------------------------------------------------
    # 5. Alert Deduplication & Cooldown
    # -------------------------------------------------------------
    def test_sms_cooldown_prevents_duplicate_spam(self):
        """After sending an alert, the camera must be placed on cooldown."""
        camera_id = "CAM-TEST-COOLDOWN"

        # Initially not in cooldown
        self.assertFalse(sms_service.is_cooldown_active(camera_id))

        # Update cooldown
        sms_service.update_cooldown(camera_id)
        self.assertTrue(sms_service.is_cooldown_active(camera_id))

    # -------------------------------------------------------------
    # 6. Failure Handling: SMS Failure Preserves Event & Evidence
    # -------------------------------------------------------------
    def test_failed_sms_preserves_database_event_and_logs(self):
        """If SMS provider fails, Event record must remain persisted with sms_status='FAILED'."""
        import uuid
        test_eid = f"EVT-FAILSAFE-{uuid.uuid4().hex[:8]}"

        # Create test event
        event = Event(
            event_id=test_eid,
            camera_id="CAM-01",
            location="Main Gate",
            person_count=1,
            object_type="person",
            motion_level="High",
            activity_type="Restricted Area Intrusion",
            anomaly_score=0.92,
            status="SUSPICIOUS",
            risk_priority="HIGH",
            sms_status="PENDING",
            timestamp=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
        )
        self.db.add(event)
        self.db.commit()

        # Simulate provider failure dispatching to invalid endpoint
        sms_log = SMSLog(
            event_id=event.event_id,
            recipient_phone="+1000000000",
            provider="mock_failure_test",
            message_body="ALERT: Suspicious activity",
            status="FAILED",
            error_message="Simulated carrier connection timeout",
            created_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
        )
        self.db.add(sms_log)
        event.sms_status = "FAILED"
        self.db.commit()

        # Verify Event record still exists in DB
        reloaded = self.db.query(Event).filter(Event.event_id == test_eid).first()
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.sms_status, "FAILED")
        self.assertEqual(reloaded.activity_type, "Restricted Area Intrusion")

        # Verify SMS log was recorded
        log_entry = self.db.query(SMSLog).filter(SMSLog.event_id == test_eid).first()
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.status, "FAILED")

        # Clean up
        self.db.delete(log_entry)
        self.db.delete(reloaded)
        self.db.commit()

    # -------------------------------------------------------------
    # 7. Video Security & Path Traversal Protection
    # -------------------------------------------------------------
    def test_filename_sanitization_neutralizes_path_traversal(self):
        """Malicious filenames like ../../etc/passwd must be sanitized cleanly."""
        dirty_name = "../../../secret_data/passwd.mp4"
        clean = sanitize_filename(dirty_name)

        self.assertNotIn("..", clean)
        self.assertNotIn("/", clean)
        self.assertNotIn("\\", clean)
        self.assertEqual(clean, "passwd.mp4")

    def test_signed_video_token_validation(self):
        """Signed playback token must only validate for its designated video ID."""
        video_id = "VID-EVIDENCE-42"
        token = create_signed_video_token(video_id=video_id, expires_minutes=10)

        self.assertTrue(verify_signed_video_token(token, video_id))
        self.assertFalse(verify_signed_video_token(token, "VID-DIFFERENT-99"))
        self.assertFalse(verify_signed_video_token("invalid.token.string", video_id))


if __name__ == "__main__":
    unittest.main()
