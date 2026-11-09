import threading
import time
import cv2
import datetime
import os
import uuid
import collections
from typing import Dict, Any

from app.database.connection import SessionLocal, DATA_DIR
from app.models.schema import Camera
from app.schemas.dto import EventCreate
from app.services.event_service import EventService
from video_processing.detector import PersonDetector
from video_processing.tracker import MultiPersonTracker
from video_processing.restricted_zone import RestrictedZone
from ml.anomaly_detection import AnomalyDetector
from ml.prediction import evaluate_event_anomaly
from app.services.notification_service import notification_service

UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
THUMBNAILS_DIR = os.path.join(DATA_DIR, "thumbnails")
MODELS_DIR = os.path.join(DATA_DIR, "models")

class LiveCameraWorker(threading.Thread):
    def __init__(self, camera_id: str, stream_url: str, location: str, restricted_zone_coords: str):
        super().__init__()
        self.camera_id = camera_id
        self.stream_url = stream_url
        self.location = location
        self.restricted_zone_coords = restricted_zone_coords
        self.is_running = False
        self.detector = PersonDetector()
        self.anomaly_detector = AnomalyDetector(model_dir=MODELS_DIR)
        
        # Buffer for pre-event recording (5 seconds @ ~15 fps = 75 frames)
        self.fps = 15
        self.frame_buffer = collections.deque(maxlen=75)
        self.is_recording = False
        self.recording_frames = []
        self.event_start_time = None
        self.max_record_frames = 150 # 10 seconds after detection

        self.current_frame = None
        self.status = "CONNECTING"
        self.daemon = True

    def run(self):
        self.is_running = True
        
        while self.is_running:
            self._process_stream()
            if self.is_running:
                # If stream disconnected, wait before reconnect
                self.status = "ERROR"
                self.update_db_status("ERROR")
                time.sleep(5)

    def stop(self):
        self.is_running = False
        self.status = "OFFLINE"
        self.update_db_status("OFFLINE")

    def update_db_status(self, status: str):
        db = SessionLocal()
        try:
            cam = db.query(Camera).filter(Camera.camera_id == self.camera_id).first()
            if cam:
                cam.status = status
                db.commit()
        finally:
            db.close()

    def _process_stream(self):
        try:
            source = int(self.stream_url) if self.stream_url and self.stream_url.isdigit() else self.stream_url
            
            if self.stream_url == "sample":
                source = os.path.join(DATA_DIR, "sample_videos", "cam03_storage_night_intrusion.mp4")
            
            if not source:
                return

            cap = cv2.VideoCapture(source)
            if not cap.isOpened():
                return
            
            self.status = "LIVE"
            self.update_db_status("LIVE")
            
            frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)) or 640
            frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)) or 480
            
            zone = RestrictedZone(self.restricted_zone_coords, frame_width=frame_width, frame_height=frame_height)
            tracker = MultiPersonTracker(max_disappeared=20, max_distance=100.0)
            
            frame_idx = 0
            frame_skip = 2
            
            max_concurrent_people = 0
            motion_scores = []
            motion_levels = []
            restricted_breached = False
            
            while self.is_running and cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    break
                
                self.current_frame = frame.copy()
                self.frame_buffer.append(frame.copy())
                
                if self.is_recording:
                    self.recording_frames.append(frame.copy())
                    if len(self.recording_frames) >= self.max_record_frames:
                        self._save_event(tracker, max_concurrent_people, motion_scores, motion_levels, restricted_breached)
                        self.is_recording = False
                        self.recording_frames = []
                        max_concurrent_people = 0
                        motion_scores = []
                        motion_levels = []
                        restricted_breached = False
                        tracker = MultiPersonTracker(max_disappeared=20, max_distance=100.0)

                frame_idx += 1
                if frame_idx % frame_skip != 0:
                    continue
                
                det_res = self.detector.detect(frame)
                boxes = det_res["boxes"]
                
                if self.is_recording:
                    motion_scores.append(det_res["motion_score"])
                    motion_levels.append(det_res["motion_level"])
                
                active_objects = tracker.update(
                    boxes,
                    frame_idx=frame_idx,
                    fps=self.fps / frame_skip,
                    restricted_zone_checker=zone
                )
                
                is_suspicious_now = False
                concurrent_count = len(active_objects)
                if concurrent_count > max_concurrent_people:
                    max_concurrent_people = concurrent_count
                
                for box in boxes:
                    if zone.check_bbox_intersection(box):
                        restricted_breached = True
                        is_suspicious_now = True
                
                if concurrent_count >= 3:
                    is_suspicious_now = True
                    
                if det_res["motion_score"] > 0.3:
                    is_suspicious_now = True
                    
                if is_suspicious_now and not self.is_recording:
                    self.is_recording = True
                    self.event_start_time = datetime.datetime.utcnow()
                    self.recording_frames.extend(list(self.frame_buffer))
                    motion_scores.append(det_res["motion_score"])
                    motion_levels.append(det_res["motion_level"])
                    
        finally:
            if 'cap' in locals() and cap.isOpened():
                cap.release()

    def _save_event(self, tracker, max_concurrent, motion_scores, motion_levels, restricted_breached):
        if not self.recording_frames:
            return
            
        timestamp_str = self.event_start_time.strftime("%Y%m%d_%H%M%S")
        video_filename = f"{self.camera_id}_{timestamp_str}.mp4"
        
        date_folder = self.event_start_time.strftime("%Y-%m-%d")
        camera_dir = os.path.join(UPLOADS_DIR, self.camera_id, date_folder, "suspicious")
        os.makedirs(camera_dir, exist_ok=True)
        video_path = os.path.join(camera_dir, video_filename)
        
        h, w = self.recording_frames[0].shape[:2]
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(video_path, fourcc, self.fps, (w, h))
        for f in self.recording_frames:
            out.write(f)
        out.release()
        
        thumbnail_filename = f"thumb_{self.camera_id}_{timestamp_str}.jpg"
        thumbnail_path = os.path.join(THUMBNAILS_DIR, thumbnail_filename)
        cv2.imwrite(thumbnail_path, self.recording_frames[len(self.recording_frames)//2])
        
        all_tracks = tracker.get_all_tracks()
        final_person_count = max(len(all_tracks), max_concurrent)
        
        total_duration_sec = len(self.recording_frames) / self.fps
        mins = int(total_duration_sec // 60)
        secs = int(total_duration_sec % 60)
        formatted_duration = f"{mins:02d}:{secs:02d}"
        
        overall_motion = "Low"
        if motion_levels:
            high_count = motion_levels.count("High")
            med_count = motion_levels.count("Medium")
            low_count = motion_levels.count("Low")
            if high_count >= med_count and high_count >= low_count:
                overall_motion = "High"
            elif med_count >= low_count:
                overall_motion = "Medium"
                
        activity_type = "Suspicious Activity"
        if restricted_breached:
            activity_type = "Restricted Area Entry"
        elif final_person_count >= 3:
            activity_type = "Group Gathering"
        
        meta = {
            "camera_id": self.camera_id,
            "timestamp": self.event_start_time,
            "location": self.location,
            "person_count": max(1, final_person_count),
            "object_type": "person",
            "motion_level": overall_motion,
            "activity_type": activity_type,
            "event_duration": int(total_duration_sec),
            "event_duration_formatted": formatted_duration,
            "restricted_area": 1 if restricted_breached else 0,
        }
        
        ml_eval = evaluate_event_anomaly(meta, detector=self.anomaly_detector)
        
        db = SessionLocal()
        try:
            event_create_data = EventCreate(
                camera_id=meta["camera_id"],
                timestamp=meta["timestamp"],
                location=meta["location"],
                person_count=meta["person_count"],
                object_type=meta["object_type"],
                motion_level=meta["motion_level"],
                activity_type=meta["activity_type"],
                event_duration=meta["event_duration"],
                event_duration_formatted=meta["event_duration_formatted"],
                restricted_area=meta["restricted_area"],
                anomaly_score=ml_eval["anomaly_score"],
                status=ml_eval["status"],
                risk_priority=ml_eval["risk_priority"],
                anomaly_reasons=ml_eval["anomaly_reasons"],
                video_filename=os.path.relpath(video_path, DATA_DIR).replace('\\', '/'),
                thumbnail_path=f"/thumbnails/{thumbnail_filename}",
            )
            created_event = EventService.create_event(db, event_create_data)

            # --- Dispatch Notifications for suspicious events ---
            if ml_eval["status"] == "SUSPICIOUS":
                # Incident creation persists the record before scheduling its email alert.
                # FCM Push Notification
                try:
                    incident = notification_service.create_incident(
                        event_id=created_event.event_id,
                        camera_id=meta["camera_id"],
                        location=meta["location"],
                        activity_type=meta["activity_type"],
                        anomaly_score=ml_eval["anomaly_score"],
                        screenshot_path=f"/thumbnails/{thumbnail_filename}",
                        video_clip_path=os.path.relpath(video_path, DATA_DIR).replace('\\', '/'),
                    )
                    if incident:
                        notification_service.send_suspicious_activity_alert(incident)
                except Exception:
                    pass  # notification failure must never stop camera processing
        finally:
            db.close()

class StreamManager:
    def __init__(self):
        self.workers = {} 

    def start_camera(self, camera: Camera):
        if camera.camera_id in self.workers:
            return
            
        stream_url = camera.stream_url
        if not stream_url:
            return
            
        worker = LiveCameraWorker(
            camera_id=camera.camera_id,
            stream_url=stream_url,
            location=camera.location,
            restricted_zone_coords=camera.restricted_zone_coords
        )
        self.workers[camera.camera_id] = worker
        worker.start()

    def stop_camera(self, camera_id: str):
        if camera_id in self.workers:
            self.workers[camera_id].stop()
            del self.workers[camera_id]

    def get_frame(self, camera_id: str):
        if camera_id in self.workers:
            return self.workers[camera_id].current_frame
        return None

stream_manager = StreamManager()
