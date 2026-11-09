import os
import uuid
import datetime
import cv2
import numpy as np
from typing import Dict, Any, List, Optional
from .restricted_zone import RestrictedZone
from .detector import PersonDetector
from .tracker import MultiPersonTracker


def format_duration(seconds: float) -> str:
    """Formats duration seconds into MM:SS format."""
    sec = int(round(seconds))
    mins = sec // 60
    rem_sec = sec % 60
    return f"{mins:02d}:{rem_sec:02d}"


def determine_activity_type(
    person_count: int,
    duration_sec: float,
    restricted_breached: bool,
    motion_level: str,
    is_loitering: bool = False,
) -> str:
    """Infers the high-level activity type based on genuine detection metrics."""
    if restricted_breached and person_count > 0:
        if person_count >= 2:
            return "Unauthorized Group Intrusion"
        return "Restricted Area Entry"

    if is_loitering or (duration_sec > 45.0 and person_count in (1, 2) and motion_level in ("Low", "Medium")):
        return "Loitering"

    if person_count >= 3:
        return "Group Gathering"

    if person_count > 0:
        if motion_level == "High":
            return "Rapid Movement"
        return "Normal Movement"

    if motion_level == "High":
        return "Scene Motion"
    return "Idle Scene"



class VideoProcessingPipeline:
    """Complete video processing pipeline for automatic metadata generation."""

    def __init__(self, thumbnails_dir: str):
        self.thumbnails_dir = thumbnails_dir
        os.makedirs(self.thumbnails_dir, exist_ok=True)
        self.detector = PersonDetector()

    def process_video(
        self,
        video_path: str,
        camera_id: str,
        camera_location: str,
        restricted_zone_coords: Optional[str] = None,
        custom_timestamp: Optional[datetime.datetime] = None,
        frame_skip: int = 2
    ) -> Dict[str, Any]:
        """
        Processes a surveillance video file, extracts people & movement,
        and automatically produces structured event metadata.
        """
        if not os.path.exists(video_path):
            raise FileNotFoundError(f"Video file not found: {video_path}")

        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise ValueError(f"Could not open video file: {video_path}")

        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)) or 640
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)) or 480
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0

        # Initialize zone checker and tracker
        zone = RestrictedZone(restricted_zone_coords, frame_width=frame_width, frame_height=frame_height)
        tracker = MultiPersonTracker(max_disappeared=20, max_distance=100.0)

        frame_idx = 0
        motion_scores = []
        motion_levels = []
        max_concurrent_people = 0
        peak_frame = None
        peak_boxes = []
        restricted_breached = False

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            frame_idx += 1

            # Process every frame_skip-th frame for speed
            if frame_idx % frame_skip != 0:
                continue

            # Run detector
            det_res = self.detector.detect(frame)
            boxes = det_res["boxes"]
            motion_score = det_res["motion_score"]
            motion_level = det_res["motion_level"]

            motion_scores.append(motion_score)
            motion_levels.append(motion_level)

            # Update tracker
            active_objects = tracker.update(
                boxes,
                frame_idx=frame_idx,
                fps=fps / frame_skip,
                restricted_zone_checker=zone
            )

            concurrent_count = len(active_objects)
            if concurrent_count > max_concurrent_people:
                max_concurrent_people = concurrent_count
                peak_frame = frame.copy()
                peak_boxes = list(boxes)

            # Check if any active box is in restricted zone
            for box in boxes:
                if zone.check_bbox_intersection(box):
                    restricted_breached = True
                    # If this is the first restricted breach, prioritize this frame for thumbnail
                    if peak_frame is None or not restricted_breached:
                        peak_frame = frame.copy()
                        peak_boxes = list(boxes)

        cap.release()

        # Gather all tracks
        all_tracks = tracker.get_all_tracks()
        unique_people_count = len(all_tracks)

        # Use genuine detected person count from tracker and detections
        final_person_count = max(unique_people_count, max_concurrent_people)
        has_loitering_track = any(t.is_loitering() for t in all_tracks)

        # Calculate duration
        if all_tracks:
            max_track_duration = max(t.duration_seconds for t in all_tracks)
            total_duration_sec = max_track_duration
        else:
            total_duration_sec = (total_frames / fps) if fps > 0 else 0.0

        # Motion level aggregation
        if motion_levels:
            high_count = motion_levels.count("High")
            med_count = motion_levels.count("Medium")
            low_count = motion_levels.count("Low")
            if high_count >= med_count and high_count >= low_count:
                overall_motion = "High"
            elif med_count >= low_count:
                overall_motion = "Medium"
            else:
                overall_motion = "Low"
        else:
            overall_motion = "Low"

        # Restricted area check from tracks
        for t in all_tracks:
            if t.entered_restricted_zone:
                restricted_breached = True

        activity_type = determine_activity_type(
            person_count=final_person_count,
            duration_sec=total_duration_sec,
            restricted_breached=restricted_breached,
            motion_level=overall_motion,
            is_loitering=has_loitering_track,
        )

        # Generate annotated thumbnail
        thumbnail_filename = f"thumb_{camera_id}_{uuid.uuid4().hex[:8]}.jpg"
        thumbnail_full_path = os.path.join(self.thumbnails_dir, thumbnail_filename)

        if peak_frame is not None:
            annotated_frame = peak_frame.copy()
            # Draw restricted zone polygon (Red with semi-transparent overlay)
            if zone.points and len(zone.points) >= 3:
                pts = np.array(zone.points, np.int32).reshape((-1, 1, 2))
                overlay = annotated_frame.copy()
                cv2.fillPoly(overlay, [pts], (0, 0, 180))
                cv2.addWeighted(overlay, 0.3, annotated_frame, 0.7, 0, annotated_frame)
                cv2.polylines(annotated_frame, [pts], True, (0, 0, 255), 2)
                # Zone label
                cv2.putText(
                    annotated_frame,
                    "RESTRICTED ZONE",
                    (zone.points[0][0] + 5, zone.points[0][1] + 20),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    (0, 0, 255),
                    2
                )

            # Draw bounding boxes
            for (bx, by, bw, bh) in peak_boxes:
                in_res = zone.check_bbox_intersection((bx, by, bw, bh))
                box_color = (0, 0, 255) if in_res else (0, 255, 0)
                cv2.rectangle(annotated_frame, (bx, by), (bx + bw, by + bh), box_color, 2)
                label = "RESTRICTED" if in_res else "PERSON"
                cv2.putText(
                    annotated_frame,
                    label,
                    (bx, max(15, by - 5)),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    box_color,
                    2
                )

            # Draw camera and event watermark
            time_str = (custom_timestamp or datetime.datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S")
            cv2.putText(
                annotated_frame,
                f"{camera_id} | {time_str}",
                (10, 25),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                (255, 255, 255),
                2
            )
            cv2.imwrite(thumbnail_full_path, annotated_frame)
        else:
            # Create a blank fallback placeholder image
            blank = np.zeros((frame_height, frame_width, 3), dtype=np.uint8)
            cv2.putText(blank, f"{camera_id} - No People Detected", (30, frame_height // 2), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            cv2.imwrite(thumbnail_full_path, blank)

        event_timestamp = custom_timestamp or datetime.datetime.utcnow()

        return {
            "camera_id": camera_id,
            "timestamp": event_timestamp,
            "location": camera_location,
            "person_count": int(max(1, final_person_count)) if final_person_count > 0 else 0,
            "object_type": "person",
            "motion_level": overall_motion,
            "activity_type": activity_type,
            "event_duration": int(round(total_duration_sec)),
            "event_duration_formatted": format_duration(total_duration_sec),
            "restricted_area": 1 if restricted_breached else 0,
            "thumbnail_path": f"/thumbnails/{thumbnail_filename}",
            "video_filename": os.path.basename(video_path),
        }
