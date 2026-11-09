import numpy as np
from collections import OrderedDict
from typing import Dict, List, Tuple, Optional, Any


class TrackedPerson:
    """Represents a single tracked person across video frames."""

    def __init__(
        self,
        person_id: int,
        bbox: Tuple[int, int, int, int],
        start_frame: int,
        fps: float,
        confidence: float = 0.85,
    ):
        self.id = person_id
        self.bbox = bbox
        self.confidence = float(confidence)
        self.centroid = (bbox[0] + bbox[2] // 2, bbox[1] + bbox[3] // 2)
        self.start_frame = start_frame
        self.last_frame = start_frame
        self.fps = fps if fps > 0 else 30.0
        self.missing_frames = 0
        self.trajectory: List[Tuple[int, int]] = [self.centroid]
        self.entered_restricted_zone = False
        self.restricted_frames_count = 0

    def update(
        self,
        bbox: Tuple[int, int, int, int],
        frame_idx: int,
        confidence: float = 0.85,
        in_restricted_zone: bool = False,
    ):
        self.bbox = bbox
        self.confidence = float(confidence)
        self.centroid = (bbox[0] + bbox[2] // 2, bbox[1] + bbox[3] // 2)
        self.last_frame = frame_idx
        self.missing_frames = 0
        self.trajectory.append(self.centroid)
        if in_restricted_zone:
            self.entered_restricted_zone = True
            self.restricted_frames_count += 1

    @property
    def duration_seconds(self) -> float:
        """Returns the total active duration in seconds."""
        frames = max(1, (self.last_frame - self.start_frame + 1))
        return frames / self.fps

    def is_loitering(self, min_duration_seconds: float = 4.0, max_span_px: float = 80.0) -> bool:
        """
        Determines whether this tracked person is loitering.
        A person is loitering if active duration exceeds min_duration_seconds
        and their total trajectory remains confined within max_span_px.
        If they walk across the scene (large span), they are in transit, not loitering.
        """
        if self.duration_seconds < min_duration_seconds or len(self.trajectory) < 8:
            return False

        xs = [pt[0] for pt in self.trajectory]
        ys = [pt[1] for pt in self.trajectory]
        span_x = max(xs) - min(xs)
        span_y = max(ys) - min(ys)
        return bool(span_x <= max_span_px and span_y <= max_span_px)


class MultiPersonTracker:
    """Centroid-based multi-person tracker for surveillance video analysis."""

    def __init__(self, max_disappeared: int = 25, max_distance: float = 90.0):
        self.next_person_id = 1
        self.objects: Dict[int, TrackedPerson] = OrderedDict()
        self.completed_tracks: List[TrackedPerson] = []
        self.max_disappeared = max_disappeared
        self.max_distance = max_distance

    @property
    def active_count(self) -> int:
        """Returns number of currently visible tracked persons."""
        return len(self.objects)

    @property
    def total_unique_count(self) -> int:
        """Returns total unique tracks registered across the lifetime of this tracker."""
        return self.next_person_id - 1

    def register(
        self,
        bbox: Tuple[int, int, int, int],
        frame_idx: int,
        fps: float,
        confidence: float = 0.85,
        in_restricted_zone: bool = False,
    ):
        person = TrackedPerson(self.next_person_id, bbox, frame_idx, fps, confidence)
        if in_restricted_zone:
            person.entered_restricted_zone = True
            person.restricted_frames_count = 1
        self.objects[self.next_person_id] = person
        self.next_person_id += 1

    def deregister(self, person_id: int):
        if person_id in self.objects:
            self.completed_tracks.append(self.objects[person_id])
            del self.objects[person_id]

    def update(
        self,
        rects: List[Tuple[int, int, int, int]],
        frame_idx: int,
        fps: float,
        confidences: Optional[List[float]] = None,
        restricted_zone_checker=None,
    ) -> Dict[int, TrackedPerson]:
        """
        Updates trackers with newly detected bounding boxes.
        """
        if confidences is None:
            confidences = [0.85] * len(rects)

        # If no detections in current frame
        if len(rects) == 0:
            for person_id in list(self.objects.keys()):
                self.objects[person_id].missing_frames += 1
                if self.objects[person_id].missing_frames > self.max_disappeared:
                    self.deregister(person_id)
            return self.objects

        # Calculate centroids of input detections
        input_centroids = np.zeros((len(rects), 2), dtype="int")
        for i, (x, y, w, h) in enumerate(rects):
            input_centroids[i] = (int(x + w / 2), int(y + h / 2))

        # If we have no active objects, register all detections
        if len(self.objects) == 0:
            for i, bbox in enumerate(rects):
                in_zone = restricted_zone_checker.check_bbox_intersection(bbox) if restricted_zone_checker else False
                conf = confidences[i] if i < len(confidences) else 0.85
                self.register(bbox, frame_idx, fps, conf, in_zone)
            return self.objects

        # Otherwise, match existing centroids to new centroids
        object_ids = list(self.objects.keys())
        object_centroids = np.array([self.objects[pid].centroid for pid in object_ids])

        # Euclidean distance matrix
        D = np.linalg.norm(object_centroids[:, np.newaxis] - input_centroids, axis=2)

        rows = D.min(axis=1).argsort()
        cols = D.argmin(axis=1)[rows]

        used_rows = set()
        used_cols = set()

        for (row, col) in zip(rows, cols):
            if row in used_rows or col in used_cols:
                continue

            if D[row, col] > self.max_distance:
                continue

            person_id = object_ids[row]
            bbox = rects[col]
            conf = confidences[col] if col < len(confidences) else 0.85
            in_zone = restricted_zone_checker.check_bbox_intersection(bbox) if restricted_zone_checker else False
            self.objects[person_id].update(bbox, frame_idx, conf, in_zone)

            used_rows.add(row)
            used_cols.add(col)

        unused_rows = set(range(0, D.shape[0])).difference(used_rows)
        unused_cols = set(range(0, D.shape[1])).difference(used_cols)

        # Mark unmatched existing objects as missing
        for row in unused_rows:
            person_id = object_ids[row]
            self.objects[person_id].missing_frames += 1
            if self.objects[person_id].missing_frames > self.max_disappeared:
                self.deregister(person_id)

        # Register new unmatched detections
        for col in unused_cols:
            bbox = rects[col]
            conf = confidences[col] if col < len(confidences) else 0.85
            in_zone = restricted_zone_checker.check_bbox_intersection(bbox) if restricted_zone_checker else False
            self.register(bbox, frame_idx, fps, conf, in_zone)

        return self.objects

    def get_all_tracks(self) -> List[TrackedPerson]:
        """Returns all completed and currently active tracks."""
        return list(self.completed_tracks) + list(self.objects.values())
