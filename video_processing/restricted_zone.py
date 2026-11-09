"""
Restricted Zone geometry and collision detection.

Supports normalized ([0.0, 1.0]) and absolute pixel coordinate polygons.
Performs point-in-polygon tests using OpenCV pointPolygonTest with ray-casting fallback.
"""

import json
import cv2
import numpy as np
from typing import List, Tuple, Optional, Any


class RestrictedZone:
    """Manages restricted zone geometry and collision detection."""

    def __init__(self, zone_config: Optional[Any] = None, frame_width: int = 640, frame_height: int = 480):
        self.frame_width = max(1, int(frame_width))
        self.frame_height = max(1, int(frame_height))
        self.points: List[Tuple[int, int]] = []
        self.normalized_points: List[Tuple[float, float]] = []
        self._parse_config(zone_config)

    def _parse_config(self, zone_config: Optional[Any]):
        """Parses JSON coordinates. Supports normalized [0.0-1.0] or absolute pixel coords."""
        if not zone_config:
            # Default restricted zone (top-right section)
            self.normalized_points = [
                (0.55, 0.20),
                (0.95, 0.20),
                (0.95, 0.85),
                (0.55, 0.85),
            ]
            self.points = [
                (int(self.frame_width * 0.55), int(self.frame_height * 0.20)),
                (int(self.frame_width * 0.95), int(self.frame_height * 0.20)),
                (int(self.frame_width * 0.95), int(self.frame_height * 0.85)),
                (int(self.frame_width * 0.55), int(self.frame_height * 0.85)),
            ]
            return

        try:
            parsed = zone_config
            if isinstance(zone_config, str):
                parsed = json.loads(zone_config)

            # Check if list of [x, y] points
            if isinstance(parsed, list) and len(parsed) >= 3:
                pixel_pts = []
                norm_pts = []
                for pt in parsed:
                    x, y = float(pt[0]), float(pt[1])
                    if 0.0 <= x <= 1.0 and 0.0 <= y <= 1.0:
                        norm_pts.append((round(x, 4), round(y, 4)))
                        pixel_pts.append((int(round(x * self.frame_width)), int(round(y * self.frame_height))))
                    else:
                        norm_pts.append((round(x / self.frame_width, 4), round(y / self.frame_height, 4)))
                        pixel_pts.append((int(round(x)), int(round(y))))
                self.points = pixel_pts
                self.normalized_points = norm_pts
            elif isinstance(parsed, dict) and "rect" in parsed:
                # [x, y, w, h] format
                r = parsed["rect"]
                rx, ry, rw, rh = float(r[0]), float(r[1]), float(r[2]), float(r[3])
                if 0.0 <= rx <= 1.0:
                    self.normalized_points = [
                        (rx, ry),
                        (rx + rw, ry),
                        (rx + rw, ry + rh),
                        (rx, ry + rh),
                    ]
                    self.points = [
                        (int(rx * self.frame_width), int(ry * self.frame_height)),
                        (int((rx + rw) * self.frame_width), int(ry * self.frame_height)),
                        (int((rx + rw) * self.frame_width), int((ry + rh) * self.frame_height)),
                        (int(rx * self.frame_width), int((ry + rh) * self.frame_height)),
                    ]
                else:
                    self.points = [
                        (int(rx), int(ry)),
                        (int(rx + rw), int(ry)),
                        (int(rx + rw), int(ry + rh)),
                        (int(rx), int(ry + rh)),
                    ]
                    self.normalized_points = [
                        (round(p[0] / self.frame_width, 4), round(p[1] / self.frame_height, 4))
                        for p in self.points
                    ]
        except Exception:
            # Fallback default
            self.normalized_points = [
                (0.55, 0.20),
                (0.95, 0.20),
                (0.95, 0.85),
                (0.55, 0.85),
            ]
            self.points = [
                (int(self.frame_width * 0.55), int(self.frame_height * 0.20)),
                (int(self.frame_width * 0.95), int(self.frame_height * 0.20)),
                (int(self.frame_width * 0.95), int(self.frame_height * 0.85)),
                (int(self.frame_width * 0.55), int(self.frame_height * 0.85)),
            ]

    def contains_point(self, point: Tuple[int, int]) -> bool:
        """Determines whether a point (x, y) is inside the restricted zone polygon."""
        if not self.points or len(self.points) < 3:
            return False

        try:
            poly_np = np.array(self.points, dtype=np.int32)
            dist = cv2.pointPolygonTest(poly_np, (float(point[0]), float(point[1])), False)
            return dist >= 0
        except Exception:
            # Ray-casting fallback
            x, y = point
            n = len(self.points)
            inside = False
            p1x, p1y = self.points[0]
            for i in range(1, n + 1):
                p2x, p2y = self.points[i % n]
                if y > min(p1y, p2y) and y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        if p1x == p2x or x <= xinters:
                            inside = not inside
                p1x, p1y = p2x, p2y
            return inside

    def check_bbox_intersection(self, bbox: Tuple[int, int, int, int]) -> bool:
        """
        Checks if bottom-center (person's ground position) or centroid is in the zone.
        In CCTV analysis, bottom-center represents the person's feet on the ground plane.
        """
        x, y, w, h = bbox
        bottom_center = (int(x + w / 2), int(y + h))
        center = (int(x + w / 2), int(y + h / 2))
        return self.contains_point(bottom_center) or self.contains_point(center)
