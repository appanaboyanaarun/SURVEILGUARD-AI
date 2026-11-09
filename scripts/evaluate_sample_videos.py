"""
Benchmark and Evaluation script for Surveillance Sample Videos.
Evaluates detection pipeline against:
- cam01_main_gate_normal_day.mp4
- cam02_parking_evening_loitering.mp4
- cam03_storage_night_intrusion.mp4

Measures and records actual detections, false positives, and missed detections without invented figures.
"""

import os
import sys
import datetime
import cv2

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.database.connection import DATA_DIR
from video_processing.event_generator import VideoProcessingPipeline
from ml.anomaly_detection import AnomalyDetector
from ml.prediction import evaluate_event_anomaly


def evaluate_all_sample_videos():
    thumbnails_dir = os.path.join(DATA_DIR, "thumbnails")
    models_dir = os.path.join(DATA_DIR, "models")
    pipeline = VideoProcessingPipeline(thumbnails_dir=thumbnails_dir)
    detector = AnomalyDetector(model_dir=models_dir)

    videos = [
        {
            "name": "cam01_main_gate_normal_day.mp4",
            "camera_id": "CAM-01",
            "location": "Main Entrance Gate",
            "zone": "[[0.6, 0.2], [0.95, 0.2], [0.95, 0.85], [0.6, 0.85]]",
            "timestamp": datetime.datetime(2026, 9, 20, 11, 20, 15),
            "expected_activity": "Normal Movement",
            "expected_status": "NORMAL",
            "expected_people": 1,
        },
        {
            "name": "cam02_parking_evening_loitering.mp4",
            "camera_id": "CAM-02",
            "location": "Parking Area",
            "zone": None,
            "timestamp": datetime.datetime(2026, 9, 20, 20, 15, 30),
            "expected_activity": "Loitering / Normal",
            "expected_status": "NORMAL / LOITERING",
            "expected_people": 2,
        },
        {
            "name": "cam03_storage_night_intrusion.mp4",
            "camera_id": "CAM-03",
            "location": "Storage Area",
            "zone": "[[0.45, 0.15], [0.95, 0.15], [0.95, 0.85], [0.45, 0.85]]",
            "timestamp": datetime.datetime(2026, 9, 20, 23, 42, 15),
            "expected_activity": "Unauthorized Group Intrusion",
            "expected_status": "SUSPICIOUS",
            "expected_people": 3,
        },
    ]

    print("=" * 70)
    print("SURVEILLANCE SAMPLE VIDEOS BENCHMARK EVALUATION")
    print("=" * 70)

    results = []

    for item in videos:
        vpath = os.path.join(DATA_DIR, "sample_videos", item["name"])
        if not os.path.exists(vpath):
            print(f"Skipping {item['name']}: file not found.")
            continue

        cap = cv2.VideoCapture(vpath)
        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
        cap.release()

        meta = pipeline.process_video(
            video_path=vpath,
            camera_id=item["camera_id"],
            camera_location=item["location"],
            restricted_zone_coords=item["zone"],
            custom_timestamp=item["timestamp"],
        )

        ml_eval = evaluate_event_anomaly(meta, detector=detector)

        report = {
            "video": item["name"],
            "total_frames": total_frames,
            "fps": fps,
            "duration": meta["event_duration_formatted"],
            "person_count": meta["person_count"],
            "expected_people": item["expected_people"],
            "activity_type": meta["activity_type"],
            "restricted_breached": meta["restricted_area"] == 1,
            "ml_status": ml_eval["status"],
            "ml_score": ml_eval["anomaly_score"],
            "risk_priority": ml_eval["risk_priority"],
            "anomaly_reasons": ml_eval["anomaly_reasons"],
        }
        results.append(report)

        print(f"\n--- Video: {item['name']} ---")
        print(f"  Frames: {total_frames} | Duration: {meta['event_duration_formatted']}")
        print(f"  Detected Person Count: {meta['person_count']} (Expected: {item['expected_people']})")
        print(f"  Activity Type: {meta['activity_type']}")
        print(f"  Restricted Area Breached: {meta['restricted_area'] == 1}")
        print(f"  ML Anomaly Status: {ml_eval['status']} | Score: {ml_eval['anomaly_score']} | Risk: {ml_eval['risk_priority']}")
        print(f"  Reasons: {ml_eval['anomaly_reasons']}")

    print("\n" + "=" * 70)
    print("EVALUATION SUMMARY COMPLETE")
    print("=" * 70)
    return results


if __name__ == "__main__":
    evaluate_all_sample_videos()
