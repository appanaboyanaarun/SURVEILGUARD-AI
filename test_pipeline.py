import os
import sys
import datetime

# Ensure project root is on Python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.database.connection import SessionLocal, Base, engine, DATA_DIR
from app.models.schema import Camera, Event, Review, User
from video_processing.event_generator import VideoProcessingPipeline
from ml.anomaly_detection import AnomalyDetector
from ml.prediction import evaluate_event_anomaly
from scripts.seed_database import seed_database


def run_pipeline_test():
    print("=========================================================")
    print("SURVEILLANCE METADATA ANOMALY DETECTION - PIPELINE TEST")
    print("=========================================================")

    # Step 1: Ensure database & test videos are seeded
    print("\n[Step 1] Seeding database and sample videos...")
    seed_database()

    # Step 2: Initialize Video Processing Pipeline & ML Detector
    print("\n[Step 2] Initializing Video Processing Pipeline and ML Detector...")
    thumbnails_dir = os.path.join(DATA_DIR, "thumbnails")
    models_dir = os.path.join(DATA_DIR, "models")
    pipeline = VideoProcessingPipeline(thumbnails_dir=thumbnails_dir)
    detector = AnomalyDetector(model_dir=models_dir)

    # Step 3: Test Video Processing on Normal Video
    print("\n[Step 3] Processing CAM-01 Normal Video (Daytime)...")
    cam01_video = os.path.join(DATA_DIR, "sample_videos", "cam01_main_gate_normal_day.mp4")
    res_normal = pipeline.process_video(
        video_path=cam01_video,
        camera_id="CAM-01",
        camera_location="Main Entrance Gate",
        custom_timestamp=datetime.datetime(2026, 9, 20, 11, 20, 15),
    )
    print("Extracted Metadata for Normal Video:")
    for k, v in res_normal.items():
        print(f"  {k}: {v}")

    eval_normal = evaluate_event_anomaly(res_normal, detector)
    print(f"ML Anomaly Result -> Status: {eval_normal['status']}, Score: {eval_normal['anomaly_score']}, Priority: {eval_normal['risk_priority']}")
    print(f"Reasons: {eval_normal['anomaly_reasons']}")
    assert eval_normal["status"] == "NORMAL", "Expected normal status for daytime passage!"

    # Step 4: Test Video Processing on Night Intrusion Video
    print("\n[Step 4] Processing CAM-03 Night Restricted Intrusion Video...")
    cam03_video = os.path.join(DATA_DIR, "sample_videos", "cam03_storage_night_intrusion.mp4")
    res_intrusion = pipeline.process_video(
        video_path=cam03_video,
        camera_id="CAM-03",
        camera_location="Storage Area",
        restricted_zone_coords="[[0.45, 0.15], [0.95, 0.15], [0.95, 0.85], [0.45, 0.85]]",
        custom_timestamp=datetime.datetime(2026, 9, 20, 23, 42, 15),
    )
    print("Extracted Metadata for Intrusion Video:")
    for k, v in res_intrusion.items():
        print(f"  {k}: {v}")

    eval_intrusion = evaluate_event_anomaly(res_intrusion, detector)
    print(f"ML Anomaly Result -> Status: {eval_intrusion['status']}, Score: {eval_intrusion['anomaly_score']}, Priority: {eval_intrusion['risk_priority']}")
    print(f"Reasons: {eval_intrusion['anomaly_reasons']}")
    assert eval_intrusion["status"] == "SUSPICIOUS", "Expected SUSPICIOUS status for night restricted intrusion!"
    assert eval_intrusion["risk_priority"] == "HIGH", "Expected HIGH risk priority!"
    assert res_intrusion["restricted_area"] == 1, "Expected restricted_area to be 1!"

    print("\n=========================================================")
    print("ALL TESTS PASSED SUCCESSFULLY! FULL PIPELINE VERIFIED.")
    print("=========================================================")


if __name__ == "__main__":
    run_pipeline_test()
