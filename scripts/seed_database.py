import os
import sys
import datetime
import random

# Ensure project root is on Python path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.database.connection import Base, engine, SessionLocal, DATA_DIR
from app.models.schema import Camera, Event, Review, User
from app.routes.auth import hash_password
from ml.anomaly_detection import AnomalyDetector
from ml.prediction import evaluate_event_anomaly
from scripts.generate_sample_videos import (
    generate_video_1_normal_day,
    generate_video_2_night_intrusion,
    generate_video_3_parking_loitering,
)


def seed_database():
    print("Initializing Database tables...")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # 1. Seed Users
    print("Seeding Users...")
    db.query(Review).delete()
    db.query(Event).delete()
    db.query(Camera).delete()
    db.query(User).delete()
    db.commit()

    admin_user = User(
        username="admin",
        password_hash=hash_password("admin123"),
        full_name="Admin",
        role="admin",
        is_active=True,
    )
    op_user = User(
        username="operator",
        password_hash=hash_password("operator123"),
        full_name="Duty Security Operator",
        role="operator",
        is_active=True,
    )
    db.add_all([admin_user, op_user])
    db.commit()

    # 2. Seed Cameras
    print("Seeding Cameras...")
    cameras = [
        Camera(
            camera_id="CAM-01",
            name="Main Gate Camera",
            location="Main Entrance Gate",
            description="Monitors primary facility entrance, turnstiles, and employee arrival",
            camera_type="CCTV",
            restricted_zone_coords="[[0.6, 0.2], [0.95, 0.2], [0.95, 0.85], [0.6, 0.85]]",
            is_active=True,
        ),
        Camera(
            camera_id="CAM-02",
            name="Parking Lot West",
            location="Parking Area",
            description="Monitors outdoor parking lanes and vehicle bays",
            camera_type="CCTV",
            restricted_zone_coords="[[0.7, 0.3], [0.98, 0.3], [0.98, 0.9], [0.7, 0.9]]",
            is_active=True,
        ),
        Camera(
            camera_id="CAM-03",
            name="Storage Room Vault",
            location="Storage Area",
            description="High security vault and hazardous materials storage room",
            camera_type="CCTV",
            restricted_zone_coords="[[0.45, 0.15], [0.95, 0.15], [0.95, 0.85], [0.45, 0.85]]",
            is_active=True,
        ),
        Camera(
            camera_id="CAM-04",
            name="Server Room Corridor",
            location="IT Infrastructure",
            description="Restricted corridor leading to primary data center server racks",
            camera_type="CCTV",
            restricted_zone_coords="[[0.5, 0.2], [0.95, 0.2], [0.95, 0.85], [0.5, 0.85]]",
            is_active=True,
        ),
    ]
    db.add_all(cameras)
    db.commit()

    # 3. Train ML Anomaly Detector
    print("Training ML Anomaly Detection Model (Baseline)...")
    models_dir = os.path.join(DATA_DIR, "models")
    detector = AnomalyDetector(model_dir=models_dir, algorithm="isolation_forest")
    detector.train_baseline()

    # 4. Seed Historical Events
    print("Seeding Historical Event Metadata Records...")
    now = datetime.datetime.utcnow()
    historical_events = []

    # A. Normal Daytime Historical Events (45 events)
    for i in range(45):
        cam = random.choice(cameras)
        day_offset = random.randint(0, 6)
        hour = random.randint(8, 18)
        minute = random.randint(0, 59)
        sec = random.randint(0, 59)
        ts = now - datetime.timedelta(days=day_offset, hours=(now.hour - hour), minutes=(now.minute - minute))

        person_count = random.choices([1, 2], weights=[0.85, 0.15])[0]
        duration = random.randint(12, 45)
        motion = random.choice(["Low", "Medium"])
        activity = "Normal Movement" if cam.camera_id != "CAM-01" else random.choice(["Normal Movement", "Person Entry"])

        ev_dict = {
            "camera_id": cam.camera_id,
            "timestamp": ts,
            "location": cam.location,
            "person_count": person_count,
            "motion_level": motion,
            "activity_type": activity,
            "event_duration": duration,
            "restricted_area": 0,
        }
        eval_res = evaluate_event_anomaly(ev_dict, detector)

        mins = duration // 60
        secs = duration % 60
        event_obj = Event(
            event_id=f"EVT-{(i + 1):04d}",
            camera_id=cam.camera_id,
            timestamp=ts,
            location=cam.location,
            person_count=person_count,
            object_type="person",
            motion_level=motion,
            activity_type=activity,
            event_duration=duration,
            event_duration_formatted=f"{mins:02d}:{secs:02d}",
            restricted_area=0,
            anomaly_score=eval_res["anomaly_score"],
            status="NORMAL",
            risk_priority="LOW",
            anomaly_reasons=eval_res["anomaly_reasons"],
            video_filename="routine_patrol.mp4",
            thumbnail_path=None,
        )
        historical_events.append(event_obj)

    # B. Notable Suspicious Historical Events
    suspicious_samples = [
        {
            "event_id": "EVT-0046",
            "camera_id": "CAM-03",
            "location": "Storage Area",
            "hour": 23,
            "minute": 42,
            "person_count": 3,
            "motion": "High",
            "activity": "Unauthorized Group Intrusion",
            "duration": 277,
            "duration_str": "04:37",
            "restricted": 1,
            "days_ago": 1,
        },
        {
            "event_id": "EVT-0047",
            "camera_id": "CAM-04",
            "location": "IT Infrastructure",
            "hour": 2,
            "minute": 15,
            "person_count": 1,
            "motion": "Medium",
            "activity": "Restricted Area Entry",
            "duration": 195,
            "duration_str": "03:15",
            "restricted": 1,
            "days_ago": 2,
        },
        {
            "event_id": "EVT-0048",
            "camera_id": "CAM-02",
            "location": "Parking Area",
            "hour": 21,
            "minute": 50,
            "person_count": 4,
            "motion": "High",
            "activity": "Group Gathering",
            "duration": 360,
            "duration_str": "06:00",
            "restricted": 0,
            "days_ago": 0,
        },
    ]

    for s in suspicious_samples:
        ts = now - datetime.timedelta(days=s["days_ago"], hours=(now.hour - s["hour"]), minutes=(now.minute - s["minute"]))
        ev_dict = {
            "camera_id": s["camera_id"],
            "timestamp": ts,
            "location": s["location"],
            "person_count": s["person_count"],
            "motion_level": s["motion"],
            "activity_type": s["activity"],
            "event_duration": s["duration"],
            "restricted_area": s["restricted"],
        }
        eval_res = evaluate_event_anomaly(ev_dict, detector)
        event_obj = Event(
            event_id=s["event_id"],
            camera_id=s["camera_id"],
            timestamp=ts,
            location=s["location"],
            person_count=s["person_count"],
            object_type="person",
            motion_level=s["motion"],
            activity_type=s["activity"],
            event_duration=s["duration"],
            event_duration_formatted=s["duration_str"],
            restricted_area=s["restricted"],
            anomaly_score=eval_res["anomaly_score"],
            status="SUSPICIOUS",
            risk_priority=eval_res["risk_priority"],
            anomaly_reasons=eval_res["anomaly_reasons"],
            video_filename="camera03_night.mp4",
            thumbnail_path=None,
        )
        historical_events.append(event_obj)

    db.add_all(historical_events)
    db.commit()

    # Add sample review annotation for EVT-0046
    review = Review(
        event_id="EVT-0046",
        review_status="CONFIRMED_SUSPICIOUS",
        annotation="Verified 3 unauthorized individuals entering storage vault at 23:42. Security team dispatched.",
        reviewed_by="Admin",
        reviewed_at=now - datetime.timedelta(hours=10),
    )
    db.add(review)
    db.commit()

    db.close()
    print("Database seeding completed successfully.")

    # 5. Generate Sample Videos
    print("Generating sample surveillance test videos...")
    generate_video_1_normal_day()
    generate_video_2_night_intrusion()
    generate_video_3_parking_loitering()


if __name__ == "__main__":
    seed_database()
