import random
import datetime
from typing import List, Dict, Any


def generate_baseline_normal_events(count: int = 600) -> List[Dict[str, Any]]:
    """
    Generates realistic normal baseline surveillance event records for training
    the unsupervised anomaly detection model.
    """
    events = []
    base_date = datetime.datetime.now() - datetime.timedelta(days=30)
    cameras = [
        {"id": "CAM-01", "location": "Main Entrance Gate"},
        {"id": "CAM-02", "location": "Parking Area"},
        {"id": "CAM-03", "location": "Storage Area"},
        {"id": "CAM-04", "location": "Office Hallway"},
    ]

    for i in range(count):
        cam = random.choice(cameras)
        day_offset = random.randint(0, 29)
        
        # 85% normal daytime hours (08:00 - 19:00), 15% early morning / evening
        if random.random() < 0.85:
            hour = random.randint(8, 18)
        else:
            hour = random.choice([6, 7, 19, 20])

        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = base_date + datetime.timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)

        # Normal person count: mostly 1 or 2
        person_count = random.choices([1, 2, 3], weights=[0.75, 0.20, 0.05])[0]

        # Normal duration: 10 to 60 seconds
        duration = random.randint(8, 55)

        # Restricted area: 0 for normal baseline events
        restricted = 0

        # Motion level: mostly Medium or Low
        motion = random.choices(["Low", "Medium", "High"], weights=[0.4, 0.55, 0.05])[0]

        activity = "Normal Movement"
        if cam["location"] == "Main Entrance Gate":
            activity = random.choice(["Normal Movement", "Person Entry"])

        events.append({
            "camera_id": cam["id"],
            "timestamp": ts,
            "location": cam["location"],
            "person_count": person_count,
            "motion_level": motion,
            "activity_type": activity,
            "event_duration": duration,
            "restricted_area": restricted,
        })

    return events
