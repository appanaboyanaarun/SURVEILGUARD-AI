import datetime
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple


MOTION_MAP = {"Low": 0, "Medium": 1, "High": 2}
ACTIVITY_MAP = {
    "Normal Movement": 0,
    "Person Entry": 1,
    "Loitering": 2,
    "Group Gathering": 3,
    "Restricted Area Entry": 4,
    "Unauthorized Group Intrusion": 5,
    "Rapid Movement": 6,
}


def extract_features_from_event(event_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Extracts numerical features from a single event dictionary.
    """
    ts = event_data.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.datetime.utcnow()
    elif not isinstance(ts, datetime.datetime):
        ts = datetime.datetime.utcnow()

    hour = ts.hour + (ts.minute / 60.0)
    is_night = 1.0 if (ts.hour < 6 or ts.hour >= 20) else 0.0
    is_weekend = 1.0 if ts.weekday() >= 5 else 0.0

    person_count = float(event_data.get("person_count", 1))
    duration = float(event_data.get("event_duration", 0))
    restricted = float(event_data.get("restricted_area", 0))

    motion_str = event_data.get("motion_level", "Medium")
    motion_val = float(MOTION_MAP.get(motion_str, 1))

    activity_str = event_data.get("activity_type", "Normal Movement")
    activity_val = float(ACTIVITY_MAP.get(activity_str, 0))

    return {
        "hour": hour,
        "is_night": is_night,
        "is_weekend": is_weekend,
        "person_count": person_count,
        "duration": duration,
        "restricted": restricted,
        "motion_level": motion_val,
        "activity_type": activity_val,
    }


FEATURE_NAMES = [
    "hour",
    "is_night",
    "is_weekend",
    "person_count",
    "duration",
    "restricted",
    "motion_level",
    "activity_type",
]


def events_to_feature_matrix(events: List[Dict[str, Any]]) -> np.ndarray:
    """Converts a list of event dicts into a 2D numpy feature matrix."""
    rows = []
    for ev in events:
        feats = extract_features_from_event(ev)
        row = [feats[name] for name in FEATURE_NAMES]
        rows.append(row)
    return np.array(rows, dtype=np.float32)
