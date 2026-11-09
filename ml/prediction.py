import json
import datetime
from typing import Dict, Any, List, Tuple
from .anomaly_detection import AnomalyDetector


def generate_anomaly_reasons(event_data: Dict[str, Any], score: float) -> List[str]:
    """
    Generates human-understandable diagnostic reasons why an event was flagged.
    """
    reasons = []
    
    # 1. Restricted Area Check
    if event_data.get("restricted_area", 0) == 1:
        reasons.append("Restricted zone boundary incursion detected")

    # 2. Time of day
    ts = event_data.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            pass

    if hasattr(ts, "hour"):
        if ts.hour < 5 or ts.hour >= 22:
            reasons.append(f"Unusual late-night activity ({ts.strftime('%H:%M')}) outside standard operating hours")
        elif ts.hour >= 19:
            reasons.append(f"After-hours presence observed ({ts.strftime('%H:%M')})")

    # 3. Person count
    count = event_data.get("person_count", 1)
    if count >= 3:
        reasons.append(f"High person count ({count} individuals) exceeding standard baseline")
    elif count == 0 and event_data.get("motion_level") == "High":
        reasons.append("Unidentified rapid movement without clear person silhouette")

    # 4. Duration
    duration = event_data.get("event_duration", 0)
    if duration >= 180:
        mins = duration // 60
        secs = duration % 60
        reasons.append(f"Extended lingering / loitering duration ({mins}m {secs:02d}s)")
    elif duration >= 60:
        reasons.append(f"Elevated dwell time ({duration}s)")

    # 5. Motion level
    motion = event_data.get("motion_level", "Medium")
    if motion == "High":
        reasons.append("Elevated motion intensity in surveillance field")

    # If no specific rule triggered but ML score is high
    if not reasons and score >= 0.60:
        reasons.append("Statistical deviation from normal baseline camera traffic patterns")

    if not reasons:
        reasons.append("Activity conforms to normal baseline patterns")

    return reasons


def evaluate_event_anomaly(
    event_data: Dict[str, Any],
    detector: AnomalyDetector,
    suspicious_threshold: float = 0.55
) -> Dict[str, Any]:
    """
    Evaluates an event metadata record and produces status, anomaly score, priority, and explanations.
    """
    score = detector.score_single(event_data)
    reasons = generate_anomaly_reasons(event_data, score)

    # Determine status
    if score >= suspicious_threshold or event_data.get("restricted_area", 0) == 1:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    # Determine priority
    if score >= 0.75 or (event_data.get("restricted_area", 0) == 1 and score >= 0.65):
        risk_priority = "HIGH"
    elif score >= 0.55:
        risk_priority = "MEDIUM"
    else:
        risk_priority = "LOW"

    return {
        "anomaly_score": score,
        "status": status,
        "risk_priority": risk_priority,
        "anomaly_reasons": json.dumps(reasons),
    }
