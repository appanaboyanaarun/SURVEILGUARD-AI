import uuid
import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional, Dict, Any
from app.models.schema import Event, Camera, Review
from app.schemas.dto import EventCreate, DashboardSummary, DashboardCharts, ChartDataset


class EventService:
    @staticmethod
    def generate_event_id(db: Session) -> str:
        """Generates a sequential readable event ID like EVT-0001, EVT-0002."""
        count = db.query(func.count(Event.event_id)).scalar() or 0
        return f"EVT-{(count + 1):04d}"

    @staticmethod
    def create_event(db: Session, event_data: EventCreate) -> Event:
        event_id = event_data.event_id or EventService.generate_event_id(db)

        # Verify camera exists
        camera = db.query(Camera).filter(Camera.camera_id == event_data.camera_id).first()
        location = event_data.location or (camera.location if camera else "Unknown Location")

        event = Event(
            event_id=event_id,
            camera_id=event_data.camera_id,
            timestamp=event_data.timestamp or datetime.datetime.utcnow(),
            location=location,
            person_count=event_data.person_count,
            object_type=event_data.object_type or "person",
            motion_level=event_data.motion_level or "Medium",
            activity_type=event_data.activity_type or "Normal Movement",
            event_duration=event_data.event_duration,
            event_duration_formatted=event_data.event_duration_formatted or "00:00",
            restricted_area=event_data.restricted_area,
            anomaly_score=event_data.anomaly_score or 0.0,
            status=event_data.status or "NORMAL",
            risk_priority=event_data.risk_priority or "LOW",
            anomaly_reasons=event_data.anomaly_reasons,
            video_filename=event_data.video_filename,
            thumbnail_path=event_data.thumbnail_path,
        )

        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def get_events(
        db: Session,
        skip: int = 0,
        limit: int = 100,
        camera_id: Optional[str] = None,
        status: Optional[str] = None,
        risk_priority: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Event]:
        q = db.query(Event)

        if camera_id:
            q = q.filter(Event.camera_id == camera_id)
        if status:
            q = q.filter(Event.status == status.upper())
        if risk_priority:
            q = q.filter(Event.risk_priority == risk_priority.upper())
        if search:
            search_pattern = f"%{search}%"
            q = q.filter(
                (Event.event_id.ilike(search_pattern))
                | (Event.location.ilike(search_pattern))
                | (Event.activity_type.ilike(search_pattern))
                | (Event.camera_id.ilike(search_pattern))
            )

        return q.order_by(desc(Event.timestamp)).offset(skip).limit(limit).all()

    @staticmethod
    def get_by_id(db: Session, event_id: str) -> Optional[Event]:
        return db.query(Event).filter(Event.event_id == event_id).first()

    @staticmethod
    def get_alerts(db: Session, skip: int = 0, limit: int = 50) -> List[Event]:
        """Returns suspicious events ordered by highest risk and latest timestamp."""
        return (
            db.query(Event)
            .filter(Event.status == "SUSPICIOUS")
            .order_by(desc(Event.anomaly_score), desc(Event.timestamp))
            .offset(skip)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_summary(db: Session) -> DashboardSummary:
        total = db.query(func.count(Event.event_id)).scalar() or 0
        normal = db.query(func.count(Event.event_id)).filter(Event.status == "NORMAL").scalar() or 0
        suspicious = db.query(func.count(Event.event_id)).filter(Event.status == "SUSPICIOUS").scalar() or 0
        high_priority = (
            db.query(func.count(Event.event_id))
            .filter(Event.status == "SUSPICIOUS", Event.risk_priority == "HIGH")
            .scalar()
            or 0
        )
        reviewed = db.query(func.count(func.distinct(Review.event_id))).scalar() or 0
        cameras_count = db.query(func.count(Camera.camera_id)).filter(Camera.is_active == True).scalar() or 0

        return DashboardSummary(
            total_events=total,
            normal_events=normal,
            suspicious_events=suspicious,
            high_priority_alerts=high_priority,
            reviewed_events=reviewed,
            cameras_active=cameras_count,
        )

    @staticmethod
    def get_charts(db: Session) -> DashboardCharts:
        # 1. Events by Camera Source (Real aggregation, joining Camera for human-readable names)
        cam_records = (
            db.query(
                Event.camera_id,
                Camera.name,
                func.count(func.distinct(Event.event_id)).label("evt_count"),
            )
            .outerjoin(Camera, Event.camera_id == Camera.camera_id)
            .group_by(Event.camera_id, Camera.name)
            .order_by(desc("evt_count"))
            .limit(6)
            .all()
        )
        cam_labels: List[str] = []
        cam_values: List[int] = []
        for cam_id, cam_name, count in cam_records:
            if not cam_id or not str(cam_id).strip():
                label = "Unassigned Camera"
            elif cam_name and str(cam_name).strip() and str(cam_name).strip() != str(cam_id).strip():
                label = f"{cam_id} ({cam_name})"
            else:
                label = str(cam_id)
            cam_labels.append(label)
            cam_values.append(int(count))

        # 2. Normal vs Suspicious Ratio (Distinct counts to avoid double counting updates)
        norm_count = (
            db.query(func.count(func.distinct(Event.event_id)))
            .filter(Event.status == "NORMAL")
            .scalar()
            or 0
        )
        susp_count = (
            db.query(func.count(func.distinct(Event.event_id)))
            .filter(Event.status == "SUSPICIOUS")
            .scalar()
            or 0
        )
        status_labels = ["Normal Events", "Suspicious Events"]
        status_values = [norm_count, susp_count]

        # 3. 24-Hour Activity Distribution (Hour 0 to 23 UTC, real events aggregated)
        all_timestamps = db.query(Event.timestamp).all()
        hour_counts = {h: 0 for h in range(24)}
        for (ts,) in all_timestamps:
            if ts:
                hour_counts[ts.hour] = hour_counts.get(ts.hour, 0) + 1

        hour_labels = [f"{h:02d}:00" for h in range(24)]
        hour_values = [hour_counts[h] for h in range(24)]

        # 4. Suspicious Incidents by Location (Filter to SUSPICIOUS status, clearly label missing locations)
        loc_records = (
            db.query(
                Event.location,
                func.count(func.distinct(Event.event_id)).label("susp_count"),
            )
            .filter(Event.status == "SUSPICIOUS")
            .group_by(Event.location)
            .order_by(desc("susp_count"))
            .limit(6)
            .all()
        )
        loc_labels: List[str] = []
        loc_values: List[int] = []
        for loc, count in loc_records:
            cleaned_loc = str(loc).strip() if (loc and str(loc).strip()) else "Unspecified Location"
            loc_labels.append(cleaned_loc)
            loc_values.append(int(count))

        # 5. Recent Activity Trend (Last 7 Days)
        now = datetime.datetime.utcnow().date()
        date_map = {}
        for d in range(6, -1, -1):
            day = now - datetime.timedelta(days=d)
            date_map[day.strftime("%b %d")] = {"normal": 0, "suspicious": 0}

        recent_events = (
            db.query(Event.timestamp, Event.status)
            .filter(Event.timestamp >= (datetime.datetime.utcnow() - datetime.timedelta(days=7)))
            .all()
        )
        for ts, status in recent_events:
            if ts:
                key = ts.strftime("%b %d")
                if key in date_map:
                    if status == "SUSPICIOUS":
                        date_map[key]["suspicious"] += 1
                    else:
                        date_map[key]["normal"] += 1

        trend_labels = list(date_map.keys())
        trend_normal = [date_map[k]["normal"] for k in trend_labels]
        trend_suspicious = [date_map[k]["suspicious"] for k in trend_labels]

        return DashboardCharts(
            events_by_camera=ChartDataset(labels=cam_labels, values=cam_values),
            status_distribution=ChartDataset(labels=status_labels, values=status_values),
            events_by_hour=ChartDataset(labels=hour_labels, values=hour_values),
            suspicious_by_location=ChartDataset(labels=loc_labels, values=loc_values),
            recent_activity_trend=ChartDataset(labels=trend_labels, values=[trend_normal, trend_suspicious]),
        )
