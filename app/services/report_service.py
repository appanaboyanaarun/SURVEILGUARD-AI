"""
Reports and Analytics Generation Service.
Generates comprehensive surveillance activity reports for daily, weekly, monthly, and custom date ranges.
Supports CSV export and structured JSON summary data.
"""

import csv
import io
import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.models.schema import Event, DetectionSession, Review, Camera, SMSLog


class ReportService:
    @staticmethod
    def get_date_range(
        period: str = "daily",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> tuple[datetime.datetime, datetime.datetime]:
        """
        Parses report timeframe.
        """
        now = datetime.datetime.utcnow()
        if start_date and end_date:
            try:
                start_dt = datetime.datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                end_dt = datetime.datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                return start_dt, end_dt
            except Exception:
                pass

        if period == "weekly":
            start_dt = now - datetime.timedelta(days=7)
        elif period == "monthly":
            start_dt = now - datetime.timedelta(days=30)
        else:  # daily
            start_dt = now - datetime.timedelta(days=1)

        return start_dt, now

    @staticmethod
    def generate_activity_report(
        db: Session,
        period: str = "daily",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        camera_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        start_dt, end_dt = ReportService.get_date_range(period, start_date, end_date)

        q = db.query(Event).filter(Event.timestamp >= start_dt, Event.timestamp <= end_dt)
        if camera_id:
            q = q.filter(Event.camera_id == camera_id)
        if status:
            q = q.filter(Event.status == status.upper())

        events = q.order_by(desc(Event.timestamp)).all()

        total_events = len(events)
        normal_count = sum(1 for e in events if e.status == "NORMAL")
        suspicious_count = sum(1 for e in events if e.status == "SUSPICIOUS")
        high_risk_count = sum(1 for e in events if e.risk_priority == "HIGH")
        sms_sent_count = sum(1 for e in events if e.sms_status == "SENT")

        # By Activity Type
        activity_dist: Dict[str, int] = {}
        for e in events:
            act = e.activity_type or "Unknown"
            activity_dist[act] = activity_dist.get(act, 0) + 1

        # By Camera
        camera_dist: Dict[str, int] = {}
        for e in events:
            cam = e.camera_id or "Unknown"
            camera_dist[cam] = camera_dist.get(cam, 0) + 1

        return {
            "period": period,
            "start_time": start_dt.isoformat(),
            "end_time": end_dt.isoformat(),
            "generated_at": datetime.datetime.utcnow().isoformat(),
            "total_events": total_events,
            "normal_events": normal_count,
            "suspicious_events": suspicious_count,
            "high_risk_events": high_risk_count,
            "sms_alerts_dispatched": sms_sent_count,
            "activity_distribution": activity_dist,
            "camera_distribution": camera_dist,
            "events": [
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "camera_id": e.camera_id,
                    "location": e.location,
                    "admin_name": e.admin_name or "Admin",
                    "person_count": e.person_count,
                    "activity_type": e.activity_type,
                    "anomaly_score": e.anomaly_score,
                    "status": e.status,
                    "risk_priority": e.risk_priority,
                    "sms_status": e.sms_status,
                    "video_filename": e.video_filename,
                    "thumbnail_path": e.thumbnail_path,
                }
                for e in events
            ],
        }

    @staticmethod
    def generate_csv_report(
        db: Session,
        period: str = "daily",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        camera_id: Optional[str] = None,
    ) -> str:
        report_data = ReportService.generate_activity_report(
            db, period=period, start_date=start_date, end_date=end_date, camera_id=camera_id
        )

        output = io.StringIO()
        writer = csv.writer(output)

        # Header Row
        writer.writerow([
            "Event ID",
            "Timestamp (UTC)",
            "Camera ID",
            "Location",
            "Monitoring Admin",
            "Person Count",
            "Inferred Activity",
            "ML Anomaly Score",
            "Detection Status",
            "Risk Priority",
            "SMS Alert Status",
            "Evidence Media",
        ])

        for e in report_data["events"]:
            writer.writerow([
                e["event_id"],
                e["timestamp"],
                e["camera_id"],
                e["location"],
                e["admin_name"],
                e["person_count"],
                e["activity_type"],
                e["anomaly_score"],
                e["status"],
                e["risk_priority"],
                e["sms_status"],
                e["video_filename"] or e["thumbnail_path"] or "None",
            ])

        return output.getvalue()


report_service = ReportService()
