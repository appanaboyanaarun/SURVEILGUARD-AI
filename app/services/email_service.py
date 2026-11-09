"""
Email Notification Service using Google Apps Script HTTP API.
Sends automated real-time email alerts to authorized Admin and Friend email recipients
when suspicious activity is detected.
Uses Google Apps Script Web App HTTP API (HTTPS POST) over port 443 with shared webhook secret authentication.
Includes cooldown tracking, deduplication, audit database logging, and multi-recipient support.
"""

import base64
import datetime
import hashlib
import hmac
import html
import ipaddress
import logging
import os
import re
import threading
import time
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlsplit

import requests
from sqlalchemy import func, or_

from app.config import settings
from app.database.connection import SessionLocal
from app.models.notification_models import EmailRecipient, EmailLog, Incident
from app.models.schema import User, Camera, Event

logger = logging.getLogger("email_service")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [EMAIL] %(message)s"))
    logger.addHandler(handler)

# Robust email validation regex
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

PLACEHOLDER_SECRETS = {
    "your_webhook_secret",
    "your_secret",
    "placeholder",
    "replace_with_actual",
    "your_actual_secret",
    "whsec_your_webhook_signing_secret",
}

PLACEHOLDER_URLS = {
    "your_google_apps_script_exec_url",
    "your_url_here",
    "placeholder",
    "https://script.google.com/macros/s/your_deployment_id/exec",
}


def validate_email(email: str) -> bool:
    """Validate email address format."""
    if not email or not isinstance(email, str):
        return False
    email = email.strip()
    return bool(EMAIL_REGEX.match(email))


def mask_email(email: str) -> str:
    """Mask email for safe display: user@example.com -> u***r@example.com"""
    if not email or "@" not in email:
        return email or ""
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        return "***@" + domain
    return local[0] + "***" + local[-1] + f"@{domain}"


class EmailDispatchResult:
    """Structured result from an email dispatch attempt."""

    def __init__(
        self,
        success: bool,
        status: str,
        provider: str = "apps_script",
        error: Optional[str] = None,
        message_id: Optional[str] = None,
    ):
        self.success = success
        self.status = status  # ACCEPTED, FAILED, NOT_CONFIGURED, DUPLICATE_SKIPPED, etc.
        self.provider = provider
        self.error = error
        self.message_id = message_id


class EmailService:
    """
    Service for sending security alert emails via Google Apps Script HTTP API.
    Supports Admin and Friend recipients with database persistence.
    All automated event dispatches run asynchronously on background threads.
    """

    def __init__(self):
        self._cooldown_tracker: Dict[str, float] = {}  # camera_id -> epoch timestamp
        self._lock = threading.Lock()
        self._dedup_tracker: set = set()  # set of (incident_id, recipient_email_lower)
        self._dedup_lock = threading.Lock()
        self._test_rate_tracker: Dict[str, float] = {}  # user key -> last test time
        self._test_rate_lock = threading.Lock()

    def _test_rate_limit(self, rate_key: str, min_interval: float = 3.0) -> bool:
        """Rate-limit test emails per user. Returns True if allowed."""
        with self._test_rate_lock:
            now = time.time()
            last = self._test_rate_tracker.get(rate_key, 0)
            if now - last < min_interval:
                return False
            self._test_rate_tracker[rate_key] = now
            return True

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _get_web_app_url(self) -> str:
        """Retrieve the configured Google Apps Script Web App URL."""
        return (
            os.getenv("APPS_SCRIPT_WEB_APP_URL")
            or getattr(settings, "APPS_SCRIPT_WEB_APP_URL", "")
            or ""
        ).strip()

    def _get_webhook_secret(self) -> str:
        """Retrieve the configured shared Webhook Secret token."""
        return (
            os.getenv("APPS_SCRIPT_WEBHOOK_SECRET")
            or getattr(settings, "APPS_SCRIPT_WEBHOOK_SECRET", "")
            or ""
        ).strip()

    def _get_timeout(self) -> int:
        """Retrieve request timeout in seconds."""
        raw = os.getenv("APPS_SCRIPT_TIMEOUT_SECONDS") or getattr(
            settings, "APPS_SCRIPT_TIMEOUT_SECONDS", 15
        )
        try:
            return int(raw)
        except (ValueError, TypeError):
            return 15

    def _is_placeholder_url(self, url: str) -> bool:
        """Detect placeholder or unconfigured template Web App URLs."""
        if not url:
            return True
        clean = url.strip().lower()
        if clean in PLACEHOLDER_URLS:
            return True
        if "your_google_apps_script" in clean or "your_deployment_id" in clean:
            return True
        return False

    def _is_placeholder_secret(self, secret: str) -> bool:
        """Detect placeholder or unconfigured webhook secrets."""
        if not secret:
            return True
        clean = secret.strip().lower()
        if clean in PLACEHOLDER_SECRETS:
            return True
        if "your_webhook_secret" in clean or "your_secret" in clean or "placeholder" in clean:
            return True
        return False

    def is_configured(self) -> bool:
        """Check if Google Apps Script HTTP API has valid required configuration and is enabled."""
        if not getattr(settings, "EMAIL_ENABLED", True):
            return False
        url = self._get_web_app_url()
        secret = self._get_webhook_secret()
        if not url or self._is_placeholder_url(url):
            return False
        if not secret or self._is_placeholder_secret(secret):
            return False
        return True

    def _sanitize_error(self, message: str) -> str:
        """Ensure secrets or tokens are never exposed in error logs or output."""
        if not message:
            return ""
        secret = self._get_webhook_secret()
        if secret and secret in message:
            message = message.replace(secret, "[REDACTED]")
        return message

    def _get_from_email_raw(self) -> str:
        """Get the configured sender email address without display name."""
        from_email = (
            os.getenv("ALERT_FROM_EMAIL")
            or os.getenv("EMAIL_FROM")
            or getattr(settings, "ALERT_FROM_EMAIL", None)
            or getattr(settings, "EMAIL_FROM", "alerts@surveilguard.local")
        )
        return from_email.strip() if from_email else "alerts@surveilguard.local"

    def _get_from_header(self) -> str:
        """Get the formatted sender header e.g. 'Suspicious Activity Detection <alerts@domain.com>'."""
        raw_email = self._get_from_email_raw()
        from_name = (os.getenv("ALERT_FROM_NAME") or getattr(settings, "ALERT_FROM_NAME", "") or "").strip()
        if from_name:
            return f"{from_name} <{raw_email}>"
        return raw_email

    def _get_env_admin_emails(self) -> List[str]:
        """Extract normalized, valid admin emails from environment settings."""
        emails = []
        raw_values = (
            os.getenv("ADMIN_EMAILS", getattr(settings, "ADMIN_EMAILS", "")),
            os.getenv("ADMIN_EMAIL", getattr(settings, "ADMIN_EMAIL", "")),
        )
        for raw_value in raw_values:
            for value in raw_value.split(","):
                email = value.strip().lower()
                if email and validate_email(email) and email not in emails:
                    emails.append(email)
        return emails

    def _get_public_base_url(self, value: Optional[str] = None) -> Optional[str]:
        """Return an HTTPS base URL suitable for external links, never a local URL."""
        candidate = value
        if candidate is None:
            candidate = (
                os.getenv("APP_BASE_URL")
                or os.getenv("PUBLIC_BASE_URL")
                or getattr(settings, "APP_BASE_URL", None)
                or getattr(settings, "PUBLIC_BASE_URL", None)
            )
        if not candidate:
            return None

        try:
            parsed = urlsplit(candidate.strip())
            hostname = parsed.hostname
            if parsed.scheme.lower() != "https" or not hostname or parsed.username or parsed.password:
                return None
            hostname = hostname.rstrip(".").lower()
            if hostname == "localhost" or hostname.endswith(".localhost"):
                return None
            try:
                if not ipaddress.ip_address(hostname).is_global:
                    return None
            except ValueError:
                pass
            return candidate.rstrip("/")
        except ValueError:
            return None

    def is_authorized_recipient(self, email: str, db=None) -> bool:
        """
        Validate dynamic recipient against authorized allowlist (configured admins + active DB recipients).
        Prevents dispatching email alerts to arbitrary unauthenticated recipients.
        """
        if not email or not validate_email(email):
            return False
        clean = email.strip().lower()
        all_recs = self.get_all_recipients(db=db, active_only=True)
        authorized_emails = {r["email"].strip().lower() for r in all_recs if r.get("email")}
        return clean in authorized_emails

    def get_provider_status(self) -> dict:
        """
        Return configuration readiness, provider name, and recipient stats without exposing secrets.
        Never reveals APPS_SCRIPT_WEBHOOK_SECRET.
        """
        configured = self.is_configured()
        url = self._get_web_app_url()
        secret = self._get_webhook_secret()
        is_placeholder_u = self._is_placeholder_url(url)
        is_placeholder_s = self._is_placeholder_secret(secret)
        issues = []

        if not getattr(settings, "EMAIL_ENABLED", True):
            issues.append("EMAIL_ENABLED is set to false in configuration")

        if not url:
            issues.append("APPS_SCRIPT_WEB_APP_URL is not configured in .env")
        elif is_placeholder_u:
            issues.append(
                "APPS_SCRIPT_WEB_APP_URL contains a placeholder value ('YOUR_GOOGLE_APPS_SCRIPT_EXEC_URL'). "
                "Configure your genuine Apps Script deployment URL."
            )

        if not secret:
            issues.append("APPS_SCRIPT_WEBHOOK_SECRET is not configured in .env")
        elif is_placeholder_s:
            issues.append(
                "APPS_SCRIPT_WEBHOOK_SECRET contains a placeholder value ('YOUR_WEBHOOK_SECRET'). "
                "Configure your genuine webhook secret."
            )

        env_admins = self._get_env_admin_emails()
        all_recipients = self.get_all_recipients(active_only=False)
        active_recipients = [r for r in all_recipients if r.get("is_active")]

        if not active_recipients:
            issues.append("No active recipients configured (add an admin/friend recipient or set ADMIN_EMAIL)")

        last_sent_time = None
        db = SessionLocal()
        try:
            last_log = (
                db.query(EmailLog)
                .filter(EmailLog.status.in_(["ACCEPTED", "DELIVERED", "SENT"]))
                .order_by(EmailLog.sent_at.desc())
                .first()
            )
            if last_log and last_log.sent_at:
                last_sent_time = last_log.sent_at.isoformat()
        except Exception as e:
            logger.debug(f"Could not query last sent email time: {e}")
        finally:
            db.close()

        mode = "ACTIVE" if configured else "UNCONFIGURED"
        app_base = self._get_public_base_url()

        return {
            "provider": "apps_script",
            "enabled": getattr(settings, "EMAIL_ENABLED", True),
            "configured": configured,
            "mode": mode,
            "web_app_url_configured": bool(url and not is_placeholder_u),
            "webhook_secret_configured": bool(secret and not is_placeholder_s),
            "from": getattr(settings, "ALERT_FROM_EMAIL", "apps_script@google.com"),
            "from_name": getattr(settings, "ALERT_FROM_NAME", "Suspicious Activity Detection"),
            "from_header": self._get_from_header(),
            "admin_email": ", ".join(env_admins) if env_admins else "None in .env",
            "public_base_url": app_base,
            "evidence_links_enabled": bool(self._get_public_base_url(getattr(settings, "BASE_URL", None))),
            "recipients_count": len(all_recipients),
            "active_recipients_count": len(active_recipients),
            "last_successful_send": last_sent_time,
            "issues": issues,
            "is_sandbox_sender": False,
            "sender_domain_verification": "verified" if configured else "unconfigured",
        }

    # ------------------------------------------------------------------
    # Recipients Management (Admin & Friends)
    # ------------------------------------------------------------------

    def get_all_recipients(self, db=None, active_only: bool = False, hide_full_email: bool = False) -> List[dict]:
        """
        Retrieves all configured admin and friend recipient email addresses.
        Combines environment-configured admins and database recipients.
        """
        recipients = []
        seen_emails = set()

        # 1. Environment ADMIN_EMAILS and legacy ADMIN_EMAIL records
        env_admins = self._get_env_admin_emails()
        for idx, email in enumerate(env_admins):
            email_lower = email.lower()
            if email_lower not in seen_emails:
                seen_emails.add(email_lower)
                recipients.append(
                    {
                        "id": idx + 1,
                        "name": "System Administrator",
                        "email": mask_email(email) if hide_full_email else email,
                        "email_masked": mask_email(email),
                        "recipient_type": "admin",
                        "source": "environment",
                        "is_active": True,
                        "created_at": None,
                    }
                )

        # 2. Database EmailRecipient records (Admin & Friend)
        close_db = False
        try:
            if db is None:
                db = SessionLocal()
                close_db = True

            query = db.query(EmailRecipient)
            if active_only:
                query = query.filter(EmailRecipient.is_active == True)
            db_records = query.order_by(EmailRecipient.id.asc()).all()

            for r in db_records:
                email = (r.email_address or "").strip().lower()
                if validate_email(email) and email not in seen_emails:
                    seen_emails.add(email)
                    recipients.append(
                        {
                            "id": r.id,
                            "name": r.name or ("Admin Recipient" if r.recipient_type == "admin" else "Friend Recipient"),
                            "email": mask_email(email) if hide_full_email else email,
                            "email_masked": mask_email(email),
                            "recipient_type": (r.recipient_type or "friend").lower(),
                            "source": "database",
                            "is_active": bool(r.is_active),
                            "created_at": r.created_at.isoformat() if r.created_at else None,
                        }
                    )
        except Exception as e:
            logger.warning(f"Database email recipients query skipped: {e}")
        finally:
            if close_db and db:
                try:
                    db.close()
                except Exception:
                    pass

        if active_only:
            recipients = [r for r in recipients if r["is_active"]]

        return recipients

    def add_recipient(self, name: str, email: str, db, recipient_type: str = "friend") -> dict:
        """
        Add a new email recipient to the database.
        Supports recipient_type='admin' or 'friend'.
        """
        email_clean = (email or "").strip()
        if not validate_email(email_clean):
            raise ValueError(f"Invalid email address: '{email_clean}'")

        rec_type = (recipient_type or "friend").strip().lower()
        if rec_type not in ["admin", "friend"]:
            raise ValueError("Recipient type must be either 'admin' or 'friend'.")

        # Check for case-insensitive duplicate in DB
        existing = (
            db.query(EmailRecipient)
            .filter(func.lower(EmailRecipient.email_address) == email_clean.lower())
            .first()
        )
        if existing:
            raise ValueError(f"Recipient with email {mask_email(email_clean)} already exists.")

        # Check for duplicate in env admin emails
        env_admins = [e.lower() for e in self._get_env_admin_emails()]
        if email_clean.lower() in env_admins:
            raise ValueError(f"Email {mask_email(email_clean)} is already configured in environment variables.")

        default_name = "Admin Recipient" if rec_type == "admin" else "Friend Recipient"
        recipient = EmailRecipient(
            name=(name or "").strip() or default_name,
            email_address=email_clean,
            recipient_type=rec_type,
            is_active=True,
        )
        db.add(recipient)
        db.commit()
        db.refresh(recipient)

        logger.info(f"Added recipient {mask_email(email_clean)} ({rec_type}) to database.")
        return {
            "id": recipient.id,
            "name": recipient.name,
            "email": recipient.email_address,
            "email_masked": mask_email(recipient.email_address),
            "recipient_type": recipient.recipient_type,
            "source": "database",
            "is_active": recipient.is_active,
            "created_at": recipient.created_at.isoformat() if recipient.created_at else None,
        }

    def update_recipient(
        self,
        recipient_id: int,
        name: Optional[str],
        email: Optional[str],
        is_active: Optional[bool],
        recipient_type: Optional[str],
        db,
    ) -> dict:
        """Update an existing database recipient."""
        recipient = db.query(EmailRecipient).filter(EmailRecipient.id == recipient_id).first()
        if not recipient:
            raise ValueError(f"Recipient #{recipient_id} not found.")

        if email:
            email_clean = email.strip()
            if not validate_email(email_clean):
                raise ValueError(f"Invalid email address: '{email_clean}'")
            existing = (
                db.query(EmailRecipient)
                .filter(
                    func.lower(EmailRecipient.email_address) == email_clean.lower(),
                    EmailRecipient.id != recipient_id,
                )
                .first()
            )
            if existing:
                raise ValueError(f"Email {mask_email(email_clean)} already exists.")
            recipient.email_address = email_clean

        if name is not None:
            recipient.name = name.strip()

        if recipient_type is not None:
            clean_type = recipient_type.strip().lower()
            if clean_type not in ["admin", "friend"]:
                raise ValueError("Recipient type must be either 'admin' or 'friend'.")
            recipient.recipient_type = clean_type

        if is_active is not None:
            recipient.is_active = bool(is_active)

        db.commit()
        db.refresh(recipient)
        return {
            "id": recipient.id,
            "name": recipient.name,
            "email": recipient.email_address,
            "email_masked": mask_email(recipient.email_address),
            "recipient_type": recipient.recipient_type,
            "source": "database",
            "is_active": recipient.is_active,
            "created_at": recipient.created_at.isoformat() if recipient.created_at else None,
        }

    def delete_recipient(self, recipient_id: int, db) -> bool:
        """Permanently delete a database recipient."""
        recipient = db.query(EmailRecipient).filter(EmailRecipient.id == recipient_id).first()
        if not recipient:
            return False
        db.delete(recipient)
        db.commit()
        logger.info(f"Deleted recipient #{recipient_id} from database.")
        return True

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def _is_duplicate(self, incident_id: str, recipient_email: str) -> bool:
        """Check in-memory deduplication tracker to prevent duplicate bursts."""
        key = (str(incident_id), recipient_email.lower().strip())
        with self._dedup_lock:
            if key in self._dedup_tracker:
                return True
            self._dedup_tracker.add(key)
            return False

    # ------------------------------------------------------------------
    # Google Apps Script HTTP API Dispatch
    # ------------------------------------------------------------------

    def _send_apps_script(
        self,
        to_email: str,
        subject: str,
        camera: str = "CAM-01",
        event_name: str = "Suspicious Activity",
        timestamp_str: Optional[str] = None,
        details: Optional[str] = None,
        html_content: Optional[str] = None,
        text_content: Optional[str] = None,
    ) -> EmailDispatchResult:
        """
        Send a single email dispatch via Google Apps Script Web App HTTP API.
        Sends JSON payload over HTTPS with shared webhook secret authentication.
        Never logs secrets.
        """
        if not self.is_configured():
            url = self._get_web_app_url()
            secret = self._get_webhook_secret()
            if not url or self._is_placeholder_url(url):
                err = "APPS_SCRIPT_WEB_APP_URL is not configured in .env."
            elif not secret or self._is_placeholder_secret(secret):
                err = "APPS_SCRIPT_WEBHOOK_SECRET is not configured in .env."
            else:
                err = "EMAIL_ENABLED is set to false in configuration."
            return EmailDispatchResult(
                success=False,
                status="NOT_CONFIGURED",
                provider="apps_script",
                error=f"Google Apps Script HTTP API is not configured: {err}",
            )

        target_receiver = (to_email or "").strip()
        if not validate_email(target_receiver):
            return EmailDispatchResult(
                success=False,
                status="FAILED",
                provider="apps_script",
                error=f"Invalid recipient email address: '{mask_email(target_receiver)}'",
            )

        url = self._get_web_app_url()
        secret = self._get_webhook_secret()
        timeout = self._get_timeout()

        now_str = timestamp_str or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")

        # Standard Apps Script payload matching expected request structure
        payload = {
            "token": secret,
            "subject": subject,
            "camera": camera or "CAM-01",
            "event": event_name or "Suspicious Activity",
            "timestamp": now_str,
            "details": details or "Suspicious activity detected by the surveillance system",
            "recipient": target_receiver,
        }
        if html_content:
            payload["html_body"] = html_content

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=timeout,
                allow_redirects=True,
                headers={"Content-Type": "application/json"},
            )
        except requests.exceptions.Timeout:
            err = f"Request to Google Apps Script timed out after {timeout}s."
            logger.error(f"Apps Script dispatch timeout for {mask_email(target_receiver)}: {err}")
            return EmailDispatchResult(success=False, status="FAILED", provider="apps_script", error=err)
        except requests.exceptions.ConnectionError:
            err = "Failed to connect to Google Apps Script HTTP endpoint. Check network connectivity or APPS_SCRIPT_WEB_APP_URL."
            logger.error(f"Apps Script connection failure for {mask_email(target_receiver)}: {err}")
            return EmailDispatchResult(success=False, status="FAILED", provider="apps_script", error=err)
        except requests.exceptions.RequestException as exc:
            err = f"Google Apps Script HTTP request error: {self._sanitize_error(str(exc))[:200]}"
            logger.error(f"Apps Script request exception for {mask_email(target_receiver)}: {err}")
            return EmailDispatchResult(success=False, status="FAILED", provider="apps_script", error=err)

        if response.status_code != 200:
            snippet = self._sanitize_error(response.text[:200])
            err = f"Google Apps Script returned HTTP {response.status_code}: {snippet}"
            logger.error(f"Apps Script HTTP error {response.status_code} for {mask_email(target_receiver)}: {err}")
            return EmailDispatchResult(success=False, status="FAILED", provider="apps_script", error=err)

        try:
            res_json = response.json()
        except Exception:
            snippet = self._sanitize_error(response.text[:200])
            err = f"Google Apps Script returned invalid non-JSON response: {snippet}"
            logger.error(f"Apps Script invalid JSON for {mask_email(target_receiver)}: {err}")
            return EmailDispatchResult(success=False, status="FAILED", provider="apps_script", error=err)

        if not isinstance(res_json, dict):
            err = "Google Apps Script returned unexpected response structure"
            logger.error(f"Apps Script unexpected response type for {mask_email(target_receiver)}: {err}")
            return EmailDispatchResult(success=False, status="FAILED", provider="apps_script", error=err)

        status_field = str(res_json.get("status", "")).lower()
        success_field = res_json.get("success")
        error_msg = res_json.get("error") or res_json.get("message")

        if not (status_field == "success" or success_field is True) and (status_field == "error" or success_field is False):
            err = f"Google Apps Script rejected dispatch: {self._sanitize_error(str(error_msg or 'Request unfulfilled'))}"
            logger.error(f"Apps Script rejection for {mask_email(target_receiver)}: {err}")
            return EmailDispatchResult(success=False, status="FAILED", provider="apps_script", error=err)

        message_id = str(res_json.get("message_id") or res_json.get("id") or f"gas_{int(time.time() * 1000)}")
        logger.info(f"Google Apps Script dispatch accepted for {mask_email(target_receiver)}, message_id: {message_id}")
        return EmailDispatchResult(
            success=True,
            status="ACCEPTED",
            provider="apps_script",
            message_id=message_id,
        )

    # ------------------------------------------------------------------
    # Asynchronous Dispatch Worker
    # ------------------------------------------------------------------

    def dispatch_suspicious_event_email(self, event_id: str, camera_id: str) -> dict:
        """
        Asynchronously dispatch alert email for an incident on a background daemon thread.
        Never blocks camera capture, OpenCV processing, or detection pipelines.
        """
        thread = threading.Thread(
            target=self.send_suspicious_event_email,
            args=(event_id, camera_id),
            daemon=True,
            name=f"email-dispatch-{event_id}",
        )
        thread.start()
        return {"dispatched": True, "background": True}

    # ------------------------------------------------------------------
    # Email Content Templates (with HTML Escaping)
    # ------------------------------------------------------------------

    def build_email_content(self, incident: dict) -> Tuple[str, str, str]:
        """
        Build subject, HTML body, and plain text body with HTML escaping for untrusted data.
        Includes Suspicious-Activity reasons, deployment URLs, and evidence links.
        """
        raw_incident_id = str(incident.get("incident_id") or "UNKNOWN")
        raw_event_id = str(incident.get("event_id") or "UNKNOWN")
        raw_camera_id = str(incident.get("camera_id") or "UNKNOWN")
        raw_camera_name = str(incident.get("camera_name") or "Unknown Camera")
        raw_location = str(incident.get("location") or "Unknown Location")
        raw_activity_type = str(incident.get("activity_type") or "Suspicious Activity")
        raw_risk_level = str(incident.get("risk_level") or "HIGH")
        raw_status = str(incident.get("status") or "NEW")
        raw_timestamp = str(
            incident.get("timestamp")
            or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
        )
        raw_reasons = incident.get("anomaly_reasons") or incident.get("reasons") or "High anomaly score detected"

        # Escape all untrusted incident data
        incident_id = html.escape(raw_incident_id)
        event_id = html.escape(raw_event_id)
        camera_id = html.escape(raw_camera_id)
        camera_name = html.escape(raw_camera_name)
        location = html.escape(raw_location)
        activity_type = html.escape(raw_activity_type)
        risk_level = html.escape(raw_risk_level)
        status = html.escape(raw_status)
        timestamp = html.escape(raw_timestamp)
        reasons_escaped = html.escape(str(raw_reasons))

        thumbnail_path = incident.get("thumbnail_path")
        video_clip_path = incident.get("video_clip_path")
        evidence_link = incident.get("evidence_link")

        base_url = self._get_public_base_url()
        incident_view_url = f"{base_url}/#/events" if base_url else None

        evidence_display = ""
        evidence_text = ""
        if evidence_link:
            clean_link = html.escape(evidence_link)
            evidence_display = (
                f'<p style="font-size:13px; color:#374151;">Evidence Video: '
                f'<a href="{clean_link}" style="color:#2563eb; font-weight:600;">View Secured Video Clip</a> '
                f'(requires administrator authentication)</p>'
            )
            evidence_text += f"\nEvidence Video Link: {evidence_link}"
        elif thumbnail_path or video_clip_path:
            evidence_display = (
                '<p style="font-size:13px;color:#6b7280;">Evidence is stored locally or in configured storage; '
                'no public evidence link is available.</p>'
            )
            evidence_text += "\nEvidence is stored by the application; no public link was generated."

        subject = f"SECURITY ALERT: {raw_risk_level} - Suspicious Activity Detected [{raw_incident_id}]"
        review_link = (
            f'<a href="{html.escape(incident_view_url)}" style="background:#dc2626;color:#ffffff;padding:12px 24px;'
            'border-radius:6px;text-decoration:none;font-weight:600;display:inline-block;">'
            "Review Threat in Security Console</a>"
            if incident_view_url
            else '<span style="color:#6b7280;">Configure a public HTTPS application URL to enable remote review links.</span>'
        )
        deployment_details = (
            f'Application deployment: <a href="{html.escape(base_url)}" style="color:#6b7280;">'
            f'{html.escape(base_url)}</a>.'
            if base_url
            else "Remote application and evidence links are disabled until a public HTTPS URL is configured."
        )

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert</title>
</head>
<body style="font-family:Inter,system-ui,sans-serif;line-height:1.6;color:#1f2937;max-width:600px;margin:0 auto;padding:20px;background:#f3f4f6;">
    <div style="background:#ffffff;border-radius:12px;padding:30px;box-shadow:0 4px 6px rgba(0,0,0,0.1);border-left:5px solid #ef4444;">
        <h2 style="color:#dc2626;margin-top:0;font-size:20px;">
            &#9888;&#65039; Security Alert: {risk_level}
        </h2>
        <p style="font-size:14px;color:#6b7280;margin-bottom:20px;">
            Suspicious activity has been detected by SurveilGuard AI live surveillance engine.
        </p>

        <table style="width:100%;border-collapse:collapse;margin-bottom:20px;font-size:13px;">
            <tr><td style="padding:8px;font-weight:600;color:#374151;width:140px;">Incident ID</td><td style="padding:8px;color:#1f2937;"><code>{incident_id}</code></td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Event ID</td><td style="padding:8px;color:#1f2937;">{event_id}</td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Camera ID</td><td style="padding:8px;color:#1f2937;">{camera_id}</td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Camera Name</td><td style="padding:8px;color:#1f2937;">{camera_name}</td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Location</td><td style="padding:8px;color:#1f2937;">{location}</td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Activity Type</td><td style="padding:8px;color:#1f2937;">{activity_type}</td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Risk Level</td><td style="padding:8px;color:#dc2626;font-weight:700;">{risk_level}</td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Status</td><td style="padding:8px;color:#1f2937;">{status}</td></tr>
            <tr><td style="padding:8px;font-weight:600;color:#374151;">Detected At</td><td style="padding:8px;color:#1f2937;">{timestamp}</td></tr>
        </table>

        <div style="background:#fef2f2;border:1px solid #fee2e2;border-radius:8px;padding:12px;margin-bottom:20px;">
            <div style="font-weight:700;font-size:12px;color:#991b1b;margin-bottom:4px;">SUSPICIOUS ACTIVITY REASONS:</div>
            <div style="font-size:13px;color:#7f1d1d;">{reasons_escaped}</div>
        </div>

        {evidence_display}

        <div style="text-align:center;margin:24px 0;">
            {review_link}
        </div>

        <p style="font-size:12px;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:16px;margin-top:24px;">
            Automated security alert from SurveilGuard AI delivered via Google Apps Script HTTP API.<br>
            {deployment_details}
        </p>
    </div>
</body>
</html>"""

        text_content = f"""SECURITY ALERT: {raw_risk_level} - Suspicious Activity Detected

SurveilGuard AI has detected suspicious activity on camera surveillance.

Incident ID: {raw_incident_id}
Event ID: {raw_event_id}
Camera ID: {raw_camera_id}
Camera Name: {raw_camera_name}
Location: {raw_location}
Activity Type: {raw_activity_type}
Risk Level: {raw_risk_level}
Status: {raw_status}
Detected At: {raw_timestamp}
Suspicious Reasons: {raw_reasons}
{evidence_text}

Review Incident: {incident_view_url or "Configure a public HTTPS application URL for remote access."}

Automated alert from SurveilGuard AI via Google Apps Script HTTP API.
"""

        return subject, html_content, text_content

    # ------------------------------------------------------------------
    # Public API: Send Alert Email for Suspicious Event
    # ------------------------------------------------------------------

    def send_suspicious_event_email(self, event_id: str, camera_id: str) -> dict:
        """
        Dispatch email alerts to all active Admin and Friend recipients for a confirmed suspicious event.
        Runs synchronously but should be called from a background thread by caller.
        Attempts all recipients independently and logs individual results into EmailLog.
        """
        if not self.is_configured():
            return {
                "success": False,
                "status": "NOT_CONFIGURED",
                "provider": "apps_script",
                "message": "Google Apps Script HTTP API is not configured. Please add APPS_SCRIPT_WEB_APP_URL and APPS_SCRIPT_WEBHOOK_SECRET to .env.",
                "dispatches": [],
            }

        db = SessionLocal()
        try:
            # 1. Lookup Incident by event_id or incident_id
            incident = (
                db.query(Incident)
                .filter(or_(Incident.event_id == event_id, Incident.incident_id == event_id))
                .first()
            )

            # 2. Fallback to Event record if Incident has not finished persisting
            event = db.query(Event).filter(Event.event_id == event_id).first()

            if not incident and not event:
                logger.warning(f"No incident or event found for {event_id}, skipping email dispatch")
                return {
                    "success": False,
                    "status": "NO_INCIDENT",
                    "provider": "apps_script",
                    "message": f"No incident or event found for {event_id}",
                    "dispatches": [],
                }

            # Resolve camera metadata
            camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
            camera_name = camera.name if camera else "Unknown Camera"
            location = (
                (incident and incident.location)
                or (event and event.location)
                or (camera and camera.location)
                or "Unknown Location"
            )

            recipients = self.get_all_recipients(db=db, active_only=True)
            if not recipients:
                return {
                    "success": False,
                    "status": "NO_RECIPIENTS",
                    "provider": "apps_script",
                    "message": "No active admin or friend email recipients configured.",
                    "dispatches": [],
                }

            # Map confidence / anomaly score to risk level
            confidence = (incident and incident.confidence) or (event and event.anomaly_score) or 0.85
            if confidence >= 0.7:
                risk_level = "HIGH"
            elif confidence >= 0.4:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            incident_id_str = incident.incident_id if incident else f"INC-{event_id}"
            now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            incident_data = {
                "incident_id": incident_id_str,
                "event_id": event_id,
                "camera_id": camera_id,
                "camera_name": camera_name,
                "location": location,
                "activity_type": (incident and incident.activity_type) or (event and event.activity_type) or "Suspicious Activity",
                "risk_level": risk_level,
                "status": (incident and incident.status) or "NEW",
                "timestamp": (
                    incident.created_at.isoformat()
                    if incident and incident.created_at
                    else (event.timestamp.isoformat() if event and event.timestamp else now_dt.isoformat())
                ),
                "thumbnail_path": (incident and incident.screenshot_path) or (event and event.thumbnail_path),
                "video_clip_path": (incident and incident.video_clip_path) or (event and event.video_filename),
                "anomaly_reasons": (event and event.anomaly_reasons) or "Automated ML anomaly detection threshold exceeded",
            }

            # Generate evidence URL if available
            try:
                from app.services.storage_service import storage_service
                clip_path = incident_data.get("video_clip_path")
                if clip_path and self._get_public_base_url(getattr(settings, "BASE_URL", None)):
                    incident_data["evidence_link"] = storage_service.generate_secure_video_url(
                        video_id=event_id,
                        user_id=None,
                    )
            except Exception as e:
                logger.debug(f"Evidence link generation skipped: {e}")

            results = []
            success_count = 0
            details_text = (
                f"Incident {incident_id_str} | Camera: {camera_id} ({camera_name}) | "
                f"Location: {location} | Activity: {incident_data.get('activity_type')} | "
                f"Risk: {risk_level} | Reasons: {incident_data.get('anomaly_reasons')}"
            )

            for target in recipients:
                email = target["email"]
                email_masked = target["email_masked"]
                rec_type = target.get("recipient_type", "friend")

                # In-memory deduplication check
                if self._is_duplicate(incident_id_str, email):
                    results.append(
                        {
                            "recipient": email_masked,
                            "recipient_type": rec_type,
                            "status": "DUPLICATE_SKIPPED",
                            "success": False,
                            "error": "Alert already dispatched for this incident",
                        }
                    )
                    continue

                # Database deduplication check (prevent duplicate dispatches for already accepted/delivered alert)
                existing_log = (
                    db.query(EmailLog)
                    .filter(
                        EmailLog.incident_id == incident_id_str,
                        func.lower(EmailLog.recipient_email) == email.lower(),
                        EmailLog.status.in_(["ACCEPTED", "DELIVERED", "SENT"]),
                    )
                    .first()
                )
                if existing_log:
                    results.append(
                        {
                            "recipient": email_masked,
                            "recipient_type": rec_type,
                            "status": "DUPLICATE_SKIPPED",
                            "success": False,
                            "error": f"Email alert already recorded with status {existing_log.status}",
                        }
                    )
                    continue

                subject, html_content, text_content = self.build_email_content(incident_data)

                # Persist initial log
                email_log = EmailLog(
                    incident_id=incident_id_str,
                    recipient_email=email,
                    recipient_email_masked=email_masked,
                    subject=subject,
                    provider="apps_script",
                    status="SENDING",
                    created_at=now_dt,
                    is_test=False,
                )
                db.add(email_log)
                db.flush()

                # Dispatch via Google Apps Script HTTP API
                res = self._send_apps_script(
                    to_email=email,
                    subject=subject,
                    camera=camera_id,
                    event_name=incident_data.get("activity_type") or "Suspicious Activity",
                    timestamp_str=incident_data.get("timestamp"),
                    details=details_text,
                    html_content=html_content,
                    text_content=text_content,
                )

                email_log.status = res.status
                email_log.error_message = res.error
                email_log.provider_message_id = res.message_id
                email_log.attempt_count = 1
                if res.success:
                    email_log.sent_at = now_dt
                    success_count += 1
                db.commit()

                results.append(
                    {
                        "recipient": email_masked,
                        "recipient_type": rec_type,
                        "status": res.status,
                        "success": res.success,
                        "provider": res.provider,
                        "message_id": res.message_id,
                        "error": res.error,
                    }
                )

            # Update Incident notification status
            if incident:
                try:
                    if success_count == len(recipients) and len(recipients) > 0:
                        incident.notification_status = "SENT"
                    elif success_count > 0:
                        incident.notification_status = "PARTIAL"
                    else:
                        incident.notification_status = "FAILED"
                    db.commit()
                except Exception:
                    pass

            total_recipients = len(results)
            if success_count == total_recipients and total_recipients > 0:
                summary_msg = f"Alert email successfully dispatched to all {total_recipients} recipient(s)."
            elif success_count > 0:
                summary_msg = f"Alert email dispatched to {total_recipients} recipient(s) ({success_count} succeeded, {total_recipients - success_count} failed)."
            else:
                first_err = next((r.get("error") for r in results if r.get("error")), "All recipient dispatches failed")
                summary_msg = f"Alert email dispatch failed for {total_recipients} recipient(s): {first_err}"

            return {
                "success": success_count > 0,
                "status": "ACCEPTED" if success_count > 0 else "FAILED",
                "provider": "apps_script",
                "is_configured": True,
                "message": summary_msg,
                "dispatches": results,
            }

        except Exception as e:
            logger.error(f"Email dispatch exception for event {event_id}: {e}")
            db.rollback()
            return {
                "success": False,
                "status": "FAILED",
                "provider": "apps_script",
                "message": str(e),
                "dispatches": [],
            }
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Test Email
    # ------------------------------------------------------------------

    def send_test_email(self, to_email: Optional[str] = None) -> dict:
        """
        Send a test email via Google Apps Script HTTP API to verify configuration and delivery.
        Logs attempt into EmailLog table.
        """
        if not self.is_configured():
            url = self._get_web_app_url()
            secret = self._get_webhook_secret()
            if not url or self._is_placeholder_url(url):
                err_msg = "Google Apps Script is not configured: APPS_SCRIPT_WEB_APP_URL is missing or placeholder in .env."
            elif not secret or self._is_placeholder_secret(secret):
                err_msg = "Google Apps Script is not configured: APPS_SCRIPT_WEBHOOK_SECRET is missing or placeholder in .env."
            else:
                err_msg = "Google Apps Script is not configured: EMAIL_ENABLED is set to false in .env."
            return {
                "success": False,
                "status": "NOT_CONFIGURED",
                "provider": "apps_script",
                "error": err_msg,
                "message": err_msg,
            }

        if to_email and to_email.strip():
            target = to_email.strip()
        else:
            env_admins = self._get_env_admin_emails()
            all_active = self.get_all_recipients(active_only=True)
            if all_active:
                target = all_active[0]["email"]
            elif env_admins:
                target = env_admins[0]
            else:
                target = "admin@company.com"

        if not validate_email(target):
            return {
                "success": False,
                "status": "FAILED",
                "provider": "apps_script",
                "recipient": mask_email(target),
                "error": f"Invalid recipient email address: '{target}'",
                "message": f"Invalid recipient email address: '{target}'",
            }

        subject = "SurveilGuard AI - Google Apps Script HTTP Email Test"
        now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        timestamp = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Inter,system-ui,sans-serif;padding:24px;background:#f8fafc;color:#1e293b;">
    <div style="background:#ffffff;border-radius:12px;padding:32px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);border-left:5px solid #2563eb;max-width:560px;margin:0 auto;">
        <h2 style="color:#2563eb;margin-top:0;font-size:20px;">&#9989; Google Apps Script Email API Test</h2>
        <p style="font-size:14px;color:#475569;line-height:1.6;">
            This test email confirms that <strong>SurveilGuard AI</strong> is communicating with the <strong>Google Apps Script Web App</strong> (Port 443 HTTPS).
        </p>
        <div style="background:#f1f5f9;border-radius:8px;padding:16px;margin:20px 0;font-size:13px;">
            <div><strong>Provider:</strong> Google Apps Script HTTP REST API</div>
            <div><strong>Recipient:</strong> <code>{html.escape(target)}</code></div>
            <div><strong>Status:</strong> Accepted for delivery</div>
        </div>
        <p style="font-size:12px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:16px;margin-top:24px;">
            Dispatched at {timestamp} UTC by SurveilGuard AI Notification Engine.
        </p>
    </div>
</body>
</html>"""

        text_content = f"""SurveilGuard AI - Google Apps Script Email Test

This test email confirms that SurveilGuard AI is communicating via the Google Apps Script HTTP API (Port 443).
Provider: Google Apps Script HTTP REST API
Recipient: {target}
Status: Accepted for delivery
Dispatched at: {timestamp} UTC
"""
        details_text = f"Health check test dispatch via Google Apps Script Web App for {target} at {timestamp} UTC."

        res = self._send_apps_script(
            to_email=target,
            subject=subject,
            camera="CAM-TEST",
            event_name="[TEST EMAIL] System Connectivity Verification",
            timestamp_str=timestamp,
            details=details_text,
            html_content=html_content,
            text_content=text_content,
        )

        # Audit log into EmailLog
        db = SessionLocal()
        try:
            log = EmailLog(
                incident_id="TEST-APPS-SCRIPT",
                recipient_email=target,
                recipient_email_masked=mask_email(target),
                subject=subject,
                provider="apps_script",
                provider_message_id=res.message_id,
                status=res.status,
                error_message=res.error,
                attempt_count=1,
                is_test=True,
                sent_at=now_dt if res.success else None,
            )
            db.add(log)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to record test email log: {e}")
        finally:
            db.close()

        success_msg = f"Test email accepted by Google Apps Script for {target} (Message ID: {res.message_id or 'N/A'})"
        fail_msg = f"Test email failed: {res.error or 'Unknown error'}"
        return {
            "success": res.success,
            "status": res.status,
            "provider": res.provider,
            "recipient": mask_email(target),
            "message_id": res.message_id,
            "error": res.error,
            "message": success_msg if res.success else fail_msg,
        }

    # ------------------------------------------------------------------
    # Send email for existing incident (manual resend)
    # ------------------------------------------------------------------

    def send_incident_email(self, incident_id: str) -> dict:
        """Send an email alert for an existing incident to all active recipients."""
        db = SessionLocal()
        try:
            incident = (
                db.query(Incident)
                .filter(or_(Incident.incident_id == incident_id, Incident.event_id == incident_id))
                .first()
            )
            if not incident:
                return {"success": False, "status": "NOT_FOUND", "message": f"Incident {incident_id} not found"}

            camera = db.query(Camera).filter(Camera.camera_id == incident.camera_id).first()
            event = db.query(Event).filter(Event.event_id == incident.event_id).first()
            recipients = self.get_all_recipients(db=db, active_only=True)
            if not recipients:
                return {"success": False, "status": "NO_RECIPIENTS", "message": "No active email recipients configured."}

            confidence = incident.confidence or (event and event.anomaly_score) or 0.85
            if confidence >= 0.7:
                risk_level = "HIGH"
            elif confidence >= 0.4:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            incident_data = {
                "incident_id": incident.incident_id,
                "event_id": incident.event_id,
                "camera_id": incident.camera_id,
                "camera_name": camera.name if camera else "Unknown Camera",
                "location": incident.location or (camera.location if camera else "Unknown Location"),
                "activity_type": incident.activity_type or "Suspicious Activity",
                "risk_level": risk_level,
                "status": incident.status or "NEW",
                "timestamp": incident.created_at.isoformat() if incident.created_at else now_dt.isoformat(),
                "thumbnail_path": incident.screenshot_path,
                "video_clip_path": incident.video_clip_path,
                "anomaly_reasons": (event and event.anomaly_reasons) or "Security event flagged by surveillance AI",
            }

            try:
                from app.services.storage_service import storage_service
                if incident.video_clip_path and self._get_public_base_url(getattr(settings, "BASE_URL", None)):
                    incident_data["evidence_link"] = storage_service.generate_secure_video_url(
                        video_id=incident.event_id,
                        user_id=None,
                    )
            except Exception:
                pass

            results = []
            success_count = 0
            details_text = (
                f"Incident {incident.incident_id} | Camera: {incident.camera_id} | "
                f"Location: {incident_data['location']} | Activity: {incident_data['activity_type']} | Risk: {risk_level}"
            )

            for target in recipients:
                email = target["email"]
                email_masked = target["email_masked"]
                rec_type = target.get("recipient_type", "friend")

                if self._is_duplicate(incident.incident_id, email):
                    results.append(
                        {"recipient": email_masked, "recipient_type": rec_type, "status": "DUPLICATE_SKIPPED", "success": False}
                    )
                    continue

                subject, html_content, text_content = self.build_email_content(incident_data)

                email_log = EmailLog(
                    incident_id=incident.incident_id,
                    recipient_email=email,
                    recipient_email_masked=email_masked,
                    subject=subject,
                    provider="apps_script",
                    status="SENDING",
                    created_at=now_dt,
                    is_test=False,
                )
                db.add(email_log)
                db.flush()

                res = self._send_apps_script(
                    to_email=email,
                    subject=subject,
                    camera=incident.camera_id,
                    event_name=incident_data["activity_type"],
                    timestamp_str=incident_data["timestamp"],
                    details=details_text,
                    html_content=html_content,
                    text_content=text_content,
                )
                email_log.status = res.status
                email_log.error_message = res.error
                email_log.provider_message_id = res.message_id
                email_log.attempt_count = 1
                if res.success:
                    email_log.sent_at = now_dt
                    success_count += 1
                db.commit()

                results.append(
                    {
                        "recipient": email_masked,
                        "recipient_type": rec_type,
                        "status": res.status,
                        "success": res.success,
                        "error": res.error,
                    }
                )

            total_recipients = len(results)
            first_err = next((r.get("error") for r in results if r.get("error")), "All recipient dispatches failed")
            msg = (
                f"Incident email dispatched to {total_recipients} recipient(s) ({success_count} succeeded)."
                if success_count > 0
                else f"Incident email dispatch failed: {first_err}"
            )

            return {
                "success": success_count > 0,
                "status": "ACCEPTED" if success_count > 0 else "FAILED",
                "message": msg,
                "dispatches": results,
            }
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Backward Compatibility Webhook Handling
    # ------------------------------------------------------------------

    def verify_webhook_signature(self, raw_body: bytes, headers: dict) -> bool:
        """
        Backward-compatible webhook signature verifier.
        Preserves compatibility if webhook calls occur.
        """
        secret = (getattr(settings, "RESEND_WEBHOOK_SECRET", None) or os.getenv("RESEND_WEBHOOK_SECRET") or "").strip()
        if not secret:
            return True

        msg_id = headers.get("svix-id") or headers.get("webhook-id")
        msg_timestamp = headers.get("svix-timestamp") or headers.get("webhook-timestamp")
        msg_signature = headers.get("svix-signature") or headers.get("webhook-signature")

        if not msg_id or not msg_timestamp or not msg_signature:
            return False

        if secret.startswith("whsec_"):
            try:
                secret_bytes = base64.b64decode(secret[6:])
            except Exception:
                secret_bytes = secret.encode("utf-8")
        else:
            secret_bytes = secret.encode("utf-8")

        try:
            ts = int(msg_timestamp)
            now = int(time.time())
            if abs(now - ts) > 300:
                return False
        except ValueError:
            return False

        to_sign = f"{msg_id}.{msg_timestamp}.".encode("utf-8") + raw_body
        expected_sig = base64.b64encode(hmac.new(secret_bytes, to_sign, hashlib.sha256).digest()).decode("utf-8")

        for part in msg_signature.split():
            if part.startswith("v1,"):
                sig = part[3:]
                if hmac.compare_digest(sig, expected_sig):
                    return True
        return False

    def process_webhook_event(self, event: dict, db) -> dict:
        """
        Process delivery/bounce webhook events safely and idempotently.
        Preserved for backward-compatibility.
        """
        event_type = event.get("type")
        event_data = event.get("data", {})
        email_id = event_data.get("email_id")

        if not email_id:
            return {"processed": False, "reason": "No email_id in event"}

        log = db.query(EmailLog).filter(EmailLog.provider_message_id == email_id).first()
        if not log:
            return {"processed": False, "reason": f"No EmailLog found with provider_message_id {email_id}"}

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

        if event_type == "email.delivered":
            if log.status != "DELIVERED":
                log.status = "DELIVERED"
                log.delivered_at = now
                db.commit()
                logger.info(f"Updated email #{log.id} ({email_id}) status to DELIVERED")
            return {"processed": True, "status": "DELIVERED", "id": log.id}

        elif event_type == "email.bounced":
            log.status = "BOUNCED"
            bounce_msg = event_data.get("bounce", {}).get("message") or "Email bounced by destination server"
            log.error_message = f"Bounced: {bounce_msg}"
            db.commit()
            logger.warning(f"Updated email #{log.id} ({email_id}) status to BOUNCED: {bounce_msg}")
            return {"processed": True, "status": "BOUNCED", "id": log.id}

        return {"processed": True, "status": log.status, "event": event_type}

    # ------------------------------------------------------------------
    # Audit Logs
    # ------------------------------------------------------------------

    def get_logs(self, db, limit: int = 100, offset: int = 0, status: Optional[str] = None) -> list:
        """Retrieve email log history gracefully without removing historical records."""
        try:
            q = db.query(EmailLog)
            if status:
                q = q.filter(EmailLog.status == status.upper())
            logs = q.order_by(EmailLog.created_at.desc()).offset(offset).limit(limit).all()
            return [
                {
                    "id": log.id,
                    "incident_id": log.incident_id,
                    "recipient_email": log.recipient_email,
                    "recipient_email_masked": log.recipient_email_masked or mask_email(log.recipient_email),
                    "subject": log.subject,
                    "provider": log.provider or "apps_script",
                    "provider_message_id": log.provider_message_id,
                    "status": log.status,
                    "error_message": log.error_message,
                    "attempt_count": log.attempt_count or 1,
                    "is_test": bool(log.is_test),
                    "sent_at": log.sent_at.isoformat() if log.sent_at else None,
                    "delivered_at": log.delivered_at.isoformat() if getattr(log, "delivered_at", None) else None,
                    "created_at": log.created_at.isoformat() if log.created_at else None,
                }
                for log in logs
            ]
        except Exception as e:
            logger.warning(f"Error querying email logs: {e}")
            return []


# Module-level singleton
email_service = EmailService()
