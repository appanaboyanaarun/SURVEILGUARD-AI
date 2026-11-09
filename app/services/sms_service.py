"""
SMS Notification Service.
Sends automated real-time SMS alerts to authorized Admin phones when suspicious activity is detected.
Includes a secure, direct browser link to view the evidence video clip.
Supports Mock (local development & testing), Twilio, Vonage, and generic HTTP webhooks.
Includes cooldown tracking, deduplication, retry logic, and audit database logging.

IMPORTANT: Mock mode is only active when SMS_PROVIDER=mock.
Unknown providers are rejected — no silent fallback.
"""

import datetime
import logging
import re
import threading
import time
from typing import Optional, Dict, Any, Tuple

import requests
from sqlalchemy.orm import Session

from app.config import settings
from app.database.connection import SessionLocal
from app.models.schema import Event, SMSLog, User, NotificationRecipient
from app.services.storage_service import storage_service

logger = logging.getLogger("sms_service")

# Twilio SDK imports (with fallback if twilio not installed)
try:
    from twilio.rest import Client
    from twilio.base.exceptions import TwilioRestException
except ImportError:
    Client = None
    TwilioRestException = Exception
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] [SMS] %(message)s"))
    logger.addHandler(handler)

# E.164 format: + followed by 1-15 digits
E164_REGEX = re.compile(r"^\+[1-9]\d{1,14}$")

# Valid SMS provider names
VALID_PROVIDERS = {"mock", "twilio", "vonage", "generic_http"}


def validate_e164(phone: str) -> bool:
    """Validate phone number is in E.164 format."""
    return bool(E164_REGEX.match(phone)) if phone else False


def mask_phone(phone: str) -> str:
    """Mask phone number for safe display: +1234567890 -> +1***890"""
    if not phone or len(phone) < 6:
        return phone or ""
    return phone[:2] + "***" + phone[-3:]


class SMSDispatchResult:
    """Structured result from an SMS dispatch attempt."""

    def __init__(
        self,
        success: bool,
        status: str,
        provider: str,
        error: Optional[str] = None,
        provider_message_id: Optional[str] = None,
        provider_accepted_at: Optional[datetime.datetime] = None,
    ):
        self.success = success
        self.status = status  # NOT_CONFIGURED, QUEUED, SENT, FAILED, MOCK
        self.provider = provider
        self.error = error
        self.provider_message_id = provider_message_id
        self.provider_accepted_at = provider_accepted_at


class SMSService:
    """
    Singleton service for sending SMS alerts to Admins.
    """

    def __init__(self):
        self._cooldown_tracker: Dict[str, float] = {}  # camera_id -> epoch timestamp
        self._lock = threading.Lock()
        self._test_rate_tracker: Dict[str, float] = {}  # IP/user key -> last test time
        self._test_rate_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Recipients Management (Multi-Admin Recipients)
    # ------------------------------------------------------------------

    def get_all_recipients(self, db: Optional[Session] = None) -> list:
        """
        Retrieves all configured active admin recipient phone numbers.
        Sources (in priority order, deduplicated):
          1. Database NotificationRecipient records (is_active=True)
          2. Environment variables ADMIN_PHONE_NUMBERS and ADMIN_PHONE_NUMBER
          3. Active Admin users with phone numbers in User table
        """
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            recipients = []
            seen_phones = set()

            # 1. Database NotificationRecipient records
            try:
                db_recipients = db.query(NotificationRecipient).filter(NotificationRecipient.is_active == True).all()
                for r in db_recipients:
                    phone = (r.phone_number or "").strip()
                    if validate_e164(phone) and phone not in seen_phones:
                        seen_phones.add(phone)
                        recipients.append({
                            "id": r.id,
                            "name": r.name,
                            "phone": phone,
                            "phone_masked": mask_phone(phone),
                            "source": "database",
                            "is_active": True,
                            "created_at": r.created_at.isoformat() if r.created_at else None,
                        })
            except Exception as e:
                logger.warning(f"Failed to query database recipients: {e}")

            # 2. Environment variables (ADMIN_PHONE_NUMBERS / ADMIN_PHONE_NUMBER)
            env_phones = settings.get_configured_admin_phones() if hasattr(settings, "get_configured_admin_phones") else []
            for p in env_phones:
                p_clean = (p or "").strip()
                if validate_e164(p_clean) and p_clean not in seen_phones:
                    seen_phones.add(p_clean)
                    recipients.append({
                        "id": None,
                        "name": "Configured Admin",
                        "phone": p_clean,
                        "phone_masked": mask_phone(p_clean),
                        "source": "environment",
                        "is_active": True,
                        "created_at": None,
                    })

            # 3. Active Admin users with phone numbers in User table
            try:
                admin_users = db.query(User).filter(
                    User.role == "admin",
                    User.phone_number.isnot(None),
                    User.is_active == True,
                ).all()
                for u in admin_users:
                    u_phone = (u.phone_number or "").strip()
                    if validate_e164(u_phone) and u_phone not in seen_phones:
                        seen_phones.add(u_phone)
                        recipients.append({
                            "id": None,
                            "name": u.full_name or u.username,
                            "phone": u_phone,
                            "phone_masked": mask_phone(u_phone),
                            "source": "user",
                            "is_active": True,
                            "created_at": u.created_at.isoformat() if u.created_at else None,
                        })
            except Exception as e:
                logger.warning(f"Failed to query admin users: {e}")

            return recipients
        finally:
            if close_db:
                db.close()

    def add_recipient(self, name: str, phone: str, db: Session) -> Dict[str, Any]:
        """Adds a new recipient phone number."""
        phone_clean = (phone or "").strip()
        if not validate_e164(phone_clean):
            raise ValueError(f"Phone number '{mask_phone(phone_clean)}' is not valid E.164 format (e.g. +14155552671).")

        existing = db.query(NotificationRecipient).filter(NotificationRecipient.phone_number == phone_clean).first()
        if existing:
            if not existing.is_active:
                existing.is_active = True
                existing.name = name.strip() or existing.name
                db.commit()
                db.refresh(existing)
                return {
                    "id": existing.id,
                    "name": existing.name,
                    "phone_masked": mask_phone(existing.phone_number),
                    "is_active": existing.is_active,
                    "message": "Re-activated existing recipient.",
                }
            raise ValueError(f"Recipient with number {mask_phone(phone_clean)} already exists.")

        rec = NotificationRecipient(
            name=name.strip() or "Admin Recipient",
            phone_number=phone_clean,
            is_active=True,
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return {
            "id": rec.id,
            "name": rec.name,
            "phone_masked": mask_phone(rec.phone_number),
            "is_active": rec.is_active,
        }

    def update_recipient(self, recipient_id: int, name: Optional[str], phone: Optional[str], is_active: Optional[bool], db: Session) -> Dict[str, Any]:
        """Updates an existing recipient."""
        rec = db.query(NotificationRecipient).filter(NotificationRecipient.id == recipient_id).first()
        if not rec:
            raise ValueError(f"Recipient #{recipient_id} not found.")

        if phone is not None:
            phone_clean = phone.strip()
            if not validate_e164(phone_clean):
                raise ValueError(f"Phone number '{mask_phone(phone_clean)}' is not valid E.164 format.")
            conflict = db.query(NotificationRecipient).filter(
                NotificationRecipient.phone_number == phone_clean,
                NotificationRecipient.id != recipient_id,
            ).first()
            if conflict:
                raise ValueError(f"Phone number {mask_phone(phone_clean)} is already in use by recipient #{conflict.id}.")
            rec.phone_number = phone_clean

        if name is not None:
            rec.name = name.strip() or rec.name

        if is_active is not None:
            rec.is_active = is_active

        db.commit()
        db.refresh(rec)
        return {
            "id": rec.id,
            "name": rec.name,
            "phone_masked": mask_phone(rec.phone_number),
            "is_active": rec.is_active,
        }

    def delete_recipient(self, recipient_id: int, db: Session) -> bool:
        """Deletes a recipient from the database."""
        rec = db.query(NotificationRecipient).filter(NotificationRecipient.id == recipient_id).first()
        if not rec:
            return False
        db.delete(rec)
        db.commit()
        return True

    # ------------------------------------------------------------------
    # Configuration Readiness
    # ------------------------------------------------------------------

    def get_provider_status(self) -> Dict[str, Any]:
        """
        Returns the current SMS provider configuration status.
        Never exposes secrets — only readiness and masked identifiers.
        """
        provider = settings.SMS_PROVIDER.lower()
        recipients = self.get_all_recipients()
        has_recipient = len(recipients) > 0

        result = {
            "provider": provider,
            "mode": "mock" if provider == "mock" else "live",
            "is_configured": False,
            "recipients_count": len(recipients),
            "recipients": recipients,
            "admin_phone_masked": recipients[0]["phone_masked"] if recipients else None,
            "sender_masked": None,
            "issues": [],
        }

        if provider == "mock":
            result["status"] = "MOCK"
            result["is_configured"] = True
            result["mode"] = "mock"
            result["issues"].append("SMS_PROVIDER is set to 'mock'. Messages are logged but not delivered.")
            if not has_recipient:
                result["issues"].append("No recipient phone numbers configured.")
            return result

        if provider not in VALID_PROVIDERS:
            result["status"] = "NOT_CONFIGURED"
            result["issues"].append(f"Unknown SMS_PROVIDER '{provider}'. Valid: {', '.join(sorted(VALID_PROVIDERS))}")
            return result

        if not has_recipient:
            result["issues"].append("No admin recipient phone numbers configured (set ADMIN_PHONE_NUMBER / ADMIN_PHONE_NUMBERS or add in Admin Dashboard).")

        if provider == "twilio":
            sid = settings.TWILIO_ACCOUNT_SID
            token = settings.TWILIO_AUTH_TOKEN
            from_num = settings.TWILIO_FROM_NUMBER

            if not sid:
                result["issues"].append("TWILIO_ACCOUNT_SID is not configured.")
            elif not sid.startswith("AC"):
                result["issues"].append("TWILIO_ACCOUNT_SID should start with 'AC'.")
            if not token:
                result["issues"].append("TWILIO_AUTH_TOKEN is not configured.")
            if not from_num:
                result["issues"].append("TWILIO_FROM_NUMBER is not configured.")
            elif not validate_e164(from_num):
                result["issues"].append(f"TWILIO_FROM_NUMBER '{mask_phone(from_num)}' is not valid E.164 format.")

            result["sender_masked"] = mask_phone(from_num) if from_num else None

            if sid and token and from_num and validate_e164(from_num) and has_recipient:
                result["is_configured"] = True

        elif provider == "vonage":
            if not settings.SMS_API_KEY:
                result["issues"].append("SMS_API_KEY (Vonage API key) is not configured.")
            if not settings.SMS_API_SECRET:
                result["issues"].append("SMS_API_SECRET (Vonage API secret) is not configured.")
            if settings.SMS_API_KEY and settings.SMS_API_SECRET and has_recipient:
                result["is_configured"] = True

        elif provider == "generic_http":
            if not settings.SMS_API_KEY:
                result["issues"].append("SMS_API_KEY (webhook URL) is not configured.")
            elif has_recipient:
                result["is_configured"] = True

        result["status"] = "READY" if result["is_configured"] else "NOT_CONFIGURED"
        return result

    # ------------------------------------------------------------------
    # Cooldown Management
    # ------------------------------------------------------------------

    def is_cooldown_active(self, camera_id: str) -> bool:
        """Check if SMS alert cooldown is currently active for this camera."""
        with self._lock:
            last_time = self._cooldown_tracker.get(camera_id)
            if last_time is None:
                return False
            elapsed = time.time() - last_time
            return elapsed < settings.SMS_COOLDOWN_SECONDS

    def update_cooldown(self, camera_id: str):
        """Reset cooldown timestamp for a camera."""
        with self._lock:
            self._cooldown_tracker[camera_id] = time.time()

    # ------------------------------------------------------------------
    # Rate Limiting for Test SMS
    # ------------------------------------------------------------------

    def check_test_rate_limit(self, key: str = "global", min_interval: float = 10.0) -> bool:
        """Returns True if allowed, False if rate-limited."""
        with self._test_rate_lock:
            now = time.time()
            last = self._test_rate_tracker.get(key)
            if last and (now - last) < min_interval:
                return False
            self._test_rate_tracker[key] = now
            return True

    # ------------------------------------------------------------------
    # Message Building
    # ------------------------------------------------------------------

    def build_alert_message(
        self,
        activity_type: str,
        location: str,
        risk_priority: str,
        timestamp: datetime.datetime,
        video_link: str,
        event_id: str = "",
        camera_id: str = "",
    ) -> str:
        """
        Builds concise, actionable SMS notification body.
        """
        time_str = timestamp.strftime("%I:%M:%S %p") if timestamp else datetime.datetime.utcnow().strftime("%I:%M:%S %p")
        parts = [
            f"ALERT: Suspicious activity detected - {activity_type}",
            f"Camera: {camera_id}" if camera_id else None,
            f"Location: {location}",
            f"Time: {time_str}",
            f"Risk: {risk_priority}",
        ]
        if event_id:
            parts.append(f"Incident: {event_id}")
        parts.append(f"Review: {video_link}")
        return "\n".join(p for p in parts if p)

    # ------------------------------------------------------------------
    # Incident SMS Dispatch (Background Thread)
    # ------------------------------------------------------------------

    def send_suspicious_event_sms(self, event_id: str, camera_id: str, recipient_phone: Optional[str] = None) -> bool:
        """
        Dispatches SMS in a background daemon thread so detection is never blocked.
        Returns True if dispatch was queued (not necessarily delivered).
        """
        if self.is_cooldown_active(camera_id):
            logger.info(f"SMS Cooldown active for camera '{camera_id}'. Skipping alert for event '{event_id}'.")
            db = SessionLocal()
            try:
                ev = db.query(Event).filter(Event.event_id == event_id).first()
                if ev and ev.sms_status == "NONE":
                    ev.sms_status = "COOLDOWN_SKIPPED"
                    db.commit()
            except Exception as e:
                logger.error(f"Failed to update cooldown SMS status for event '{event_id}': {e}")
            finally:
                db.close()
            return False

        # Mark event SMS status as PENDING immediately so incident review shows progress
        db = SessionLocal()
        try:
            ev = db.query(Event).filter(Event.event_id == event_id).first()
            if ev and ev.sms_status == "NONE":
                ev.sms_status = "PENDING"
                db.commit()
        except Exception as e:
            logger.error(f"Failed to mark initial PENDING SMS status for event '{event_id}': {e}")
        finally:
            db.close()

        thread = threading.Thread(
            target=self._send_sms_worker,
            args=(event_id, camera_id, recipient_phone),
            daemon=True,
        )
        thread.start()
        return True

    def _send_sms_worker(self, event_id: str, camera_id: str, recipient_phone: Optional[str] = None):
        """Worker executed in background thread. Dispatches to all configured recipients independently."""
        db: Session = SessionLocal()
        try:
            event = db.query(Event).filter(Event.event_id == event_id).first()
            if not event:
                logger.error(f"Event '{event_id}' not found for SMS delivery.")
                return

            if recipient_phone:
                targets = [{"phone": recipient_phone, "name": "Admin"}]
            else:
                targets = self.get_all_recipients(db)

            if not targets:
                logger.error(f"No admin phone number configured for SMS delivery of event '{event_id}'.")
                event.sms_status = "NOT_CONFIGURED"
                db.commit()
                return

            video_link = storage_service.generate_admin_event_link(event.event_id)
            message_body = self.build_alert_message(
                activity_type=event.activity_type,
                location=event.location,
                risk_priority=event.risk_priority,
                timestamp=event.timestamp,
                video_link=video_link,
                event_id=event.event_id,
                camera_id=event.camera_id,
            )

            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            success_count = 0
            latest_status = "FAILED"
            dispatched_masks = []

            for target in targets:
                phone = target["phone"]
                phone_masked = mask_phone(phone)
                dispatched_masks.append(phone_masked)

                # --- DUPLICATE PREVENTION: same incident + same recipient ---
                existing_log = (
                    db.query(SMSLog)
                    .filter(
                        SMSLog.event_id == event.event_id,
                        SMSLog.recipient_phone == phone,
                        SMSLog.is_test == False,
                    )
                    .first()
                )
                if existing_log and existing_log.status in ("SENT", "QUEUED", "DELIVERED", "MOCK"):
                    logger.info(
                        f"SMS already dispatched for event '{event.event_id}' to {phone_masked} "
                        f"(status={existing_log.status}). Skipping duplicate."
                    )
                    continue
                # -----------------------------------------------------------

                if not validate_e164(phone):
                    logger.error(f"Invalid phone number format for SMS delivery: {phone_masked}")
                    sms_log = SMSLog(
                        event_id=event.event_id,
                        recipient_phone=phone,
                        provider=settings.SMS_PROVIDER,
                        message_body=message_body,
                        status="FAILED",
                        error_message=f"Phone number {phone_masked} is not valid E.164 format.",
                        created_at=now,
                        is_test=False,
                    )
                    db.add(sms_log)
                    continue

                result = self._dispatch_provider_sms(phone, message_body)
                latest_status = result.status

                sms_log = SMSLog(
                    event_id=event.event_id,
                    recipient_phone=phone,
                    provider=result.provider,
                    provider_message_id=result.provider_message_id,
                    message_body=message_body,
                    video_link=video_link,
                    status=result.status,
                    error_message=result.error,
                    sent_at=now if result.success else None,
                    provider_accepted_at=result.provider_accepted_at,
                    created_at=now,
                    is_test=False,
                )
                db.add(sms_log)

                if result.success:
                    success_count += 1
                    logger.info(f"SMS alert dispatched for event '{event.event_id}' to {phone_masked} via {result.provider} (status={result.status})")
                else:
                    logger.warning(f"SMS alert failed for event '{event.event_id}' to {phone_masked}: {result.error}")

            # Update event record
            if success_count > 0:
                event.sms_status = latest_status
                event.sms_sent_at = now
                event.sms_phone = ", ".join(dispatched_masks)
                self.update_cooldown(camera_id)
            else:
                event.sms_status = "FAILED"
                event.sms_phone = ", ".join(dispatched_masks)
            db.commit()

        except Exception as exc:
            logger.error(f"Unexpected error in SMS worker: {str(exc)}", exc_info=True)
            db.rollback()
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Provider Dispatch
    # ------------------------------------------------------------------

    def _dispatch_provider_sms(self, to_phone: str, body: str) -> SMSDispatchResult:
        """
        Dispatches the message to the configured SMS provider.
        Returns a structured SMSDispatchResult.
        """
        provider = settings.SMS_PROVIDER.lower()

        # 1. Mock Provider (for development & testing ONLY)
        if provider == "mock":
            logger.info(
                f"\n"
                f"=================== [MOCK SMS DISPATCH] ===================\n"
                f"TO:      {to_phone}\n"
                f"FROM:    {settings.SMS_SENDER}\n"
                f"MESSAGE:\n{body}\n"
                f"==========================================================="
            )
            return SMSDispatchResult(
                success=True,
                status="MOCK",
                provider="mock",
                provider_message_id=f"MOCK-{int(time.time())}",
            )

        # 2. Twilio Provider (Official SDK)
        if provider == "twilio":
            return self._dispatch_twilio(to_phone, body)

        # 3. Vonage / Nexmo Provider
        if provider == "vonage":
            return self._dispatch_vonage(to_phone, body)

        # 4. Generic HTTP Webhook Provider
        if provider == "generic_http":
            return self._dispatch_generic_http(to_phone, body)

        # REJECTED: Unknown provider — never silently fall back to mock
        logger.error(f"Unknown SMS provider '{provider}'. Message NOT sent. Valid providers: {', '.join(sorted(VALID_PROVIDERS))}")
        return SMSDispatchResult(
            success=False,
            status="FAILED",
            provider=provider,
            error=f"Unknown SMS provider '{provider}'. Configure SMS_PROVIDER to one of: {', '.join(sorted(VALID_PROVIDERS))}",
        )

    def _dispatch_twilio(self, to_phone: str, body: str) -> SMSDispatchResult:
        """Dispatch SMS via Twilio official Python SDK."""
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        from_number = settings.TWILIO_FROM_NUMBER

        if not account_sid or not auth_token or not from_number:
            missing = []
            if not account_sid:
                missing.append("TWILIO_ACCOUNT_SID")
            if not auth_token:
                missing.append("TWILIO_AUTH_TOKEN")
            if not from_number:
                missing.append("TWILIO_FROM_NUMBER")
            return SMSDispatchResult(
                success=False,
                status="NOT_CONFIGURED",
                provider="twilio",
                error=f"Twilio not configured. Missing: {', '.join(missing)}",
            )

        if not validate_e164(from_number):
            return SMSDispatchResult(
                success=False,
                status="FAILED",
                provider="twilio",
                error=f"TWILIO_FROM_NUMBER is not valid E.164 format.",
            )

        if not validate_e164(to_phone):
            return SMSDispatchResult(
                success=False,
                status="FAILED",
                provider="twilio",
                error=f"Destination phone number is not valid E.164 format.",
            )

        try:
            if Client is None:
                raise ImportError("twilio package is not installed.")

            client = Client(account_sid, auth_token)

            # Build create kwargs
            create_kwargs = {
                "body": body,
                "from_": from_number,
                "to": to_phone,
            }

            # Add status callback URL if configured
            if settings.TWILIO_STATUS_CALLBACK_URL:
                create_kwargs["status_callback"] = settings.TWILIO_STATUS_CALLBACK_URL

            message = client.messages.create(**create_kwargs)

            # Twilio statuses: queued, sending, sent, delivered, undelivered, failed
            twilio_status = message.status or "queued"
            mapped_status = "QUEUED"
            if twilio_status in ("sent", "delivered"):
                mapped_status = "SENT"
            elif twilio_status == "failed":
                mapped_status = "FAILED"

            accepted_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

            logger.info(f"Twilio message created: SID={message.sid}, status={twilio_status}")

            return SMSDispatchResult(
                success=True,
                status=mapped_status,
                provider="twilio",
                provider_message_id=message.sid,
                provider_accepted_at=accepted_at,
            )

        except Exception as e:
            error_msg = str(e)[:500]
            # Check for common Twilio errors
            if "authenticate" in error_msg.lower() or "401" in error_msg:
                return SMSDispatchResult(
                    success=False,
                    status="FAILED",
                    provider="twilio",
                    error=f"Twilio authentication failed. Check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN.",
                )
            if "is not a valid phone number" in error_msg.lower():
                return SMSDispatchResult(
                    success=False,
                    status="FAILED",
                    provider="twilio",
                    error=f"Phone number validation failed: {error_msg}",
                )

            return SMSDispatchResult(
                success=False,
                status="FAILED",
                provider="twilio",
                error=f"Twilio error: {error_msg}",
            )

    def _dispatch_vonage(self, to_phone: str, body: str) -> SMSDispatchResult:
        """Dispatch SMS via Vonage/Nexmo REST API."""
        api_key = settings.SMS_API_KEY
        api_secret = settings.SMS_API_SECRET
        if not api_key or not api_secret:
            return SMSDispatchResult(
                success=False,
                status="NOT_CONFIGURED",
                provider="vonage",
                error="Vonage api_key or api_secret is not configured.",
            )

        url = "https://rest.nexmo.com/sms/json"
        try:
            resp = requests.post(
                url,
                json={
                    "api_key": api_key,
                    "api_secret": api_secret,
                    "from": settings.SMS_SENDER,
                    "to": to_phone.replace("+", ""),  # Vonage expects without +
                    "text": body,
                },
                timeout=15,
            )
            data = resp.json()
            messages = data.get("messages", [])
            if messages and messages[0].get("status") == "0":
                msg_id = messages[0].get("message-id")
                return SMSDispatchResult(
                    success=True,
                    status="SENT",
                    provider="vonage",
                    provider_message_id=msg_id,
                    provider_accepted_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
                )
            error_text = messages[0].get("error-text") if messages else resp.text
            return SMSDispatchResult(
                success=False,
                status="FAILED",
                provider="vonage",
                error=f"Vonage API Error: {error_text}",
            )
        except Exception as e:
            return SMSDispatchResult(
                success=False,
                status="FAILED",
                provider="vonage",
                error=f"Vonage connection error: {str(e)}",
            )

    def _dispatch_generic_http(self, to_phone: str, body: str) -> SMSDispatchResult:
        """Dispatch SMS via a generic HTTP webhook."""
        webhook_url = settings.SMS_API_KEY
        if not webhook_url:
            return SMSDispatchResult(
                success=False,
                status="NOT_CONFIGURED",
                provider="generic_http",
                error="SMS webhook URL not configured in SMS_API_KEY.",
            )
        try:
            resp = requests.post(
                webhook_url,
                json={
                    "to": to_phone,
                    "from": settings.SMS_SENDER,
                    "message": body,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                },
                headers={"Authorization": f"Bearer {settings.SMS_API_SECRET}"} if settings.SMS_API_SECRET else {},
                timeout=15,
            )
            if resp.status_code in (200, 201, 204):
                return SMSDispatchResult(
                    success=True,
                    status="SENT",
                    provider="generic_http",
                    provider_accepted_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None),
                )
            return SMSDispatchResult(
                success=False,
                status="FAILED",
                provider="generic_http",
                error=f"Webhook Error ({resp.status_code}): {resp.text[:200]}",
            )
        except Exception as e:
            return SMSDispatchResult(
                success=False,
                status="FAILED",
                provider="generic_http",
                error=f"Webhook connection error: {str(e)}",
            )

    # ------------------------------------------------------------------
    # Test SMS
    # ------------------------------------------------------------------

    def send_test_sms(self, phone: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends a test SMS to verify carrier connectivity without creating a fake incident.
        Returns truthful result with provider status and message ID.
        """
        provider_status = self.get_provider_status()
        target_phone = phone or settings.ADMIN_PHONE_NUMBER
        if not target_phone:
            db_temp = SessionLocal()
            try:
                recips = self.get_all_recipients(db_temp)
                if recips:
                    target_phone = recips[0]["phone"]
            except Exception as e:
                logger.warning(f"Failed to lookup fallback recipient: {e}")
            finally:
                db_temp.close()

        # Validate phone
        if not target_phone:
            return {
                "success": False,
                "status": "NOT_CONFIGURED",
                "provider": settings.SMS_PROVIDER,
                "provider_mode": provider_status["mode"],
                "recipient": None,
                "recipient_masked": None,
                "error": "No admin phone number configured. Set ADMIN_PHONE_NUMBER in .env or add in Admin Dashboard.",
                "provider_message_id": None,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "is_mock": settings.SMS_PROVIDER.lower() == "mock",
            }

        if not validate_e164(target_phone):
            return {
                "success": False,
                "status": "FAILED",
                "provider": settings.SMS_PROVIDER,
                "provider_mode": provider_status["mode"],
                "recipient": None,
                "recipient_masked": mask_phone(target_phone),
                "error": f"Phone number {mask_phone(target_phone)} is not valid E.164 format (e.g. +14155551234).",
                "provider_message_id": None,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "is_mock": settings.SMS_PROVIDER.lower() == "mock",
            }

        body = (
            f"[SurveilGuard AI] Test Notification\n"
            f"SMS monitoring gateway is online and functional.\n"
            f"Time: {datetime.datetime.utcnow().strftime('%I:%M:%S %p')} UTC\n"
            f"Provider: {settings.SMS_PROVIDER.upper()}"
        )

        result = self._dispatch_provider_sms(target_phone, body)

        # Log test SMS in database
        db = SessionLocal()
        try:
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            sms_log = SMSLog(
                event_id=None,  # No event for test SMS
                recipient_phone=target_phone,
                provider=result.provider,
                provider_message_id=result.provider_message_id,
                message_body=body,
                status=result.status,
                error_message=result.error,
                sent_at=now if result.success else None,
                provider_accepted_at=result.provider_accepted_at,
                created_at=now,
                is_test=True,
            )
            db.add(sms_log)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to log test SMS: {e}")
            db.rollback()
        finally:
            db.close()

        return {
            "success": result.success,
            "status": result.status,
            "provider": result.provider,
            "provider_mode": provider_status["mode"],
            "recipient": target_phone if settings.SMS_PROVIDER.lower() == "mock" else None,
            "recipient_masked": mask_phone(target_phone),
            "error": result.error,
            "provider_message_id": result.provider_message_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "is_mock": result.provider == "mock",
            "note": "SENT means accepted by the provider, not confirmed delivery to the phone." if result.status in ("SENT", "QUEUED") and result.provider != "mock" else None,
        }

    # ------------------------------------------------------------------
    # Suspicious Activity Alert SMS Dispatch
    # ------------------------------------------------------------------

    def send_alert_sms(
        self,
        phone: Optional[str] = None,
        activity_type: str = "Suspicious Activity",
        camera_id: str = "CAM-01",
        location: str = "Main Entrance",
        risk_priority: str = "HIGH",
        event_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Sends a high-priority Alert SMS formatted specifically for suspicious activity.
        Targets the specified phone or all configured admin recipients.
        """
        db = SessionLocal()
        try:
            if phone:
                targets = [{"phone": phone.strip(), "name": "Admin"}]
            else:
                targets = self.get_all_recipients(db)

            if not targets:
                return {
                    "success": False,
                    "status": "NOT_CONFIGURED",
                    "error": "No admin recipient phone numbers configured. Set ADMIN_PHONE_NUMBER or add in Admin Dashboard.",
                    "dispatches": [],
                }

            video_link = storage_service.generate_admin_event_link(event_id) if event_id else "http://127.0.0.1:8000"
            message_body = self.build_alert_message(
                activity_type=activity_type,
                location=location,
                risk_priority=risk_priority,
                timestamp=datetime.datetime.utcnow(),
                video_link=video_link,
                event_id=event_id,
                camera_id=camera_id,
            )

            results = []
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            success_count = 0

            for target in targets:
                p = target["phone"]
                p_masked = mask_phone(p)

                if not validate_e164(p):
                    sms_log = SMSLog(
                        event_id=event_id,
                        recipient_phone=p,
                        provider=settings.SMS_PROVIDER,
                        message_body=message_body,
                        video_link=video_link,
                        status="FAILED",
                        error_message=f"Phone number {p_masked} is not valid E.164 format.",
                        created_at=now,
                        is_test=False,
                    )
                    db.add(sms_log)
                    results.append({
                        "recipient": p_masked,
                        "status": "FAILED",
                        "success": False,
                        "error": f"Invalid E.164 phone: {p_masked}",
                    })
                    continue

                res = self._dispatch_provider_sms(p, message_body)
                sms_log = SMSLog(
                    event_id=event_id,
                    recipient_phone=p,
                    provider=res.provider,
                    provider_message_id=res.provider_message_id,
                    message_body=message_body,
                    video_link=video_link,
                    status=res.status,
                    error_message=res.error,
                    sent_at=now if res.success else None,
                    provider_accepted_at=res.provider_accepted_at,
                    created_at=now,
                    is_test=False,
                )
                db.add(sms_log)
                if res.success:
                    success_count += 1
                results.append({
                    "recipient": p_masked,
                    "status": res.status,
                    "success": res.success,
                    "provider": res.provider,
                    "provider_message_id": res.provider_message_id,
                    "error": res.error,
                })

            db.commit()
            return {
                "success": success_count > 0,
                "status": "SENT" if success_count > 0 else "FAILED",
                "provider": settings.SMS_PROVIDER,
                "is_mock": settings.SMS_PROVIDER.lower() == "mock",
                "message": f"Alert SMS dispatched to {len(results)} recipient(s) ({success_count} succeeded).",
                "message_body": message_body,
                "dispatches": results,
            }
        except Exception as e:
            logger.error(f"Error in send_alert_sms: {e}")
            db.rollback()
            return {
                "success": False,
                "status": "ERROR",
                "error": str(e),
                "dispatches": [],
            }
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Twilio Status Webhook
    # ------------------------------------------------------------------

    def handle_twilio_status_callback(self, data: Dict[str, Any]) -> bool:
        """
        Process a Twilio status callback webhook.
        Updates the SMS log with delivery status.
        Idempotent — safe to receive duplicate callbacks.
        """
        message_sid = data.get("MessageSid")
        message_status = data.get("MessageStatus")

        if not message_sid or not message_status:
            logger.warning("Twilio status callback missing MessageSid or MessageStatus")
            return False

        db = SessionLocal()
        try:
            sms_log = db.query(SMSLog).filter(
                SMSLog.provider_message_id == message_sid
            ).first()

            if not sms_log:
                logger.warning(f"Twilio callback for unknown message SID: {message_sid}")
                return False

            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            sms_log.delivery_status = message_status

            if message_status == "delivered":
                sms_log.status = "DELIVERED"
                sms_log.delivered_at = now
            elif message_status in ("undelivered", "failed"):
                sms_log.status = "FAILED"
                error_code = data.get("ErrorCode")
                error_message = data.get("ErrorMessage", "")
                sms_log.error_message = f"Delivery failed: {error_message} (code: {error_code})" if error_code else f"Delivery failed: {message_status}"
            elif message_status == "sent":
                sms_log.status = "SENT"

            # Also update the associated event if present
            if sms_log.event_id:
                event = db.query(Event).filter(Event.event_id == sms_log.event_id).first()
                if event:
                    event.sms_status = sms_log.status

            db.commit()
            logger.info(f"Twilio status callback: SID={message_sid}, status={message_status}")
            return True

        except Exception as e:
            logger.error(f"Error processing Twilio callback: {e}")
            db.rollback()
            return False
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Retry Failed SMS
    # ------------------------------------------------------------------

    def retry_failed_sms(self, sms_log_id: int) -> Dict[str, Any]:
        """
        Retry a failed SMS notification.
        Returns the result of the retry attempt.
        """
        db = SessionLocal()
        try:
            sms_log = db.query(SMSLog).filter(SMSLog.id == sms_log_id).first()
            if not sms_log:
                return {"success": False, "error": "SMS log entry not found."}

            if sms_log.status not in ("FAILED", "NOT_CONFIGURED"):
                return {"success": False, "error": f"Cannot retry SMS with status '{sms_log.status}'. Only FAILED or NOT_CONFIGURED can be retried."}

            if sms_log.retry_count >= 3:
                return {"success": False, "error": "Maximum retry attempts (3) reached for this notification."}

            # Re-dispatch
            result = self._dispatch_provider_sms(sms_log.recipient_phone, sms_log.message_body)

            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            sms_log.status = result.status
            sms_log.provider = result.provider
            sms_log.provider_message_id = result.provider_message_id
            sms_log.error_message = result.error
            sms_log.retry_count = (sms_log.retry_count or 0) + 1
            sms_log.sent_at = now if result.success else sms_log.sent_at
            sms_log.provider_accepted_at = result.provider_accepted_at

            # Update event status too
            if sms_log.event_id:
                event = db.query(Event).filter(Event.event_id == sms_log.event_id).first()
                if event:
                    event.sms_status = result.status

            db.commit()

            return {
                "success": result.success,
                "status": result.status,
                "provider": result.provider,
                "provider_message_id": result.provider_message_id,
                "error": result.error,
                "retry_count": sms_log.retry_count,
            }

        except Exception as e:
            db.rollback()
            return {"success": False, "error": f"Retry failed: {str(e)}"}
        finally:
            db.close()


sms_service = SMSService()
