"""
Centralized configuration loaded from environment variables / .env file.
"""

import os
import re
from pathlib import Path
from typing import List

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(_env_path)
except ImportError:
    pass  # python-dotenv is optional; fall back to OS-level env vars


def _parse_cors(raw: str) -> List[str]:
    """Parse CORS_ORIGINS env var into a list of origin strings."""
    raw = raw.strip()
    if raw == "*":
        return ["*"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


class Settings:
    """Application settings sourced from environment variables."""

    # Server & Environment
    DEBUG: bool = os.getenv("DEBUG", "true").lower() in ("true", "1", "yes")
    DEVELOPMENT: bool = os.getenv("DEVELOPMENT", "true").lower() in ("true", "1", "yes")
    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))

    # URLs
    BASE_URL: str = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", os.getenv("BASE_URL", "http://127.0.0.1:8000")).rstrip("/")

    # CORS
    CORS_ORIGINS: List[str] = _parse_cors(os.getenv("CORS_ORIGINS", "*"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")

    # Security & JWT Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "surveilguard-ai-secure-secret-key-2026")
    JWT_SECRET: str = os.getenv("JWT_SECRET", os.getenv("SECRET_KEY", "surveilguard-jwt-signing-secret-2026"))
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours
    SIGNED_URL_EXPIRE_MINUTES: int = int(os.getenv("SIGNED_URL_EXPIRE_MINUTES", "120"))  # 2 hours

    # Live Detection & False Positive Control
    DETECTION_SENSITIVITY: float = float(os.getenv("DETECTION_SENSITIVITY", "0.35"))
    DETECTION_CONFIDENCE_THRESHOLD: float = float(os.getenv("DETECTION_CONFIDENCE_THRESHOLD", "0.60"))
    SUSPICIOUS_CONFIRMATION_SECONDS: float = float(os.getenv("SUSPICIOUS_CONFIRMATION_SECONDS", "1.5"))
    RECORDING_DURATION_SECONDS: int = int(os.getenv("RECORDING_DURATION_SECONDS", "8"))
    WS_HEARTBEAT_INTERVAL: int = int(os.getenv("WS_HEARTBEAT_INTERVAL", "30"))

    # SMS Notifications (Twilio / Vonage / Mock)
    SMS_PROVIDER: str = os.getenv("SMS_PROVIDER", "mock").lower()
    TWILIO_ACCOUNT_SID: str = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN: str = os.getenv("TWILIO_AUTH_TOKEN", "")
    TWILIO_FROM_NUMBER: str = os.getenv("TWILIO_FROM_NUMBER", "")
    ADMIN_PHONE_NUMBER: str = os.getenv("ADMIN_PHONE_NUMBER", "")

    # Email Notifications (Google Apps Script HTTP API)
    EMAIL_ENABLED: bool = os.getenv("EMAIL_ENABLED", "true").lower() in ("true", "1", "yes")
    EMAIL_PROVIDER: str = os.getenv("EMAIL_PROVIDER", "apps_script").lower()

    # Google Apps Script Web App Configuration
    APPS_SCRIPT_WEB_APP_URL: str = os.getenv("APPS_SCRIPT_WEB_APP_URL", "").strip()
    APPS_SCRIPT_WEBHOOK_SECRET: str = os.getenv("APPS_SCRIPT_WEBHOOK_SECRET", "").strip()
    APPS_SCRIPT_TIMEOUT_SECONDS: int = int(os.getenv("APPS_SCRIPT_TIMEOUT_SECONDS", "15"))

    # Sender & Recipient Management (backward-compatible)
    ALERT_FROM_EMAIL: str = (os.getenv("ALERT_FROM_EMAIL") or os.getenv("EMAIL_FROM") or "alerts@surveilguard.local").strip()
    ALERT_FROM_NAME: str = (os.getenv("ALERT_FROM_NAME") or "Suspicious Activity Detection").strip()
    EMAIL_FROM: str = (os.getenv("ALERT_FROM_EMAIL") or os.getenv("EMAIL_FROM") or "alerts@surveilguard.local").strip()
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "arunrgmcollege@gmail.com").strip()
    ADMIN_EMAILS: str = os.getenv("ADMIN_EMAILS", "").strip()
    EMAIL_COOLDOWN_SECONDS: int = int(os.getenv("EMAIL_COOLDOWN_SECONDS", "30"))

    # Legacy Resend Configuration (preserved for historical compatibility)
    RESEND_API_KEY: str = os.getenv("RESEND_API_KEY", "").strip()
    RESEND_TIMEOUT_SECONDS: int = int(os.getenv("RESEND_TIMEOUT_SECONDS", "15"))
    RESEND_WEBHOOK_SECRET: str = os.getenv("RESEND_WEBHOOK_SECRET", "").strip()

    SMS_COOLDOWN_SECONDS: int = int(os.getenv("SMS_COOLDOWN_SECONDS", "30"))
    APP_BASE_URL: str = (os.getenv("APP_BASE_URL") or os.getenv("PUBLIC_BASE_URL") or os.getenv("BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
    PUBLIC_BASE_URL: str = (os.getenv("APP_BASE_URL") or os.getenv("PUBLIC_BASE_URL") or os.getenv("BASE_URL", "http://127.0.0.1:8000")).rstrip("/")

    def get_configured_admin_emails(self) -> list:
        """Returns normalized list of configured admin email addresses from environment."""
        emails = []
        raw_values = (
            os.getenv("ADMIN_EMAILS", self.ADMIN_EMAILS),
            os.getenv("ADMIN_EMAIL", self.ADMIN_EMAIL),
        )
        for raw_value in raw_values:
            for value in raw_value.split(","):
                email = value.strip().lower()
                if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email) and email not in emails:
                    emails.append(email)
        return emails

    # Storage Management (local development vs S3/cloud)
    STORAGE_PROVIDER: str = os.getenv("STORAGE_PROVIDER", "local").lower()  # local, s3
    STORAGE_BUCKET: str = os.getenv("STORAGE_BUCKET", "surveilguard-evidence")
    STORAGE_ACCESS_KEY: str = os.getenv("STORAGE_ACCESS_KEY", "")
    STORAGE_SECRET_KEY: str = os.getenv("STORAGE_SECRET_KEY", "")
    STORAGE_ENDPOINT_URL: str = os.getenv("STORAGE_ENDPOINT_URL", "")
    STORAGE_REGION: str = os.getenv("STORAGE_REGION", "us-east-1")

    # Firebase Cloud Messaging (Push Notifications)
    FIREBASE_CREDENTIALS_PATH: str = os.getenv("FIREBASE_CREDENTIALS_PATH", "")
    FIREBASE_PROJECT_ID: str = os.getenv("FIREBASE_PROJECT_ID", "")
    FIREBASE_CLIENT_EMAIL: str = os.getenv("FIREBASE_CLIENT_EMAIL", "")
    FIREBASE_PRIVATE_KEY: str = os.getenv("FIREBASE_PRIVATE_KEY", "")
    NOTIFICATION_COOLDOWN_SECONDS: int = int(os.getenv("NOTIFICATION_COOLDOWN_SECONDS", "30"))


settings = Settings()
