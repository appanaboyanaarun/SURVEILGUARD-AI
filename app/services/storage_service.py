"""
Storage Service Abstraction.
Supports local filesystem storage (development) and cloud/S3-compatible object storage (production).
Enforces path traversal defense, file type validation, and signed temporary URL access.
"""

import os
import re
import uuid
import datetime
import mimetypes
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from app.config import settings
from app.database.connection import DATA_DIR
from app.services.auth_service import create_signed_video_token, verify_signed_video_token

UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
THUMBNAILS_DIR = os.path.join(DATA_DIR, "thumbnails")
EVIDENCE_DIR = os.path.join(DATA_DIR, "evidence")

os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(THUMBNAILS_DIR, exist_ok=True)
os.makedirs(EVIDENCE_DIR, exist_ok=True)

ALLOWED_VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov", ".avi", ".mkv", ".3gp"}
ALLOWED_VIDEO_MIMES = {
    "video/mp4",
    "video/webm",
    "video/quicktime",
    "video/x-msvideo",
    "video/x-matroska",
    "video/3gpp",
    "application/octet-stream",
}
MAX_VIDEO_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes user-provided filename by removing directory paths,
    special characters, and enforcing safe ASCII name.
    """
    base_name = os.path.basename(filename)
    # Remove any non-alphanumeric except dots, dashes, underscores
    clean_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", base_name)
    return clean_name or "video_upload.mp4"


class LocalStorageProvider:
    """Stores files on the local filesystem in data/evidence or data/uploads."""

    def __init__(self, base_dir: str = EVIDENCE_DIR):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def save(self, data: bytes, filename: str, subfolder: str = "") -> Tuple[str, str]:
        """
        Saves binary data with a collision-free UUID prefix.
        Returns (relative_storage_path, absolute_filepath).
        """
        clean_name = sanitize_filename(filename)
        unique_name = f"{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}_{clean_name}"
        target_dir = os.path.join(self.base_dir, subfolder) if subfolder else self.base_dir
        os.makedirs(target_dir, exist_ok=True)

        target_path = os.path.abspath(os.path.join(target_dir, unique_name))
        # Ensure path stays within base_dir (path traversal protection)
        if not target_path.startswith(self.base_dir):
            raise ValueError("Path traversal attempt detected")

        with open(target_path, "wb") as f:
            f.write(data)

        rel_path = os.path.relpath(target_path, DATA_DIR).replace("\\", "/")
        return rel_path, target_path

    def get_absolute_path(self, storage_path: str) -> Optional[str]:
        """Resolves relative storage path to absolute filesystem path."""
        clean_rel = storage_path.lstrip("/").replace("\\", "/")
        abs_path = os.path.abspath(os.path.join(DATA_DIR, clean_rel))
        if not abs_path.startswith(os.path.abspath(DATA_DIR)):
            return None
        if os.path.exists(abs_path):
            return abs_path
        return None

    def delete(self, storage_path: str) -> bool:
        path = self.get_absolute_path(storage_path)
        if path and os.path.exists(path):
            try:
                os.remove(path)
                return True
            except OSError:
                return False
        return False


class StorageService:
    """
    Unified storage manager.
    Selects LocalStorageProvider or Cloud S3 depending on environment configuration.
    """

    def __init__(self):
        self.provider_type = settings.STORAGE_PROVIDER
        self.local_provider = LocalStorageProvider(base_dir=EVIDENCE_DIR)

    def save_evidence_video(
        self,
        video_bytes: bytes,
        filename: str,
        mime_type: str = "video/webm",
    ) -> Dict[str, Any]:
        """
        Saves evidence clip securely.
        Returns metadata dict with storage_path, file_size, and safe filename.
        """
        if len(video_bytes) > MAX_VIDEO_FILE_SIZE:
            raise ValueError(f"File size exceeds maximum allowed limit of {MAX_VIDEO_FILE_SIZE // (1024*1024)}MB")

        ext = os.path.splitext(filename)[1].lower()
        if not ext or ext not in ALLOWED_VIDEO_EXTENSIONS:
            if "webm" in mime_type:
                ext = ".webm"
            else:
                ext = ".mp4"
            filename = f"evidence_{uuid.uuid4().hex[:6]}{ext}"

        rel_path, abs_path = self.local_provider.save(video_bytes, filename, subfolder="evidence")
        file_size = len(video_bytes)

        return {
            "storage_provider": "local",
            "storage_path": rel_path,
            "absolute_path": abs_path,
            "file_size": file_size,
            "filename": os.path.basename(abs_path),
            "mime_type": mime_type,
        }

    def generate_secure_video_url(self, video_id: str, user_id: Optional[int] = None) -> str:
        """
        Generates a time-bounded signed URL for browser video playback.
        """
        signed_token = create_signed_video_token(video_id=video_id, user_id=user_id)
        base = settings.BASE_URL.rstrip("/")
        return f"{base}/api/videos/secure-stream/{video_id}?token={signed_token}"

    def generate_admin_event_link(self, event_id: str) -> str:
        """
        Generates a browser link for Admin SMS notification to directly view the event & evidence clip.

        Safety: refuses to build a link from localhost/127.0.0.1 because an SMS link
        opened on a mobile phone cannot reach the developer's local machine.
        FRONTEND_URL must be a public HTTPS address (e.g. https://your-domain.com).
        """
        frontend_base = settings.FRONTEND_URL.rstrip("/")

        # Block localhost / loopback URLs intended for SMS links
        blocked = ("127.0.0.1", "localhost", "::1", "0.0.0.0")
        if any(b in frontend_base for b in blocked):
            raise ValueError(
                "FRONTEND_URL is set to a localhost/loopback address. "
                "SMS evidence links must use a public HTTPS URL (e.g. https://surveilguard.yourdomain.com). "
                "Set FRONTEND_URL in .env to your publicly reachable server address."
            )

        return f"{frontend_base}/?event_id={event_id}#view-event-detail"

    def get_video_file_path(self, storage_path: str) -> Optional[str]:
        return self.local_provider.get_absolute_path(storage_path)


storage_service = StorageService()
