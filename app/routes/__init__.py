from .auth import router as auth_router
from .cameras import router as cameras_router
from .videos import router as videos_router
from .events import router as events_router
from .alerts import router as alerts_router
from .reviews import router as reviews_router
from .analytics import router as analytics_router
from .live_monitoring import router as live_monitoring_router
from .live_monitoring import live_detection_ws
from .incidents import router as incidents_router
from .reports import router as reports_router
from .email_routes import router as email_router

__all__ = [
    "auth_router",
    "cameras_router",
    "videos_router",
    "events_router",
    "alerts_router",
    "reviews_router",
    "analytics_router",
    "live_monitoring_router",
    "live_detection_ws",
    "incidents_router",
    "reports_router",
    "email_router",
]
