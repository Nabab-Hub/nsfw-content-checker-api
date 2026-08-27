from app.api.routes.health import router as health_router
from app.api.routes.nsfw import router as nsfw_router

__all__ = [
    "health_router",
    "nsfw_router",
]
