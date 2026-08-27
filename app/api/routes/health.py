from fastapi import APIRouter
from app.models.schemas import HealthResponse, RootResponse

router = APIRouter(tags=["Health & Info"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
)
def health():
    """
    Returns server status. Used for container health checks and uptime monitoring.
    """
    return HealthResponse(
        success=True,
        status="ok",
    )


@router.get(
    "/",
    response_model=RootResponse,
    summary="Root service information",
)
def root():
    """
    Returns service name, version, and online status.
    """
    return RootResponse(
        success=True,
        name="NSFW Checker API",
        version="1.0.0",
        status="online",
    )
