from fastapi import FastAPI
from app.api.routes import health_router, nsfw_router

# ============================================================
# FastAPI Application Factory / Initialization
# ============================================================

app = FastAPI(
    title="NSFW Checker API",
    version="1.0.0",
    description="High-performance automated NSFW content and nudity detection API powered by NudeNet and Firestore.",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ============================================================
# Include Route Handlers
# ============================================================

app.include_router(health_router)
app.include_router(nsfw_router)
