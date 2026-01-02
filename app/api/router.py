from fastapi import APIRouter

from app.api.routes import admin, auth, service, sessions

api_router = APIRouter()
api_router.include_router(service.router, tags=["service"])
api_router.include_router(auth.router, tags=["auth"])
api_router.include_router(sessions.router, tags=["sessions"])
api_router.include_router(admin.router, tags=["admin"])
