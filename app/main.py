import asyncio
import logging

from fastapi import FastAPI

from app.api.router import api_router
from app.config import settings
from app.db import SessionLocal, engine
from app.models import audit, challenge, session as session_model, user  # noqa: F401
from app.models.base import Base
from app.models.user import User
from app.services.ip_pool_init import sync_ip_pool
from app.services.qurantine import create_quarantine_releaser
from app.services.revoker import create_revoker
from app.services.security import hash_password

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

revoker = create_revoker()
quarantine_releaser = create_quarantine_releaser()


def _seed_default_user() -> None:
    with SessionLocal() as db:
        existing = db.query(User).filter(User.username == "demo").first()
        if existing:
            return
        demo = User(
            username="demo",
            password_hash=hash_password("changeme"),
            mfa_secret="JBSWY3DPEHPK3PXP",  # base32 for demo
        )
        db.add(demo)
        db.commit()
        logger.info("Seeded default user 'demo' with password 'changeme'")


def create_app() -> FastAPI:
    app = FastAPI(title=settings.project_name)
    app.include_router(api_router)

    @app.on_event("startup")
    async def startup() -> None:  # pragma: no cover - wiring
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            sync_ip_pool(db)
        if settings.seed_default_user: _seed_default_user()
        revoker.start()
        quarantine_releaser.start()

    @app.on_event("shutdown")
    async def shutdown() -> None:  # pragma: no cover - wiring
        await revoker.stop()
        await quarantine_releaser.stop()

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
