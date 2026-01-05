import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.session import Session as SessionModel, SessionStatus
from app.services.ip_alloc import quarantine_session
from app.services.wireguard import wireguard_service
from app.services.audit import audit

logger = logging.getLogger(__name__)


def _ensure_aware(dt: datetime) -> datetime:
    """Normalize naive datetimes from DB to UTC-aware."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def _revoke_loop(stop_event: asyncio.Event, interval_seconds: int = 30) -> None:
    while not stop_event.is_set():
        await asyncio.sleep(interval_seconds)
        _revoke_expired_once()


def _revoke_expired_once() -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        expired_sessions = (
            db.query(SessionModel)
            .filter(SessionModel.status == SessionStatus.ACTIVE)
            .filter(SessionModel.expires_at <= now)
            .all()
        )
        for sess in expired_sessions:
            expires_at = _ensure_aware(sess.expires_at)
            if expires_at > now:
                continue

            try:
                wireguard_service.remove_peer(sess.id, sess.client_pubkey)  # best-effort first
            except Exception as e:
                logger.exception("Failed to remove peer for %s: %s", sess.id, e)
                continue

            sess.status = SessionStatus.EXPIRED
            sess.updated_at = now
            db.add(sess)
            db.commit()
            quarantine_session(db, sess.id)
            audit(db, action="session_expired", user_id=sess.user_id, session_id=sess.id, detail="Auto-expire")
            logger.info("Session %s expired automatically", sess.id)


class Revoker:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self, interval_seconds: int = 30) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(_revoke_loop(self._stop, interval_seconds))

    async def stop(self) -> None:
        if self._task:
            self._stop.set()
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


def create_revoker() -> Revoker:
    return Revoker()
