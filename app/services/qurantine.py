import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import func

from app.db import SessionLocal
from app.models import IpPool
from app.models.ip_pool import IpState

logger = logging.getLogger(__name__)

async def _release_loop(stop_event: asyncio.Event, interval_seconds: int = 10) -> None:
    while not stop_event.is_set():
        await asyncio.sleep(interval_seconds)
        _release_quarantine_once()


def _release_quarantine_once() -> int:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        q = (
            db.query(IpPool)
            .filter(IpPool.state == IpState.QUARANTINED)
            .filter(IpPool.quarantined_until.isnot(None))
            .filter(IpPool.quarantined_until <= now)
        )
        updated = q.update(
            {
                IpPool.state: IpState.FREE,
                IpPool.quarantined_until: None,
                IpPool.updated_at: func.now(),
            },
            synchronize_session=False,
        )
        if updated:
            db.commit()
            logger.info("Automatically released %d IPs from quarantine", updated)
        return updated

class QuarantineReleaser:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self, interval_seconds: int = 5) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(_release_loop(self._stop, interval_seconds))

    async def stop(self) -> None:
        if self._task:
            self._stop.set()
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


def create_quarantine_releaser() -> QuarantineReleaser:
    return QuarantineReleaser()
