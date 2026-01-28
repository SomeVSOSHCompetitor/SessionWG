from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session

from app.config import settings
from app.models.ip_pool import IpPool, IpState


class IpPoolExhausted(Exception):
    pass


def allocate_ip(db: Session, session_id) -> str:
    row = (
        db.execute(
            select(IpPool)
            .where(IpPool.state == IpState.FREE)
            .order_by(func.random())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        .scalars()
        .first()
    )
    if row is None:
        raise IpPoolExhausted("No free IPs available")

    row.state = IpState.ASSIGNED
    row.session_id = session_id
    row.updated_at = func.now()
    return str(row.ip)


def quarantine_ip(db: Session, ip: str) -> None:
    # безопасно: только если этот IP был привязан к этой сессии
    row = db.get(IpPool, ip)
    if not row:
        return

    now = datetime.now(timezone.utc)
    row.quarantined_until = now + timedelta(seconds=settings.ip_quarantine_duration_seconds)
    row.state = IpState.QUARANTINED
    row.session_id = None
    row.updated_at = func.now()
    db.add(row)
    db.commit()

def quarantine_session(db: Session, session_id: str) -> None:
    query = select(IpPool).where(IpPool.session_id == session_id)
    row: IpPool = db.execute(query).scalar()
    if not row:
        return
    quarantine_ip(db, row.ip)
