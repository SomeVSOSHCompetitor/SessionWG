import ipaddress
import logging
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.models.ip_pool import IpPool, IpState

logger = logging.getLogger(__name__)

def sync_ip_pool(db: Session) -> None:
    net = ipaddress.ip_network(settings.network_cidr, strict=False)
    reserved = set(settings.reserved_ips)

    # advisory lock, чтобы 2 инстанса не синкались одновременно
    db.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), {"k": settings.project_name})

    try:
        desired = {str(ip) for ip in net.hosts()}
        desired -= reserved

        # 1) загрузим существующие ip и state
        rows = db.query(IpPool.ip, IpPool.state).all()
        existing = {str(ip) for (ip, _) in rows}

        # 2) добавить недостающие
        to_add = desired - existing
        if to_add:
            db.bulk_save_objects([IpPool(ip=ip, state=IpState.FREE) for ip in sorted(to_add)])
            logger.info("ip_pool: added %d IPs", len(to_add))

        # 3) удалить лишние (ТОЛЬКО FREE/QUARANTINED)
        # сначала найдём кандидатов вне desired
        extras = []
        for ip, st in rows:
            ip_str = str(ip)
            if ip_str not in desired:
                extras.append((ip_str, st))

        deletable = [ip for ip, st in extras if st in (IpState.FREE, IpState.QUARANTINED)]
        assigned_outside = [ip for ip, st in extras if st == IpState.ASSIGNED]

        if deletable:
            db.query(IpPool).filter(IpPool.ip.in_(deletable)).delete(synchronize_session=False)
            logger.info("ip_pool: removed %d IPs (FREE/QUARANTINED) outside CIDR", len(deletable))

        if assigned_outside:
            # не трогаем, но это важный сигнал
            logger.warning(
                "ip_pool: %d ASSIGNED IPs are outside current CIDR; manual action required. examples=%s",
                len(assigned_outside),
                assigned_outside[:5],
            )

        db.commit()
    finally:
        db.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": settings.project_name})
