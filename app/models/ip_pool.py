
import enum
from datetime import datetime
from sqlalchemy import Column, DateTime, Enum, Index, String, ForeignKey
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.sql import func

from app.models.base import Base

class IpState(str, enum.Enum):
    FREE = "FREE"
    ASSIGNED = "ASSIGNED"
    QUARANTINED = "QUARANTINED"


class IpPool(Base):
    __tablename__ = "ip_pool"

    ip = Column(INET, primary_key=True) # 10.10.0.42
    state = Column(Enum(IpState, name="ip_state"), nullable=False, index=True) # FREE / ASSIGNED / QUARANTINED
    session_id = Column(String, ForeignKey("sessions.id"), nullable=True, index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    quarantined_until = Column(DateTime(timezone=True), nullable=True, index=True)

    __table_args__ = (
        # полезно для запросов "дай FREE" + сортировка
        Index("ix_ip_pool_state_ip", "state", "ip"),
    )