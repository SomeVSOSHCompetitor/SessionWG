from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String

from app.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    occurred_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    user_id = Column(Integer, nullable=True, index=True)
    session_id = Column(String, nullable=True, index=True)
    action = Column(String, nullable=False)
    detail = Column(String, nullable=True)
