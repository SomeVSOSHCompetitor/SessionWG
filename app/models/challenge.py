import uuid
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Boolean, Column, DateTime, Enum as SAEnum, ForeignKey, Integer, String

from app.models.base import Base


class ChallengeType(str, Enum):
    LOGIN = "LOGIN"
    RENEW = "RENEW"
    STEPUP = "STEPUP"


class Challenge(Base):
    __tablename__ = "challenges"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=True, index=True)
    type = Column(SAEnum(ChallengeType), nullable=False)
    tries = Column(Integer, nullable=False, default=0)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
