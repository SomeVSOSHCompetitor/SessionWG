from sqlalchemy import Boolean, Column, Integer, String

from app.models.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    mfa_secret = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
