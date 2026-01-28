from datetime import datetime
from pydantic import BaseModel


class AdminSessionView(BaseModel):
    session_id: str
    user_id: int
    status: str
    expires_at: datetime
    started_at: datetime


class AuditEntry(BaseModel):
    occurred_at: datetime
    user_id: int | None
    session_id: str | None
    action: str
    detail: str | None
