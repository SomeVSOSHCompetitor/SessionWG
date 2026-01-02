from app.models.audit import AuditLog
from sqlalchemy.orm import Session


def audit(session: Session, action: str, user_id: int | None = None, session_id: str | None = None, detail: str | None = None) -> None:
    entry = AuditLog(action=action, user_id=user_id, session_id=session_id, detail=detail)
    session.add(entry)
    session.commit()
