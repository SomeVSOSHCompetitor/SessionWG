from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin
from app.models.audit import AuditLog
from app.models.session import Session as SessionModel, SessionStatus
from app.schemas.admin import AdminSessionView, AuditEntry
from app.services.wireguard import wireguard_service
from app.services.audit import audit

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/v1/admin/sessions", response_model=list[AdminSessionView])
def list_sessions(status: str | None = Query(default=None), db: Session = Depends(get_db)) -> list[AdminSessionView]:
    query = db.query(SessionModel)
    if status:
        try:
            status_enum = SessionStatus(status)
        except ValueError:
            raise HTTPException(status_code=http_status.HTTP_400_BAD_REQUEST, detail="Bad status filter")
        query = query.filter(SessionModel.status == status_enum)
    sessions = query.all()
    return [
        AdminSessionView(
            session_id=s.id,
            user_id=s.user_id,
            status=s.status.value,
            expires_at=s.expires_at,
            started_at=s.started_at,
        )
        for s in sessions
    ]


@router.post("/v1/admin/sessions/{session_id}/revoke")
def admin_revoke(session_id: str, db: Session = Depends(get_db)) -> dict[str, str]:
    sess = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not sess:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Session not found")
    now = datetime.now(timezone.utc)
    sess.status = SessionStatus.REVOKED
    sess.updated_at = now
    db.add(sess)
    db.commit()
    wireguard_service.remove_peer(sess.id, sess.client_pubkey)
    audit(db, action="admin_revoke", user_id=sess.user_id, session_id=sess.id)
    return {"status": sess.status.value}


@router.get("/v1/admin/audit", response_model=list[AuditEntry])
def audit_list(session_id: str | None = Query(default=None), db: Session = Depends(get_db)) -> list[AuditEntry]:
    query = db.query(AuditLog)
    if session_id:
        query = query.filter(AuditLog.session_id == session_id)
    logs = query.order_by(AuditLog.occurred_at.desc()).limit(200).all()
    return [
        AuditEntry(
            occurred_at=log.occurred_at,
            user_id=log.user_id,
            session_id=log.session_id,
            action=log.action,
            detail=log.detail,
        )
        for log in logs
    ]
