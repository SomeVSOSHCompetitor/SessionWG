from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, get_current_proofed_user
from app.config import settings
from app.models import IpPool as IPModel
from app.models.session import Session as SessionModel, SessionStatus
from app.models.user import User
from app.schemas.session import (
    RenewVerifyResponse,
    SessionConfigResponse,
    SessionCreateRequest,
    SessionCreateResponse,
    SessionRevokeResponse,
    SessionStatusResponse,
    WgInterface,
    WgPeer,
)
from app.services.audit import audit
from app.services.ip_alloc import allocate_ip, IpPoolExhausted, quarantine_session
from app.services.wireguard import wireguard_service

CHALLENGE_TTL_SECONDS = 120

router = APIRouter()


def _ensure_aware(dt: datetime) -> datetime:
    """Normalize naive datetimes from DB to UTC-aware to avoid comparison errors."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _expire_if_needed(db: Session, sess: SessionModel) -> SessionModel:
    now = datetime.now(timezone.utc)
    expires_at = _ensure_aware(sess.expires_at)
    if sess.status == SessionStatus.ACTIVE and expires_at <= now:
        sess.status = SessionStatus.EXPIRED
        sess.updated_at = now
        db.add(sess)
        db.commit()
        wireguard_service.remove_peer(sess.id, sess.client_pubkey)
        audit(db, action="session_expired", user_id=sess.user_id, session_id=sess.id, detail="On-access check")
    return sess


def _validate_owner(sess: SessionModel, user: User) -> None:
    if sess.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not owner")


def _allocate_address(db: Session, session_id: str) -> str:
    try:
        allocated_ip = allocate_ip(db, session_id)
        return f"{allocated_ip}/32"
    except IpPoolExhausted as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/v1/sessions", response_model=SessionCreateResponse)
def create_session(
    payload: SessionCreateRequest,
    user: User = Depends(get_current_proofed_user),
    db: Session = Depends(get_db),
) -> SessionCreateResponse:
    active = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id, SessionModel.status == SessionStatus.ACTIVE)
        .first()
    )
    if active and not settings.allow_multiple_active_sessions:
        active = _expire_if_needed(db, active)
        if active.status == SessionStatus.ACTIVE:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active session exists")

    ttl_step = payload.ttl_step_seconds or settings.ttl_step_default_seconds
    if ttl_step <= 0 or ttl_step > settings.ttl_max_seconds:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ttl_step")

    now = datetime.now(timezone.utc)
    ttl_max = settings.ttl_max_seconds
    max_expires = now + timedelta(seconds=ttl_max)
    expires_at = min(now + timedelta(seconds=ttl_step), max_expires)

    sess = SessionModel(
        user_id=user.id,
        status=SessionStatus.ACTIVE,
        started_at=now,
        expires_at=expires_at,
        max_expires_at=max_expires,
        ttl_max_seconds=ttl_max,
        ttl_step_seconds=ttl_step,
        client_pubkey=payload.client_pubkey,
        updated_at=now,
    )
    db.add(sess)
    db.commit()

    allowed_ips = _allocate_address(db, sess.id)
    wireguard_service.add_peer(sess.id, payload.client_pubkey, allowed_ips)
    audit(db, action="session_created", user_id=user.id, session_id=sess.id, detail="Created session. Allocated IPs: " + allowed_ips)

    return SessionCreateResponse(
        session_id=sess.id,
        started_at=now,
        expires_at=expires_at,
        max_expires_at=max_expires,
        status=sess.status.value,
    )


@router.get("/v1/sessions/{session_id}", response_model=SessionStatusResponse)
def session_status(
    session_id: str = Path(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SessionStatusResponse:
    sess = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not sess:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    _validate_owner(sess, user)
    sess = _expire_if_needed(db, sess)
    now = datetime.now(timezone.utc)
    expires_at = _ensure_aware(sess.expires_at)
    remaining = max(0, int((expires_at - now).total_seconds()))
    return SessionStatusResponse(
        session_id=sess.id,
        status=sess.status.value,
        started_at=sess.started_at,
        expires_at=sess.expires_at,
        max_expires_at=sess.max_expires_at,
        remaining_seconds=remaining,
    )


@router.post("/v1/sessions/{session_id}/revoke", response_model=SessionRevokeResponse)
def revoke_session(
    session_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SessionRevokeResponse:
    sess = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not sess:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    _validate_owner(sess, user)

    sess = _expire_if_needed(db, sess)
    if sess.status != SessionStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Session not active")

    now = datetime.now(timezone.utc)
    sess.status = SessionStatus.REVOKED
    sess.updated_at = now
    db.add(sess)
    db.commit()

    wireguard_service.remove_peer(sess.id, sess.client_pubkey)
    quarantine_session(db, sess.id)
    audit(db, action="session_revoked", user_id=user.id, session_id=sess.id, detail="Manual revoke")

    return SessionRevokeResponse(status=sess.status.value, revoked_at=now)


@router.post("/v1/sessions/{session_id}/renew", response_model=RenewVerifyResponse)
def renew_verify(
    session_id: str,
    user: User = Depends(get_current_proofed_user),
    db: Session = Depends(get_db),
) -> RenewVerifyResponse:
    now = datetime.now(timezone.utc)

    sess = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not sess:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    _validate_owner(sess, user)
    sess = _expire_if_needed(db, sess)
    if sess.status != SessionStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Session not active")
    max_expires_at = _ensure_aware(sess.max_expires_at)
    if now >= max_expires_at:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="TTL max reached")

    new_expires = min(now + timedelta(seconds=sess.ttl_step_seconds), max_expires_at)
    if new_expires <= _ensure_aware(sess.expires_at):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No extension possible")

    sess.expires_at = new_expires
    sess.updated_at = now
    db.add(sess)
    db.commit()

    audit(db, action="session_renewed", user_id=user.id, session_id=sess.id)
    return RenewVerifyResponse(
        status=sess.status.value,
        expires_at=sess.expires_at,
        max_expires_at=sess.max_expires_at,
    )


@router.post("/v1/sessions/{session_id}/config", response_model=SessionConfigResponse)
def session_config(
    session_id: str,
    user: User = Depends(get_current_proofed_user),
    db: Session = Depends(get_db),
) -> SessionConfigResponse:
    sess = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not sess:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    _validate_owner(sess, user)

    sess = _expire_if_needed(db, sess)
    if sess.status != SessionStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Session not active")

    ip: IPModel | None = db.query(IPModel).filter(IPModel.session_id == session_id).first()
    if not ip:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="IP not found")

    return SessionConfigResponse(
        interface=WgInterface(address=ip.ip, dns=[settings.dns]),
        peer=WgPeer(
            public_key=settings.gateway_pubkey,
            endpoint=settings.endpoint,
            allowed_ips=settings.allowed_ips,
        ),
    )


# shared constant
