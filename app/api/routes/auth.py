from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.challenge import Challenge, ChallengeType
from app.models.user import User
from app.config import settings
from app.schemas.auth import (
    AuthStartRequest,
    AuthStartResponse,
    VerifyMfaRequest,
    VerifyMfaResponse, StepUpStartResponse, StepUpVerifyResponse,
)
from app.services import security
from app.services.audit import audit

router = APIRouter()
CHALLENGE_TTL_SECONDS = 120


def _ensure_aware(dt: datetime) -> datetime:
    """Normalize naive datetimes from DB to UTC-aware to avoid comparison errors."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _get_user_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).first()


@router.post("/v1/auth/start", response_model=AuthStartResponse)
def auth_start(payload: AuthStartRequest, db: Session = Depends(get_db)) -> AuthStartResponse:
    user = _get_user_by_username(db, payload.username)
    if not user or not security.verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    now = datetime.now(timezone.utc)
    challenge = Challenge(
        user_id=user.id,
        type=ChallengeType.LOGIN,
        expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
    )
    db.add(challenge)
    db.commit()
    audit(db, action="auth_start", user_id=user.id, detail="MFA challenge issued")

    return AuthStartResponse(
        challenge_id=challenge.id,
        mfa_required=True,
        challenge_expires_in=CHALLENGE_TTL_SECONDS,
    )


@router.post("/v1/auth/verify-mfa", response_model=VerifyMfaResponse)
def verify_mfa(payload: VerifyMfaRequest, db: Session = Depends(get_db)) -> VerifyMfaResponse:
    challenge: Challenge | None = db.query(Challenge).filter(Challenge.id == payload.challenge_id).first()
    if not challenge or challenge.type != ChallengeType.LOGIN:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found")
    if challenge.consumed:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Challenge consumed")

    now = datetime.now(timezone.utc)
    expires_at = _ensure_aware(challenge.expires_at)
    if expires_at <= now:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Challenge expired")

    user: User | None = db.query(User).filter(User.id == challenge.user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if challenge.tries >= 5:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many tries, challenge expired")

    if not security.verify_totp(payload.totp_code, user.mfa_secret):
        challenge.tries += 1
        db.add(challenge)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA")

    challenge.consumed = True
    db.add(challenge)
    db.commit()

    access_token = security.create_access_token(user.id)
    proof_token = security.create_proof_token(user.id)

    audit(db, action="auth_mfa_verified", user_id=user.id, detail="Access and proof token issued")

    return VerifyMfaResponse(
        access_token=access_token,
        access_expires_in=settings.access_token_expires_seconds,
        proof_token=proof_token,
        proof_expires_in=settings.proof_token_expires_seconds,
    )

@router.post("/v1/auth/step-up/start", response_model=StepUpStartResponse)
def auth_stepup(
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    now = datetime.now(timezone.utc)
    challenge = Challenge(
        user_id=user.id,
        type=ChallengeType.STEPUP,
        expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
    )
    db.add(challenge)
    db.commit()
    audit(db, action="stepup_start", user_id=user.id, detail="Step-up MFA challenge issued")

    return StepUpStartResponse(
        challenge_id=challenge.id,
        challenge_expires_in=CHALLENGE_TTL_SECONDS,
    )

@router.post("/v1/auth/step-up/verify", response_model=StepUpVerifyResponse)
def verify_stepup(
        payload: VerifyMfaRequest,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    challenge: Challenge | None = db.query(Challenge).filter(Challenge.id == payload.challenge_id).first()
    if not challenge or challenge.type != ChallengeType.STEPUP:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found")
    if challenge.consumed:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Challenge consumed")

    now = datetime.now(timezone.utc)
    expires_at = _ensure_aware(challenge.expires_at)
    if expires_at <= now:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Challenge expired")

    if user.id != challenge.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Challenge not authorized")

    if challenge.tries >= 5:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many tries, challenge expired")

    if not security.verify_totp(payload.totp_code, user.mfa_secret):
        challenge.tries += 1
        db.add(challenge)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA")

    challenge.consumed = True
    db.add(challenge)
    db.commit()

    proof_token = security.create_proof_token(user.id)

    audit(db, action="stepup_mfa_verified", user_id=user.id, detail="Proof token issued")

    return StepUpVerifyResponse(
        proof_token=proof_token,
        proof_expires_in=settings.proof_token_expires_seconds,
    )
