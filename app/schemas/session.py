from datetime import datetime
from pydantic import BaseModel, Field


class SessionCreateRequest(BaseModel):
    client_pubkey: str = Field(min_length=16)
    ttl_step_seconds: int | None = Field(default=None, gt=0)


class SessionCreateResponse(BaseModel):
    session_id: str
    started_at: datetime
    expires_at: datetime
    max_expires_at: datetime
    status: str
    proof_token: str
    proof_expires_in: int


class SessionStatusResponse(BaseModel):
    session_id: str
    status: str
    started_at: datetime
    expires_at: datetime
    max_expires_at: datetime
    remaining_seconds: int


class SessionRevokeResponse(BaseModel):
    status: str
    revoked_at: datetime


class RenewStartResponse(BaseModel):
    renew_challenge_id: str
    challenge_expires_in: int


class RenewVerifyRequest(BaseModel):
    renew_challenge_id: str
    totp_code: str = Field(min_length=6, max_length=6)


class RenewVerifyResponse(BaseModel):
    status: str
    expires_at: datetime
    max_expires_at: datetime
    proof_token: str
    proof_expires_in: int


class WgInterface(BaseModel):
    address: str
    dns: list[str]


class WgPeer(BaseModel):
    public_key: str
    endpoint: str
    allowed_ips: list[str]
    persistent_keepalive: int = 25


class SessionConfigResponse(BaseModel):
    interface: WgInterface
    peer: WgPeer
