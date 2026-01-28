from pydantic import BaseModel, Field


class AuthStartRequest(BaseModel):
    username: str
    password: str


class AuthStartResponse(BaseModel):
    challenge_id: str
    mfa_required: bool = True
    challenge_expires_in: int


class VerifyMfaRequest(BaseModel):
    challenge_id: str
    totp_code: str = Field(min_length=6, max_length=6)


class VerifyMfaResponse(BaseModel):
    access_token: str
    access_expires_in: int
    proof_token: str
    proof_expires_in: int


class StepUpStartResponse(BaseModel):
    challenge_id: str
    challenge_expires_in: int


class StepUpVerifyResponse(BaseModel):
    proof_token: str
    proof_expires_in: int
