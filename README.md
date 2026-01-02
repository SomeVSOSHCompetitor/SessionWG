# WireGuard Session Controller (FastAPI)

FastAPI service that issues short-lived WireGuard VPN sessions guarded by MFA. Sessions have bounded lifetime (`TTL_max`) and can only be renewed with MFA. A short-lived proof token is required to fetch WireGuard config.

## Quickstart

1) Create and activate a virtualenv (optional) and install deps:

```bash
pip install -r requirements.txt
```

2) Run the API (dev):

```bash
uvicorn app.main:app --reload --port 8000
```

Default demo credentials (seeded on startup):
- username: `demo`
- password: `changeme`
- TOTP secret (base32): `JBSWY3DPEHPK3PXP` (use any authenticator; current code is time-based 30s step)
- Admin token header: `X-Admin-Token: admin-token-change-me`

## Key settings (env vars with prefix `WG_`)
- `WG_DATABASE_URL` (default `sqlite:///./data.db`)
- `WG_JWT_SECRET_KEY` (change in production)
- `WG_ACCESS_TOKEN_EXPIRES_SECONDS` (default 900)
- `WG_PROOF_TOKEN_EXPIRES_SECONDS` (default 60)
- `WG_TTL_MAX_SECONDS` (default 28800)
- `WG_TTL_STEP_DEFAULT_SECONDS` (default 900)
- `WG_ADMIN_TOKEN` (default `admin-token-change-me`)
- WireGuard defaults: `WG_ENDPOINT`, `WG_GATEWAY_PUBKEY`, `WG_ALLOWED_IPS`, `WG_DNS`, `WG_ADDRESS_PREFIX`

## API map (high level)
- `POST /v1/auth/start` → issue MFA challenge after password check
- `POST /v1/auth/verify-mfa` → verify TOTP, issue access token
- `POST /v1/sessions` → create session (+ WireGuard peer stub), return proof token
- `POST /v1/sessions/{id}/config` → with proof token, return WG config params
- `GET /v1/sessions/{id}` → session status
- `POST /v1/sessions/{id}/revoke` → user revocation
- `POST /v1/sessions/{id}/renew/start` → start MFA for renewal
- `POST /v1/sessions/{id}/renew/verify` → verify MFA, extend `expires_at`, new proof token
- Admin: `GET /v1/admin/sessions`, `POST /v1/admin/sessions/{id}/revoke`, `GET /v1/admin/audit`
- Service: `GET /health`, `GET /metrics`

## Implementation notes
- Proof/access tokens are JWT (HS256) with scoped claims (`scope=access|proof`, `sid` for session).
- Session TTL enforcement: `expires_at = min(now + ttl_step, started_at + TTL_max)`; renewal prohibited past `max_expires_at`.
- Automatic revoker runs every 30s and removes peers via WireGuard stub.
- WireGuard operations are stubbed (`app/services/wireguard.py`); swap with real CLI/API integration.
- Storage uses SQLAlchemy sync engine; `Base.metadata.create_all` is invoked on startup. Replace SQLite URL with Postgres in production and add migrations.

## Minimal flow (happy path)
1. `POST /v1/auth/start` with demo creds → `challenge_id`.
2. Generate TOTP from secret → `POST /v1/auth/verify-mfa` → `access_token`.
3. `POST /v1/sessions` with `Authorization: Bearer <access_token>` and `client_pubkey` → get `proof_token`.
4. `POST /v1/sessions/{id}/config` with `Authorization: Bearer <proof_token>` → receive WG params.
5. Renew: `POST /v1/sessions/{id}/renew/start` → TOTP → `POST /v1/sessions/{id}/renew/verify`.
6. Revoke or let auto-revoker expire; peer removal is triggered.
