# tools-api.riyanathariq.space

Go API for **cloud tools** on [tools.riyanathariq.space](https://tools.riyanathariq.space).

Local browser tools stay in the Next.js app. This service handles login-gated server features.

## Phases

| Phase | Status | Feature |
|-------|--------|---------|
| 1 | done | Google OAuth + session cookie (`/auth/*`) |
| 2 | **in progress** | SMTP Tester (BYO SMTP) |
| 3 | pending | Webhook Bin |

## Auth endpoints (Phase 1)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness |
| GET | `/readyz` | Readiness (fails in production if Google OAuth missing) |
| GET | `/auth/status` | `{ googleConfigured: bool }` |
| GET | `/auth/google?next=/path` | Start Google login |
| GET | `/auth/google/callback` | OAuth callback (sets HTTP-only cookie) |
| GET | `/auth/me` | Current user (401 if logged out) |
| POST | `/auth/logout` | Clear session cookie |
| POST | `/api/cloud/smtp/test` | BYO SMTP test send (**auth required**, 10/hour) |

Session cookie: `tools_session` (JWT HS256, HttpOnly, SameSite=Lax).

### SMTP test body

```json
{
  "host": "smtp.example.com",
  "port": 587,
  "security": "starttls",
  "username": "user@example.com",
  "password": "app-password",
  "from": "user@example.com",
  "to": "you@example.com",
  "subject": "SMTP test",
  "text": "hello"
}
```

`security`: `starttls` | `ssl` | `none`. Password is never logged or stored.

## Local

```bash
cp .env.example .env
# set SESSION_SECRET (>=32 chars)
# optionally set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
go mod tidy
make test
make run
```

Listen: `http://127.0.0.1:3003`

## Google OAuth setup (when ready)

1. Google Cloud Console → OAuth 2.0 Web client  
2. Authorized redirect URI: `https://tools.riyanathariq.space/auth/google/callback`  
3. Put `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in `/opt/tools-api/.env`  
4. Ensure nginx proxies `/auth/` to this service (see `deploy/nginx-tools-api.conf`)

## Production (VPS)

- Path: `/opt/tools-api`
- Bind: `127.0.0.1:3003`
- Image: `ghcr.io/riyanathariq/tools-api.riyanathariq.space:latest`
- Nginx on `tools.riyanathariq.space`: `/auth`, `/api`, `/hook` → Go; rest → Next (`3002`)

```bash
cd /opt/tools-api
docker compose pull && docker compose up -d
curl -sS http://127.0.0.1:3003/healthz
```
