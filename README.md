# tools-api.riyanathariq.space

Go API for **cloud tools** on [tools.riyanathariq.space](https://tools.riyanathariq.space).

Local browser tools stay in the Next.js app. This service handles login-gated server features.

## Stack

| Piece | Role |
|-------|------|
| Postgres 16 | Persistent data (webhook bins + hits) |
| Valkey 8 | Rate limits (Redis-compatible) |
| Go API | Auth, SMTP tester, webhook ingest |

## Phases

| Phase | Status | Feature |
|-------|--------|---------|
| 1 | done | Google OAuth + session cookie (`/auth/*`) |
| 2 | done | SMTP Tester (BYO SMTP) |
| 3 | done | Webhook Bin (`/hook/{id}` + `/api/cloud/webhook/*`) |
| 4 | done | Postgres + Valkey (replace file store / in-memory limiter) |

## Auth endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness |
| GET | `/readyz` | Readiness (Postgres + Valkey + Google in prod) |
| GET | `/auth/status` | `{ googleConfigured: bool }` |
| GET | `/auth/google?next=/path` | Start Google login |
| GET | `/auth/google/callback` | OAuth callback (sets HTTP-only cookie) |
| GET | `/auth/me` | Current user (401 if logged out) |
| POST | `/auth/logout` | Clear session cookie |
| POST | `/api/cloud/smtp/test` | BYO SMTP test send (**auth required**, 10/hour) |

### Webhook Bin

Public ingest (no auth):

| Method | Path | Description |
|--------|------|-------------|
| * | `/hook/{id}` | Capture request |
| * | `/hook/{id}/{path...}` | Capture with trailing path |

Management (**auth required**): list/create/get/delete bins, clear/get hits under `/api/cloud/webhook/bins…`

Limits: 3 bins/user, 100 hits/bin, 256 KiB body, 72h TTL. Sensitive headers redacted.

## Local

```bash
cp .env.example .env
docker compose up -d postgres valkey
go mod tidy
make test
make run
```

Listen: `http://127.0.0.1:3003`

## Production (VPS)

- Path: `/opt/tools-api`
- API: `127.0.0.1:3003`
- Postgres: `127.0.0.1:5432` (localhost only)
- Valkey: `127.0.0.1:6379` (localhost only)
- Image: `ghcr.io/riyanathariq/tools-api.riyanathariq.space:latest`

```bash
cd /opt/tools-api
docker compose pull && docker compose up -d
curl -sS http://127.0.0.1:3003/readyz
```

### DataGrip (via SSH tunnel)

Postgres is **not** exposed publicly. In DataGrip:

1. SSH: `root@43.157.202.233`
2. Host: `127.0.0.1` · Port: `5432`
3. DB / user from `/opt/tools-api/.env` (`POSTGRES_*`)
