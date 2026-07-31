-- +goose Up
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  picture TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL,
  last_login_at TIMESTAMPTZ NOT NULL,
  last_login_ip TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);
CREATE INDEX IF NOT EXISTS users_last_login_at_idx ON users (last_login_at DESC);

CREATE TABLE IF NOT EXISTS visitors (
  visitor_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  referer TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  city TEXT NOT NULL DEFAULT '',
  user_id TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  first_path TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS visitors_first_seen_at_idx ON visitors (first_seen_at DESC);
CREATE INDEX IF NOT EXISTS visitors_last_seen_at_idx ON visitors (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS visitors_user_id_idx ON visitors (user_id);

-- +goose Down
DROP TABLE IF EXISTS visitors;
DROP TABLE IF EXISTS users;
