-- +goose Up
CREATE TABLE IF NOT EXISTS webhook_bins (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  hit_count INT NOT NULL DEFAULT 0,
  last_hit_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS webhook_bins_user_id_idx ON webhook_bins (user_id);
CREATE INDEX IF NOT EXISTS webhook_bins_expires_at_idx ON webhook_bins (expires_at);

CREATE TABLE IF NOT EXISTS webhook_hits (
  id TEXT PRIMARY KEY,
  bin_id TEXT NOT NULL REFERENCES webhook_bins(id) ON DELETE CASCADE,
  received_at TIMESTAMPTZ NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query TEXT NOT NULL DEFAULT '',
  query_params JSONB NOT NULL DEFAULT '{}'::jsonb,
  headers JSONB NOT NULL DEFAULT '{}'::jsonb,
  content_type TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  body_truncated BOOLEAN NOT NULL DEFAULT FALSE,
  body_bytes INT NOT NULL DEFAULT 0,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS webhook_hits_bin_received_idx ON webhook_hits (bin_id, received_at DESC);

-- +goose Down
DROP TABLE IF EXISTS webhook_hits;
DROP TABLE IF EXISTS webhook_bins;
