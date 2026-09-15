-- Control plane schema, milestone M1.
-- Times are RFC 3339 UTC strings. Hashes are raw SHA-256 bytes.

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

-- Single row. Bumped in the same transaction as any change gateways must see.
CREATE TABLE snapshot_version (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  version    INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO snapshot_version (id, version, updated_at) VALUES (1, 1, '1970-01-01T00:00:00Z');

CREATE TABLE devices (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  hostname       TEXT NOT NULL DEFAULT '',
  platform       TEXT NOT NULL DEFAULT '',
  key_kind       TEXT NOT NULL DEFAULT '',
  hardware_bound INTEGER NOT NULL DEFAULT 0,
  spki_hash      BLOB NOT NULL UNIQUE,
  cert_der       BLOB NOT NULL,
  attrs_json     TEXT NOT NULL DEFAULT '{}',
  status         TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'revoked')),
  requested_at   TEXT NOT NULL,
  request_ip     TEXT NOT NULL DEFAULT '',
  approved_at    TEXT,
  approved_by    TEXT,
  revoked_at     TEXT,
  revoked_by     TEXT,
  last_seen_at   TEXT
);
CREATE INDEX devices_status ON devices (status);

CREATE TABLE gateways (
  id                    TEXT PRIMARY KEY,
  name                  TEXT NOT NULL UNIQUE,
  token_hash            BLOB NOT NULL UNIQUE,
  public_addr           TEXT NOT NULL DEFAULT '',
  server_name           TEXT NOT NULL DEFAULT '',
  cert_pem              TEXT NOT NULL DEFAULT '',
  last_seen_at          TEXT,
  last_snapshot_version INTEGER NOT NULL DEFAULT 0,
  active_tunnels        INTEGER NOT NULL DEFAULT 0,
  created_at            TEXT NOT NULL,
  created_by            TEXT NOT NULL
);

CREATE TABLE log_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TEXT NOT NULL,
  stream     TEXT NOT NULL,
  actor      TEXT NOT NULL DEFAULT '',
  device_id  TEXT,
  session_id TEXT,
  gateway_id TEXT,
  message    TEXT NOT NULL,
  attrs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX log_events_stream_ts ON log_events (stream, ts);
CREATE INDEX log_events_device_ts ON log_events (device_id, ts);
