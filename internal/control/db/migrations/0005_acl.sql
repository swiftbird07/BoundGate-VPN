-- Milestone M3: Cedar policies (scoped per enforcing node), tunnel history
-- reported by hubs (connection graph, M6.5) and shipped flow logs.

CREATE TABLE policies (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  cedar       TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  -- node ids the policy is sent to; [] = every node
  scope_json  TEXT NOT NULL DEFAULT '[]',
  created_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL DEFAULT '',
  updated_at  TEXT NOT NULL,
  updated_by  TEXT NOT NULL DEFAULT ''
);

-- One row per tunnel a hub accepted. Hubs report open, periodic byte
-- counters and close; the row survives node revocation for the history.
CREATE TABLE tunnels (
  id             TEXT PRIMARY KEY,
  hub_id         TEXT NOT NULL,
  peer_id        TEXT NOT NULL,
  peer_addr      TEXT NOT NULL DEFAULT '',
  opened_at      TEXT NOT NULL,
  closed_at      TEXT,
  close_reason   TEXT NOT NULL DEFAULT '',
  bytes_in       INTEGER NOT NULL DEFAULT 0,
  bytes_out      INTEGER NOT NULL DEFAULT 0,
  packets_in     INTEGER NOT NULL DEFAULT 0,
  packets_out    INTEGER NOT NULL DEFAULT 0,
  last_report_at TEXT NOT NULL
);
CREATE INDEX tunnels_hub_opened ON tunnels (hub_id, opened_at);
CREATE INDEX tunnels_peer_opened ON tunnels (peer_id, opened_at);
CREATE INDEX tunnels_closed ON tunnels (closed_at);
