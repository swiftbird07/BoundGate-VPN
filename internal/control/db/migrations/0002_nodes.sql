-- Milestone M1.5: devices become nodes with roles, overlay addresses and
-- announced prefixes; gateways are hubs (nodes) and lose their token table.
-- SQLite cannot alter CHECK constraints, so the table is rebuilt.

CREATE TABLE nodes (
  id                      TEXT PRIMARY KEY,
  name                    TEXT NOT NULL,
  hostname                TEXT NOT NULL DEFAULT '',
  platform                TEXT NOT NULL DEFAULT '',
  key_kind                TEXT NOT NULL DEFAULT '',
  hardware_bound          INTEGER NOT NULL DEFAULT 0,
  spki_hash               BLOB NOT NULL UNIQUE,
  cert_der                BLOB NOT NULL,
  attrs_json              TEXT NOT NULL DEFAULT '{}',
  -- what the node asked for (claims) and what an admin granted
  requested_roles_json    TEXT NOT NULL DEFAULT '[]',
  requested_prefixes_json TEXT NOT NULL DEFAULT '[]',
  roles_json              TEXT NOT NULL DEFAULT '[]',
  prefixes_json           TEXT NOT NULL DEFAULT '[]',
  overlay_ip              TEXT NOT NULL DEFAULT '',
  public_addr             TEXT NOT NULL DEFAULT '',
  status                  TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'approved', 'revoked')),
  requested_at            TEXT NOT NULL,
  request_ip              TEXT NOT NULL DEFAULT '',
  confirmed_at            TEXT,
  confirmed_by            TEXT,
  approved_at             TEXT,
  approved_by             TEXT,
  revoked_at              TEXT,
  revoked_by              TEXT,
  last_seen_at            TEXT,
  last_snapshot_version   INTEGER NOT NULL DEFAULT 0,
  active_tunnels          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX nodes_status ON nodes (status);
CREATE UNIQUE INDEX nodes_overlay_ip ON nodes (overlay_ip) WHERE overlay_ip <> '';

INSERT INTO nodes (id, name, hostname, platform, key_kind, hardware_bound, spki_hash, cert_der, attrs_json,
                   roles_json, status, requested_at, request_ip, approved_at, approved_by, revoked_at, revoked_by, last_seen_at)
  SELECT id, name, hostname, platform, key_kind, hardware_bound, spki_hash, cert_der, attrs_json,
         '["endpoint"]', status, requested_at, request_ip, approved_at, approved_by, revoked_at, revoked_by, last_seen_at
  FROM devices;

DROP TABLE devices;
DROP TABLE gateways;
