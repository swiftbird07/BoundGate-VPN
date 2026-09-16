-- Milestone M2: user sessions (OIDC) bound to nodes, login flows, and the
-- node kind (interactive needs a session, workload does not; signed).

ALTER TABLE nodes ADD COLUMN kind TEXT NOT NULL DEFAULT 'interactive' CHECK (kind IN ('interactive', 'workload'));

-- The binding gained a field; every existing signature is over the old
-- form and no longer verifies. Approved nodes go back to confirmed.
UPDATE nodes SET status = 'confirmed', binding_json = '', binding_sig = '', signed_by = '', signed_at = NULL,
                 approved_at = NULL, approved_by = NULL
  WHERE status = 'approved';
UPDATE snapshot_version SET version = version + 1
  WHERE EXISTS (SELECT 1 FROM nodes WHERE status = 'confirmed');

CREATE TABLE login_flows (
  id            TEXT PRIMARY KEY,
  node_id       TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  state         TEXT NOT NULL UNIQUE,
  nonce         TEXT NOT NULL,
  pkce_verifier TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('pending', 'done', 'failed')),
  session_id    TEXT,
  error         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX login_flows_node ON login_flows (node_id);

-- One active session per node. Sessions are control-plane state and travel
-- only inside snapshots; nothing here is a bearer secret.
CREATE TABLE user_sessions (
  id          TEXT PRIMARY KEY,
  node_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  subject     TEXT NOT NULL,
  email       TEXT NOT NULL DEFAULT '',
  username    TEXT NOT NULL DEFAULT '',
  groups_json TEXT NOT NULL DEFAULT '[]',
  login_ip    TEXT NOT NULL DEFAULT '',
  issued_at   TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  revoked_at  TEXT,
  revoked_by  TEXT,
  end_reason  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX user_sessions_node ON user_sessions (node_id);
CREATE UNIQUE INDEX user_sessions_active ON user_sessions (node_id) WHERE revoked_at IS NULL;
