-- Milestone M4: admin authentication (OIDC admin group + passkey), admin
-- sessions, API tokens for automation. The bootstrap token only works
-- until the first passkey exists.

CREATE TABLE admin_login_flows (
  id            TEXT PRIMARY KEY,
  state         TEXT NOT NULL UNIQUE,
  nonce         TEXT NOT NULL,
  pkce_verifier TEXT NOT NULL,
  next          TEXT NOT NULL DEFAULT '/',
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('pending', 'done', 'failed')),
  error         TEXT NOT NULL DEFAULT ''
);

-- A browser session. level oidc_only until a passkey assertion succeeded.
CREATE TABLE admin_sessions (
  id            TEXT PRIMARY KEY,
  subject       TEXT NOT NULL,
  email         TEXT NOT NULL DEFAULT '',
  name          TEXT NOT NULL DEFAULT '',
  groups_json   TEXT NOT NULL DEFAULT '[]',
  level         TEXT NOT NULL CHECK (level IN ('oidc_only', 'full')),
  login_ip      TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  revoked_at    TEXT,
  -- WebAuthn ceremony state between begin and finish
  ceremony_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX admin_sessions_subject ON admin_sessions (subject);

CREATE TABLE admin_passkeys (
  id              TEXT PRIMARY KEY,
  subject         TEXT NOT NULL,
  email           TEXT NOT NULL DEFAULT '',
  label           TEXT NOT NULL DEFAULT '',
  credential_json TEXT NOT NULL,
  credential_id   BLOB NOT NULL UNIQUE,
  status          TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
  created_at      TEXT NOT NULL,
  approved_at     TEXT,
  approved_by     TEXT,
  last_used_at    TEXT,
  revoked_at      TEXT,
  revoked_by      TEXT
);
CREATE INDEX admin_passkeys_subject ON admin_passkeys (subject);

CREATE TABLE api_tokens (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  token_hash   BLOB NOT NULL UNIQUE,
  created_by   TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  expires_at   TEXT,
  last_used_at TEXT,
  revoked_at   TEXT,
  revoked_by   TEXT
);
