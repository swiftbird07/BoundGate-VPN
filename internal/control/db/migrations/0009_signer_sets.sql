-- The admin key list becomes a signed chain (internal/binding/signerset.go):
-- every version is signed by a key of the version before it, nodes follow
-- the chain from the list they pinned. The control plane stores and
-- forwards it and cannot extend it: it holds no admin key.
--
-- admin_signers stays as the directory of names and owners; which keys are
-- valid is decided by the newest signer set alone. Keys registered before
-- this migration are not part of any signed set: they show up as
-- "unsigned" until an administrator signs the first list.
CREATE TABLE signer_sets (
  version    INTEGER PRIMARY KEY,       -- 1 = genesis; consecutive
  set_json   TEXT NOT NULL,             -- canonical binding.SignerSet
  signature  TEXT NOT NULL,             -- SSHSIG, namespace boundgate-signers
  hash       TEXT NOT NULL UNIQUE,      -- hex SHA-256 of set_json
  signed_by  TEXT NOT NULL,             -- fingerprint of the signing admin key
  admin      TEXT NOT NULL,             -- admin session that proposed the change
  created_at TEXT NOT NULL
);

-- A proposed next set, waiting for its signature: minted in the admin UI,
-- fetched and signed by `boundgatectl admin sign-signers` with a one-time
-- token (10 minutes, single use), like a node binding.
CREATE TABLE signer_changes (
  token_hash BLOB PRIMARY KEY,
  set_json   TEXT NOT NULL,
  meta_json  TEXT NOT NULL,             -- names and owners of the keys, for admin_signers
  admin      TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at    TEXT
);
