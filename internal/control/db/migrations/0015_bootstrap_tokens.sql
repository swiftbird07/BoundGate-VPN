-- An API token minted with the bootstrap token is as strong as the
-- bootstrap token, which dies when the first passkey is registered (R54);
-- the token must die with it. bootstrap marks such tokens; those minted
-- before this migration are recognised by their creator, and are revoked
-- now if a passkey is already active.
ALTER TABLE api_tokens ADD COLUMN bootstrap INTEGER NOT NULL DEFAULT 0;
UPDATE api_tokens SET bootstrap = 1 WHERE created_by = 'bootstrap';
UPDATE api_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), revoked_by = 'minted with the bootstrap token'
  WHERE bootstrap = 1 AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM admin_passkeys WHERE status = 'active');
