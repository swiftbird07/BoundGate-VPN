-- public_addr makes every peer route that address around the overlay
-- (PATHS.md, R97), so only an administrator sets it. What a node asks for
-- at enrollment is a request, kept apart in requested_public_addr and
-- shown to the administrator. Pending requests lose the address they
-- brought; confirmed and approved nodes keep theirs, an administrator
-- confirmed it.
ALTER TABLE nodes ADD COLUMN requested_public_addr TEXT NOT NULL DEFAULT '';
UPDATE nodes SET requested_public_addr = public_addr;
UPDATE nodes SET public_addr = '' WHERE status = 'pending';
