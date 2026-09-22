-- Lists: named sets of addresses, DNS names or TLS server names that
-- policies refer to as BoundGate::List::"<name>" (allow- and block-lists
-- maintained apart from the rules that use them). kind is ip, dns or sni;
-- entries_json is a JSON array of strings: addresses or CIDR prefixes, or
-- names with an optional leading "*." wildcard, lowercase, sorted.
CREATE TABLE lists (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  kind         TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  entries_json TEXT NOT NULL DEFAULT '[]',
  created_at   TEXT NOT NULL,
  created_by   TEXT NOT NULL DEFAULT '',
  updated_at   TEXT NOT NULL,
  updated_by   TEXT NOT NULL DEFAULT ''
);

-- A group is a label that keeps the policy list readable in the admin UI.
-- It has no effect on evaluation.
ALTER TABLE policies ADD COLUMN group_name TEXT NOT NULL DEFAULT '';
