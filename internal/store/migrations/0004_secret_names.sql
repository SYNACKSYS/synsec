-- A secret is one entry, addressed by its name.
--
-- The hierarchy is gone: no folders, no prefixes, and nothing that hands back
-- a set of secrets at once. It bought prefix-scoped tokens and a batch export,
-- and it cost a vocabulary nobody outside development recognises - a "path"
-- that looks like a file, needs a leading slash, and cannot be renamed.
--
-- Only the column is renamed here, never a stored value. The name is part of
-- the data authenticated into each ciphertext, so rewriting it in SQL would
-- leave every existing secret undecryptable. Rows written under the old scheme
-- keep their slashes and keep working; new ones must be plain identifiers.

ALTER TABLE secrets RENAME COLUMN path TO name;

DROP INDEX idx_secrets_lookup;
CREATE INDEX idx_secrets_lookup ON secrets (project_id, env, name);

-- A token's scope no longer has a path half: with no hierarchy there is no
-- prefix to restrict, so a token opens a vault and an environment, for reading
-- or for writing.
ALTER TABLE service_tokens DROP COLUMN path_prefix;
