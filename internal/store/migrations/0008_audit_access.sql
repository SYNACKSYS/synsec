-- Who may read the audit log.
--
-- The log is the one place where everything that happened to every vault is
-- written down: which secrets were opened, by whom, from where. Handing it to
-- anyone holding the administrator flag would give away, in one page, exactly
-- what the vault separation is there to keep apart.
--
-- So it belongs to one account - the one the server was set up with - who may
-- hand it to other administrators one at a time.
ALTER TABLE users ADD COLUMN is_root INTEGER NOT NULL DEFAULT 0;

-- The account the server was set up with is the earliest administrator: the
-- command line makes the first account an administrator whether asked to or
-- not, and nothing else could have existed before it.
UPDATE users SET is_root = 1 WHERE id = (
    SELECT id FROM users WHERE is_admin = 1 ORDER BY created_at, id LIMIT 1
);

-- A grant is its own row rather than a column on users: it is not a property
-- of the person but a decision someone made, and the log is the wrong place to
-- lose track of who opened the log to whom.
CREATE TABLE audit_readers (
    user_id    TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    granted_at INTEGER NOT NULL,
    granted_by TEXT NOT NULL
);
