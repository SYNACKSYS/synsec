-- Access control for human accounts, at two granularities.
--
-- Machine tokens were scoped from the first day; browser sessions were not, so
-- any account that could sign in could read every secret on the server. This
-- closes that, and adds the case the vault level cannot express: handing one
-- secret to one person without opening the rest of the vault to them.

CREATE TABLE vault_members (
    project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('reader', 'writer', 'manager')),
    granted_at INTEGER NOT NULL,
    granted_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, user_id)
);

-- Listing what a person may see is the most frequent query in the interface,
-- and it starts from the user.
CREATE INDEX idx_members_user ON vault_members (user_id);

-- A share on a single secret.
--
-- Only reader and writer: deleting a secret, with all its history, stays a
-- vault-level right. Someone handed one password should be able to read it, or
-- rotate it, but not to destroy it on behalf of its owner.
CREATE TABLE secret_shares (
    secret_id  TEXT NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('reader', 'writer')),
    granted_at INTEGER NOT NULL,
    granted_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (secret_id, user_id)
);

CREATE INDEX idx_shares_user ON secret_shares (user_id);

-- Existing installations have vaults and no memberships. Without this, the
-- upgrade would hide every vault from everyone and look exactly like data
-- loss. Server administrators become managers of what already exists; anything
-- created afterwards belongs to whoever creates it.
INSERT INTO vault_members (project_id, user_id, role, granted_at, granted_by)
SELECT p.id, u.id, 'manager', unixepoch(), 'migration'
FROM projects p
CROSS JOIN users u
WHERE u.is_admin = 1;
