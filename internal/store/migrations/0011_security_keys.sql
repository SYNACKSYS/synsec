-- Security keys: the second factor for people who would rather touch a piece
-- of metal than read six digits off a phone.
--
-- Nothing here is a secret. A public key is public, and the credential
-- identifier is what the browser must be told before the key will answer. What
-- the row is worth to an attacker is the fact that this account has a key at
-- all - which is why the sign-in page never reveals it before the password.
CREATE TABLE security_keys (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Unique across the server: one credential belongs to one account, and a
    -- key registered twice would otherwise answer for either.
    credential_id BLOB NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,
    aaguid        BLOB,
    -- The authenticator's own counter. It must climb; one that stands still
    -- means the key keeps none, one that falls means the credential was copied.
    sign_count    INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);

CREATE INDEX idx_security_keys_user ON security_keys (user_id);
