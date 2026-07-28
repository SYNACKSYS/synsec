-- Recovery codes, for the day the phone is lost.
--
-- Stored hashed, like tokens: single use, never shown again. Without them, a
-- lost phone means an account nobody can open, and the only way back would be
-- to turn the second factor off for everyone.
CREATE TABLE totp_recovery (
    user_id   TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL,
    used_at   INTEGER,
    PRIMARY KEY (user_id, code_hash)
);
