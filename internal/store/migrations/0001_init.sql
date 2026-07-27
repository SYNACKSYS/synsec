-- Timestamps are Unix seconds in INTEGER columns: compact, sortable, and free
-- of the timezone ambiguity that bites when a home server moves country or
-- crosses a daylight saving boundary.

-- meta holds singleton server state: schema fingerprint, unseal provider in
-- use, and the handle that provider needs to recover the wrapping key.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- key_slots mirrors internal/crypto.KeySlot. Several rows wrap the very same
-- root key, so revoking a passphrase or moving to a new machine rewrites a few
-- hundred bytes here and never touches an encrypted secret.
CREATE TABLE key_slots (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('passphrase', 'recovery', 'machine')),
    salt       BLOB,
    params     TEXT,
    blob       BLOB NOT NULL,
    provider   TEXT,
    handle     BLOB,
    created_at INTEGER NOT NULL
);

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL COLLATE NOCASE,
    display_name    TEXT NOT NULL DEFAULT '',
    password_hash   BLOB NOT NULL,
    password_salt   BLOB NOT NULL,
    password_params TEXT NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    totp_secret     BLOB,
    created_at      INTEGER NOT NULL,
    last_login_at   INTEGER,
    UNIQUE (username)
);

-- Only the hash of a session token is stored, so a database dump does not hand
-- an attacker a set of live sessions.
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    token_hash   BLOB NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    user_agent   TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    UNIQUE (token_hash)
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);

-- projects are what the interface calls "Coffres". Each owns one data
-- encryption key, stored wrapped by the root key.
CREATE TABLE projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    wrapped_dek BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    UNIQUE (name)
);

-- Environments exist from day one so the data model never needs reshaping, but
-- the interface hides them behind an advanced toggle: a household running Home
-- Assistant has exactly one, created as 'prod' during setup.
CREATE TABLE environments (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    position   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (project_id, slug)
);

-- secrets carries the metadata; the values live in secret_versions. Splitting
-- them keeps listing a vault cheap, because the interface can enumerate names
-- and paths without ever unwrapping a project key.
CREATE TABLE secrets (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    env             TEXT NOT NULL,
    path            TEXT NOT NULL,
    current_version INTEGER NOT NULL,
    comment         TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (project_id, env, path)
);

CREATE INDEX idx_secrets_lookup ON secrets (project_id, env, path);

-- Versions are immutable and append-only. Editing a secret writes a new row,
-- which is what makes "revert to the previous value" a metadata update rather
-- than a restore from backup.
CREATE TABLE secret_versions (
    secret_id  TEXT NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    version    INTEGER NOT NULL,
    blob       BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (secret_id, version)
);

-- service_tokens authenticate machines. Only an HMAC of the secret half is
-- stored; the token itself is shown once, at creation, and never again.
CREATE TABLE service_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    secret_hash  BLOB NOT NULL,
    project_id   TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    env          TEXT NOT NULL,
    path_prefix  TEXT NOT NULL DEFAULT '/',
    can_write    INTEGER NOT NULL DEFAULT 0,
    expires_at   INTEGER,
    ip_allowlist TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    last_used_at INTEGER,
    revoked_at   INTEGER
);

CREATE INDEX idx_tokens_project ON service_tokens (project_id);

-- audit_log is append-only by convention: nothing in SYNSEC issues UPDATE or
-- DELETE against it. It is the only defence left once an attacker holds the
-- root key, so it records reads as well as writes.
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    actor_kind  TEXT NOT NULL CHECK (actor_kind IN ('user', 'token', 'system')),
    actor_id    TEXT NOT NULL DEFAULT '',
    actor_label TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target      TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_at ON audit_log (at);
CREATE INDEX idx_audit_actor ON audit_log (actor_kind, actor_id);
