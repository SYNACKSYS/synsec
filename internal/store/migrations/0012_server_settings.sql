-- Settings that belong to the server rather than to a person.
--
-- The same key/value shape as user_settings, and for the same reasons: they
-- are small, they arrive one at a time, and an older binary reading a newer
-- database falls back to its defaults instead of failing.
--
-- Only the settings that can change while the server runs live here. An
-- address to listen on or a certificate to load is read once at start-up, and
-- storing it would promise a change that nothing applies.
CREATE TABLE server_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
