-- Per-account preferences.
--
-- A key/value table rather than a column per setting: these are small, they
-- will arrive one at a time, and none of them is worth a migration each. The
-- interface validates the values it understands and ignores the rest, so an
-- older binary reading a newer database simply falls back to its defaults.
CREATE TABLE user_settings (
    user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key     TEXT NOT NULL,
    value   TEXT NOT NULL,
    PRIMARY KEY (user_id, key)
);
