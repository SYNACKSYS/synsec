-- Per-secret address restrictions.
--
-- A service token can already be pinned to an address, but that binds the
-- credential rather than the thing it opens. This binds the secret: whoever
-- asks and however they authenticate, the Zigbee key is only handed out to the
-- addresses listed here.
--
-- An empty list means no restriction, which is the default and the case for
-- every secret that already exists - the table simply starts empty.

CREATE TABLE secret_networks (
    secret_id TEXT NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    -- A single address or a CIDR block, stored in the canonical form the
    -- parser produced rather than as it was typed, so "192.168.01.1" and
    -- "192.168.1.1" cannot both sit in the list meaning the same thing.
    network   TEXT NOT NULL,
    added_at  INTEGER NOT NULL,
    added_by  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (secret_id, network)
);

-- Every read of a restricted secret consults this, and the export endpoint
-- consults it once per secret it returns.
CREATE INDEX idx_secret_networks ON secret_networks (secret_id);
