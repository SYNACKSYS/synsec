-- A token may be narrowed to a few secrets.
--
-- Until now a token opened a whole vault while an address restriction applied
-- to a single secret: the same server answered "at what level is a machine's
-- access decided" two different ways. Both now decide it at the secret.
--
-- Secrets are stored by name rather than by row identifier, because the name
-- is what the API addresses and what the encryption binds. It also lets a
-- write-capable token be scoped to a secret that does not exist yet, which is
-- exactly what a device that creates its own entry needs.
CREATE TABLE token_secrets (
    token_id    TEXT NOT NULL REFERENCES service_tokens (id) ON DELETE CASCADE,
    secret_name TEXT NOT NULL,
    PRIMARY KEY (token_id, secret_name)
);
