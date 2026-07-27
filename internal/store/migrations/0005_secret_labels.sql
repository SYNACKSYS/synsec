-- A secret gets two names: one for people, one for machines.
--
-- The label is what its owner writes - "Mot de passe MQTT", accents, spaces and
-- all. The slug, stored in `name`, is what addresses it: a device asks for
-- mqtt_password, and that is what goes into the encryption.
--
-- The split earns its keep in what it makes possible: the label can be changed
-- at any time, because nothing depends on it. The slug cannot, because it is
-- part of the data authenticated into every version of the ciphertext -
-- changing it would mean decrypting and resealing the whole history.

ALTER TABLE secrets ADD COLUMN label TEXT NOT NULL DEFAULT '';

-- Secrets written before this migration have no label. The interface falls
-- back to the slug rather than showing a blank, so nothing needs backfilling.
