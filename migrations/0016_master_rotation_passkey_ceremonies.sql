-- Passkey registration challenges are recomputed from the active master key.
-- A master cutover therefore retires their durable ceremony rows alongside the
-- other in-flight master-keyed protocol state and journals the exact count.
ALTER TABLE openproof.master_key_rotations
    ADD COLUMN passkey_registrations bigint NOT NULL DEFAULT 0
        CHECK (passkey_registrations >= 0);

ALTER TABLE openproof.master_key_rotations
    ALTER COLUMN passkey_registrations DROP DEFAULT;
