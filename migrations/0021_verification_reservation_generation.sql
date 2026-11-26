-- A native challenge owns one reservation generation. No FK to the
-- challenge: successful consumption removes the proof before completion
-- releases the reservation. Untagged legacy rows retain their old meaning.
ALTER TABLE openproof.pending_external_identity_reservations
    ADD COLUMN verification_id text NULL
    CHECK (verification_id IS NULL OR length(verification_id) BETWEEN 1 AND 200);
CREATE UNIQUE INDEX pending_external_identity_reservation_generation
    ON openproof.pending_external_identity_reservations(verification_id)
    WHERE verification_id IS NOT NULL;
