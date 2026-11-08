-- Align the native bounded active-session list with PostgreSQL's
-- identity+recency B-tree ordering. The original identity/state index is
-- retained for legacy queries; this additional partial index is smaller
-- because revoked/expired history must not consume active-list work.
--
-- Native query:
--   WHERE identity_id=$1 AND state=0
--     AND absolute_expires_at_ms>$2
--     AND last_seen_at_ms+idle_timeout_ms>$2
--   ORDER BY last_seen_at_ms DESC, id ASC LIMIT 257
--
-- The index provides index-order, deterministic bounded pagination without
-- scanning inactive history; expiry predicates are evaluated on the selected
-- active rows and do not change authorization or retention semantics.
-- Do not CONCURRENTLY index within Migrator's atomic transaction.
CREATE INDEX IF NOT EXISTS sessions_active_identity_recency
    ON openproof.sessions (identity_id, last_seen_at_ms DESC, id ASC)
    WHERE state = 0;
