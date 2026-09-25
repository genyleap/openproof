-- Seed only display-only canonical profile fields from already verified Farcaster links.
-- Security-bearing email and phone ownership claims are deliberately untouched.
-- Existing canonical values always win over provider presentation metadata.

WITH farcaster_presentation AS (
    SELECT DISTINCT ON (e.identity_id)
        e.identity_id,
        NULLIF(btrim(e.display_name), '') AS display_name,
        NULLIF(btrim(e.preferred_username), '') AS preferred_username,
        NULLIF(btrim(e.picture_url), '') AS picture_url
    FROM openproof.external_identities e
    WHERE e.provider = 'farcaster'
      AND (
          NULLIF(btrim(e.display_name), '') IS NOT NULL
          OR NULLIF(btrim(e.preferred_username), '') IS NOT NULL
          OR NULLIF(btrim(e.picture_url), '') IS NOT NULL
      )
    ORDER BY e.identity_id, e.linked_at_ms DESC
),
missing_profiles AS (
    SELECT
        f.identity_id,
        COALESCE(f.display_name, f.preferred_username) AS display_name,
        f.preferred_username,
        f.picture_url,
        i.created_at_ms
    FROM farcaster_presentation f
    JOIN openproof.identities i ON i.id = f.identity_id
    LEFT JOIN openproof.identity_profiles p ON p.identity_id = f.identity_id
    WHERE p.identity_id IS NULL
)
INSERT INTO openproof.identity_profiles(
    identity_id,
    display_name,
    preferred_username,
    picture_url,
    created_at_ms,
    updated_at_ms
)
SELECT
    identity_id,
    display_name,
    preferred_username,
    picture_url,
    created_at_ms,
    GREATEST(
        created_at_ms,
        (extract(epoch FROM clock_timestamp()) * 1000)::bigint
    )
FROM missing_profiles;

-- Fill only missing fields on profiles that already exist.
WITH farcaster_presentation AS (
    SELECT DISTINCT ON (e.identity_id)
        e.identity_id,
        NULLIF(btrim(e.display_name), '') AS display_name,
        NULLIF(btrim(e.preferred_username), '') AS preferred_username,
        NULLIF(btrim(e.picture_url), '') AS picture_url
    FROM openproof.external_identities e
    WHERE e.provider = 'farcaster'
      AND (
          NULLIF(btrim(e.display_name), '') IS NOT NULL
          OR NULLIF(btrim(e.preferred_username), '') IS NOT NULL
          OR NULLIF(btrim(e.picture_url), '') IS NOT NULL
      )
    ORDER BY e.identity_id, e.linked_at_ms DESC
)
UPDATE openproof.identity_profiles p
SET
    display_name = CASE
        WHEN NULLIF(btrim(p.display_name), '') IS NULL
            THEN COALESCE(f.display_name, f.preferred_username)
        ELSE p.display_name
    END,
    preferred_username = CASE
        WHEN NULLIF(btrim(p.preferred_username), '') IS NULL
            THEN f.preferred_username
        ELSE p.preferred_username
    END,
    picture_url = CASE
        WHEN NULLIF(btrim(p.picture_url), '') IS NULL
            THEN f.picture_url
        ELSE p.picture_url
    END,
    updated_at_ms = GREATEST(
        p.updated_at_ms,
        (extract(epoch FROM clock_timestamp()) * 1000)::bigint
    )
FROM farcaster_presentation f
WHERE p.identity_id = f.identity_id
  AND (
      (
          NULLIF(btrim(p.display_name), '') IS NULL
          AND COALESCE(f.display_name, f.preferred_username) IS NOT NULL
      )
      OR (
          NULLIF(btrim(p.preferred_username), '') IS NULL
          AND f.preferred_username IS NOT NULL
      )
      OR (
          NULLIF(btrim(p.picture_url), '') IS NULL
          AND f.picture_url IS NOT NULL
      )
  );
