-- Correct the canonical Genycaster application registration on deployments
-- that applied migration 0020 before the product was marked production.

UPDATE openproof.applications
SET environment = 2,
    status = 0,
    display_name = 'Genycaster',
    updated_at_ms = (extract(epoch FROM clock_timestamp()) * 1000)::bigint
WHERE organization_id = 'genyleap'
  AND identifier = 'genycaster';
