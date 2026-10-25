-- Register the public browser OAuth client used by Tegra CMS.
-- Browser clients never embed a client secret; authorization uses PKCE.

INSERT INTO openproof.applications(
    id, organization_id, identifier, display_name, environment, status,
    created_at_ms, updated_at_ms)
VALUES(
    'tegra-cms-application', 'genyleap', 'tegra-cms', 'Tegra CMS',
    0, 0,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint)
ON CONFLICT (organization_id, identifier) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    environment = EXCLUDED.environment,
    status = EXCLUDED.status,
    updated_at_ms = EXCLUDED.updated_at_ms;

INSERT INTO openproof.oauth_clients(
    id, application_id, display_name, kind, status, secret_digest,
    created_at_ms, updated_at_ms)
SELECT
    'tegra-cms-browser-v1',
    application.id,
    'Tegra CMS Browser',
    2,
    0,
    NULL,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint
FROM openproof.applications AS application
WHERE application.organization_id = 'genyleap'
  AND application.identifier = 'tegra-cms'
ON CONFLICT (id) DO UPDATE SET
    application_id = EXCLUDED.application_id,
    display_name = EXCLUDED.display_name,
    kind = EXCLUDED.kind,
    status = EXCLUDED.status,
    secret_digest = NULL,
    updated_at_ms = EXCLUDED.updated_at_ms;

DELETE FROM openproof.oauth_client_redirect_uris
WHERE client_id = 'tegra-cms-browser-v1';

INSERT INTO openproof.oauth_client_redirect_uris(client_id, redirect_uri)
VALUES(
    'tegra-cms-browser-v1',
    'https://genyleap.com/dev/tegra/auth/openproof/callback');

DELETE FROM openproof.oauth_client_scopes
WHERE client_id = 'tegra-cms-browser-v1';

INSERT INTO openproof.oauth_client_scopes(client_id, scope)
VALUES
    ('tegra-cms-browser-v1', 'openid'),
    ('tegra-cms-browser-v1', 'profile'),
    ('tegra-cms-browser-v1', 'email');
