-- Register the public native OAuth client used by Genycaster.
-- Device authorization carries no client secret; the desktop app never embeds one.

INSERT INTO openproof.applications(
    id, organization_id, identifier, display_name, environment, status,
    created_at_ms, updated_at_ms)
VALUES(
    'genycaster-application', 'genyleap', 'genycaster', 'Genycaster',
    0, 0,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint)
ON CONFLICT DO NOTHING;

INSERT INTO openproof.oauth_clients(
    id, application_id, display_name, kind, status, secret_digest,
    created_at_ms, updated_at_ms)
SELECT
    'genycaster-native-v1',
    application.id,
    'Genycaster Native',
    1,
    0,
    NULL,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint,
    (extract(epoch FROM clock_timestamp()) * 1000)::bigint
FROM openproof.applications AS application
WHERE application.organization_id = 'genyleap'
  AND application.identifier = 'genycaster'
ON CONFLICT (id) DO UPDATE SET
    application_id = EXCLUDED.application_id,
    display_name = EXCLUDED.display_name,
    kind = EXCLUDED.kind,
    status = EXCLUDED.status,
    secret_digest = NULL,
    updated_at_ms = EXCLUDED.updated_at_ms;

DELETE FROM openproof.oauth_client_redirect_uris
WHERE client_id = 'genycaster-native-v1';

INSERT INTO openproof.oauth_client_redirect_uris(client_id, redirect_uri)
VALUES(
    'genycaster-native-v1',
    'http://127.0.0.1:48765/openproof/callback');

DELETE FROM openproof.oauth_client_scopes
WHERE client_id = 'genycaster-native-v1';

INSERT INTO openproof.oauth_client_scopes(client_id, scope)
VALUES
    ('genycaster-native-v1', 'openid'),
    ('genycaster-native-v1', 'profile'),
    ('genycaster-native-v1', 'account'),
    ('genycaster-native-v1', 'offline_access');
