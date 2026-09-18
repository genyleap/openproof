# OpenProof C++/QML identity demo

This Qt 6 application calls the real OpenProof HTTP account/authentication API.
It preserves pre-authentication and session cookies in `QNetworkAccessManager`
and supports readiness, real and simulated Farcaster FIP-11 sign-in, dynamic
Google/Apple/Microsoft/GitHub/LinkedIn/Telegram browser sign-in through
Authorization Code + PKCE, signup, email
verification, two-step password/TOTP login, profile read/update and logout.

The complete GUI, including C++ status/error messages, is available in Persian
RTL and English LTR. Use the language button at the top of the sidebar; the
selection changes layout direction as well as copy. Navigation uses the bundled
Material Symbols font and does not require internet access.

From the repository root, build OpenProof and launch the complete disposable
stack plus GUI:

```bash
cmake --build --preset gcc-release
./scripts/run-qml-demo.sh
```

The launcher builds this app, creates an isolated Unix-socket-only PostgreSQL
cluster, provisions a verified disposable consumer, starts the Release OpenProof
server behind a local TLS edge, passes the generated CA and credentials through
a mode-`0600` connection file and opens the GUI. Close the GUI to stop every
temporary process. The temporary directory is retained for inspection.

The app never disables TLS verification. Plain HTTP is accepted only for an
explicit loopback address; the supplied demo uses HTTPS with its generated CA.

## Sign in with a real account

The default command remains deterministic so automated smoke tests never need a
personal account. To use your own Farcaster account, switch the same launcher to
real-account mode:

```bash
OPENPROOF_DEMO_REAL_AUTH=1 ./scripts/run-qml-demo.sh
```

Open **Farcaster** and select **Sign in with Farcaster**. The client creates a
short-lived channel at the public Farcaster relay, opens the system browser and
polls for the approved FIP-11 message. OpenProof then independently verifies the
signature, FID and active custody/auth address against the live Optimism
registries before issuing its own session. The relay token stays in memory and
neither OpenProof nor the QML client asks for a seed phrase or private key.

Redirect providers additionally require their upstream OAuth/OIDC application
credentials. The launcher detects every complete provider pair. The client
keeps every supported provider visible for discoverability, but enables sign-in
only for providers actually returned by `/auth/providers`. Register this
exact callback for the local demo (Google requires an OAuth 2.0 **Web
application** client):

```text
https://127.0.0.1:18443/auth/federated/callback
```

Then launch without putting the secret in the repository or command history.
The launcher asks for it with hidden input:

```bash
export OPENPROOF_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
OPENPROOF_DEMO_REAL_AUTH=1 ./scripts/run-qml-demo.sh
```

Before starting the disposable stack, the launcher sends a deliberately invalid
authorization code to Google's official token endpoint. An `invalid_grant`
response proves that the client ID and secret match; `invalid_client` stops
immediately with a configuration error. The secret is read from the child
process environment and is never placed in command-line arguments or output.

Use the same pattern with `OPENPROOF_LINKEDIN_*`, `OPENPROOF_TELEGRAM_*`,
`OPENPROOF_GITHUB_*`, `OPENPROOF_APPLE_*`, or `OPENPROOF_MICROSOFT_*`.
Provider-specific issuer requirements are documented in
[`docs/02-CONFIGURATION.md`](../../docs/02-CONFIGURATION.md#external-federated-login).

If the Google consent screen is in testing mode, add the account you will use as
a test user. The system browser may ask you to accept the generated local TLS
certificate for `127.0.0.1`; this exception applies only to the disposable local
demo. Production deployments must use their normal publicly trusted TLS origin.

The native app never receives a provider password or provider client secret.
Secrets remain in the OpenProof server process; QML uses a registered public
native client, a random loopback callback port and PKCE. After any real login,
the **Canonical profile** page reads `/account/profile` for the OpenProof identity.

## Test the product flow

The launcher opens the **Overview** page after the disposable account and local
TLS service are ready. Use the client in this order:

1. Select **Check connection** to call the real readiness endpoint.
2. In the default deterministic mode, open **Farcaster** to inspect and execute the complete SIWF flow. The demo
   signer address, FID and deterministic ERC-1271 signature are prefilled. The
   client shows the exact FIP-11 message before completion and reports whether
   the authorized signer was the FID custody address or an active auth address.
3. Open **Sign in**. The disposable subject and password are already filled in;
   select **Sign in securely** to run both cookie-bound login steps. TOTP is
   optional for the generated account.
4. A successful login opens **Profile** automatically and reads the authenticated
   profile. Change the display name or locale to exercise the update endpoint,
   then use **Sign out** to revoke the session.
5. **Sign up** exposes the account creation and email-verification calls for
   delivery-service integration testing. Select **Web tools** on the overview
   page to open the loopback-only inbox, then use **Verify this account** on the
   delivered message. The same web lab includes a bilingual, direction-aware
   Developer Portal with an **Identity Workbench** for the complete
   account → verification → login → profile → logout flow, a searchable
   reference generated from every OpenAPI operation, purpose-built request
   forms with a raw-body fallback, live status/latency/response bodies, and
   syntax-highlighted cURL, JavaScript, PHP, C++/STL, C++/Qt, C++/Boost and
   Web3 examples.
   Protected Explorer requests explicitly select the portal session or a
   Bearer token. `GET /account/profile` therefore reads the owner of that
   credential and never accepts an arbitrary email or identity ID.
6. **Show API response** displays the latest response body, while **Connection
   settings** keeps the generated origin and CA details out of the normal user
   flow.

Closing the window stops the disposable server and PostgreSQL processes. To run
the same health, Farcaster SIWF, login, profile and logout sequence without a
visible window:

```bash
OPENPROOF_QML_SMOKE=1 ./scripts/run-qml-demo.sh
```

See [`docs/DELIVERY_WEBHOOK.md`](../../docs/DELIVERY_WEBHOOK.md) for the local
workflow, production webhook payload and provider-adapter configuration.

To build only the client:

```bash
cmake -S examples/qml-identity-client -B examples/qml-identity-client/build -G Ninja
cmake --build examples/qml-identity-client/build
```

For a deterministic screenshot or an explicit startup language, run the built
client with `--language fa` or `--language en`; `--page farcaster` opens the
Farcaster lab, `--page connections` opens linked accounts, `--page connection`
opens connection settings, and `--snapshot /path/view.png` captures the selected
interface for visual regression checks.

The macOS executable is generated inside
`build/openproof_qml_client.app/Contents/MacOS/openproof_qml_client`; on Linux it
is `build/openproof_qml_client`.
