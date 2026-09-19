# Verification delivery webhook

OpenProof owns verification issuance and validation but delegates message
delivery. This keeps the identity core independent from a particular email or
SMS vendor. The production flow is:

```text
OpenProof -> authenticated HTTPS webhook -> email/SMS adapter -> provider -> user
user/product UI -> OpenProof verification endpoint
```

## Local inbox and API Explorer

Run the interactive demo from the repository root:

```bash
./scripts/run-qml-demo.sh
```

The launcher creates a loopback-only web lab and passes its URL to the QML
client. Select **Web tools** on the overview page. After creating an account in
QML, the `signup_email` delivery appears in the web inbox with its expiry,
verification identifier and one-time secret. **Verify this account** calls the
real `POST /account/email/verify` endpoint. The new account can then sign in
with the email and password entered during signup.

The **API Explorer** tab sends requests through a loopback-only development
proxy to the same certificate-validating OpenProof instance. It retains its own
cookie jar for two-step login and displays the real status, latency, headers and
response body. Its session is intentionally separate from the QML client's
session. The complete machine-readable contract is available from the
**OpenAPI contract** link.

The inbox, proxy and secrets are development tooling. They bind only to
`127.0.0.1`, use a disposable database and stop with the QML client. Do not
deploy this web lab.

## Production webhook contract

Configure the private delivery adapter under `[account]`:

```toml
[account]
enabled = true
delivery_host = "notifications.internal.example"
delivery_port = 443
delivery_tls = true
delivery_path = "/v1/openproof/verification"
delivery_ca_file = "/etc/openproof/notification-ca.pem"
delivery_authorization = "file:/run/openproof/secrets/verification-webhook.token"
```

OpenProof sends an authenticated `POST` with `Content-Type: application/json`
and `Authorization: Bearer <delivery token>`:

```json
{
  "verification_id": "verification identifier",
  "identity_id": "identity identifier",
  "purpose": "signup_email",
  "channel": "email",
  "destination": "rider@example.com",
  "secret": "single-use secret",
  "expires_at_ms": 1787414400000
}
```

The adapter validates the bearer token, selects an email/SMS template by
`purpose`, and submits the message to the chosen provider. For signup email, a
product can send a link such as:

```text
https://app.example.com/verify-email?id=VERIFICATION_ID&secret=ONE_TIME_SECRET
```

That product page completes the ceremony with:

```http
POST /account/email/verify
Content-Type: application/json

{"verification_id":"VERIFICATION_ID","secret":"ONE_TIME_SECRET"}
```

Return any `2xx` status only after the provider accepts the message. OpenProof
treats a non-`2xx` response as failed delivery instead of reporting a false
success. Never log the bearer credential or one-time secret, use a private
network where possible, validate TLS with the configured CA, enforce request
size/time limits, and redact provider error output.

## Optional same-host Postfix adapter

`deploy/verification-delivery-postfix.php` is a small reference adapter for operators
that deliver transactional email through a Postfix MTA on the same host. It binds only
on loopback through `deploy/openproof-delivery.service`, validates the OpenProof bearer,
accepts only the email purposes, builds application action URLs, and submits mail to a
loopback-only SMTP listener. The adapter uses SMTP rather than the local `sendmail`
queue helper so the hardened unit can keep `NoNewPrivileges=true`.

Configure the three public action URLs and sender in `/etc/openproof/delivery.env` from
`deploy/openproof-delivery.env.example`. For this topology, OpenProof itself points
`delivery_host` to `127.0.0.1`, `delivery_port` to `18444` and `delivery_tls` to `false`;
the absence of TLS is acceptable only because the entire hop is same-host loopback.
The adapter returns `204` only after Postfix replies that it accepted the message into
its local queue. Final delivery to the recipient MX is asynchronous, so operators must
monitor the Postfix queue and bounce stream rather than interpreting queue acceptance
as proof that the recipient inbox accepted the message.

Direct-to-MX delivery needs DNS hygiene before production traffic. The sending IP should
have PTR/rDNS to the SMTP hostname and that hostname must resolve forward to the same
address. Publish an SPF record authorizing the sending address, publish the DKIM public
key for the selector used by the signer, and publish DMARC for the From domain. If the
host has both address families, either provision valid PTR/forward DNS for IPv6 too or
keep outbound SMTP on IPv4 until that work is complete. Test the exact public records
from multiple recursive resolvers because negative DNS caching can make a newly added
PTR appear inconsistently for several hours.

A direct-sending MTA should identify itself with the same hostname used by PTR, sign
mail after submission, accept submission only from trusted local callers, and never be
an open relay. Keep the OpenProof delivery adapter private even when the MTA itself must
reach public MX hosts over TCP/25.

Delivery purposes currently include signup email, password reset, email change
and phone verification. Password-reset deliveries must lead to
`POST /account/password/reset`; they cannot be consumed by the signup-email
verification endpoint.
