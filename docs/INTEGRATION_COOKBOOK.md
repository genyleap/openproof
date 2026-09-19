# OpenProof integration cookbook

This cookbook explains how a product consumes OpenProof from different
languages. The protocol is HTTP + OAuth 2.0/OIDC, so a product is not tied to a
specific framework. The complete machine-readable contract is
[`openapi.yaml`](openapi.yaml); the interactive local Developer Portal renders
every operation and generates language-specific examples.

## Choose the correct integration boundary

| Consumer | Recommended flow | Credential held by the product |
|---|---|---|
| Browser, mobile or desktop app | Authorization Code + PKCE | access/refresh/ID tokens |
| OpenProof account/settings UI | Account + Auth APIs | OpenProof session cookie |
| Product backend/API | Validate or introspect access token | access token or introspection client |
| Background service | `client_credentials` | service client ID/secret |
| Ethereum or Farcaster login | Web3 start/complete ceremony | wallet signature, then OpenProof session/token |
| Enterprise provisioning | SCIM 2.0 | tenant SCIM bearer |

Do not copy the `__Host-openproof-session` cookie into a product domain. That
cookie is for OpenProof account/admin self-service. Products use OAuth/OIDC
access tokens with explicit scope and audience.

## Run the interactive documentation

```bash
./scripts/run-qml-demo.sh
```

Select **Web tools** in the QML overview. The Developer Portal contains:

- a bilingual Persian/English guided architecture and onboarding page;
- an **Identity Workbench** that runs signup, delivery verification, the
  cookie-bound two-call login, full profile read/update and logout against the
  real local service while showing every request and state transition;
- a searchable master/detail reference generated from all OpenAPI operations;
- a live request editor with purpose-built forms for common account, profile,
  OAuth, Web3, admin and evidence operations, plus raw JSON/form fallback for
  every operation;
- generated cURL, JavaScript, PHP, C++/STL (libcurl), C++/Qt, C++/Boost
  (Beast/Asio) and Web3 examples in a
  syntax-highlighted editor with line numbers and one-click copy;
- the verification delivery inbox.

Use the language control in the portal header to switch the entire interface
between Persian RTL and English LTR. Select an operation in **API reference** to
read its authentication model and response contract, then choose **Open in
Explorer** to prefill a runnable request. Language tabs change only the client
implementation; the HTTP operation and security ceremony remain identical.

For the fastest end-to-end check, open **Identity Workbench** and follow the
five visible stages: **Account → Verify → Login → Profile → Logout**. Use
**Create a new account** to exercise authenticated delivery and ownership
verification, or **Use prepared account** to start at login. The profile stage
deliberately keeps verified email and phone read-only: update
`display_name`, `preferred_username`, `locale` or `picture` with
`PATCH /account/profile`; change email or phone only through their separate
verification ceremonies.

In **API Explorer & code**, choose a workflow preset or open any operation from
the complete reference. **Guided form** labels each supported field and omits
empty optional values. **JSON / Form raw** is the universal escape hatch for
the complete OpenAPI contract. `GET /account/profile` sends no body, while
`PATCH /account/profile` sends only the profile fields you supplied. The
response panel is the real status/body returned by the local OpenProof process;
the code panel generates the equivalent cURL, JavaScript, PHP, C++/STL,
C++/Qt, C++/Boost or Web3 request. The C++ tabs are intentionally separate:
STL uses libcurl for HTTP transport, Qt uses `QNetworkAccessManager`, and Boost
uses Beast/Asio over a validating TLS stream.

The Explorer treats the credential as a first-class input. For protected
operations, select either **Portal session** or **Access token**. Portal session
uses only the server-side cookie jar created by the Identity Workbench; Access
token sends only `Authorization: Bearer …`. The two are never sent together.
Public operations send neither. Path and query parameters are extracted from
OpenAPI into labelled controls, validated before execution and reflected in a
live resolved-URL preview and every generated code sample.

### What `GET /account/profile` means

`GET /account/profile` is intentionally a self-service endpoint. It does not
accept an email, `identity_id`, query parameter or request body. The selected
credential determines the subject:

- with **Portal session**, it returns the user who completed login in the
  Identity Workbench;
- with **Access token**, it returns the subject represented by that allowed
  token;
- with no valid credential, it returns `401`.

This is not a directory-search API, and adding a user ID to it would let a
normal user probe other identities. A product that needs standard token claims
uses `GET /oauth/userinfo` with a scoped access token. Administrative
provisioning uses the protected Administration/SCIM surfaces and their explicit
tenant roles; it must not reuse the self-service profile route as an arbitrary
user lookup.

The live executor proxies only to the disposable local OpenProof instance and
validates its generated TLS CA. Code examples use
`https://identity.example.com`; replace it with the production issuer. For
direct local cURL calls, use the generated CA with `--cacert`.

The deterministic portal behavior regression can be run without starting the
database:

```bash
node scripts/test-local-demo-portal-ui.mjs
```

It renders all five pages in both directions and checks profile credential
selection, required-field errors, 401/200 response states, disabled invalid
methods and path/query URL resolution.

## Register and verify a user

The signup response deliberately does not return the secret. OpenProof sends it
to the configured authenticated delivery webhook.

```bash
BASE_URL=https://identity.example.com

curl --fail-with-body "$BASE_URL/account/signup" \
  -H 'Content-Type: application/json' \
  --data '{
    "email":"rider@example.com",
    "password":"correct horse battery staple",
    "display_name":"Example Rider"
  }'

curl --fail-with-body "$BASE_URL/account/email/verify" \
  -H 'Content-Type: application/json' \
  --data '{
    "verification_id":"VERIFICATION_ID_FROM_DELIVERY",
    "secret":"ONE_TIME_SECRET_FROM_DELIVERY"
  }'
```

The local inbox exposes **Verify this account** only for development. A
production email links to the product verification page, which submits the same
proof to `/account/email/verify`.

## Password login is a cookie-bound two-step ceremony

The cookie jar returned by `/auth/login` must be reused by
`/auth/mfa/verify`. The first `202` is not an authenticated session.

### cURL

```bash
curl --fail-with-body -c openproof.cookies \
  "$BASE_URL/auth/login" \
  -H 'Content-Type: application/json' \
  --data '{"subject":"rider@example.com"}'

curl --fail-with-body -b openproof.cookies -c openproof.cookies \
  "$BASE_URL/auth/mfa/verify" \
  -H 'Content-Type: application/json' \
  --data '{
    "transaction_id":"TRANSACTION_ID",
    "challenge_id":"CHALLENGE_ID",
    "password":"correct horse battery staple",
    "totp":"123456"
  }'

curl --fail-with-body -b openproof.cookies \
  "$BASE_URL/account/profile"
```

### JavaScript in a browser

Use this direct account flow only when deployment/CORS/cookie policy allows the
browser to talk to the identity origin. A normal standalone product should use
Authorization Code + PKCE instead.

```javascript
const issuer = "https://identity.example.com";

const started = await fetch(`${issuer}/auth/login`, {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ subject: "rider@example.com" })
}).then(async response => {
  if (!response.ok) throw new Error(await response.text());
  return response.json();
});

const completed = await fetch(`${issuer}/auth/mfa/verify`, {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    transaction_id: started.transaction_id,
    challenge_id: started.challenge_id,
    password: "correct horse battery staple"
  })
});
if (!completed.ok) throw new Error(await completed.text());
```

### PHP

Keep the cookie file private and reuse it for both calls. Production code should
also bound network timeouts and map non-2xx responses to typed errors.

```php
<?php
function openProof(string $method, string $path, ?array $json = null): array {
    $cookie = __DIR__ . '/openproof.cookies';
    $curl = curl_init('https://identity.example.com' . $path);
    curl_setopt_array($curl, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_COOKIEJAR => $cookie,
        CURLOPT_COOKIEFILE => $cookie,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => $json === null ? null : json_encode($json, JSON_THROW_ON_ERROR),
        CURLOPT_TIMEOUT => 10,
    ]);
    $body = curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    if ($body === false || $status < 200 || $status >= 300) {
        throw new RuntimeException(curl_error($curl) ?: (string) $body);
    }
    return $body === '' ? [] : json_decode($body, true, flags: JSON_THROW_ON_ERROR);
}

$challenge = openProof('POST', '/auth/login', ['subject' => 'rider@example.com']);
$session = openProof('POST', '/auth/mfa/verify', [
    'transaction_id' => $challenge['transaction_id'],
    'challenge_id' => $challenge['challenge_id'],
    'password' => 'correct horse battery staple',
]);
$profile = openProof('GET', '/account/profile');
```

### C++ / STL + libcurl

The C++ standard library has no HTTP client. This variant keeps payload,
response and error handling in STL types and uses libcurl only for transport.
Keep one cookie file (or one libcurl share/session abstraction) for every call
in a session-bound ceremony.

```cpp
#include <curl/curl.h>
#include <stdexcept>
#include <string>
#include <string_view>

static size_t append(char *data, size_t size, size_t count, void *output) {
    static_cast<std::string *>(output)->append(data, size * count);
    return size * count;
}

std::string openProof(std::string_view method, std::string_view path,
                      std::string_view json = {}) {
    CURL *curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");
    const std::string url = "https://identity.example.com" + std::string(path);
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.data());
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "openproof.cookies");
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "openproof.cookies");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    if (!json.empty()) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.data());
    curl_slist *headers = curl_slist_append(nullptr, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    const CURLcode result = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (result != CURLE_OK || status >= 400) throw std::runtime_error(response);
    return response;
}
```

### C++ / Qt 6

Keep one `QNetworkAccessManager` alive for the complete ceremony. It owns the
cookie jar and performs asynchronous requests. The working implementation is in
[`examples/qml-identity-client/identityclient.cpp`](../examples/qml-identity-client/identityclient.cpp).

```cpp
QNetworkAccessManager manager;
manager.setCookieJar(new QNetworkCookieJar(&manager));

QNetworkRequest request(
    QUrl(QStringLiteral("https://identity.example.com/auth/login")));
request.setHeader(QNetworkRequest::ContentTypeHeader,
                  QStringLiteral("application/json"));

const QByteArray payload = QJsonDocument(QJsonObject{
    {QStringLiteral("subject"), QStringLiteral("rider@example.com")}
}).toJson(QJsonDocument::Compact);

QNetworkReply *reply = manager.post(request, payload);
QObject::connect(reply, &QNetworkReply::finished, reply, [reply] {
    const int status = reply->attribute(
        QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QJsonObject challenge = QJsonDocument::fromJson(reply->readAll()).object();
    // Send transaction_id/challenge_id with the same manager to /auth/mfa/verify.
    qInfo() << status << challenge;
    reply->deleteLater();
});
```

### C++ / Boost Beast + Asio

Use Beast when the product already standardizes on Boost.Asio. Create a
validating `ssl::context`, resolve and connect with `beast::tcp_stream`, then
reuse the cookie returned by OpenProof across the complete ceremony. The
Developer Portal generates the complete request for the currently selected
endpoint, including method, target, headers and body.

```cpp
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

asio::io_context io;
ssl::context tls{ssl::context::tls_client};
tls.set_default_verify_paths();
beast::ssl_stream<beast::tcp_stream> stream{io, tls};
stream.set_verify_mode(ssl::verify_peer);
if (!SSL_set_tlsext_host_name(stream.native_handle(), "identity.example.com"))
    throw std::runtime_error("failed to configure TLS SNI");
tcp::resolver resolver{io};
beast::get_lowest_layer(stream).connect(
    resolver.resolve("identity.example.com", "443"));
stream.handshake(ssl::stream_base::client);

http::request<http::string_body> request{http::verb::get,
                                         "/account/profile", 11};
request.set(http::field::host, "identity.example.com");
request.set(http::field::cookie, "__Host-openproof-session=SESSION_COOKIE");
http::write(stream, request);
beast::flat_buffer buffer;
http::response<http::string_body> response;
http::read(stream, buffer, response);
if (response.result_int() >= 400) throw std::runtime_error(response.body());
```

## Connect a product with Authorization Code + PKCE

1. Create an application and a `browser`, `native` or `web` client.
2. Generate a high-entropy verifier, its SHA-256 base64url challenge, state and
   nonce.
3. Navigate the user to `/oauth/authorize` with exact registered redirect URI.
4. Validate callback `state` and `iss`.
5. Exchange the single-use code and saved verifier at `/oauth/token`.
6. Validate the RS256 ID Token with Discovery/JWKS and verify `iss`, `aud`,
   `exp`, `iat` and the original nonce.
7. Use the access token for `/oauth/userinfo` or the product API.

```bash
curl --fail-with-body "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=CLIENT_ID' \
  --data-urlencode 'code=AUTHORIZATION_CODE' \
  --data-urlencode 'redirect_uri=https://app.example.com/callback' \
  --data-urlencode 'code_verifier=PKCE_VERIFIER'
```

Refresh tokens rotate. Persist the new refresh token atomically and discard the
old value; replay revokes the token family. Public browser/native clients must
not embed a confidential client secret.

## Web3 / SIWE login

OpenProof supports Ethereum SIWE and Farcaster SIWF ceremonies when the operator
configures their EVM RPC adapters. For Ethereum, request the message first and
sign that exact message. Never submit a private key or seed phrase.

```javascript
const address = await signer.getAddress();
const start = await fetch(`${issuer}/auth/web3/start`, {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ provider: "ethereum-wallet", address })
}).then(response => response.json());

const signature = await signer.signMessage(start.message);
const result = await fetch(`${issuer}/auth/web3/complete`, {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: start.message, signature })
});
if (!result.ok) throw new Error(await result.text());
```

The start/complete cookie jar, message, nonce, domain and chain binding are part
of one ceremony. Do not construct a replacement message in the client.
Contract wallets are verified through ERC-1271 when configured.

For Farcaster AuthKit/QR, begin without an address. Pass the returned `nonce`,
`domain`, `uri`, `expires_at`, statement `Farcaster Auth`, chain ID `10` and
resource prefix to the Farcaster client. Preserve the same cookie jar and send
the resulting exact message/signature to completion:

```javascript
const siwf = await fetch(`${issuer}/auth/web3/start`, {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ provider: "farcaster" })
}).then(response => response.json());

// Configure @farcaster/auth-kit with siwf.domain, siwf.uri and siwf.nonce.
// The signed message must contain:
//   Farcaster Auth
//   Chain ID: 10
//   Resources:\n- farcaster://fid/<fid>
const completed = await fetch(`${issuer}/auth/web3/complete`, {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: authKitResult.message,
                         signature: authKitResult.signature })
});
```

For a wallet-controlled direct flow, start with all three fields:
`{"provider":"farcaster","address":"0x...","fid":"6841"}`. OpenProof
returns the canonical FIP-11 message and verifies either current IdRegistry
custody or an active KeyRegistry type-2 auth address. Authorization is checked
again after signature validation so a transfer or revocation fails closed.

To connect Farcaster to a user who is already signed in, use the same payloads
against `/account/connections/web3/start` and
`/account/connections/web3/complete`. The start requires the current OpenProof
session. The target canonical identity and connection purpose are retained in
the server-side transaction; successful completion returns the connected
provider/subject and deliberately does not mint a new login session.

Redirect providers use
`/account/connections/start?provider=google&return_to=%2F`. Inspect the current
set with `GET /account/connections`, and disconnect a non-final method with
`POST /account/connections/disconnect` and a `{provider, subject}` body.

For a native client, first call `POST /account/connections/handoff` with the
app's bearer token and `{"provider":"google","return_to":"/"}`, then open the
returned local `handoff_url` in the system browser. Never append the bearer or
session cookie to that URL. Its one-time ticket expires after two minutes and
the identity, provider and return path cannot be changed by the browser.

## Service-to-service token

Provision a `service` client and allowed resource/scope first. The client secret
belongs only in the backend secret store.

```bash
curl --fail-with-body "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=CLIENT_ID' \
  --data-urlencode 'client_secret=CLIENT_SECRET' \
  --data-urlencode 'scope=rides:read' \
  --data-urlencode 'resource=https://api.example.com/rides'
```

This returns an access token without a human session or refresh token. The
resource server must enforce its audience and scope.

## Error-handling rules

- Treat every non-2xx response as a failed operation and parse the documented
  error body; never infer success from an empty body.
- Preserve cookies only within the intended ceremony/session; do not manually
  recreate pre-auth cookies.
- Retry only idempotent/read operations or explicitly documented safe accepts.
  One-time proof, code and refresh operations are replay-sensitive.
- Use exact issuer and redirect URI comparison. Do not use prefix/substring
  matching.
- Never log passwords, cookie values, client secrets, refresh tokens,
  verification secrets or wallet signatures.
- Use HTTPS in production. Plain HTTP is accepted only by examples on exact
  loopback hosts.
