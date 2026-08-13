# OpenProof JavaScript SDK

Browser-focused Authorization Code + PKCE client. It generates state, nonce and
PKCE material using WebCrypto and validates callback state before producing a
token request. Public browser clients do not use a client secret.

Run the included smoke tests with `npm test`.
