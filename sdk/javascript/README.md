# OpenProof JavaScript SDK

Browser-focused Authorization Code + PKCE client. It generates state, nonce and
PKCE material using WebCrypto and validates callback state/issuer before
producing a token request. For `openid` flows it then verifies the RS256 ID
Token against the issuer JWKS and fails closed on signature, key ambiguity,
issuer, audience/authorized-party, expiry, issued-at, not-before, nonce or
optional access-token-hash mismatch. Verified claims are returned as
`id_token_claims`. Public browser clients do not use a client secret.

Run the included smoke tests with `npm test`.
