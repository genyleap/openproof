# OpenProof Swift SDK

Apple-platform Authorization Code + PKCE client for iOS 17+ and macOS 14+.
Cryptographic material is generated with CryptoKit. The package intentionally
contains no embedded confidential client secret.

The SDK accepts HTTPS issuers, plus plain HTTP only for exact loopback hosts
(`localhost`, `127.0.0.1` or `[::1]`). Issuers containing credentials, a query
or a fragment are rejected. `handleCallback` validates both the one-time
`state` and the authorization-response `iss` value before returning the code.

Run the package tests with:

```bash
swift test
```
