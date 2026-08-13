# OpenProof Kotlin SDK

Kotlin/JVM/Android Authorization Code + PKCE client. The SDK builds protocol
requests and validates both the one-time state and authorization-response
issuer while leaving HTTP execution to the application's networking stack.

The SDK accepts HTTPS issuers, plus plain HTTP only for exact loopback hosts
(`localhost`, `127.0.0.1` or `[::1]`). Issuers containing credentials, a query
or a fragment are rejected; hostname lookalikes such as `localhost.evil` are
not treated as loopback.

Build it with the repository-pinned Gradle Wrapper; a machine-wide Kotlin
compiler or Kotlin Gradle plugin download is not required. The build uses the
compiler embedded in the checksummed Gradle distribution:

```bash
./gradlew build
```
