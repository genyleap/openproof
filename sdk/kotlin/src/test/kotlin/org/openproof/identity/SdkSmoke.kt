package org.openproof.identity

fun main() {
    val config = OpenProofConfig(
        issuer = "https://identity.example.test",
        clientId = "mobile-client",
        redirectUri = "com.example.app:/oauth/callback",
        scopes = listOf("profile", "openid", "profile")
    )
    val authorization = OpenProofIdentity.begin(config)
    check(authorization.url.startsWith("https://identity.example.test/oauth/authorize?"))
    check("code_challenge_method=S256" in authorization.url)
    check("scope=openid%20profile" in authorization.url)

    val token = OpenProofIdentity.tokenRequest(
        code = "authorization-code",
        returnedState = authorization.state,
        returnedIssuer = "https://identity.example.test",
        authorization = authorization,
        config = config
    )
    check(token.method == "POST")
    check(token.url.endsWith("/oauth/token"))
    check(token.body?.contains("code_verifier=") == true)
    check(OpenProofIdentity.userInfoRequest("access-token", config).authorization
        == "Bearer access-token")

    for (invalidIssuer in listOf(
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example",
        "https://user:password@identity.example.test",
        "https://identity.example.test?issuer=other"
    )) {
        check(runCatching {
            OpenProofIdentity.begin(config.copy(issuer = invalidIssuer))
        }.isFailure)
    }
}
