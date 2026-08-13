package org.openproof.identity

import java.net.URLEncoder
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

data class OpenProofConfig(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scopes: List<String> = listOf("openid", "profile")
)

data class OpenProofAuthorization(
    val url: String,
    val verifier: String,
    val state: String,
    val nonce: String
)

data class OpenProofHttpRequest(
    val method: String,
    val url: String,
    val contentType: String? = null,
    val body: String? = null,
    val authorization: String? = null
)

object OpenProofIdentity {
    private val random = SecureRandom()

    private fun token(bytes: Int): String = ByteArray(bytes)
        .also(random::nextBytes)
        .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }

    private fun enc(value: String): String = URLEncoder
        .encode(value, StandardCharsets.UTF_8)
        .replace("+", "%20")

    private fun secureEquals(left: String, right: String): Boolean =
        MessageDigest.isEqual(left.toByteArray(), right.toByteArray())

    fun begin(config: OpenProofConfig): OpenProofAuthorization {
        require(config.clientId.isNotBlank() && config.redirectUri.isNotBlank())
        require(config.scopes.isNotEmpty())
        val issuer = config.issuer.trimEnd('/')
        val parsedIssuer = URI(issuer)
        val loopbackHttp = parsedIssuer.scheme.equals("http", ignoreCase = true)
            && parsedIssuer.host?.lowercase() in setOf("127.0.0.1", "::1", "localhost")
        require(parsedIssuer.scheme.equals("https", ignoreCase = true) || loopbackHttp)
        require(parsedIssuer.host?.isNotBlank() == true && parsedIssuer.rawUserInfo == null
            && parsedIssuer.rawQuery == null && parsedIssuer.rawFragment == null)
        val parsedRedirect = URI(config.redirectUri)
        require(!parsedRedirect.scheme.isNullOrBlank() && parsedRedirect.rawUserInfo == null)
        val verifier = token(32)
        val state = token(32)
        val nonce = token(24)
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()))
        val url = "$issuer/oauth/authorize?response_type=code&client_id=${enc(config.clientId)}" +
            "&redirect_uri=${enc(config.redirectUri)}" +
            "&scope=${enc(config.scopes.distinct().sorted().joinToString(" "))}" +
            "&code_challenge=${enc(challenge)}&code_challenge_method=S256" +
            "&state=${enc(state)}&nonce=${enc(nonce)}"
        return OpenProofAuthorization(url, verifier, state, nonce)
    }

    fun tokenRequest(
        code: String, returnedState: String, returnedIssuer: String,
        authorization: OpenProofAuthorization, config: OpenProofConfig
    ): OpenProofHttpRequest {
        require(code.isNotBlank() && secureEquals(returnedState, authorization.state))
        require(returnedIssuer == config.issuer.trimEnd('/'))
        val body = listOf(
            "grant_type" to "authorization_code", "client_id" to config.clientId,
            "code" to code, "redirect_uri" to config.redirectUri,
            "code_verifier" to authorization.verifier
        ).joinToString("&") { "${enc(it.first)}=${enc(it.second)}" }
        return OpenProofHttpRequest("POST", "${config.issuer.trimEnd('/')}/oauth/token",
            "application/x-www-form-urlencoded", body)
    }

    fun refreshRequest(refreshToken: String, config: OpenProofConfig): OpenProofHttpRequest {
        require(refreshToken.isNotBlank())
        val body = "grant_type=refresh_token&client_id=${enc(config.clientId)}" +
            "&refresh_token=${enc(refreshToken)}"
        return OpenProofHttpRequest("POST", "${config.issuer.trimEnd('/')}/oauth/token",
            "application/x-www-form-urlencoded", body)
    }

    fun userInfoRequest(accessToken: String, config: OpenProofConfig): OpenProofHttpRequest {
        require(accessToken.isNotBlank())
        return OpenProofHttpRequest("GET", "${config.issuer.trimEnd('/')}/oauth/userinfo",
            authorization = "Bearer $accessToken")
    }
}
