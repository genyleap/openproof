import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import CryptoKit

public struct OpenProofConfiguration: Sendable {
    public let issuer: URL
    public let clientID: String
    public let redirectURI: URL
    public let scopes: [String]

    public init(issuer: URL, clientID: String, redirectURI: URL,
                scopes: [String] = ["openid", "profile"]) {
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scopes = Array(Set(scopes)).sorted()
    }
}

public struct OpenProofAuthorization: Sendable {
    public let url: URL
    public let verifier: String
    public let state: String
    public let nonce: String
}

public enum OpenProofError: Error, Sendable {
    case invalidConfiguration
    case invalidCallback
    case missingCredential
}

public enum OpenProofSDK {
    private static func random(_ count: Int) -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
        return Data(bytes).base64URLEncoded
    }

    public static func begin(_ config: OpenProofConfiguration) throws -> OpenProofAuthorization {
        let scheme = config.issuer.scheme?.lowercased()
        let host = config.issuer.host?.lowercased()
        let loopbackHTTP = scheme == "http"
            && (host == "127.0.0.1" || host == "::1" || host == "localhost")
        guard (scheme == "https" || loopbackHTTP),
              config.issuer.user == nil, config.issuer.password == nil,
              config.issuer.query == nil, config.issuer.fragment == nil,
              config.redirectURI.scheme != nil,
              config.redirectURI.user == nil, config.redirectURI.password == nil,
              !config.clientID.isEmpty, !config.scopes.isEmpty else {
            throw OpenProofError.invalidConfiguration
        }
        let verifier = random(32)
        let state = random(32)
        let nonce = random(24)
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncoded
        var parts = URLComponents(
            url: config.issuer.appending(path: "oauth/authorize"),
            resolvingAgainstBaseURL: false)!
        parts.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: config.clientID),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: config.scopes.joined(separator: " ")),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
        ]
        guard let url = parts.url else { throw OpenProofError.invalidConfiguration }
        return OpenProofAuthorization(url: url, verifier: verifier, state: state, nonce: nonce)
    }

    public static func tokenRequest(
        code: String, returnedState: String, returnedIssuer: String,
        authorization: OpenProofAuthorization,
        config: OpenProofConfiguration) throws -> URLRequest {
        guard !code.isEmpty,
              constantTimeEqual(returnedState, authorization.state),
              returnedIssuer == config.issuer.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) else {
            throw OpenProofError.invalidCallback
        }
        let values = [
            "grant_type": "authorization_code", "client_id": config.clientID,
            "code": code, "redirect_uri": config.redirectURI.absoluteString,
            "code_verifier": authorization.verifier,
        ]
        return formRequest(url: config.issuer.appending(path: "oauth/token"), values: values)
    }

    public static func refreshRequest(
        refreshToken: String, config: OpenProofConfiguration) throws -> URLRequest {
        guard !refreshToken.isEmpty else { throw OpenProofError.missingCredential }
        return formRequest(url: config.issuer.appending(path: "oauth/token"), values: [
            "grant_type": "refresh_token", "client_id": config.clientID,
            "refresh_token": refreshToken,
        ])
    }

    public static func userInfoRequest(
        accessToken: String, config: OpenProofConfiguration) throws -> URLRequest {
        guard !accessToken.isEmpty else { throw OpenProofError.missingCredential }
        var request = URLRequest(url: config.issuer.appending(path: "oauth/userinfo"))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return request
    }

    private static func formRequest(url: URL, values: [String: String]) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = values.sorted { $0.key < $1.key }
            .map { "\($0.key.formEncoded)=\($0.value.formEncoded)" }
            .joined(separator: "&").data(using: .utf8)
        return request
    }

    private static func constantTimeEqual(_ left: String, _ right: String) -> Bool {
        let a = Array(left.utf8)
        let b = Array(right.utf8)
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }
}

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private extension String {
    var formEncoded: String {
        addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(
            CharacterSet(charactersIn: "-._~"))) ?? ""
    }
}
