import Foundation
import Testing
@testable import OpenProof

@Test func authorizationUsesPkceAndRejectsIssuerLookalikes() throws {
    let config = OpenProofConfiguration(
        issuer: URL(string: "https://identity.example.test")!,
        clientID: "mobile-client",
        redirectURI: URL(string: "com.example.app:/oauth/callback")!)
    let authorization = try OpenProofSDK.begin(config)
    let components = URLComponents(url: authorization.url, resolvingAgainstBaseURL: false)
    let values = Dictionary(uniqueKeysWithValues:
        (components?.queryItems ?? []).map { ($0.name, $0.value ?? "") })
    #expect(values["code_challenge_method"] == "S256")
    #expect(values["state"] == authorization.state)
    #expect(values["nonce"] == authorization.nonce)

    for issuer in [
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example",
        "https://user:password@identity.example.test",
        "https://identity.example.test?issuer=other",
    ] {
        let invalid = OpenProofConfiguration(
            issuer: URL(string: issuer)!, clientID: "mobile-client",
            redirectURI: URL(string: "com.example.app:/oauth/callback")!)
        #expect(throws: OpenProofError.self) {
            _ = try OpenProofSDK.begin(invalid)
        }
    }
}
