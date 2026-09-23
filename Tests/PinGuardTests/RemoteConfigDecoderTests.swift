//
//  RemoteConfigDecoderTests.swift
//  PinGuard
//
//  Created by Çağatay Eğilmez on 23.09.2026.
//

import CryptoKit
import Foundation
@testable import PinGuard
import Testing

@Suite
struct RemoteConfigDecoderTests {

    private let secret = Data("secret".utf8)

    private var verifier: HMACRemoteConfigVerifier {
        HMACRemoteConfigVerifier { [secret] _ in secret }
    }

    private func signedBlob(_ json: String) -> RemoteConfigBlob {
        let payload = Data(json.utf8)
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: secret))
        return RemoteConfigBlob(payload: payload, signature: Data(mac), signatureType: .hmacSHA256(secretID: "id"))
    }

    @Test
    func decodesMinimalPayloadWithDefaults() throws {
        let json = """
        {"version":1,"policySet":{"policies":[\
        {"pattern":"*.example.com","policy":{"pins":[{"type":"spki","hash":"abc"}]}}]}}
        """
        let blob = signedBlob(json)
        let policySet = try RemoteConfigDecoder(verifier: verifier).decode(blob)
        let policy = PinningPolicy(pins: [Pin(type: .spki, hash: "abc")])
        let expected = PolicySet(policies: [HostPolicy(pattern: .wildcard("example.com"), policy: policy)])
        #expect(policySet == expected)
    }

    @Test
    func decodesEncodedPayloadRoundTrip() throws {
        let policySet = PolicySet(policies: [
            HostPolicy(pattern: .exact("api.example.com"),
                       policy: PinningPolicy(pins: [Pin(type: .certificate, hash: "x", role: .backup, scope: .root)],
                                             failStrategy: .permissive,
                                             requireSystemTrust: false,
                                             allowSystemTrustFallback: true))
        ], defaultPolicy: PinningPolicy(pins: []))
        let data = try JSONEncoder().encode(RemoteConfigPayload(policySet: policySet))
        let json = try #require(String(data: data, encoding: .utf8))
        let blob = signedBlob(json)
        let decoded = try RemoteConfigDecoder(verifier: verifier).decode(blob)
        #expect(decoded == policySet)
    }

    @Test
    func rejectsInvalidSignatureBeforeDecoding() {
        let blob = RemoteConfigBlob(payload: Data("{}".utf8),
                                    signature: Data("bad".utf8),
                                    signatureType: .hmacSHA256(secretID: "id"))
        #expect(throws: PinGuardError.invalidRemoteConfigSignature) {
            try RemoteConfigDecoder(verifier: verifier).decode(blob)
        }
    }

    @Test
    func rejectsMalformedPayload() {
        let decoder = RemoteConfigDecoder(verifier: verifier)
        let notJSON = signedBlob("not json")
        let missingPolicySet = signedBlob(#"{"version":1}"#)
        #expect(throws: PinGuardError.invalidRemoteConfigPayload) {
            try decoder.decode(notJSON)
        }
        #expect(throws: PinGuardError.invalidRemoteConfigPayload) {
            try decoder.decode(missingPolicySet)
        }
    }

    @Test
    func rejectsUnsupportedVersion() {
        let blob = signedBlob(#"{"version":2,"policySet":{"policies":[]}}"#)
        #expect(throws: PinGuardError.unsupportedRemoteConfigVersion(2)) {
            try RemoteConfigDecoder(verifier: verifier).decode(blob)
        }
    }
}
