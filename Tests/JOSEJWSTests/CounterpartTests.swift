import Foundation
import JOSECore
import JOSEJWK
import TestSupport
import Testing

@testable import JOSEJWS

private struct CompactFixture: Decodable {
    struct Case: Decodable {
        struct Jose: Decodable {
            let accepted: Bool
            let payload: String?
        }
        let name: String
        let token: String
        let jose: Jose
    }
    let jwk: String
    let cases: [Case]
}

@Suite("Against jose")
struct CounterpartTests {
    /// Tokens jose 6.2.12 accepts and this package refuses, with the error case expected here.
    ///
    /// - Duplicate `alg`: jose (`JSON.parse`) takes the last value. RFC 7515 §4 allows that or
    ///   rejection; this package rejects, because Foundation would take the first.
    /// - Padding and a trailing newline: jose's base64url decoder tolerates both. RFC 7515 §2
    ///   defines the encoding as unpadded, and neither can come from an encoder.
    /// - `b64` without `crit`: jose ignores `b64` unless it is critical. RFC 7797 §6 requires it
    ///   to be critical, and guessing which payload encoding was meant is not safe.
    /// - `kid`/`typ` as numbers: RFC 7515 §4.1.4 and §4.1.9 define both as strings.
    static let stricterThanJose: [String: String] = [
        "header has duplicate alg, first is none": "invalidHeaderStructure",
        "signature segment padded": "paddingNotAllowed",
        "trailing newline": "invalidBase64URL",
        "b64 false without crit": "unencodedPayloadNotCritical",
        "kid is a number": "headerParameterWrongType",
        "typ is a number": "headerParameterWrongType",
    ]

    @Test("compact JWSs: accepts and rejects what jose does, apart from the documented stricter cases")
    func compactVerdictsAgree() async throws {
        let fixture = try CompactFixture(fixture: "compact-verification", in: .module)
        let keys = VerificationKeys([try AnyVerifier(algorithm: "ES256", jwk: fixture.jwk)])
        var accepted = 0
        var rejected = 0
        var stricter = 0
        for testCase in fixture.cases {
            let label = Comment(rawValue: testCase.name)
            let outcome: Result<Data, JWSError>
            do {
                outcome = .success(try await SimpleJWS.Unverified(compact: testCase.token).verify(with: keys).payload)
            } catch {
                outcome = .failure(error)
            }

            if let expectedCase = Self.stricterThanJose[testCase.name] {
                #expect(testCase.jose.accepted, "listed as a deviation, but jose rejects it too: \(testCase.name)")
                guard case .failure(let error) = outcome else {
                    Issue.record("accepted: \(testCase.name)")
                    continue
                }
                #expect(caseName(error) == expectedCase, label)
                stricter += 1
            } else if testCase.jose.accepted {
                let expected = try Data(hex: try #require(testCase.jose.payload))
                guard case .success(let payload) = outcome else {
                    Issue.record("rejected although jose accepts: \(testCase.name): \(outcome)")
                    continue
                }
                #expect(payload == expected, label)
                accepted += 1
            } else {
                guard case .failure = outcome else {
                    Issue.record("accepted although jose rejects: \(testCase.name)")
                    continue
                }
                rejected += 1
            }
        }
        #expect(accepted >= 4)
        #expect(rejected >= 30)
        #expect(stricter == Self.stricterThanJose.count)
    }

    @Test("the well-known forgeries fail for the reason they should")
    func forgeriesFailSpecifically() async throws {
        let fixture = try CompactFixture(fixture: "compact-verification", in: .module)
        let keys = VerificationKeys([try AnyVerifier(algorithm: "ES256", jwk: fixture.jwk)])
        func outcome(_ name: String) async throws -> String? {
            let token = try #require(fixture.cases.first { $0.name == name }).token
            return await thrownCase { () async throws(JWSError) in
                try await SimpleJWS.Unverified(compact: token).verify(with: keys)
            }
        }
        #expect(try await outcome("valid (positive control)") == nil)
        #expect(try await outcome("alg none, no signature") == "noVerifierForAlgorithm")
        #expect(try await outcome("alg none, original signature") == "noVerifierForAlgorithm")
        #expect(try await outcome("alg None (mixed case)") == "noVerifierForAlgorithm")
        #expect(try await outcome("alg es256 (lower case)") == "noVerifierForAlgorithm")
        #expect(try await outcome("alg HS256 keyed with the public key") == "noVerifierForAlgorithm")
        #expect(try await outcome("alg ES384 with a P-256 signature") == "noVerifierForAlgorithm")
        #expect(try await outcome("payload altered") == "signatureInvalid")
        #expect(try await outcome("signature altered") == "signatureInvalid")
        #expect(try await outcome("signed by a different key") == "signatureInvalid")
        #expect(try await outcome("header altered") == "noVerifierForKeyID")
        #expect(try await outcome("signature in DER") == "malformedSignature")
        #expect(try await outcome("signature truncated") == "malformedSignature")
        #expect(try await outcome("signature empty") == "malformedSignature")
        #expect(try await outcome("alg missing") == "missingAlgorithm")
        #expect(try await outcome("alg is a number") == "headerParameterWrongType")
        #expect(try await outcome("two segments") == "invalidCompactSerialization")
        #expect(try await outcome("four segments") == "invalidCompactSerialization")
        #expect(try await outcome("header empty") == "missingProtectedHeader")
        #expect(try await outcome("header is not JSON") == "invalidHeaderStructure")
        #expect(try await outcome("header is a JSON array") == "invalidHeaderStructure")
        #expect(try await outcome("header has duplicate alg") == "invalidHeaderStructure")
        #expect(try await outcome("header segment padded") == "paddingNotAllowed")
        #expect(try await outcome("payload segment padded") == "paddingNotAllowed")
        #expect(try await outcome("header segment in standard base64") == "invalidBase64URL")
        #expect(try await outcome("leading space") == "invalidBase64URL")
        #expect(try await outcome("crit names an unknown extension") == "unsupportedCriticalParameter")
        #expect(try await outcome("crit is empty") == "invalidCritical")
        #expect(try await outcome("crit is not an array") == "headerParameterWrongType")
        #expect(try await outcome("crit names alg") == "invalidCritical")
        #expect(try await outcome("crit names a parameter that is absent") == "invalidCritical")
        #expect(try await outcome("crit names b64 but b64 is absent") == "invalidCritical")
        #expect(try await outcome("b64 is a string") == "headerParameterWrongType")
    }

    @Test("every serialization jose produces verifies, for every algorithm")
    func validTokens() async throws {
        let fixture = try ValidFixture(fixture: "valid", in: .module)
        #expect(
            fixture.tokens.map(\.algorithm) == [
                "ES256", "ES384", "ES512", "Ed25519", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                "HS256", "HS384", "HS512",
            ]
        )
        for token in fixture.tokens {
            let label = Comment(rawValue: token.algorithm)
            let keys = VerificationKeys([try AnyVerifier(algorithm: token.algorithm, jwk: token.jwk)])
            let payload = try Data(hex: token.payload)

            // Compact, with a custom header type reading the extension parameter jose wrote.
            let compact = try JWS<ExampleHeader>.Unverified(compact: token.compact)
            let verified = try await compact.verify(with: keys)
            #expect(verified.payload == payload, label)
            #expect(verified.header.algorithm.rawValue == token.algorithm, label)
            #expect(verified.header.keyID == KeyID(rawValue: "\(token.algorithm)-key"), label)
            #expect(verified.header.type == MediaType(rawValue: "application/example+jws"), label)
            #expect(verified.header.custom.level == 7, label)
            #expect(verified.header.rawParameters["urn:example:level"] == 7, label)
            #expect(verified.header.unprotectedParameterNames.isEmpty, label)
            #expect(verified.header.isPayloadBase64URLEncoded, label)

            // Compact with the payload removed and supplied separately.
            let detached = try SimpleJWS.Unverified(compact: token.compactDetached)
            #expect(try await detached.verify(with: keys, detachedPayload: payload).payload == payload, label)
            #expect(
                await thrownCase { () async throws(JWSError) in
                    try await detached.verify(with: keys, detachedPayload: payload + [0])
                }
                    == "signatureInvalid",
                label
            )

            // Flattened JSON, where jose put `kid` in the unprotected header.
            let flattened = try SimpleJWS.Unverified(json: Data(token.flattened.utf8))
            let flattenedVerified = try await flattened.verify(with: keys)
            #expect(flattenedVerified.payload == payload, label)
            #expect(flattenedVerified.header.keyID == KeyID(rawValue: "\(token.algorithm)-key"), label)
            #expect(
                flattenedVerified.header.unprotectedParameterNames == ["kid", "urn:example:note"],
                label
            )

            // RFC 7797 unencoded payload, carried and detached.
            let unencodedPayload = try Data(hex: token.unencodedPayload)
            let unencoded = try SimpleJWS.Unverified(json: Data(token.unencodedFlattened.utf8))
            let unencodedVerified = try await unencoded.verify(with: keys)
            #expect(unencodedVerified.payload == unencodedPayload, label)
            #expect(!unencodedVerified.header.isPayloadBase64URLEncoded, label)
            #expect(unencodedVerified.header.critical == ["b64"], label)

            let unencodedDetached = try SimpleJWS.Unverified(json: Data(token.unencodedFlattenedDetached.utf8))
            #expect(
                try await unencodedDetached.verify(with: keys, detachedPayload: unencodedPayload).payload
                    == unencodedPayload,
                label
            )
            #expect(
                await thrownCase { () async throws(JWSError) in try await unencodedDetached.verify(with: keys) }
                    == "payloadMissing",
                label
            )
        }
    }

    @Test("a general-serialization JWS from jose verifies with any one of its signers' keys")
    func generalSerialization() async throws {
        let general = try ValidFixture(fixture: "valid", in: .module).general
        let payload = try Data(hex: general.payload)
        let jws = try SimpleJWS.Unverified(json: Data(general.json.utf8))
        #expect(jws.headers.count == general.signers.count)
        #expect(general.signers.count == 11)

        var all: [AnyVerifier] = []
        for signer in general.signers {
            let verifier = try AnyVerifier(algorithm: signer.algorithm, jwk: signer.jwk)
            all.append(verifier)
            let verified = try await jws.verify(with: VerificationKeys([verifier]))
            #expect(verified.payload == payload)
            #expect(verified.verifiedHeaders.count == 1)
            #expect(verified.header.algorithm.rawValue == signer.algorithm)
        }
        #expect(try await jws.verify(with: VerificationKeys(all)).verifiedHeaders.count == general.signers.count)

        // A key that belongs to none of the signers verifies nothing.
        let stranger = AnyVerifier(try ECDSAVerifier(publicKey: (try ECPrivateKey<P256Curve>()).publicKey))
        do {
            _ = try await jws.verify(with: VerificationKeys([stranger]))
            Issue.record("verified with an unrelated key")
        } catch {
            guard case .noSignatureVerified(let reasons) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(reasons.count == general.signers.count)
        }
    }
}
