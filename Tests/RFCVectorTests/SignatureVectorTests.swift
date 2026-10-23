import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import Testing

/// RFC 7520 §4 (JWS), RFC 7797 (unencoded payloads) and the RFC 8037 Ed25519 example, from the
/// JOSE cookbook.
@Suite("RFC vectors: signatures")
struct SignatureVectorTests {
    /// Examples with a single signer.
    static let singleSigner = [
        "jws/4_1.rsa_v15_signature.json",
        "jws/4_2.rsa-pss_signature.json",
        "jws/4_3.ecdsa_signature.json",
        "jws/4_4.hmac-sha2_integrity_protection.json",
        "jws/4_5.signature_with_detached_content.json",
        "jws/4_6.protecting_specific_header_fields.json",
        "jws/4_7.protecting_content_only.json",
        "rfc7797/hmac-sha2_b64_false.json",
        "curve25519/jws.json",
    ]

    /// The payload a serialization should be verified with: `nil` when it carries its own,
    /// the input payload when it is detached.
    private func detachedPayload(_ vector: Vector, serialization: JSONValue) throws -> Data? {
        let payload = Data(try vector.string("input", "payload").utf8)
        switch serialization {
        case .string(let compact):
            let segments = compact.split(separator: ".", omittingEmptySubsequences: false)
            guard segments.count == 3, segments[1].isEmpty else {
                return nil
            }
            return payload
        case .object(let members):
            guard members["payload"] == nil else {
                return nil
            }
            return payload
        default:
            throw VectorError(description: "\(vector.name): unexpected serialization \(serialization)")
        }
    }

    @Test("every serialization of each single-signer example verifies and yields the payload", arguments: singleSigner)
    func singleSignerVerifies(file: String) async throws {
        let vector = try Vector(file)
        let algorithm = try vector.string("input", "alg")
        let keys = VerificationKeys([
            try AnyVerifier(algorithm: algorithm, key: try vector.value("input", "key"))
        ])
        let payload = Data(try vector.string("input", "payload").utf8)

        var checked = 0
        for form in ["compact", "json", "json_flat"] where vector.has("output", form) {
            let serialization = try vector.value("output", form)
            let unverified: SimpleJWS.Unverified
            if case .string(let compact) = serialization {
                unverified = try SimpleJWS.Unverified(compact: compact)
            } else {
                unverified = try SimpleJWS.Unverified(json: try serialization.json)
            }
            let detached = try detachedPayload(vector, serialization: serialization)
            let verified = try await unverified.verify(with: keys, detachedPayload: detached)
            #expect(verified.payload == payload, "\(file) \(form)")
            #expect(verified.header.algorithm.rawValue == algorithm, "\(file) \(form)")
            checked += 1
        }
        #expect(checked >= 2, "\(file) has fewer serializations than expected")
    }

    @Test("an altered payload or signature is refused", arguments: singleSigner)
    func singleSignerRefusesTampering(file: String) async throws {
        let vector = try Vector(file)
        let algorithm = try vector.string("input", "alg")
        let keys = VerificationKeys([
            try AnyVerifier(algorithm: algorithm, key: try vector.value("input", "key"))
        ])
        guard case .object(var flattened) = try vector.value("output", "json_flat") else {
            throw VectorError(description: "\(file): json_flat is not an object")
        }
        var signature = try vector.bytes("signing", "sig")
        signature[0] ^= 0x01
        flattened["signature"] = .string(String(base64URLEncoding: signature))
        let tampered = try SimpleJWS.Unverified(json: try JSONValue.object(flattened).json)
        let detached = try detachedPayload(vector, serialization: .object(flattened))
        await #expect(throws: JWSError.self, "\(file)") {
            try await tampered.verify(with: keys, detachedPayload: detached)
        }
    }

    /// RSASSA-PKCS1-v1_5 and HMAC are deterministic, so signing the example's signing input must
    /// give exactly the example's signature.
    @Test("deterministic signatures are reproduced byte for byte")
    func reproducesDeterministicSignatures() async throws {
        for file in ["jws/4_1.rsa_v15_signature.json", "jws/4_4.hmac-sha2_integrity_protection.json"] {
            let vector = try Vector(file)
            let input = Data(try vector.string("signing", "sig-input").utf8)
            let expected = try vector.bytes("signing", "sig")
            let key = try vector.value("input", "key").json
            switch try vector.string("input", "alg") {
            case "RS256":
                guard case .rsa(let privateKey) = try PrivateJWK(json: key).key else {
                    throw VectorError(description: "\(file): not an RSA key")
                }
                let signature = try await RSASigner<RS256>(privateKey: privateKey).sign(input)
                #expect(signature.rawRepresentation == expected, "\(file)")
            case "HS256":
                let signature = try await HMACSigner<HS256>(jwk: try SymmetricJWK(json: key)).sign(input)
                #expect(signature.rawRepresentation == expected, "\(file)")
            default:
                Issue.record("\(file): unexpected algorithm")
            }
        }
        // RFC 7797 examples: the payload enters the signing input unencoded. Both files' own
        // `sig-input` is built from a different header from the one their output carries, so the
        // input is rebuilt from the output.
        for file in ["rfc7797/4.2.hmac-sha2_b64_false.json", "rfc7797/hmac-sha2_b64_false.json"] {
            let vector = try Vector(file)
            let input =
                try vector.string("output", "json_flat", "protected") + "."
                + (try vector.string("output", "json_flat", "payload"))
            let signature = try await HMACSigner<HS256>(
                jwk: try SymmetricJWK(json: try vector.value("input", "key").json)
            )
            .sign(Data(input.utf8))
            #expect(signature.rawRepresentation == (try vector.bytes("output", "json_flat", "signature")), "\(file)")
        }
    }

    /// The cookbook's RFC 7797 §4.2 example signs the header `{"alg":"HS256","b64":false}`,
    /// without `crit`, although its description lists `crit`. RFC 7797 §6 requires `b64` to be
    /// listed in `crit`, so the token is refused even though its signature is good (shown above).
    @Test("documented deviation: the RFC 7797 example whose header omits crit is refused")
    func unencodedWithoutCrit() throws {
        let vector = try Vector("rfc7797/4.2.hmac-sha2_b64_false.json")
        #expect(throws: JWSError.unencodedPayloadNotCritical) {
            try SimpleJWS.Unverified(json: try vector.value("output", "json_flat").json)
        }
    }

    @Test("RFC 7520 §4.8: each of three signatures verifies with its own key, and all three together")
    func multipleSignatures() async throws {
        let vector = try Vector("jws/4_8.multiple_signatures.json")
        let algorithms = try vector.value("input", "alg").elements.map { try $0.text }
        let keys = try vector.value("input", "key").elements
        #expect(algorithms == ["RS256", "ES512", "HS256"])
        let payload = Data(try vector.string("input", "payload").utf8)
        let jws = try SimpleJWS.Unverified(json: try vector.value("output", "json").json)
        #expect(jws.headers.count == 3)

        var all: [AnyVerifier] = []
        for (algorithm, key) in zip(algorithms, keys) {
            let verifier = try AnyVerifier(algorithm: try algorithm, key: key)
            all.append(verifier)
            let verified = try await jws.verify(with: VerificationKeys([verifier]))
            #expect(verified.payload == payload)
            #expect(verified.verifiedHeaders.map(\.algorithm.rawValue) == [algorithm])
        }
        let verified = try await jws.verify(with: VerificationKeys(all))
        #expect(verified.verifiedHeaders.map(\.algorithm.rawValue) == algorithms)
    }

    @Test("RFC 7520 §4.6 and §4.7: parameters from the unprotected header are read and flagged")
    func unprotectedHeaders() async throws {
        let specific = try Vector("jws/4_6.protecting_specific_header_fields.json")
        let partly = try SimpleJWS.Unverified(json: try specific.value("output", "json_flat").json)
        #expect(partly.header.unprotectedParameterNames == ["kid"])
        #expect(partly.header.keyID == "018c0ae5-4d9b-471b-bfd6-eef314bc7037")

        let contentOnly = try Vector("jws/4_7.protecting_content_only.json")
        let unprotected = try SimpleJWS.Unverified(json: try contentOnly.value("output", "json_flat").json)
        #expect(unprotected.header.unprotectedParameterNames == ["alg", "kid"])
    }
}
