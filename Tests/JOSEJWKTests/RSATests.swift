import Foundation
import JOSECore
import Testing

@testable import JOSEJWK

@Suite("RSA")
struct RSATests {
    private func verify<Algorithm: RSASignatureAlgorithm>(
        _ algorithm: Algorithm.Type,
        jwk: JWK,
        testCase: KeysFixture.RSASignatureCase
    ) async throws {
        let verifier = try RSAVerifier<Algorithm>(jwk: jwk)
        let message = try Data(hex: testCase.message)
        try await verifier.verify(try Signature(rawRepresentation: try Data(hex: testCase.signature)), for: message)
        await #expect(throws: VerificationError.self, "\(testCase.algorithm) tampered") {
            try await verifier.verify(
                try Signature(rawRepresentation: try Data(hex: testCase.tamperedSignature)),
                for: message
            )
        }
        if let otherSalt = testCase.nonStandardSaltSignature {
            await #expect(
                throws: VerificationError.self,
                "\(testCase.algorithm) salt length other than the digest length"
            ) {
                try await verifier.verify(try Signature(rawRepresentation: try Data(hex: otherSalt)), for: message)
            }
        }
        #expect(testCase.algorithm.hasPrefix("PS") == (testCase.nonStandardSaltSignature != nil))
        await #expect(throws: VerificationError.self, "\(testCase.algorithm) other message") {
            try await verifier.verify(
                try Signature(rawRepresentation: try Data(hex: testCase.signature)),
                for: message + [0]
            )
        }
    }

    @Test("signatures made by OpenSSL verify under all six algorithms, and tampered ones do not")
    func counterpartSignatures() async throws {
        let fixture = try KeysFixture.load()
        var checked = 0
        for key in fixture.rsaKeys {
            let jwk = try JWK(json: try JSONEncoder().encode(key.publicJwk))
            #expect(key.signatures.map(\.algorithm) == ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
            for testCase in key.signatures {
                switch testCase.algorithm {
                case "RS256":
                    try await verify(RS256.self, jwk: jwk, testCase: testCase)
                case "RS384":
                    try await verify(RS384.self, jwk: jwk, testCase: testCase)
                case "RS512":
                    try await verify(RS512.self, jwk: jwk, testCase: testCase)
                case "PS256":
                    try await verify(PS256.self, jwk: jwk, testCase: testCase)
                case "PS384":
                    try await verify(PS384.self, jwk: jwk, testCase: testCase)
                case "PS512":
                    try await verify(PS512.self, jwk: jwk, testCase: testCase)
                default:
                    Issue.record("unexpected algorithm \(testCase.algorithm)")
                }
                checked += 1
            }
        }
        #expect(checked == 24)
    }

    @Test("a signature is only valid under the algorithm it was made with")
    func algorithmsAreNotInterchangeable() async throws {
        let key = try #require(try KeysFixture.load().rsaKeys.first)
        let jwk = try JWK(json: try JSONEncoder().encode(key.publicJwk))
        let rs256 = try #require(key.signatures.first { $0.algorithm == "RS256" })
        let ps256 = try #require(key.signatures.first { $0.algorithm == "PS256" })
        let rs256Message = try Data(hex: rs256.message)
        let rs256Signature = try Data(hex: rs256.signature)

        // Positive control.
        try await RSAVerifier<RS256>(jwk: jwk).verify(
            try Signature(rawRepresentation: rs256Signature),
            for: rs256Message
        )
        // Same padding, different hash.
        await #expect(throws: VerificationError.self) {
            try await RSAVerifier<RS384>(jwk: jwk).verify(
                try Signature(rawRepresentation: rs256Signature),
                for: rs256Message
            )
        }
        // Same hash, different padding, in both directions.
        await #expect(throws: VerificationError.self) {
            try await RSAVerifier<PS256>(jwk: jwk).verify(
                try Signature(rawRepresentation: rs256Signature),
                for: rs256Message
            )
        }
        await #expect(throws: VerificationError.self) {
            try await RSAVerifier<RS256>(jwk: jwk).verify(
                try Signature(rawRepresentation: try Data(hex: ps256.signature)),
                for: try Data(hex: ps256.message)
            )
        }
    }

    @Test("thumbprints and thumbprint URIs match jose")
    func thumbprints() throws {
        let hashes: [(String, JWKThumbprint.HashAlgorithm)] = [
            ("sha256", .sha256), ("sha384", .sha384), ("sha512", .sha512),
        ]
        for key in try KeysFixture.load().rsaKeys {
            let jwk = try JWK(json: try JSONEncoder().encode(key.publicJwk))
            for (name, hash) in hashes {
                let thumbprint = try jwk.thumbprint(using: hash)
                #expect(thumbprint.base64URLEncoded == key.thumbprints[name])
                #expect(thumbprint.uri == key.thumbprintUris[name])
            }
        }
        let key = try RSAPrivateKey().publicKey
        let n = String(base64URLEncoding: key.modulus)
        let e = String(base64URLEncoding: key.exponent)
        #expect(key.canonicalJSON == #"{"e":"\#(e)","kty":"RSA","n":"\#(n)"}"#)
    }

    @Test("PKCS#1 DER produced here is byte-identical to OpenSSL's, and OpenSSL's parses back")
    func pkcs1MatchesCounterpart() throws {
        for key in try KeysFixture.load().rsaKeys {
            let publicDER = try Data(hex: key.publicPkcs1)
            let privateDER = try Data(hex: key.privatePkcs1)

            guard case .rsa(let publicKey) = try JWK(json: try JSONEncoder().encode(key.publicJwk)).key else {
                Issue.record("not an RSA key")
                continue
            }
            #expect(publicKey.pkcs1DERRepresentation == publicDER)
            #expect(try RSAPublicKey(pkcs1DERRepresentation: publicDER) == publicKey)

            guard case .rsa(let privateKey) = try PrivateJWK(json: try JSONEncoder().encode(key.privateJwk)).key else {
                Issue.record("not an RSA private key")
                continue
            }
            #expect(privateKey.pkcs1DERRepresentation == privateDER)
            let reparsed = try RSAPrivateKey(pkcs1DERRepresentation: privateDER)
            #expect(reparsed.publicKey == publicKey)
            #expect(reparsed.pkcs1DERRepresentation == privateDER)
        }
    }

    @Test("private JWKs from jose parse, re-export identically, and sign what their public JWK verifies")
    func privateJWKs() async throws {
        for key in try KeysFixture.load().rsaKeys {
            let privateJWK = try PrivateJWK(json: try JSONEncoder().encode(key.privateJwk))
            let exported = try JSONDecoder().decode([String: String].self, from: try privateJWK.jsonRepresentation())
            #expect(exported == key.privateJwk)
            let publicExport = try JSONDecoder().decode(
                [String: String].self,
                from: try privateJWK.publicJWK.jsonRepresentation()
            )
            #expect(publicExport == key.publicJwk)

            guard case .rsa(let privateKey) = privateJWK.key else {
                Issue.record("not an RSA private key")
                continue
            }
            let message = Data("signed in Swift".utf8)
            let publicJWK = try JWK(json: try JSONEncoder().encode(key.publicJwk))

            let pkcs1 = try await RSASigner<RS256>(privateKey: privateKey, keyID: "k").sign(message)
            #expect(pkcs1.rawRepresentation.count == key.bitCount / 8)
            try await RSAVerifier<RS256>(jwk: publicJWK).verify(pkcs1, for: message)

            let pss = try await RSASigner<PS384>(privateKey: privateKey).sign(message)
            #expect(pss.rawRepresentation.count == key.bitCount / 8)
            try await RSAVerifier<PS384>(jwk: publicJWK).verify(pss, for: message)
            // PSS is randomised; PKCS#1 v1.5 is not.
            let pssAgain = try await RSASigner<PS384>(privateKey: privateKey).sign(message)
            #expect(pssAgain.rawRepresentation != pss.rawRepresentation)
            let pkcs1Again = try await RSASigner<RS256>(privateKey: privateKey).sign(message)
            #expect(pkcs1Again.rawRepresentation == pkcs1.rawRepresentation)
        }
    }

    @Test("a private JWK whose private values belong to a different key is refused")
    func mismatchedPrivateKey() throws {
        let keys = try KeysFixture.load().rsaKeys
        var mixed = keys[1].privateJwk
        mixed["n"] = keys[0].privateJwk["n"]
        // Positive control.
        _ = try PrivateJWK(json: try JSONEncoder().encode(keys[1].privateJwk))
        #expect(throws: JWKError.self) {
            try PrivateJWK(json: try JSONEncoder().encode(mixed))
        }
    }

    @Test("a private JWK whose public exponent is not the one its private values were made for is refused")
    func privateValuesForAnotherExponent() throws {
        // Every private value is internally consistent, so the key can sign; only the claimed
        // public exponent is wrong (3 instead of 65537), so nothing it signs verifies under the
        // public key it would publish.
        let key = try #require(try KeysFixture.load().rsaKeys.first)
        #expect(key.privateJwk["e"] == "AQAB")
        var wrongExponent = key.privateJwk
        wrongExponent["e"] = "Aw"
        _ = try PrivateJWK(json: try JSONEncoder().encode(key.privateJwk))
        // Both platform implementations refuse this themselves, at different points: BoringSSL
        // when the key is imported, Security.framework when it is first asked to sign (it checks
        // its own result against `e`). Either way it surfaces from the trial signature made
        // while the key is being read, so which error comes back depends on the platform.
        #expect(throws: JWKError.self) {
            try PrivateJWK(json: try JSONEncoder().encode(wrongExponent))
        }
    }

    @Test("a PKCS#1 private key marked as multi-prime is refused")
    func multiPrimeDER() throws {
        let key = try #require(try KeysFixture.load().rsaKeys.first)
        var der = try Data(hex: key.privatePkcs1)
        _ = try RSAPrivateKey(pkcs1DERRepresentation: der)
        // 30 82 LL LL | 02 01 00 (version) ...
        #expect(Array(der[4..<7]) == [0x02, 0x01, 0x00])
        der[6] = 0x01
        #expect(throws: JWKError.unsupportedRSAPrivateKey(reason: "PKCS#1 version 1 (multi-prime)")) {
            try RSAPrivateKey(pkcs1DERRepresentation: der)
        }
    }

    // Pins a platform difference rather than a guarantee: see the comment in
    // `RSAPrivateKey.init(components:)`. If Security.framework starts checking `d`, the Apple
    // branch here will fail and the comment must be updated.
    @Test("a private JWK whose d has been altered: refused by BoringSSL, accepted by Security.framework")
    func alteredPrivateExponent() throws {
        let key = try #require(try KeysFixture.load().rsaKeys.first)
        var altered = key.privateJwk
        var d = try Data(base64URLEncoded: try #require(altered["d"]))
        d[d.count / 2] ^= 0x01
        altered["d"] = String(base64URLEncoding: d)
        _ = try PrivateJWK(json: try JSONEncoder().encode(key.privateJwk))
        #if canImport(Security)
            _ = try PrivateJWK(json: try JSONEncoder().encode(altered))
        #else
            #expect(throws: JWKError.self) {
                try PrivateJWK(json: try JSONEncoder().encode(altered))
            }
        #endif
    }

    @Test("an RSA key operation failure is a key-operation error, not an invalid-key error")
    func operationFailureIsNotAKeyError() {
        let failure: any Error = RSAOperationError(description: "x")
        #expect(!(failure is JWKError))
        #expect(String(describing: failure) == "x")
    }

    @Test("private JWKs without CRT values, or with extra primes, are refused with a reason")
    func unsupportedPrivateForms() throws {
        let key = try #require(try KeysFixture.load().rsaKeys.first)
        for member in ["p", "q", "dp", "dq", "qi"] {
            var incomplete = key.privateJwk
            incomplete[member] = nil
            #expect(throws: JWKError.unsupportedRSAPrivateKey(reason: "the CRT value \"\(member)\" is missing")) {
                try PrivateJWK(json: try JSONEncoder().encode(incomplete))
            }
        }
        var noD = key.privateJwk
        noD["d"] = nil
        #expect(throws: JWKError.missingMember(name: "d", keyType: "RSA")) {
            try PrivateJWK(json: try JSONEncoder().encode(noD))
        }
        var object = try JSONDecoder().decode(
            [String: JSONValue].self,
            from: try JSONEncoder().encode(key.privateJwk)
        )
        object["oth"] = [["r": "AQ", "d": "AQ", "t": "AQ"]]
        #expect(throws: JWKError.self) {
            try PrivateJWK(json: try JSONEncoder().encode(object))
        }
    }

    @Test("a public RSA JWK carrying any private member is refused")
    func publicJWKRejectsPrivateMembers() throws {
        let key = try #require(try KeysFixture.load().rsaKeys.first)
        _ = try JWK(json: try JSONEncoder().encode(key.publicJwk))
        for member in ["d", "p", "q", "dp", "dq", "qi"] {
            var jwk = key.publicJwk
            jwk[member] = key.privateJwk[member]
            #expect(throws: JWKError.privateMemberInPublicKey(member: member, keyType: "RSA")) {
                try JWK(json: try JSONEncoder().encode(jwk))
            }
        }
        var object = try JSONDecoder().decode([String: JSONValue].self, from: try JSONEncoder().encode(key.publicJwk))
        object["oth"] = []
        #expect(throws: JWKError.privateMemberInPublicKey(member: "oth", keyType: "RSA")) {
            try JWK(json: try JSONEncoder().encode(object))
        }
    }

    @Test("key size limits are enforced when building and when generating")
    func keySizeLimits() throws {
        // 2047 bits: top byte 0x7F of 256 bytes.
        var modulus = Data(repeating: 0xFF, count: 256)
        modulus[0] = 0x7F
        #expect(throws: JWKError.rsaKeyTooSmall(bitCount: 2047, minimum: 2048)) {
            try RSAPublicKey(modulus: modulus, exponent: Data([0x01, 0x00, 0x01]))
        }
        #expect(throws: JWKError.rsaKeyTooLarge(bitCount: 16392, maximum: 16384)) {
            try RSAPublicKey(modulus: Data(repeating: 0xFF, count: 2049), exponent: Data([0x01, 0x00, 0x01]))
        }
        #expect(throws: JWKError.rsaKeyTooSmall(bitCount: 1024, minimum: 2048)) {
            try RSAPrivateKey(bitCount: 1024)
        }
        #expect(throws: JWKError.rsaKeyTooLarge(bitCount: 32768, maximum: 16384)) {
            try RSAPrivateKey(bitCount: 32768)
        }
        #expect(throws: JWKError.nonMinimalInteger(member: "n")) {
            try RSAPublicKey(modulus: Data([0x00]) + Data(repeating: 0xFF, count: 256), exponent: Data([0x03]))
        }
        #expect(throws: JWKError.invalidRSAKey(reason: "\"e\" is empty")) {
            try RSAPublicKey(modulus: Data(repeating: 0xFF, count: 256), exponent: Data())
        }
        // RFC 8017: e < n. An exponent equal to, or longer than, the modulus is refused.
        let modulus256 = Data(repeating: 0xFF, count: 256)
        #expect(throws: JWKError.invalidRSAKey(reason: "the public exponent is not smaller than the modulus")) {
            try RSAPublicKey(modulus: modulus256, exponent: modulus256)
        }
        #expect(throws: JWKError.invalidRSAKey(reason: "the public exponent is not smaller than the modulus")) {
            try RSAPublicKey(modulus: modulus256, exponent: Data([0x01]) + modulus256)
        }
    }

    @Test("a generated key has the requested size and signs and verifies")
    func generation() async throws {
        let key = try RSAPrivateKey(bitCount: 2048)
        #expect(key.publicKey.bitCount == 2048)
        #expect(key.publicKey.exponent == Data([0x01, 0x00, 0x01]))
        let message = Data("generated".utf8)
        let signature = try await RSASigner<PS256>(privateKey: key).sign(message)
        try await RSAVerifier<PS256>(publicKey: key.publicKey).verify(signature, for: message)

        let other = try RSAPrivateKey()
        #expect(other.publicKey != key.publicKey)
        await #expect(throws: VerificationError.self) {
            try await RSAVerifier<PS256>(publicKey: other.publicKey).verify(signature, for: message)
        }

        let roundTripped = try PrivateJWK(json: try PrivateJWK(.rsa(key)).jsonRepresentation())
        #expect(roundTripped.publicJWK == JWK(.rsa(key.publicKey)))
    }

    @Test("an RSA verifier honours the JWK's restrictions and key type")
    func jwkRestrictions() throws {
        let key = JWK.Key.rsa(try RSAPrivateKey().publicKey)
        _ = try RSAVerifier<RS256>(jwk: JWK(key, metadata: JWKMetadata(algorithm: "RS256")))
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "RS256", required: "PS256")) {
            try RSAVerifier<PS256>(jwk: JWK(key, metadata: JWKMetadata(algorithm: "RS256")))
        }
        #expect(throws: JWKError.useNotPermitted(use: "enc", required: "sig")) {
            try RSAVerifier<RS256>(jwk: JWK(key, metadata: JWKMetadata(use: .encryption)))
        }
        let p256 = JWK(.p256((try ECPrivateKey<P256Curve>()).publicKey))
        #expect(throws: JWKError.keyTypeMismatch(expected: "RSA", found: "EC P-256")) {
            try RSAVerifier<RS256>(jwk: p256)
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC P-256", found: "RSA")) {
            try ECDSAVerifier<P256Curve>(jwk: JWK(key))
        }
    }

    @Test("an RSA private key's description does not contain the key")
    func redaction() throws {
        let key = try RSAPrivateKey()
        for rendered in [String(describing: key), String(reflecting: key), "\(PrivateJWK(.rsa(key)))"] {
            #expect(rendered.contains("redacted"))
            #expect(!rendered.contains(String(base64URLEncoding: key.components.privateExponent)))
            #expect(!rendered.contains(key.components.prime1.hex))
        }
    }

    @Test("malformed PKCS#1 DER reports what is wrong")
    func malformedDER() throws {
        let valid = try RSAPrivateKey().publicKey.pkcs1DERRepresentation
        _ = try RSAPublicKey(pkcs1DERRepresentation: valid)

        func reason(_ der: Data) -> String? {
            do {
                _ = try RSAPublicKey(pkcs1DERRepresentation: der)
                return nil
            } catch {
                guard case .invalidDER(let reason) = error else {
                    return "other: \(error)"
                }
                return reason
            }
        }
        #expect(reason(Data()) == "input ends inside key")
        #expect(reason(valid.dropLast()) == "SEQUENCE declares 266 bytes but 265 follow")
        #expect(reason(valid + [0x00]) == "SEQUENCE declares 266 bytes but 267 follow")
        var wrongTag = valid
        wrongTag[0] = 0x31
        #expect(reason(wrongTag) == "key has tag 0x31; expected 0x30")
        // SEQUENCE { INTEGER 5 } : exponent missing.
        #expect(reason(Data([0x30, 0x03, 0x02, 0x01, 0x05])) == "input ends inside publicExponent")
        #expect(reason(Data([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x80])) == "publicExponent is negative")
        #expect(
            reason(Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x03]))
                == "modulus has a redundant leading zero"
        )
        #expect(reason(Data([0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x03])) == "modulus is an empty INTEGER")
        #expect(
            reason(Data([0x30, 0x06, 0x02, 0x05, 0x01, 0x02, 0x01, 0x03])) == "modulus declares 5 bytes but 4 remain"
        )
        #expect(reason(Data([0x30, 0x81, 0x03, 0x02, 0x01, 0x05])) == "key has a non-minimal length encoding")
        #expect(reason(Data([0x30, 0x80, 0x02, 0x01, 0x05])) == "key has an unsupported length encoding")
        #expect(
            reason(Data([0x30, 0x09, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03, 0x02, 0x01, 0x01]))
                == "3 unexpected bytes after the last value"
        )
        // A private key handed over as a public key is not silently truncated to its first two values.
        let privateDER = try RSAPrivateKey().pkcs1DERRepresentation
        #expect(reason(privateDER)?.contains("unexpected bytes") == true)
    }
}
