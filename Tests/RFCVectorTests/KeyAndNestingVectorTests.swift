import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import JOSEJWS
import JOSEJWT
import JOSEJWTEncrypted
import Testing

/// RFC 7520 §3 (keys) and §6 (a JWT signed, then encrypted), from the JOSE cookbook.
@Suite("RFC vectors: keys and nesting")
struct KeyAndNestingVectorTests {
    @Test("RFC 7520 §3: the example keys parse, and each private key's public half is the public example")
    func keys() throws {
        let ecPublic = try JWK(json: try Vector("jwk/3_1.ec_public_key.json").root.json)
        let ecPrivate = try PrivateJWK(json: try Vector("jwk/3_2.ec_private_key.json").root.json)
        #expect(ecPrivate.publicJWK == ecPublic)
        #expect(ecPublic.keyType == "EC")
        #expect(ecPublic.keyID == "bilbo.baggins@hobbiton.example")

        let rsaPublic = try JWK(json: try Vector("jwk/3_3.rsa_public_key.json").root.json)
        let rsaPrivate = try PrivateJWK(json: try Vector("jwk/3_4.rsa_private_key.json").root.json)
        #expect(rsaPrivate.publicJWK == rsaPublic)
        #expect(rsaPublic.keyType == "RSA")

        let mac = try SymmetricJWK(json: try Vector("jwk/3_5.symmetric_key_mac_computation.json").root.json)
        #expect(mac.metadata.algorithm == "HS256")
        #expect(mac.key.rawRepresentation.count == 32)
        let encryption = try SymmetricJWK(json: try Vector("jwk/3_6.symmetric_key_encryption.json").root.json)
        #expect(encryption.metadata.algorithm == "A256GCM")
        #expect(encryption.key.rawRepresentation.count == 32)

        // A private or symmetric key is never accepted where a public key is expected.
        #expect(throws: JWKError.self) { try JWK(json: try Vector("jwk/3_2.ec_private_key.json").root.json) }
        #expect(throws: JWKError.self) {
            try JWK(json: try Vector("jwk/3_5.symmetric_key_mac_computation.json").root.json)
        }
    }

    @Test("RFC 7520 §6: the nested example decrypts, verifies and validates as a nested JWT")
    func nestedJWT() async throws {
        let vector = try Vector("6.nesting_signatures_and_encryption.json")
        let decryption = DecryptionKeys([
            try AnyKeyDecrypter(algorithm: "RSA-OAEP", key: try vector.value("encrypt", "input", "key"))
        ])
        let verification = VerificationKeys([
            try AnyVerifier(algorithm: "PS256", key: try vector.value("sign", "input", "key"))
        ])
        // The claims expire at 1300819380 (2011-03-22T18:43:00Z); validate just before then.
        let policy = JWTValidationPolicy(
            issuer: .exactly("hobbiton.example"),
            audience: .unchecked,
            type: .exactly("JWT"),
            clock: .fixed(Date(timeIntervalSince1970: 1_300_819_000))
        )
        let inner = try vector.string("sign", "output", "compact")
        for form in ["compact", "json", "json_flat"] where vector.has("encrypt", "output", form) {
            let serialization = try vector.value("encrypt", "output", form)
            let outer: SimpleJWE.Encrypted
            if case .string(let compact) = serialization {
                outer = try SimpleJWE.Encrypted(compact: compact)
            } else {
                outer = try SimpleJWE.Encrypted(json: try serialization.json)
            }
            #expect(outer.header.contentType == "JWT", "\(form)")
            let plaintext = try await outer.decrypt(with: decryption).plaintext
            #expect(String(decoding: plaintext, as: UTF8.self) == inner, "\(form)")
        }

        let compact = try vector.string("encrypt", "output", "compact")
        let validated = try await SimpleNestedJWT.Encrypted(compact: compact)
            .decrypt(with: decryption)
            .verify(with: verification)
            .validate(policy)
        #expect(validated.claims.issuer == "hobbiton.example")
        #expect(validated.rawClaims["http://example.com/is_root"] == true)
    }
}
