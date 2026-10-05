import Foundation
import JOSECore
import Testing

@testable import JOSEJWK

@Suite("Private and symmetric keys")
struct PrivateKeyTests {
    @Test("private JWKs exported by jose parse, and re-export with identical members")
    func parsesCounterpartPrivateKeys() throws {
        for key in try KeysFixture.load().keys {
            let jwk = try PrivateJWK(json: try key.privateJSON())
            let exported = try JSONDecoder().decode([String: String].self, from: try jwk.jsonRepresentation())
            #expect(exported == key.privateJwk)
            let publicExport = try JSONDecoder().decode(
                [String: String].self,
                from: try jwk.publicJWK.jsonRepresentation()
            )
            #expect(publicExport == key.publicJwk)
            #expect(publicExport["d"] == nil)
        }
    }

    @Test("a private JWK whose d belongs to a different key is refused")
    func mismatchedPrivateKey() throws {
        let keys = try KeysFixture.load().keys
        for curve in ["P-256", "P-384", "P-521", "Ed25519"] {
            let pair = keys.filter { $0.curve == curve }
            var mixed = pair[0].privateJwk
            mixed["d"] = pair[1].privateJwk["d"]
            // Positive control: the unmixed key parses.
            _ = try PrivateJWK(json: try pair[0].privateJSON())
            #expect(throws: JWKError.privateKeyDoesNotMatchPublicKey(curve: curve)) {
                try PrivateJWK(json: try JSONEncoder().encode(mixed))
            }
        }
    }

    @Test("private JWK parsing reports missing and malformed members")
    func privateErrors() throws {
        let key = try #require(try KeysFixture.load().keys.first { $0.curve == "P-256" })
        var missingD = key.privateJwk
        missingD["d"] = nil
        #expect(throws: JWKError.missingMember(name: "d", keyType: "EC")) {
            try PrivateJWK(json: try JSONEncoder().encode(missingD))
        }
        var shortD = key.privateJwk
        shortD["d"] = "AA"
        #expect(throws: JWKError.wrongByteCount(member: "d", curve: "P-256", expected: 32, found: 1)) {
            try PrivateJWK(json: try JSONEncoder().encode(shortD))
        }
        var zeroD = key.privateJwk
        zeroD["d"] = String(repeating: "A", count: 43)
        #expect(throws: JWKError.invalidPrivateKey(curve: "P-256")) {
            try PrivateJWK(json: try JSONEncoder().encode(zeroD))
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC, OKP or RSA", found: "oct")) {
            try PrivateJWK(json: Data(#"{"kty":"oct","k":"AAAA"}"#.utf8))
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC P-256, P-384 or P-521", found: "EC secp256k1")) {
            try PrivateJWK(json: Data(#"{"kty":"EC","crv":"secp256k1"}"#.utf8))
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "OKP Ed25519 or X25519", found: "OKP Ed448")) {
            try PrivateJWK(json: Data(#"{"kty":"OKP","crv":"Ed448","x":"AA","d":"AA"}"#.utf8))
        }
    }

    @Test("generated private keys round-trip through their raw and JWK forms")
    func generatedKeysRoundTrip() throws {
        let p256 = try ECPrivateKey<P256Curve>()
        #expect(p256.rawRepresentation.count == 32)
        #expect(try ECPrivateKey<P256Curve>(rawRepresentation: p256.rawRepresentation).publicKey == p256.publicKey)
        let p521 = try ECPrivateKey<P521Curve>()
        #expect(p521.rawRepresentation.count == 66)
        #expect(p521.publicKey.x.count == 66)

        let jwk = PrivateJWK(.p256(p256), metadata: JWKMetadata(keyID: "mine"))
        let reparsed = try PrivateJWK(json: try jwk.jsonRepresentation())
        #expect(reparsed.publicJWK == jwk.publicJWK)
        #expect(reparsed.metadata.keyID == "mine")

        let edwards = try Ed25519PrivateKey()
        #expect(try Ed25519PrivateKey(rawRepresentation: edwards.rawRepresentation).publicKey == edwards.publicKey)
        #expect(throws: JWKError.wrongByteCount(member: "d", curve: "Ed25519", expected: 32, found: 31)) {
            try Ed25519PrivateKey(rawRepresentation: Data(count: 31))
        }
        #expect(throws: JWKError.wrongByteCount(member: "d", curve: "P-256", expected: 32, found: 33)) {
            try ECPrivateKey<P256Curve>(rawRepresentation: Data(count: 33))
        }
        #expect(throws: JWKError.invalidPrivateKey(curve: "P-256")) {
            try ECPrivateKey<P256Curve>(rawRepresentation: Data(repeating: 0xFF, count: 32))
        }
    }

    @Test("descriptions of secret-bearing types do not contain the secret")
    func redaction() throws {
        let p256 = try ECPrivateKey<P256Curve>()
        let edwards = try Ed25519PrivateKey()
        let secret = SymmetricKeyMaterial(rawRepresentation: Data(repeating: 0xAB, count: 32))
        let values: [(Any, Data)] = [
            (p256, p256.rawRepresentation),
            (edwards, edwards.rawRepresentation),
            (secret, secret.rawRepresentation),
            (PrivateJWK(.p256(p256)), p256.rawRepresentation),
            (SymmetricJWK(secret), secret.rawRepresentation),
        ]
        for (value, material) in values {
            for rendered in [String(describing: value), String(reflecting: value), "\(value)"] {
                #expect(rendered.contains("redacted"))
                #expect(!rendered.contains(Base64URL.encode(material)))
                #expect(!rendered.contains(material.hex))
                #expect(!rendered.contains("\(material.count) bytes") || value is SymmetricKeyMaterial)
            }
        }
    }

    @Test("descriptions are exactly the redacted form")
    func exactDescriptions() throws {
        #expect("\(try ECPrivateKey<P384Curve>())" == "ECPrivateKey<P-384>(redacted)")
        #expect("\(try Ed25519PrivateKey())" == "Ed25519PrivateKey(redacted)")
        #expect("\(PrivateJWK(.p256(try ECPrivateKey<P256Curve>())))" == "PrivateJWK(EC, redacted)")
        #expect("\(PrivateJWK(.ed25519(try Ed25519PrivateKey())))" == "PrivateJWK(OKP, redacted)")
        #expect("\(SymmetricJWK(SymmetricKeyMaterial(randomByteCount: 32)))" == "SymmetricJWK(redacted)")
        #expect("\(SymmetricKeyMaterial(randomByteCount: 32))" == "SymmetricKeyMaterial(32 bytes, redacted)")
    }

    @Test("symmetric JWKs parse and write, and other key types are refused")
    func symmetricJWK() throws {
        let json = Data(
            #"{"alg":"HS256","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","kid":"s","kty":"oct"}"#.utf8
        )
        let jwk = try SymmetricJWK(json: json)
        #expect(jwk.key.rawRepresentation == Data(0..<32))
        #expect(jwk.metadata.keyID == "s")
        #expect(jwk.metadata.algorithm == "HS256")
        #expect(try jwk.jsonRepresentation() == json)

        #expect(throws: JWKError.keyTypeMismatch(expected: "oct", found: "EC")) {
            try SymmetricJWK(json: Data(#"{"kty":"EC"}"#.utf8))
        }
        #expect(throws: JWKError.missingMember(name: "k", keyType: "oct")) {
            try SymmetricJWK(json: Data(#"{"kty":"oct"}"#.utf8))
        }
        #expect(throws: JWKError.invalidBase64URL(member: "k", .invalidLength(count: 1))) {
            try SymmetricJWK(json: Data(#"{"kty":"oct","k":"A"}"#.utf8))
        }
    }
}
