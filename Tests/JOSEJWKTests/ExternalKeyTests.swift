import Foundation
import JOSECore
import TestSupport
import Testing

@testable import JOSEJWK

/// A key type for exercising the extension point without any real curve: a `kty`/`crv` pair whose
/// key is just its `x` member.
private struct FakeKey: ExternalPublicKey, Equatable {
    let keyType: String
    let curve: String
    let x: String

    var jwkMembers: [String: JSONValue] {
        ["crv": .string(curve), "x": .string(x)]
    }

    var keyDescription: String {
        "\(keyType) \(curve)"
    }

    func thumbprint(using hashAlgorithm: JWKThumbprint.HashAlgorithm) -> JWKThumbprint {
        JWKThumbprint(canonicalJSON: "{\"fake\":\"\(x)\"}", hashAlgorithm: hashAlgorithm)
    }
}

private struct FakePrivateKey: ExternalPrivateKey {
    let publicKey: FakeKey
    let d: String

    var privateJWKMembers: [String: JSONValue] {
        ["d": .string(d)]
    }
}

private struct FakeKeyType: ExternalKeyType {
    let keyType: String
    let curve: String
    /// Claims every document, whatever its `kty` and `crv`.
    var isGreedy = false

    private func matches(_ members: [String: JSONValue]) -> Bool {
        isGreedy || (members["kty"] == .string(keyType) && members["crv"] == .string(curve))
    }

    func publicKey(from members: [String: JSONValue]) throws(JWKError) -> (any ExternalPublicKey)? {
        guard matches(members) else {
            return nil
        }
        guard case .string(let x) = members["x"] else {
            throw .missingMember(name: "x", keyType: keyType)
        }
        return FakeKey(keyType: keyType, curve: curve, x: x)
    }

    func privateKey(from members: [String: JSONValue]) throws(JWKError) -> (any ExternalPrivateKey)? {
        guard let publicKey = try publicKey(from: members) as? FakeKey else {
            return nil
        }
        guard case .string(let d) = members["d"] else {
            throw .missingMember(name: "d", keyType: keyType)
        }
        return FakePrivateKey(publicKey: publicKey, d: d)
    }
}

@Suite("External key types")
struct ExternalKeyTests {
    private static let okp = FakeKeyType(keyType: "OKP", curve: "Fake448")
    private static let ec = FakeKeyType(keyType: "EC", curve: "fake256")
    private static let other = FakeKeyType(keyType: "XYZ", curve: "fake")

    private static func json(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private static func external(_ jwk: JWK) throws -> FakeKey {
        guard case .external(let external) = jwk.key, let key = external.key as? FakeKey else {
            throw FixtureError(description: "\(jwk.key) is not an external fake key")
        }
        return key
    }

    @Test("a key type listed in keyTypes is read as an external key, for an unlisted curve or kty")
    func listedKeyTypes() throws {
        for keyType in [Self.okp, Self.ec, Self.other] {
            let json = try Self.json([
                "kty": keyType.keyType, "crv": keyType.curve, "x": "abc", "kid": "k1", "x5c": ["MII"],
            ])
            let jwk = try JWK(json: json, keyTypes: [Self.okp, Self.ec, Self.other])
            #expect(try Self.external(jwk) == FakeKey(keyType: keyType.keyType, curve: keyType.curve, x: "abc"))
            #expect(jwk.keyType == keyType.keyType)
            #expect(jwk.keyID == "k1")
            // Members the key does not account for are carried, as for the listed key types.
            #expect(jwk.additionalParameters == ["x5c": .array(["MII"])])
            #expect(try jwk.jsonRepresentation() == json)
            #expect(try JWK(json: try jwk.jsonRepresentation(), keyTypes: [keyType]) == jwk)

            guard case .unrecognized(let unrecognized) = try JWK(json: json).key else {
                Issue.record("\(keyType.keyType) \(keyType.curve) was not unrecognised without keyTypes")
                continue
            }
            #expect(unrecognized.keyType == keyType.keyType)
        }
    }

    @Test("a key type, P-256 or otherwise, that JOSEJWK lists is never handed to keyTypes")
    func listedTypesComeFirst() throws {
        let greedy = FakeKeyType(keyType: "EC", curve: "P-256", isGreedy: true)
        let p256 = try JWK(json: try JWK(.p256(try ECPrivateKey<P256Curve>().publicKey)).jsonRepresentation())
        let parsed = try JWK(json: try p256.jsonRepresentation(), keyTypes: [greedy])
        #expect(parsed == p256)
    }

    @Test("an external key with a private member is refused, even when its key type ignores it")
    func privateMemberRefused() throws {
        let json = try Self.json(["kty": "OKP", "crv": "Fake448", "x": "abc", "d": "secret"])
        #expect(throws: JWKError.reservedParameterName("d")) { try JWK(json: json, keyTypes: [Self.okp]) }
        #expect(throws: JWKError.privateMemberInPublicKey(member: "d", keyType: "OKP")) { try JWK(json: json) }
    }

    @Test("an error from the key type is reported, not hidden behind an unrecognised key")
    func keyTypeErrorsSurface() throws {
        let json = try Self.json(["kty": "OKP", "crv": "Fake448"])
        #expect(throws: JWKError.missingMember(name: "x", keyType: "OKP")) { try JWK(json: json, keyTypes: [Self.okp]) }
    }

    @Test("external keys are equal, and hash alike, exactly when their kty and members are")
    func equality() throws {
        let key = JWK.ExternalKey(FakeKey(keyType: "OKP", curve: "Fake448", x: "abc"))
        let same = JWK.ExternalKey(FakeKey(keyType: "OKP", curve: "Fake448", x: "abc"))
        let otherX = JWK.ExternalKey(FakeKey(keyType: "OKP", curve: "Fake448", x: "abd"))
        let otherType = JWK.ExternalKey(FakeKey(keyType: "EC", curve: "Fake448", x: "abc"))
        #expect(key == same)
        #expect(key.hashValue == same.hashValue)
        #expect(key != otherX)
        #expect(key != otherType)
        #expect(Set([key, same, otherX, otherType]).count == 3)
    }

    @Test("the thumbprint and the error-message description come from the external key")
    func thumbprintAndDescription() throws {
        let key = FakeKey(keyType: "OKP", curve: "Fake448", x: "abc")
        let jwk = JWK(.external(JWK.ExternalKey(key)))
        #expect(try jwk.thumbprint(using: .sha384) == key.thumbprint(using: .sha384))
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC P-256", found: "OKP Fake448")) {
            try ECDSAVerifier<P256Curve>(jwk: jwk)
        }
    }

    @Test("a JWK Set reads its keys with the keyTypes it is given")
    func keySet() throws {
        let json = try Self.json(["keys": [["kty": "OKP", "crv": "Fake448", "x": "abc"]]])
        #expect(try Self.external(try JWKSet(json: json, keyTypes: [Self.okp]).keys[0]).x == "abc")
        guard case .unrecognized = try JWKSet(json: json).keys[0].key else {
            Issue.record("the key was not unrecognised without keyTypes")
            return
        }
    }

    @Test("a private key type listed in keyTypes is read, written back and gives its public half")
    func privateKeys() throws {
        let expectedErrors: [(FakeKeyType, JWKError)] = [
            (Self.okp, .keyTypeMismatch(expected: "OKP Ed25519 or X25519", found: "OKP Fake448")),
            (Self.ec, .keyTypeMismatch(expected: "EC P-256, P-384 or P-521", found: "EC fake256")),
            (Self.other, .keyTypeMismatch(expected: "EC, OKP or RSA", found: "XYZ")),
        ]
        for (keyType, error) in expectedErrors {
            let json = try Self.json([
                "kty": keyType.keyType, "crv": keyType.curve, "x": "abc", "d": "secret", "kid": "k",
            ])
            let jwk = try PrivateJWK(json: json, keyTypes: [Self.okp, Self.ec, Self.other])
            guard case .external(let key) = jwk.key, let fake = key as? FakePrivateKey else {
                Issue.record("\(keyType.keyType) \(keyType.curve) was not read as an external private key")
                continue
            }
            #expect(fake.d == "secret")
            #expect(try Self.external(jwk.publicJWK) == fake.publicKey)
            #expect(jwk.publicJWK.keyID == "k")
            #expect(try jwk.jsonRepresentation() == json)
            #expect(throws: error) { try PrivateJWK(json: json) }
        }
    }
}
