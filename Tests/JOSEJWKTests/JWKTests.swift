import Foundation
import JOSECore
import Testing

@testable import JOSEJWK

private struct ParsingFixture: Decodable {
    struct Case: Decodable {
        struct Jose: Decodable {
            let accepted: Bool
            let importedAs: String?
        }
        let curve: String
        let name: String
        let json: String
        let jose: Jose
    }
    let cases: [Case]
}

@Suite("JWK")
struct JWKTests {
    /// Documents that this package refuses as a public key whatever jose does with them.
    ///
    /// - Padding: jose strips it; here it is accepted only when it is the correct amount, which
    ///   for a 48- or 66-byte coordinate is none.
    /// - Coordinate length: jose (WebCrypto) tolerates a missing or extra leading zero byte;
    ///   RFC 7518 §6.2.1.2 requires the full coordinate size, and equal keys must have equal JWKs.
    /// - `oct` and `d`: jose imports these as secret and private keys. `JWK` is the public-key
    ///   type, so they are refused here and read through `SymmetricJWK` and `PrivateJWK` instead.
    /// - Ed25519 with `+`/`/`: jose's decoder accepts the standard alphabet for this key type.
    static func expectedStricterError(curve: String, name: String) -> JWKError? {
        let coordinateByteCount = ["P-256": 32, "P-384": 48, "P-521": 66, "Ed25519": 32][curve] ?? 0
        switch (name, curve) {
        case ("x is padded", "P-384"), ("x is padded", "P-521"):
            return .invalidBase64URL(member: "x", .wrongPaddingLength(expected: 0, found: 1))
        case ("x has one byte too many", "P-256"), ("x has one byte too many", "P-384"),
            ("x has one byte too many", "P-521"):
            return .wrongByteCount(
                member: "x",
                curve: curve,
                expected: coordinateByteCount,
                found: coordinateByteCount + 1
            )
        case ("x has one byte too few", "P-521"):
            return .wrongByteCount(member: "x", curve: curve, expected: 66, found: 65)
        case ("x is not base64url (standard alphabet)", "Ed25519"):
            return .invalidBase64URL(member: "x", .invalidCharacter(byte: 0x2B, offset: 41))
        case ("kty is oct", _):
            return .symmetricKeyInPublicKey
        // RSA. jose's importJWK (WebCrypto) checks almost nothing about an RSA key when importing
        // it; it refuses a key under 2048 bits only when the key is used. Here an RSA key that
        // could never be valid is refused when it is read.
        case ("n is a number", "RSA"):
            return .wrongMemberType(name: "n", expected: "a string")
        case ("n is not base64url (standard alphabet)", "RSA"):
            return .invalidBase64URL(member: "n", .invalidCharacter(byte: 0x2B, offset: 340))
        case ("n is empty", "RSA"):
            return .invalidRSAKey(reason: "\"n\" is empty")
        case ("1024-bit key", "RSA"):
            return .rsaKeyTooSmall(bitCount: 1024, minimum: 2048)
        case ("n has a leading zero byte", "RSA"):
            return .nonMinimalInteger(member: "n")
        case ("e has a leading zero byte", "RSA"):
            return .nonMinimalInteger(member: "e")
        case ("e is even", "RSA"):
            return .invalidRSAKey(reason: "the public exponent is even")
        case ("e is 1", "RSA"):
            return .invalidRSAKey(reason: "the public exponent is 1")
        case ("n is even", "RSA"):
            return .invalidRSAKey(reason: "the modulus is even")
        case ("private member d present", "RSA"):
            return .privateMemberInPublicKey(member: "d", keyType: "RSA")
        case ("private member d present", "Ed25519"):
            return .privateMemberInPublicKey(member: "d", keyType: "OKP")
        case ("private member d present", _):
            return .privateMemberInPublicKey(member: "d", keyType: "EC")
        default:
            return nil
        }
    }

    @Test("public JWKs exported by jose parse, and re-export with identical members")
    func parsesCounterpartKeys() throws {
        let fixture = try KeysFixture.load()
        #expect(fixture.keys.count == 16)
        for key in fixture.keys {
            let jwk = try JWK(json: try key.publicJSON())
            #expect(jwk.keyDescription.hasSuffix(key.curve))
            let exported = try JSONDecoder().decode([String: String].self, from: try jwk.jsonRepresentation())
            #expect(exported == key.publicJwk)
        }
        #expect(fixture.rsaKeys.map(\.bitCount) == [2048, 2048, 3072, 4096])
        for key in fixture.rsaKeys {
            let jwk = try JWK(json: try JSONEncoder().encode(key.publicJwk))
            guard case .rsa(let publicKey) = jwk.key else {
                Issue.record("RSA key was not recognised")
                continue
            }
            #expect(publicKey.bitCount == key.bitCount)
            let exported = try JSONDecoder().decode([String: String].self, from: try jwk.jsonRepresentation())
            #expect(exported == key.publicJwk)
        }
    }

    @Test("the X9.63 form of each key matches WebCrypto's raw export")
    func x963MatchesCounterpart() throws {
        for key in try KeysFixture.load().keys {
            let jwk = try JWK(json: try key.publicJSON())
            let raw = try Data(hex: key.rawPublicKey)
            switch jwk.key {
            case .p256(let publicKey):
                #expect(publicKey.x963Representation == raw)
                #expect(try ECPublicKey<P256Curve>(x963Representation: raw) == publicKey)
            case .p384(let publicKey):
                #expect(publicKey.x963Representation == raw)
                #expect(try ECPublicKey<P384Curve>(x963Representation: raw) == publicKey)
            case .p521(let publicKey):
                #expect(publicKey.x963Representation == raw)
                #expect(try ECPublicKey<P521Curve>(x963Representation: raw) == publicKey)
            case .ed25519(let publicKey):
                #expect(publicKey.rawRepresentation == raw)
            case .x25519, .rsa, .unrecognized:
                Issue.record("\(key.curve) key was not recognised as itself")
            }
        }
    }

    @Test("accepts and rejects the same documents as jose, apart from the documented stricter cases")
    func parsingAgreesWithCounterpart() throws {
        let fixture = try ParsingFixture(fixture: "jwk-parsing")
        var accepted = 0
        var rejected = 0
        var stricter = 0
        var unrecognized = 0
        for testCase in fixture.cases {
            let label = Comment(rawValue: "\(testCase.curve): \(testCase.name)")
            let json = Data(testCase.json.utf8)
            if let expected = Self.expectedStricterError(curve: testCase.curve, name: testCase.name) {
                #expect(throws: expected, label) { try JWK(json: json) }
                stricter += 1
            } else if testCase.jose.accepted {
                #expect(testCase.jose.importedAs == "public", label)
                let jwk = try JWK(json: json)
                #expect(jwk.keyDescription.hasSuffix(testCase.curve), label)
                accepted += 1
            } else {
                // jose refuses these. Here the document either fails to parse, or parses as an
                // unrecognised key type that is kept for add-ons but cannot be used to verify.
                do {
                    let jwk = try JWK(json: json)
                    guard case .unrecognized = jwk.key else {
                        Issue.record("\(label): parsed as a usable key although jose rejects it")
                        continue
                    }
                    #expect(throws: JWKError.self, label) { try ECDSAVerifier<P256Curve>(jwk: jwk) }
                    #expect(throws: JWKError.self, label) { try ECDSAVerifier<P384Curve>(jwk: jwk) }
                    #expect(throws: JWKError.self, label) { try ECDSAVerifier<P521Curve>(jwk: jwk) }
                    #expect(throws: JWKError.self, label) { try Ed25519Verifier<EdDSA>(jwk: jwk) }
                    #expect(throws: JWKError.self, label) { try RSAVerifier<RS256>(jwk: jwk) }
                    #expect(throws: JWKError.self, label) { try jwk.thumbprint() }
                    unrecognized += 1
                } catch {
                    rejected += 1
                }
            }
        }
        #expect(accepted >= 10)
        #expect(rejected >= 22)
        #expect(stricter >= 20)
        #expect(unrecognized == 8)
    }

    private static let p256JSON = Data(
        #"{"kty":"EC","crv":"P-256","x":"14WOA3x9aO7J8tMOtPxoPGIwkuYSC2lLy7CUkrtmGPQ","y":"0_1BAqhrUqYCXcuUxFn85i82ffUwusSsGshwqvbDh74"}"#
            .utf8
    )

    @Test("each malformed JWK reports which member is wrong")
    func specificErrors() throws {
        _ = try JWK(json: Self.p256JSON)

        func parse(_ json: String) throws(JWKError) -> JWK {
            try JWK(json: Data(json.utf8))
        }
        #expect(throws: JWKError.missingMember(name: "kty", keyType: nil)) { try parse("{}") }
        #expect(throws: JWKError.wrongMemberType(name: "kty", expected: "a string")) { try parse(#"{"kty":1}"#) }
        #expect(throws: JWKError.missingMember(name: "crv", keyType: "EC")) { try parse(#"{"kty":"EC"}"#) }
        #expect(throws: JWKError.missingMember(name: "x", keyType: "EC")) {
            try parse(#"{"kty":"EC","crv":"P-256","y":"AA"}"#)
        }
        #expect(throws: JWKError.missingMember(name: "y", keyType: "EC")) {
            try parse(#"{"kty":"EC","crv":"P-256","x":"AA"}"#)
        }
        #expect(throws: JWKError.missingMember(name: "x", keyType: "OKP")) {
            try parse(#"{"kty":"OKP","crv":"Ed25519"}"#)
        }
        #expect(throws: JWKError.wrongMemberType(name: "x", expected: "a string")) {
            try parse(#"{"kty":"EC","crv":"P-256","x":5,"y":"AA"}"#)
        }
        #expect(throws: JWKError.invalidBase64URL(member: "x", .invalidCharacter(byte: 0x2B, offset: 1))) {
            try parse(#"{"kty":"EC","crv":"P-256","x":"A+","y":"AA"}"#)
        }
        #expect(throws: JWKError.wrongByteCount(member: "x", curve: "P-256", expected: 32, found: 1)) {
            try parse(#"{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#)
        }
        #expect(throws: JWKError.wrongByteCount(member: "x", curve: "Ed25519", expected: 32, found: 1)) {
            try parse(#"{"kty":"OKP","crv":"Ed25519","x":"AA"}"#)
        }
        let zeros = String(repeating: "A", count: 43)
        #expect(throws: JWKError.wrongByteCount(member: "y", curve: "P-256", expected: 32, found: 1)) {
            try parse(#"{"kty":"EC","crv":"P-256","x":"\#(zeros)","y":"AA"}"#)
        }
        #expect(throws: JWKError.pointNotOnCurve(curve: "P-256")) {
            try parse(#"{"kty":"EC","crv":"P-256","x":"\#(zeros)","y":"\#(zeros)"}"#)
        }
        #expect(throws: JWKError.symmetricKeyInPublicKey) { try parse(#"{"kty":"oct","k":"AAAA"}"#) }
        #expect(throws: JWKError.invalidJSONStructure(.duplicateMember(name: "kty", offset: 12))) {
            try parse(#"{"kty":"EC","kty":"OKP"}"#)
        }
        #expect(throws: JWKError.invalidJSONStructure(.rootNotObject)) { try parse("[]") }
        #expect(throws: JWKError.wrongMemberType(name: "kid", expected: "a string")) {
            try parse(#"{"kty":"XYZ","kid":7}"#)
        }
        #expect(throws: JWKError.wrongMemberType(name: "key_ops", expected: "an array of strings")) {
            try parse(#"{"kty":"XYZ","key_ops":"verify"}"#)
        }
        #expect(throws: JWKError.wrongMemberType(name: "key_ops", expected: "an array of strings")) {
            try parse(#"{"kty":"XYZ","key_ops":[1]}"#)
        }
        #expect(throws: JWKError.duplicateKeyOperation("verify")) {
            try parse(#"{"kty":"XYZ","key_ops":["verify","verify"]}"#)
        }
    }

    @Test("metadata and additional parameters are read, kept apart from key material, and written back")
    func metadataAndAdditionalParameters() throws {
        var object = try JSONDecoder().decode([String: JSONValue].self, from: Self.p256JSON)
        object["kid"] = "key-1"
        object["use"] = "sig"
        object["alg"] = "ES256"
        object["key_ops"] = ["verify"]
        object["x5t"] = "abc"
        object["custom"] = ["nested": 1]
        let jwk = try JWK(json: try JSONEncoder().encode(object))

        #expect(jwk.keyID == "key-1")
        #expect(jwk.metadata.use == .signature)
        #expect(jwk.metadata.algorithm == "ES256")
        #expect(jwk.metadata.keyOperations == [.verify])
        #expect(jwk.additionalParameters == ["x5t": "abc", "custom": ["nested": 1]])
        #expect(jwk.keyType == "EC")

        let exported = try JSONDecoder().decode([String: JSONValue].self, from: try jwk.jsonRepresentation())
        #expect(exported == object)

        // Metadata and extras do not make two keys different keys for thumbprint purposes.
        #expect(try jwk.thumbprint() == (try JWK(json: Self.p256JSON)).thumbprint())
    }

    @Test("additional parameters cannot use names that carry key material or metadata")
    func reservedAdditionalParameters() throws {
        var jwk = try JWK(json: Self.p256JSON)
        let reserved = [
            "kty", "crv", "x", "y", "d", "k", "n", "e", "p", "q", "dp", "dq", "qi", "oth", "kid", "use", "key_ops",
            "alg",
        ]
        for name in reserved {
            #expect(throws: JWKError.reservedParameterName(name)) {
                try jwk.setAdditionalParameter(name, to: "value")
            }
        }
        try jwk.setAdditionalParameter("x5t", to: "abc")
        #expect(jwk.additionalParameters == ["x5t": "abc"])
        try jwk.setAdditionalParameter("x5t", to: nil)
        #expect(jwk.additionalParameters.isEmpty)
    }

    @Test("an unrecognised key type carrying private material is refused, so a JWK never holds a secret")
    func unrecognizedRejectsPrivateMembers() {
        for member in ["d", "k", "p", "q", "dp", "dq", "qi", "oth"] {
            let json = Data(#"{"kty":"AKP","pub":"abc","\#(member)":"secret"}"#.utf8)
            #expect(throws: JWKError.privateMemberInPublicKey(member: member, keyType: "AKP")) {
                try JWK(json: json)
            }
        }
        // An unknown curve of a known type is the other way into the unrecognised branch.
        #expect(throws: JWKError.privateMemberInPublicKey(member: "d", keyType: "OKP")) {
            try JWK(json: Data(#"{"kty":"OKP","crv":"Ed448","x":"abc","d":"secret"}"#.utf8))
        }
    }

    @Test("a member the typed properties own is refused when parsed as an extra, as it is when set")
    func reservedMembersOnParse() {
        #expect(throws: JWKError.reservedParameterName("k")) {
            try JWK(json: Self.p256JSON.dropLast() + Data(#","k":"AAAA"}"#.utf8))
        }
        #expect(throws: JWKError.reservedParameterName("n")) {
            try JWK(json: Self.p256JSON.dropLast() + Data(#","n":"AAAA"}"#.utf8))
        }
    }

    @Test("an unrecognised key type keeps every member and writes them back unchanged")
    func unrecognizedRoundTrip() throws {
        let json = Data(#"{"alg":"ML-DSA-44","kid":"pq-1","kty":"AKP","pub":"abc","use":"sig"}"#.utf8)
        let jwk = try JWK(json: json)
        guard case .unrecognized(let key) = jwk.key else {
            Issue.record("expected an unrecognised key")
            return
        }
        #expect(key.keyType == "AKP")
        #expect(key.parameters == ["pub": "abc"])
        #expect(jwk.keyID == "pq-1")
        #expect(jwk.keyType == "AKP")
        #expect(try jwk.jsonRepresentation() == json)
        #expect(throws: JWKError.thumbprintUnavailable(keyType: "AKP")) { try jwk.thumbprint() }
    }

    @Test("a JWK embedded in another Codable type decodes and encodes")
    func codable() throws {
        struct Header: Codable {
            let jwk: JWK
        }
        let document = Data(#"{"jwk":"#.utf8) + Self.p256JSON + Data("}".utf8)
        let header = try JSONDecoder().decode(Header.self, from: document)
        #expect(header.jwk == (try JWK(json: Self.p256JSON)))
        let reencoded = try JSONDecoder().decode(Header.self, from: try JSONEncoder().encode(header))
        #expect(reencoded.jwk == header.jwk)
        #expect(throws: JWKError.symmetricKeyInPublicKey) {
            try JSONDecoder().decode(Header.self, from: Data(#"{"jwk":{"kty":"oct","k":"AAAA"}}"#.utf8))
        }
    }

    @Test("X9.63 input is checked for length, the 0x04 marker, and being on the curve")
    func x963Validation() throws {
        let valid = (try ECPrivateKey<P256Curve>()).publicKey.x963Representation
        #expect(valid.count == 65)
        #expect(try ECPublicKey<P256Curve>(x963Representation: valid).x963Representation == valid)

        #expect(throws: JWKError.x963WrongLength(curve: "P-256", expected: 65, found: 64)) {
            try ECPublicKey<P256Curve>(x963Representation: valid.dropLast())
        }
        #expect(throws: JWKError.x963WrongLength(curve: "P-384", expected: 97, found: 65)) {
            try ECPublicKey<P384Curve>(x963Representation: valid)
        }
        for marker: UInt8 in [0x00, 0x02, 0x03, 0x06] {
            var wrongMarker = valid
            wrongMarker[0] = marker
            #expect(throws: JWKError.x963NotUncompressed(curve: "P-256", marker: marker)) {
                try ECPublicKey<P256Curve>(x963Representation: wrongMarker)
            }
        }
        var offCurve = valid
        offCurve[64] ^= 0x01
        #expect(throws: JWKError.pointNotOnCurve(curve: "P-256")) {
            try ECPublicKey<P256Curve>(x963Representation: offCurve)
        }
    }

    @Test("coordinates are read correctly from a Data slice with a non-zero start index")
    func x963Slices() throws {
        let valid = (try ECPrivateKey<P256Curve>()).publicKey
        let padded = Data([0xAA, 0xBB]) + valid.x963Representation
        let key = try ECPublicKey<P256Curve>(x963Representation: padded.dropFirst(2))
        #expect(key == valid)
        #expect(key.x == valid.x963Representation[1..<33])
        #expect(key.y == valid.x963Representation[33..<65])
        #expect(try ECPublicKey<P256Curve>(x: key.x, y: key.y) == valid)
    }

    @Test("a JWK Set keeps usable keys and records why the others were skipped")
    func keySet() throws {
        let good = String(decoding: Self.p256JSON, as: UTF8.self)
        let json = Data(
            #"{"keys":[\#(good),{"kty":"EC","crv":"P-256","x":"AA","y":"AA"},{"kty":"AKP","pub":"abc","kid":"r"},7,{"kty":"oct","k":"AAAA"}]}"#
                .utf8
        )
        let set = try JWKSet(json: json)
        #expect(set.keys.count == 2)
        #expect(set.keys[0] == (try JWK(json: Self.p256JSON)))
        #expect(set.keys(withID: "r").count == 1)
        #expect(set.keys(withID: "missing").isEmpty)
        #expect(
            set.rejected == [
                JWKSet.RejectedKey(
                    index: 1,
                    error: .wrongByteCount(member: "x", curve: "P-256", expected: 32, found: 1)
                ),
                JWKSet.RejectedKey(index: 3, error: .wrongMemberType(name: "keys", expected: "objects")),
                JWKSet.RejectedKey(index: 4, error: .symmetricKeyInPublicKey),
            ]
        )

        let reparsed = try JWKSet(json: try set.jsonRepresentation())
        #expect(reparsed.keys == set.keys)
        #expect(reparsed.rejected.isEmpty)

        #expect(throws: JWKError.invalidKeySet) { try JWKSet(json: Data("{}".utf8)) }
        #expect(throws: JWKError.invalidKeySet) { try JWKSet(json: Data(#"{"keys":{}}"#.utf8)) }
        #expect(throws: JWKError.invalidJSONStructure(.duplicateMember(name: "kty", offset: 21))) {
            try JWKSet(json: Data(#"{"keys":[{"kty":"EC","kty":"EC"}]}"#.utf8))
        }
    }

    @Test("every error has a message naming what was wrong")
    func descriptions() {
        let errors: [(JWKError, String)] = [
            (.invalidJSONStructure(.rootNotObject), "object"),
            (.invalidJSON(description: "boom"), "boom"),
            (.missingMember(name: "crv", keyType: "EC"), "crv"),
            (.missingMember(name: "kty", keyType: nil), "kty"),
            (.wrongMemberType(name: "x", expected: "a string"), "a string"),
            (.invalidBase64URL(member: "y", .invalidLength(count: 5)), "\"y\""),
            (.wrongByteCount(member: "x", curve: "P-256", expected: 32, found: 31), "31"),
            (.pointNotOnCurve(curve: "P-384"), "P-384"),
            (.x963WrongLength(curve: "P-256", expected: 65, found: 64), "64"),
            (.x963NotUncompressed(curve: "P-256", marker: 0x02), "0x2"),
            (.invalidPrivateKey(curve: "P-521"), "P-521"),
            (.privateKeyDoesNotMatchPublicKey(curve: "P-256"), "does not correspond"),
            (.privateMemberInPublicKey(member: "d", keyType: "EC"), "\"d\""),
            (.symmetricKeyInPublicKey, "oct"),
            (.keyTypeMismatch(expected: "EC P-256", found: "OKP Ed25519"), "OKP Ed25519"),
            (.useNotPermitted(use: "enc", required: "sig"), "enc"),
            (.keyOperationNotPermitted(operations: ["sign"], required: "verify"), "verify"),
            (.algorithmMismatch(keyAlgorithm: "ES384", required: "ES256"), "ES384"),
            (.keyTooShort(algorithm: "HS256", minimumByteCount: 32, found: 16), "16"),
            (.keyWrongSize(algorithm: "A256KW", expectedByteCount: 32, found: 16), "exactly 32"),
            (.duplicateKeyOperation("verify"), "verify"),
            (.invalidKeySet, "keys"),
            (.thumbprintUnavailable(keyType: "AKP"), "AKP"),
            (.rsaKeyTooSmall(bitCount: 1024, minimum: 2048), "1024"),
            (.rsaKeyTooLarge(bitCount: 32768, maximum: 16384), "32768"),
            (.nonMinimalInteger(member: "n"), "\"n\""),
            (.invalidRSAKey(reason: "even"), "even"),
            (.unsupportedRSAPrivateKey(reason: "oth"), "oth"),
            (.invalidDER(reason: "truncated"), "truncated"),
            (.reservedParameterName("d"), "\"d\""),
            (.invalidPEM(reason: "no END line"), "no END line"),
            (.wrongPEMType(found: "CERTIFICATE", expected: ["PUBLIC KEY", "RSA PUBLIC KEY"]), "CERTIFICATE"),
            (.wrongPEMType(found: "CERTIFICATE", expected: ["PUBLIC KEY", "RSA PUBLIC KEY"]), "PUBLIC KEY or RSA"),
            (.unsupportedKeyAlgorithm(oid: "1.3.101.113"), "1.3.101.113"),
        ]
        for (error, fragment) in errors {
            #expect(error.description.contains(fragment), "\(error.description)")
        }
    }
}
