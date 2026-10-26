#if canImport(P256K)
    import Foundation
    import JOSECore
    import JOSEJWK
    import JOSESecp256k1
    import TestSupport
    import Testing

    @Suite("secp256k1 keys")
    struct Secp256k1KeyTests {
        private static func publicKey(_ jwk: JWK) throws -> ECPublicKey<Secp256k1Curve> {
            guard case .external(let external) = jwk.key, let key = external.key as? ECPublicKey<Secp256k1Curve> else {
                throw FixtureError(description: "\(jwk.key) is not an external secp256k1 key")
            }
            return key
        }

        private static func privateKey(_ jwk: PrivateJWK) throws -> ECPrivateKey<Secp256k1Curve> {
            guard case .external(let key) = jwk.key, let key = key as? ECPrivateKey<Secp256k1Curve> else {
                throw FixtureError(description: "\(jwk.key) is not an external secp256k1 private key")
            }
            return key
        }

        @Test("OpenSSL's keys read as secp256k1 keys, with the point and thumbprints OpenSSL and jose give")
        func counterpartKeys() throws {
            let fixture = try KeysFixture(fixture: "keys", in: .module)
            #expect(fixture.keys.count == 4)
            for key in fixture.keys {
                let jwk = try JWK(json: Data(key.publicJwk.utf8), keyTypes: [.secp256k1])
                let publicKey = try Self.publicKey(jwk)
                #expect(publicKey.x963Representation == (try Data(hex: key.x963)))
                #expect(try jwk.thumbprint(using: .sha256).base64URLEncoded == key.thumbprints["sha256"])
                #expect(try jwk.thumbprint(using: .sha384).base64URLEncoded == key.thumbprints["sha384"])
                #expect(try jwk.thumbprint(using: .sha512).base64URLEncoded == key.thumbprints["sha512"])
                #expect(try JWK(json: try jwk.jsonRepresentation(), keyTypes: [.secp256k1]) == jwk)

                let privateJWK = try PrivateJWK(json: Data(key.privateJwk.utf8), keyTypes: [.secp256k1])
                let privateKey = try Self.privateKey(privateJWK)
                #expect(privateKey.publicKey == publicKey)
                #expect(privateJWK.publicJWK == jwk)
                #expect(
                    try ECPrivateKey<Secp256k1Curve>(rawRepresentation: privateKey.rawRepresentation).publicKey
                        == publicKey
                )
                let written = try PrivateJWK(json: try privateJWK.jsonRepresentation(), keyTypes: [.secp256k1])
                #expect(try Self.privateKey(written).rawRepresentation == privateKey.rawRepresentation)

                // Without keyTypes the key is kept, but as an unrecognised key with no thumbprint.
                let unrecognized = try JWK(json: Data(key.publicJwk.utf8))
                guard case .unrecognized = unrecognized.key else {
                    Issue.record("a secp256k1 key was recognised without keyTypes")
                    continue
                }
                #expect(throws: JWKError.thumbprintUnavailable(keyType: "EC")) { try unrecognized.thumbprint() }
            }
        }

        /// Documents that are refused here whatever OpenSSL does with them.
        ///
        /// - Coordinate and scalar length: OpenSSL tolerates a leading zero byte too many or too few;
        ///   RFC 7518 §6.2.1.2 and §6.2.2.1 require the full size, and equal keys must have equal JWKs.
        /// - `d` in a public key: OpenSSL derives the public key from it. `JWK` is the public-key type.
        /// - A `d` that is not a key, or that belongs to another key: OpenSSL reads `d`, `x` and `y`
        ///   without checking that they belong together, or that `d` is in range.
        static func expectedStricterError(type: String, name: String) -> JWKError? {
            switch (type, name) {
            case ("public", "x has one byte too many"):
                return .wrongByteCount(member: "x", curve: "secp256k1", expected: 32, found: 33)
            case ("public", "private member d present"):
                return .privateMemberInPublicKey(member: "d", keyType: "EC")
            case ("private", "d from a different key"):
                return .privateKeyDoesNotMatchPublicKey(curve: "secp256k1")
            case ("private", "d is zero"), ("private", "d is the order"):
                return .invalidPrivateKey(curve: "secp256k1")
            case ("private", "d has one byte too few"):
                return .wrongByteCount(member: "d", curve: "secp256k1", expected: 32, found: 31)
            default:
                return nil
            }
        }

        @Test("accepts and rejects the same documents as OpenSSL, apart from the documented stricter cases")
        func parsingAgreesWithCounterpart() throws {
            let fixture = try ParsingFixture(fixture: "jwk-parsing", in: .module)
            var accepted = 0
            var rejected = 0
            var stricter = 0
            for testCase in fixture.cases {
                let label = Comment(rawValue: "\(testCase.type): \(testCase.name)")
                let json = Data(testCase.json.utf8)
                func parse() throws {
                    if testCase.type == "public" {
                        _ = try Self.publicKey(try JWK(json: json, keyTypes: [.secp256k1]))
                    } else {
                        _ = try Self.privateKey(try PrivateJWK(json: json, keyTypes: [.secp256k1]))
                    }
                }
                if let expected = Self.expectedStricterError(type: testCase.type, name: testCase.name) {
                    #expect(throws: expected, label) { try parse() }
                    stricter += 1
                } else if testCase.openssl.accepted {
                    #expect(throws: Never.self, label) { try parse() }
                    accepted += 1
                } else {
                    #expect(throws: JWKError.self, label) { try parse() }
                    rejected += 1
                }

                // A public key read without keyTypes is unrecognised, and building a verifier from it
                // checks it as reading it with keyTypes would.
                if testCase.type == "public" {
                    let viaKeyTypes = Self.succeeds { _ = try JWK(json: json, keyTypes: [.secp256k1]) }
                    let viaVerifier = Self.succeeds { _ = try ECDSAVerifier<Secp256k1Curve>(jwk: try JWK(json: json)) }
                    #expect(viaKeyTypes == viaVerifier, label)
                }
            }
            #expect(accepted == 5)
            #expect(rejected == 9)
            #expect(stricter == 6)
        }

        private static func succeeds(_ body: () throws -> Void) -> Bool {
            do {
                try body()
                return true
            } catch {
                return false
            }
        }

        @Test("keyTypes reads an EC key on secp256k1, and no other kty or curve")
        func onlyECOnSecp256k1() throws {
            let key = try ECPrivateKey<Secp256k1Curve>()
            let x = String(base64URLEncoding: key.publicKey.x)
            let y = String(base64URLEncoding: key.publicKey.y)
            let d = String(base64URLEncoding: key.rawRepresentation)
            let cases: [(kty: String, crv: String, privateError: JWKError)] = [
                ("OKP", "secp256k1", .keyTypeMismatch(expected: "OKP Ed25519 or X25519", found: "OKP secp256k1")),
                ("EC", "P-999", .keyTypeMismatch(expected: "EC P-256, P-384 or P-521", found: "EC P-999")),
            ]
            for (kty, crv, privateError) in cases {
                let members = #""kty":"\#(kty)","crv":"\#(crv)","x":"\#(x)","y":"\#(y)""#
                guard case .unrecognized = try JWK(json: Data("{\(members)}".utf8), keyTypes: [.secp256k1]).key else {
                    Issue.record("read as a secp256k1 key: \(kty) \(crv)")
                    continue
                }
                #expect(throws: privateError) {
                    try PrivateJWK(json: Data(#"{\#(members),"d":"\#(d)"}"#.utf8), keyTypes: [.secp256k1])
                }
            }
        }

        @Test("generated keys are distinct, valid and agree with their own JWKs")
        func generatedKeys() throws {
            var scalars: Set<Data> = []
            for _ in 0..<8 {
                let key = try ECPrivateKey<Secp256k1Curve>()
                scalars.insert(key.rawRepresentation)
                let jwk = PrivateJWK(.external(key))
                let read = try PrivateJWK(json: try jwk.jsonRepresentation(), keyTypes: [.secp256k1])
                #expect(try Self.privateKey(read).publicKey == key.publicKey)
                #expect(try Self.publicKey(read.publicJWK) == key.publicKey)
            }
            #expect(scalars.count == 8)
        }
    }
#endif
