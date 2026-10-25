#if canImport(P256K)
    import Foundation
    import JOSECore
    import JOSEJWK
    import JOSEJWS
    import TestSupport
    import Testing

    @testable import JOSESecp256k1

    @Suite("ES256K")
    struct ES256KTests {
        private static func verdict(_ token: String, keys: VerificationKeys) async -> Data? {
            do {
                return try await SimpleJWS.Unverified(compact: token).verify(with: keys).payload
            } catch {
                return nil
            }
        }

        @Test("verdicts on OpenSSL's JWSs match OpenSSL's, in both S forms, for a key read either way")
        func counterpartSignatures() async throws {
            let fixture = try SignaturesFixture(fixture: "signatures", in: .module)
            var accepted: [String: Int] = [:]
            for testCase in fixture.cases {
                let label = Comment(rawValue: testCase.name)
                let json = Data(testCase.jwk.utf8)
                let set = try JWKSet(json: Data(#"{"keys":[\#(testCase.jwk)]}"#.utf8), keyTypes: [.secp256k1])
                let viaKeyTypes = VerificationKeys(jwks: set, allowing: [.es256k])
                #expect(viaKeyTypes.algorithms == ["ES256K"], label)
                // Read without keyTypes, the key is unrecognised, and the verifier interprets it.
                let viaUnrecognized = VerificationKeys([try ES256K().verifier(for: try JWK(json: json))])

                for keys in [viaKeyTypes, viaUnrecognized] {
                    let payload = await Self.verdict(testCase.token, keys: keys)
                    if testCase.openssl.accepted {
                        #expect(payload == (try Data(hex: testCase.payload)), label)
                        accepted[testCase.name, default: 0] += 1
                    } else {
                        #expect(payload == nil, label)
                    }
                }
            }
            #expect(accepted == ["low S": 12, "high S": 12])
        }

        @Test("signs JWSs that verify, always with a low S")
        func signing() async throws {
            let key = try ECPrivateKey<Secp256k1Curve>()
            let signer = try ECDSASigner(privateKey: key, keyID: "k1")
            let keys = VerificationKeys([try ES256K().verifier(for: JWK(.external(JWK.ExternalKey(key.publicKey))))])
            for index in 0..<64 {
                let payload = Data("message \(index)".utf8)
                let signed = try await SimpleJWS.Signed(signing: payload, with: signer, header: JWSHeaderParameters())
                #expect(signed.header.algorithm == "ES256K")
                #expect(signed.header.keyID == "k1")
                let token = try signed.compactSerialization()
                #expect(await Self.verdict(token, keys: keys) == payload)

                let signature = RawECDSASignature(
                    rawSignature: try Data(base64URLEncoded: String(token.split(separator: ".")[2]))
                )
                #expect(!RawECDSASignature.halfOrder.lexicographicallyPrecedes(signature.s))
            }
        }

        @Test("S above half the order is replaced by order minus S, and S at or below it is kept")
        func lowSBoundary() throws {
            func signature(s: [UInt8]) -> RawECDSASignature {
                RawECDSASignature(rawSignature: Data([UInt8](repeating: 0xAB, count: 32) + s))
            }
            func lowS(_ s: [UInt8]) -> [UInt8] {
                Array(signature(s: s).lowS.suffix(32))
            }
            let half = RawECDSASignature.halfOrder
            let order = RawECDSASignature.order
            let one = [UInt8](repeating: 0, count: 31) + [1]
            var halfPlusOne = half
            halfPlusOne[31] += 1
            var orderMinusOne = order
            orderMinusOne[31] -= 1

            #expect(lowS(one) == one)
            #expect(lowS(half) == half)
            // The order is odd, so order - (half + 1) is half.
            #expect(lowS(halfPlusOne) == half)
            #expect(lowS(orderMinusOne) == one)
            #expect(signature(s: half).lowS.prefix(32) == Data(repeating: 0xAB, count: 32))
        }

        @Test("the key's use, key_ops and alg are honoured, however the key was read")
        func keyRestrictions() throws {
            let key = try ECPrivateKey<Secp256k1Curve>().publicKey
            let base =
                #""kty":"EC","crv":"secp256k1","x":"\#(String(base64URLEncoding: key.x))","y":"\#(String(base64URLEncoding: key.y))""#
            let restricted: [(String, JWKError)] = [
                (#""use":"enc""#, .useNotPermitted(use: "enc", required: "sig")),
                (#""key_ops":["sign"]"#, .keyOperationNotPermitted(operations: ["sign"], required: "verify")),
                (#""alg":"ES256""#, .algorithmMismatch(keyAlgorithm: "ES256", required: "ES256K")),
            ]
            for (member, error) in restricted {
                let json = Data("{\(base),\(member)}".utf8)
                #expect(throws: error) { try ES256K().verifier(for: try JWK(json: json, keyTypes: [.secp256k1])) }
                #expect(throws: error) { try ES256K().verifier(for: try JWK(json: json)) }
            }
            #expect(throws: Never.self) {
                try ES256K().verifier(for: try JWK(json: Data(#"{\#(base),"alg":"ES256K"}"#.utf8)))
            }
        }

        @Test("ES256K takes only secp256k1 keys, and the NIST algorithms take none")
        func keyTypeMismatch() throws {
            let secp256k1 = JWK(.external(JWK.ExternalKey(try ECPrivateKey<Secp256k1Curve>().publicKey)))
            let p256 = JWK(.p256(try ECPrivateKey<P256Curve>().publicKey))
            #expect(throws: JWKError.keyTypeMismatch(expected: "EC secp256k1", found: "EC P-256")) {
                try ES256K().verifier(for: p256)
            }
            #expect(throws: JWKError.keyTypeMismatch(expected: "EC P-256", found: "EC secp256k1")) {
                try ES256().verifier(for: secp256k1)
            }
            #expect(throws: JWKError.self) {
                try ES256().verifier(for: try JWK(json: try secp256k1.jsonRepresentation()))
            }
            #expect(
                VerificationKeys(jwks: JWKSet(keys: [secp256k1, p256]), allowing: [.es256k, .es256]).algorithms == [
                    "ES256K", "ES256",
                ]
            )
        }
    }
#endif
