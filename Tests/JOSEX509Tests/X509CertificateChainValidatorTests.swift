import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import JOSEX509
import TestSupport
import Testing

@Suite("X.509 certificate chain validation")
struct X509CertificateChainValidatorTests {
    private static func validator(
        for testCase: ChainsFixture.Case,
        in fixture: ChainsFixture
    ) throws -> X509CertificateChainValidator {
        let time = Date(timeIntervalSince1970: testCase.validationTime)
        return try X509CertificateChainValidator(anchors: try testCase.anchorDERs(in: fixture), clock: { time })
    }

    /// Chains refused here, or keys not returned, whatever OpenSSL makes of them.
    ///
    /// - Key usage without `digitalSignature`: the signing certificate's key is about to verify a
    ///   signature. OpenSSL checks a leaf's key usage only when asked for a purpose.
    /// - secp256k1: the chain is valid, but swift-certificates cannot read a certificate whose key
    ///   is on a curve it does not support.
    static func expectedStricterOutcome(_ name: String) -> Outcome? {
        switch name {
        case "leaf key usage without digitalSignature":
            return .refused
        case "secp256k1 leaf":
            return .unreadable(index: 0)
        default:
            return nil
        }
    }

    @Test("accepts and refuses the same chains as OpenSSL, apart from the documented stricter cases")
    func agreesWithCounterpart() async throws {
        let fixture = try ChainsFixture.load()
        var accepted = 0
        var refused = 0
        var stricter = 0
        for testCase in fixture.cases {
            let label = Comment(rawValue: testCase.name)
            let validator = try Self.validator(for: testCase, in: fixture)
            let chain = try testCase.chainDERs()
            let outcome = await Outcome { try await validator.validate(chain: chain) }
            if let expected = Self.expectedStricterOutcome(testCase.name) {
                #expect(outcome == expected, label)
                stricter += 1
            } else {
                #expect(outcome == (try testCase.opensslOutcome()), label)
                accepted += testCase.openssl.accepted ? 1 : 0
                refused += testCase.openssl.accepted ? 0 : 1
            }
        }
        #expect(accepted == 9)
        #expect(refused == 12)
        #expect(stricter == 2)
    }

    @Test("the clock decides validity: the expired leaf is accepted inside its validity and not after")
    func clock() async throws {
        let fixture = try ChainsFixture.load()
        let testCase = try fixture.testCase("expired leaf, validated during its validity")
        let anchors = try testCase.anchorDERs(in: fixture)
        let chain = try testCase.chainDERs()
        let backThen = Date(timeIntervalSince1970: testCase.validationTime)
        let then = try X509CertificateChainValidator(anchors: anchors, clock: { backThen })
        #expect(await Outcome { try await then.validate(chain: chain) } == (try testCase.opensslOutcome()))
        // The default clock is the current time, by which this leaf, valid during 2020, has expired.
        let now = try X509CertificateChainValidator(anchors: anchors)
        #expect(await Outcome { try await now.validate(chain: chain) } == .refused)
    }

    @Test("data that is not a certificate is reported by its position, in the chain and in the anchors")
    func unreadable() async throws {
        let fixture = try ChainsFixture.load()
        let testCase = try fixture.testCase("RSA leaf under an intermediate")
        let validator = try Self.validator(for: testCase, in: fixture)
        let chain = try testCase.chainDERs()
        let garbage = Data("garbage".utf8)
        #expect(await Outcome { try await validator.validate(chain: [garbage]) } == .unreadable(index: 0))
        #expect(await Outcome { try await validator.validate(chain: [chain[0], garbage]) } == .unreadable(index: 1))
        #expect(await Outcome { try await validator.validate(chain: []) } == .refused)

        let anchors = try testCase.anchorDERs(in: fixture)
        #expect(throws: CertificateValidationError.self) {
            try X509CertificateChainValidator(anchors: [])
        }
        #expect(throws: CertificateValidationError.self) {
            try X509CertificateChainValidator(anchors: anchors + [garbage])
        }
    }

    @Test("a JWS carrying its certificate chain in x5c verifies against the CA, and not against another")
    func endToEnd() async throws {
        let fixture = try ChainsFixture.load()
        for name in ["P-256 leaf under the root", "RSA leaf under an intermediate"] {
            let testCase = try fixture.testCase(name)
            let label = Comment(rawValue: name)
            let chain = try testCase.chainDERs()
            var header = JWSHeaderParameters<EmptyHeaderParameters>()
            header.x509CertificateChain = chain.map { $0.base64EncodedString() }

            let privateJWK = try PrivateJWK(json: Data(testCase.privateJwk.utf8))
            let token: String
            let forged: String
            switch privateJWK.key {
            case .p256(let key):
                token = try await Self.sign(with: try ECDSASigner(privateKey: key), header: header)
                forged = try await Self.sign(
                    with: try ECDSASigner(privateKey: try ECPrivateKey<P256Curve>()),
                    header: header
                )
            case .rsa(let key):
                token = try await Self.sign(with: try RSASigner<RS256>(privateKey: key), header: header)
                forged = try await Self.sign(
                    with: try RSASigner<RS256>(privateKey: try RSAPrivateKey()),
                    header: header
                )
            default:
                Issue.record("\(name): unexpected key type")
                continue
            }

            let time = Date(timeIntervalSince1970: testCase.validationTime)
            func resolver(anchor: String) throws -> HeaderKeyResolver {
                HeaderKeyResolver(
                    algorithms: [.es256, .rs256],
                    certificateChainValidator: try X509CertificateChainValidator(
                        anchors: [try fixture.anchor(anchor)],
                        clock: { time }
                    )
                )
            }
            let trusted = try resolver(anchor: "root")
            let verified = try await SimpleJWS.Unverified(compact: token).verify(resolving: trusted)
            #expect(verified.payload == Data("signed".utf8), label)

            await #expect(throws: JWSError.self, label) {
                try await SimpleJWS.Unverified(compact: token).verify(resolving: try resolver(anchor: "other-root"))
            }
            // The certificate is trusted, but the token was not signed by its key.
            await #expect(throws: JWSError.self, label) {
                try await SimpleJWS.Unverified(compact: forged).verify(resolving: trusted)
            }
        }
    }

    private static func sign<S: Signer>(
        with signer: S,
        header: JWSHeaderParameters<EmptyHeaderParameters>
    ) async throws -> String {
        try await SimpleJWS.Signed(signing: Data("signed".utf8), with: signer, header: header).compactSerialization()
    }
}
