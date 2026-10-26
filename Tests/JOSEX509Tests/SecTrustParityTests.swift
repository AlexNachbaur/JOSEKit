#if canImport(Security)
    import Foundation
    import JOSEJWK
    import JOSEJWS
    import TestSupport
    import Testing

    /// The same chains through ``SecTrustCertificateChainValidator``, the Apple-only alternative,
    /// so that where the two validators differ is written down rather than discovered.
    @Suite("SecTrust certificate chain validation against OpenSSL")
    struct SecTrustParityTests {
        /// Where Security.framework and OpenSSL part company.
        ///
        /// - Ed25519: the chain is valid, but `SecKey` has no Ed25519 keys, so the signing
        ///   certificate's key cannot be read. `X509CertificateChainValidator` returns it.
        /// - Malformed key usage: refused, as OpenSSL refuses it, but when the certificate is read
        ///   rather than during evaluation.
        /// - secp256k1: Security.framework refuses the chain. OpenSSL accepts it, and
        ///   `X509CertificateChainValidator` cannot read the certificate.
        ///
        /// Unlike `X509CertificateChainValidator`, Security.framework accepts a signing certificate
        /// whose key usage leaves out `digitalSignature`, as OpenSSL does.
        static func expectedDifference(_ name: String) -> Outcome? {
            switch name {
            case "Ed25519 leaf under an intermediate":
                return .unsupportedKey
            case "malformed key usage":
                return .unreadable(index: 0)
            case "secp256k1 leaf":
                return .refused
            default:
                return nil
            }
        }

        @Test("accepts and refuses the same chains as OpenSSL, apart from the documented differences")
        func agreesWithCounterpart() async throws {
            let fixture = try ChainsFixture.load()
            for testCase in fixture.cases {
                let label = Comment(rawValue: testCase.name)
                let time = Date(timeIntervalSince1970: testCase.validationTime)
                let validator = try SecTrustCertificateChainValidator(
                    anchors: try testCase.anchorDERs(in: fixture),
                    clock: { time }
                )
                let chain = try testCase.chainDERs()
                let outcome = await Outcome { try await validator.validate(chain: chain) }
                let expected = try Self.expectedDifference(testCase.name) ?? testCase.opensslOutcome()
                #expect(outcome == expected, label)
            }
        }
    }
#endif
