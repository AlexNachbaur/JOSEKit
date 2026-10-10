// X.509 evaluation through Security.framework, which exists only on Apple platforms.
#if canImport(Security)
    import Foundation
    import JOSECore
    import JOSEJWK
    import Security

    /// Why ``SecTrustCertificateChainValidator`` refused a chain or could not use its key.
    public enum CertificateValidationError: Error, Sendable {
        /// An element of the chain is not a DER certificate.
        case certificateUnreadable(index: Int)
        case trustEvaluationFailed(description: String)
        /// The first certificate's key is not a type this package can verify with.
        case unsupportedKey(description: String)
        case keyUnusable(JWKError)
    }

    extension CertificateValidationError: CustomStringConvertible {
        public var description: String {
            switch self {
            case .certificateUnreadable(let index):
                return "certificate \(index) in the chain is not DER"
            case .trustEvaluationFailed(let description):
                return "certificate chain is not trusted: \(description)"
            case .unsupportedKey(let description):
                return "the signing certificate's key cannot be used: \(description)"
            case .keyUnusable(let error):
                return "the signing certificate's key cannot be used: \(error)"
            }
        }
    }

    /// `SecCertificate` is not declared `Sendable`. The anchors are created once and only read
    /// afterwards, which Apple documents as safe.
    private struct Anchors: @unchecked Sendable {
        let certificates: [SecCertificate]
    }

    /// Validates `x5c` chains with Security.framework against explicit trust anchors.
    ///
    /// The anchors are the whole story: a chain is accepted only if it ends at one of them. The
    /// system's root store is not consulted, because a certificate from any public CA is not
    /// evidence that the expected issuer signed the token. Pass the issuer's own CA certificates.
    public struct SecTrustCertificateChainValidator: CertificateChainValidator {
        private let anchors: Anchors
        private let clock: @Sendable () -> Date

        /// - Parameters:
        ///   - anchors: DER certificates the chain must end at. At least one is required.
        ///   - clock: The time at which validity periods are checked. Injectable for tests.
        public init(anchors: [Data], clock: @escaping @Sendable () -> Date = { Date() })
            throws(CertificateValidationError)
        {
            var certificates: [SecCertificate] = []
            for (index, der) in anchors.enumerated() {
                guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
                    throw .certificateUnreadable(index: index)
                }
                certificates.append(certificate)
            }
            guard !certificates.isEmpty else {
                throw .trustEvaluationFailed(description: "no trust anchors were given")
            }
            self.anchors = Anchors(certificates: certificates)
            self.clock = clock
        }

        public func validate(chain: [Data]) async throws -> JWK {
            var certificates: [SecCertificate] = []
            for (index, der) in chain.enumerated() {
                guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
                    throw CertificateValidationError.certificateUnreadable(index: index)
                }
                certificates.append(certificate)
            }
            guard let leaf = certificates.first else {
                throw CertificateValidationError.trustEvaluationFailed(description: "the chain is empty")
            }

            var trust: SecTrust?
            let creation = SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust)
            guard creation == errSecSuccess, let trust else {
                throw CertificateValidationError.trustEvaluationFailed(
                    description: "SecTrustCreateWithCertificates: \(creation)"
                )
            }
            SecTrustSetAnchorCertificates(trust, anchors.certificates as CFArray)
            // Only the given anchors, not these plus the system's. No test fails when this is
            // turned off: the fixtures contain no chain to a system root, so there is nothing
            // the system store could wrongly accept. It is kept on its documented behaviour.
            SecTrustSetAnchorCertificatesOnly(trust, true)
            SecTrustSetVerifyDate(trust, clock() as CFDate)

            var error: CFError?
            guard SecTrustEvaluateWithError(trust, &error) else {
                var description = "evaluation failed"
                if let error {
                    description = String(describing: error)
                }
                throw CertificateValidationError.trustEvaluationFailed(description: description)
            }
            return try Self.publicKey(of: leaf)
        }

        /// The certificate's subject public key as a JWK.
        static func publicKey(of certificate: SecCertificate) throws -> JWK {
            guard let key = SecCertificateCopyKey(certificate) else {
                throw CertificateValidationError.unsupportedKey(description: "the key could not be read")
            }
            guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] else {
                throw CertificateValidationError.unsupportedKey(description: "the key has no attributes")
            }
            var error: Unmanaged<CFError>?
            guard let external = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
                throw CertificateValidationError.unsupportedKey(description: "the key could not be exported")
            }
            let keyType = attributes[kSecAttrKeyType] as? String
            let rsaType = kSecAttrKeyTypeRSA as String
            let ecType = kSecAttrKeyTypeECSECPrimeRandom as String
            do {
                switch keyType {
                case rsaType:
                    return JWK(.rsa(try RSAPublicKey(pkcs1DERRepresentation: external)))
                case ecType:
                    // The external representation of an EC key is its X9.63 point; the curve
                    // follows from its length.
                    switch external.count {
                    case 65:
                        return JWK(.p256(try ECPublicKey<P256Curve>(x963Representation: external)))
                    case 97:
                        return JWK(.p384(try ECPublicKey<P384Curve>(x963Representation: external)))
                    case 133:
                        return JWK(.p521(try ECPublicKey<P521Curve>(x963Representation: external)))
                    default:
                        throw CertificateValidationError.unsupportedKey(
                            description: "EC key of \(external.count) bytes"
                        )
                    }
                default:
                    throw CertificateValidationError.unsupportedKey(description: "key type \(keyType ?? "unknown")")
                }
            } catch let error as JWKError {
                throw CertificateValidationError.keyUnusable(error)
            }
        }
    }
#endif
