// X.509 evaluation through Security.framework, which exists only on Apple platforms.
#if canImport(Security)
    import Foundation
    import JOSECore
    import JOSEJWK
    import Security

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
            // Each setting is checked: a failed call would leave the evaluation running with
            // the framework's defaults, which are the opposite of what this validator promises.
            let settings: [(String, OSStatus)] = [
                ("anchors", SecTrustSetAnchorCertificates(trust, anchors.certificates as CFArray)),
                // Only the given anchors, not these plus the system's. No test fails when this is
                // turned off: the fixtures contain no chain to a system root, so there is nothing
                // the system store could wrongly accept. It is kept on its documented behaviour.
                ("anchors only", SecTrustSetAnchorCertificatesOnly(trust, true)),
                // A missing intermediate must not make this process fetch it from a URL the
                // certificate names; the chain in `x5c` has to stand on its own.
                ("network fetch", SecTrustSetNetworkFetchAllowed(trust, false)),
                ("verify date", SecTrustSetVerifyDate(trust, clock() as CFDate)),
            ]
            for (setting, status) in settings where status != errSecSuccess {
                throw CertificateValidationError.trustEvaluationFailed(
                    description: "could not set \(setting): \(status)"
                )
            }

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
