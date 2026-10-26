import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import SwiftASN1
// The SPI is swift-certificates' supported way to validate at a time other than "now", which
// its deprecation notice for `RFC5280Policy(validationTime:)` points to.
@_spi(FixedExpiryValidationTime) import X509

/// Validates `x5c` chains by RFC 5280 path validation against explicit trust anchors, on every
/// platform, with [swift-certificates](https://github.com/apple/swift-certificates).
///
/// The anchors are the whole story: a chain is accepted only if it ends at one of them. No
/// system root store is consulted, because a certificate from any public CA is not evidence that
/// the expected issuer signed the token. Pass the issuer's own CA certificates.
///
/// Checked: signatures along the chain, validity periods, basic constraints and path length,
/// name constraints, unhandled critical extensions, and key usage (an issuer's must allow
/// certificate signing and the signing certificate's must allow digital signatures, wherever
/// the extension is present). Not checked: revocation, by OCSP or CRLs. A missing intermediate
/// is not fetched from anywhere; the chain in `x5c` has to stand on its own.
public struct X509CertificateChainValidator: CertificateChainValidator {
    private let anchors: CertificateStore
    private let clock: @Sendable () -> Date

    /// - Parameters:
    ///   - anchors: DER certificates the chain must end at. At least one is required.
    ///   - clock: The time at which validity periods are checked. Injectable for tests.
    public init(anchors: [Data], clock: @escaping @Sendable () -> Date = { Date() })
        throws(CertificateValidationError)
    {
        let certificates = try Self.certificates(anchors)
        guard !certificates.isEmpty else {
            throw .trustEvaluationFailed(description: "no trust anchors were given")
        }
        self.anchors = CertificateStore(certificates)
        self.clock = clock
    }

    public func validate(chain: [Data]) async throws -> JWK {
        let certificates = try Self.certificates(chain)
        guard let leaf = certificates.first else {
            throw CertificateValidationError.trustEvaluationFailed(description: "the chain is empty")
        }
        let validationTime = clock()
        var verifier = X509.Verifier(rootCertificates: anchors) {
            RFC5280Policy(fixedExpiryValidationTime: validationTime)
            KeyUsagePolicy()
        }
        let result = await verifier.validate(leaf: leaf, intermediates: CertificateStore(certificates.dropFirst()))
        guard case .validCertificate = result else {
            throw CertificateValidationError.trustEvaluationFailed(description: Self.describe(result))
        }
        return try Self.publicKey(of: leaf)
    }

    private static func certificates(_ ders: [Data]) throws(CertificateValidationError) -> [Certificate] {
        var certificates: [Certificate] = []
        for (index, der) in ders.enumerated() {
            do {
                certificates.append(try Certificate(derEncoded: [UInt8](der)))
            } catch {
                throw .certificateUnreadable(index: index)
            }
        }
        return certificates
    }

    private static func describe(_ result: CertificateValidationResult) -> String {
        guard case .couldNotValidate(let failures) = result, !failures.isEmpty else {
            return "no chain to a trust anchor could be built"
        }
        return failures.map(\.policyFailureReason.description).joined(separator: "; ")
    }

    /// The certificate's subject public key as a JWK.
    private static func publicKey(of certificate: Certificate) throws(CertificateValidationError) -> JWK {
        var serializer = DER.Serializer()
        do {
            try serializer.serialize(certificate.publicKey)
        } catch {
            throw .unsupportedKey(description: "the key could not be encoded: \(error)")
        }
        do {
            return try JWK(derRepresentation: Data(serializer.serializedBytes))
        } catch {
            throw .keyUnusable(error)
        }
    }
}

/// Key usage (RFC 5280 §4.2.1.3), which swift-certificates' `RFC5280Policy` deliberately leaves
/// unchecked. Where the extension is present, an issuer's must allow certificate signing, as
/// OpenSSL and Security.framework require, and the signing certificate's must allow digital
/// signatures, since its key is about to verify one.
struct KeyUsagePolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [.X509ExtensionID.keyUsage]

    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        for (index, certificate) in chain.enumerated() {
            let keyUsage: KeyUsage?
            do {
                keyUsage = try certificate.extensions.keyUsage
            } catch {
                return .failsToMeetPolicy(reason: "certificate \(index) has a malformed key usage extension")
            }
            guard let keyUsage else {
                continue
            }
            if index == 0 {
                guard keyUsage.digitalSignature else {
                    return .failsToMeetPolicy(reason: "the signing certificate's key usage does not allow signatures")
                }
            } else {
                guard keyUsage.keyCertSign else {
                    return .failsToMeetPolicy(
                        reason: "certificate \(index)'s key usage does not allow signing certificates"
                    )
                }
            }
        }
        return .meetsPolicy
    }
}
