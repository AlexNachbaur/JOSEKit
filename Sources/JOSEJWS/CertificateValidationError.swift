import JOSEJWK

/// Why a ``CertificateChainValidator`` refused a chain or could not use its key: the error of
/// ``SecTrustCertificateChainValidator`` and of JOSEX509's `X509CertificateChainValidator`.
public enum CertificateValidationError: Error, Sendable {
    /// An element of the chain is not a certificate the validator can read: not DER, or, for
    /// `X509CertificateChainValidator`, holding a key swift-certificates does not support.
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
            return "certificate \(index) in the chain could not be read"
        case .trustEvaluationFailed(let description):
            return "certificate chain is not trusted: \(description)"
        case .unsupportedKey(let description):
            return "the signing certificate's key cannot be used: \(description)"
        case .keyUnusable(let error):
            return "the signing certificate's key cannot be used: \(error)"
        }
    }
}
