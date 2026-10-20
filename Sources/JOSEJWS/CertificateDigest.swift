import Foundation

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// The digests `x5t` and `x5t#S256` carry: over the DER of the first certificate in `x5c`.
enum CertificateDigest {
    /// `x5t` (RFC 7515 §4.1.7).
    case sha1
    /// `x5t#S256` (RFC 7515 §4.1.8).
    case sha256

    /// The header parameter that carries this digest.
    var parameter: String {
        switch self {
        case .sha1:
            return "x5t"
        case .sha256:
            return "x5t#S256"
        }
    }

    func digest(of der: Data) -> Data {
        switch self {
        case .sha1:
            return Data(Insecure.SHA1.hash(data: der))
        case .sha256:
            return Data(SHA256.hash(data: der))
        }
    }
}
