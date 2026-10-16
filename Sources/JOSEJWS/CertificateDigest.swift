import Foundation

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// The digests `x5t` and `x5t#S256` carry: over the DER of the first certificate in `x5c`.
struct CertificateDigest {
    private init() {}

    static func sha1(_ der: Data) -> Data {
        Data(Insecure.SHA1.hash(data: der))
    }

    static func sha256(_ der: Data) -> Data {
        Data(SHA256.hash(data: der))
    }
}
