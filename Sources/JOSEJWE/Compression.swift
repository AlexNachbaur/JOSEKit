import Foundation

/// Why compressed content could not be produced or read.
enum CompressionError: Error, Equatable {
    /// The output passed the limit; reading stopped there.
    case tooLarge
    /// The input is not a single, complete stream in the algorithm's format.
    case malformed
    /// The compressor itself failed.
    case failed
}

/// A way of compressing the plaintext before encryption, as `zip` names it.
protocol CompressionAlgorithm: Sendable {
    func compress(_ data: Data) throws(CompressionError) -> Data
    /// Decompresses `data`, refusing it as soon as the output would exceed `limit` bytes.
    func decompress(_ data: Data, limit: Int) throws(CompressionError) -> Data
}

/// How the plaintext is compressed before encryption, the `zip` header parameter
/// (RFC 7516 §4.1.3).
///
/// Only the compressions this platform supports are cases, so code that asks for one that is not
/// available does not compile. A received JWE naming one is refused with
/// ``JWEError/unsupportedCompression(algorithm:)``.
public enum JWECompression: RawRepresentable, Sendable, Hashable {
    #if canImport(CZlib)
        /// Raw DEFLATE (RFC 1951), `zip` value `DEF`. It uses the system zlib, so it is not
        /// available on Windows, which has none.
        case deflate
    #endif

    /// The largest decompressed plaintext a decryption accepts by default, in bytes. The same as
    /// panva/jose's default. Compression lets a small token expand into a large plaintext, so a
    /// decryption refuses anything larger.
    public static let defaultMaximumDecompressedByteCount = 250_000

    /// The compression `zip` names, or `nil` if this platform does not support it.
    public init?(rawValue: String) {
        switch rawValue {
        #if canImport(CZlib)
            case "DEF":
                self = .deflate
        #endif
        default:
            return nil
        }
    }

    /// The `zip` value.
    public var rawValue: String {
        switch self {
        #if canImport(CZlib)
            case .deflate:
                return "DEF"
        #endif
        }
    }

    var algorithm: any CompressionAlgorithm {
        switch self {
        #if canImport(CZlib)
            case .deflate:
                return DeflateCompression()
        #endif
        }
    }

    func compress(_ data: Data) throws(CompressionError) -> Data {
        try algorithm.compress(data)
    }

    func decompress(_ data: Data, limit: Int) throws(CompressionError) -> Data {
        try algorithm.decompress(data, limit: limit)
    }
}
