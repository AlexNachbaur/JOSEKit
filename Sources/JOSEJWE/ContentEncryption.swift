import Foundation
import JOSECore
import JOSEJWK

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// An authenticated content encryption algorithm, the `enc` of a JWE (RFC 7518 §5).
///
/// The built-in algorithms are the cases of ``ContentEncryption``. To add one this package does
/// not ship, conform a type to this protocol, pass an instance when encrypting, and include it in
/// the list passed when decrypting.
public protocol ContentEncryptionAlgorithm: Sendable {
    var identifier: AlgorithmIdentifier { get }
    var keyByteCount: Int { get }
    var initializationVectorByteCount: Int { get }
    var authenticationTagByteCount: Int { get }

    func encrypt(
        _ plaintext: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> (ciphertext: Data, tag: Data)

    /// Must throw ``JWEError/decryptionFailed``, and nothing more specific, when the content
    /// does not authenticate.
    func decrypt(
        _ ciphertext: Data,
        tag: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> Data
}

// MARK: - The built-in algorithms

/// The content encryption algorithms this package implements. Each case delegates to the type
/// that implements it, such as ``A256GCM``.
public enum ContentEncryption: ContentEncryptionAlgorithm, CaseIterable, Hashable {
    case a128gcm
    case a192gcm
    case a256gcm
    case a128cbcHS256
    case a192cbcHS384
    case a256cbcHS512

    /// The type that implements this algorithm.
    public var algorithm: any ContentEncryptionAlgorithm {
        switch self {
        case .a128gcm:
            return A128GCM()
        case .a192gcm:
            return A192GCM()
        case .a256gcm:
            return A256GCM()
        case .a128cbcHS256:
            return A128CBCHS256()
        case .a192cbcHS384:
            return A192CBCHS384()
        case .a256cbcHS512:
            return A256CBCHS512()
        }
    }

    public var identifier: AlgorithmIdentifier {
        algorithm.identifier
    }

    public var keyByteCount: Int {
        algorithm.keyByteCount
    }

    public var initializationVectorByteCount: Int {
        algorithm.initializationVectorByteCount
    }

    public var authenticationTagByteCount: Int {
        algorithm.authenticationTagByteCount
    }

    public func encrypt(
        _ plaintext: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> (ciphertext: Data, tag: Data) {
        try algorithm.encrypt(
            plaintext,
            key: key,
            initializationVector: initializationVector,
            additionalAuthenticatedData: additionalAuthenticatedData
        )
    }

    public func decrypt(
        _ ciphertext: Data,
        tag: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> Data {
        try algorithm.decrypt(
            ciphertext,
            tag: tag,
            key: key,
            initializationVector: initializationVector,
            additionalAuthenticatedData: additionalAuthenticatedData
        )
    }
}

// So that `using: .a256gcm` reads naturally where any algorithm is accepted (SE-0299).
extension ContentEncryptionAlgorithm where Self == A128GCM {
    public static var a128gcm: A128GCM { A128GCM() }
}

extension ContentEncryptionAlgorithm where Self == A192GCM {
    public static var a192gcm: A192GCM { A192GCM() }
}

extension ContentEncryptionAlgorithm where Self == A256GCM {
    public static var a256gcm: A256GCM { A256GCM() }
}

extension ContentEncryptionAlgorithm where Self == A128CBCHS256 {
    public static var a128cbcHS256: A128CBCHS256 { A128CBCHS256() }
}

extension ContentEncryptionAlgorithm where Self == A192CBCHS384 {
    public static var a192cbcHS384: A192CBCHS384 { A192CBCHS384() }
}

extension ContentEncryptionAlgorithm where Self == A256CBCHS512 {
    public static var a256cbcHS512: A256CBCHS512 { A256CBCHS512() }
}

// MARK: - AES-GCM

/// AES-GCM with one key, for content encryption and for key wrapping.
struct AESGCM {
    let key: Data

    func seal(_ plaintext: Data, nonce: Data, aad: Data) throws(JWEError) -> (Data, Data) {
        do {
            let box = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: try AES.GCM.Nonce(data: nonce),
                authenticating: aad
            )
            return (Data(box.ciphertext), Data(box.tag))
        } catch {
            throw .contentEncryptionFailed(description: String(describing: error))
        }
    }

    func open(_ ciphertext: Data, tag: Data, nonce: Data, aad: Data) throws(JWEError) -> Data {
        do {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
        } catch {
            throw .decryptionFailed
        }
    }
}

protocol AESGCMContentEncryption: ContentEncryptionAlgorithm {}

extension AESGCMContentEncryption {
    public var initializationVectorByteCount: Int {
        12
    }

    public var authenticationTagByteCount: Int {
        16
    }

    public func encrypt(
        _ plaintext: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> (ciphertext: Data, tag: Data) {
        try AESGCM(key: key).seal(plaintext, nonce: initializationVector, aad: additionalAuthenticatedData)
    }

    public func decrypt(
        _ ciphertext: Data,
        tag: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> Data {
        try AESGCM(key: key).open(ciphertext, tag: tag, nonce: initializationVector, aad: additionalAuthenticatedData)
    }
}

/// AES GCM with a 128-bit key (RFC 7518 §5.3).
public struct A128GCM: AESGCMContentEncryption {
    public let identifier: AlgorithmIdentifier = "A128GCM"
    public let keyByteCount = 16

    public init() {}
}

/// AES GCM with a 192-bit key (RFC 7518 §5.3).
public struct A192GCM: AESGCMContentEncryption {
    public let identifier: AlgorithmIdentifier = "A192GCM"
    public let keyByteCount = 24

    public init() {}
}

/// AES GCM with a 256-bit key (RFC 7518 §5.3).
public struct A256GCM: AESGCMContentEncryption {
    public let identifier: AlgorithmIdentifier = "A256GCM"
    public let keyByteCount = 32

    public init() {}
}

// MARK: - AES-CBC with HMAC

/// AES_CBC_HMAC_SHA2 (RFC 7518 §5.2). The key is two halves: the first authenticates, the second
/// encrypts. The tag is the first half of an HMAC over the additional data, IV, ciphertext and
/// the additional data's length.
protocol AESCBCHMACContentEncryption: ContentEncryptionAlgorithm {
    associatedtype Hash: HashFunction
}

extension AESCBCHMACContentEncryption {
    public var initializationVectorByteCount: Int {
        16
    }

    public var authenticationTagByteCount: Int {
        keyByteCount / 2
    }

    private func tag(macKey: Data, aad: Data, iv: Data, ciphertext: Data) -> Data {
        var length = UInt64(aad.count) * 8
        var lengthBytes = Data(count: 8)
        for index in stride(from: 7, through: 0, by: -1) {
            lengthBytes[index] = UInt8(length & 0xFF)
            length >>= 8
        }
        var mac = HMAC<Hash>(key: SymmetricKey(data: macKey))
        mac.update(data: aad)
        mac.update(data: iv)
        mac.update(data: ciphertext)
        mac.update(data: lengthBytes)
        return Data(mac.finalize()).prefix(authenticationTagByteCount)
    }

    public func encrypt(
        _ plaintext: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> (ciphertext: Data, tag: Data) {
        let half = keyByteCount / 2
        let keyBytes = Data(key)
        let ciphertext: Data
        do {
            ciphertext = try PlatformAESCBC(key: keyBytes.suffix(half)).encrypt(plaintext, iv: initializationVector)
        } catch {
            throw .contentEncryptionFailed(description: String(describing: error))
        }
        let tag = tag(
            macKey: keyBytes.prefix(half),
            aad: additionalAuthenticatedData,
            iv: initializationVector,
            ciphertext: ciphertext
        )
        return (ciphertext, tag)
    }

    public func decrypt(
        _ ciphertext: Data,
        tag: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> Data {
        let half = keyByteCount / 2
        let keyBytes = Data(key)
        let expected = self.tag(
            macKey: keyBytes.prefix(half),
            aad: additionalAuthenticatedData,
            iv: initializationVector,
            ciphertext: ciphertext
        )
        // The tag is checked, in constant time, before any decryption. Decrypting first and
        // reporting bad padding is the classic padding-oracle mistake.
        guard expected.constantTimeEquals(tag) else {
            throw .decryptionFailed
        }
        do {
            return try PlatformAESCBC(key: keyBytes.suffix(half)).decrypt(ciphertext, iv: initializationVector)
        } catch {
            throw .decryptionFailed
        }
    }
}

extension Data {
    /// Compares without stopping at the first difference, so that timing does not reveal how
    /// many leading bytes of a forged tag were right.
    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else {
            return false
        }
        var difference: UInt8 = 0
        for (left, right) in zip(self, other) {
            difference |= left ^ right
        }
        return difference == 0
    }
}

/// AES-128-CBC with HMAC-SHA-256 (RFC 7518 §5.2.3).
public struct A128CBCHS256: AESCBCHMACContentEncryption {
    typealias Hash = SHA256
    public let identifier: AlgorithmIdentifier = "A128CBC-HS256"
    public let keyByteCount = 32

    public init() {}
}

/// AES-192-CBC with HMAC-SHA-384 (RFC 7518 §5.2.4).
public struct A192CBCHS384: AESCBCHMACContentEncryption {
    typealias Hash = SHA384
    public let identifier: AlgorithmIdentifier = "A192CBC-HS384"
    public let keyByteCount = 48

    public init() {}
}

/// AES-256-CBC with HMAC-SHA-512 (RFC 7518 §5.2.5).
public struct A256CBCHS512: AESCBCHMACContentEncryption {
    typealias Hash = SHA512
    public let identifier: AlgorithmIdentifier = "A256CBC-HS512"
    public let keyByteCount = 64

    public init() {}
}
