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
/// To add one this package does not ship, conform a type to this protocol and include it in the
/// list passed when decrypting.
public protocol ContentEncryptionAlgorithm: Sendable {
    static var identifier: AlgorithmIdentifier { get }
    static var keyByteCount: Int { get }
    static var initializationVectorByteCount: Int { get }
    static var authenticationTagByteCount: Int { get }

    static func encrypt(
        _ plaintext: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> (ciphertext: Data, tag: Data)

    /// Must throw ``JWEError/decryptionFailed``, and nothing more specific, when the content
    /// does not authenticate.
    static func decrypt(
        _ ciphertext: Data,
        tag: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> Data
}

// MARK: - AES-GCM

struct AESGCM {
    private init() {}

    static func seal(_ plaintext: Data, key: Data, nonce: Data, aad: Data) throws(JWEError) -> (Data, Data) {
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

    static func open(_ ciphertext: Data, tag: Data, key: Data, nonce: Data, aad: Data) throws(JWEError) -> Data {
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
    public static var initializationVectorByteCount: Int {
        12
    }

    public static var authenticationTagByteCount: Int {
        16
    }

    public static func encrypt(
        _ plaintext: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> (ciphertext: Data, tag: Data) {
        try AESGCM.seal(plaintext, key: key, nonce: initializationVector, aad: additionalAuthenticatedData)
    }

    public static func decrypt(
        _ ciphertext: Data,
        tag: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> Data {
        try AESGCM.open(ciphertext, tag: tag, key: key, nonce: initializationVector, aad: additionalAuthenticatedData)
    }
}

/// AES GCM with a 128-bit key (RFC 7518 §5.3).
public struct A128GCM: AESGCMContentEncryption {
    public static let identifier: AlgorithmIdentifier = "A128GCM"
    public static let keyByteCount = 16
}

/// AES GCM with a 192-bit key (RFC 7518 §5.3).
public struct A192GCM: AESGCMContentEncryption {
    public static let identifier: AlgorithmIdentifier = "A192GCM"
    public static let keyByteCount = 24
}

/// AES GCM with a 256-bit key (RFC 7518 §5.3).
public struct A256GCM: AESGCMContentEncryption {
    public static let identifier: AlgorithmIdentifier = "A256GCM"
    public static let keyByteCount = 32
}

// MARK: - AES-CBC with HMAC

/// AES_CBC_HMAC_SHA2 (RFC 7518 §5.2). The key is two halves: the first authenticates, the second
/// encrypts. The tag is the first half of an HMAC over the additional data, IV, ciphertext and
/// the additional data's length.
protocol AESCBCHMACContentEncryption: ContentEncryptionAlgorithm {
    associatedtype Hash: HashFunction
}

extension AESCBCHMACContentEncryption {
    public static var initializationVectorByteCount: Int {
        16
    }

    public static var authenticationTagByteCount: Int {
        keyByteCount / 2
    }

    private static func tag(macKey: Data, aad: Data, iv: Data, ciphertext: Data) -> Data {
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

    public static func encrypt(
        _ plaintext: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> (ciphertext: Data, tag: Data) {
        let half = keyByteCount / 2
        let keyBytes = Data(key)
        let ciphertext: Data
        do {
            ciphertext = try AESCBC.encrypt(plaintext, key: keyBytes.suffix(half), iv: initializationVector)
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

    public static func decrypt(
        _ ciphertext: Data,
        tag: Data,
        key: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws(JWEError) -> Data {
        let half = keyByteCount / 2
        let keyBytes = Data(key)
        let expected = Self.tag(
            macKey: keyBytes.prefix(half),
            aad: additionalAuthenticatedData,
            iv: initializationVector,
            ciphertext: ciphertext
        )
        // The tag is checked, in constant time, before any decryption. Decrypting first and
        // reporting bad padding is the classic padding-oracle mistake.
        guard ConstantTime.equal(expected, tag) else {
            throw .decryptionFailed
        }
        do {
            return try AESCBC.decrypt(ciphertext, key: keyBytes.suffix(half), iv: initializationVector)
        } catch {
            throw .decryptionFailed
        }
    }
}

struct ConstantTime {
    private init() {}

    /// Compares without stopping at the first difference, so that timing does not reveal how
    /// many leading bytes of a forged tag were right.
    static func equal(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else {
            return false
        }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            difference |= left ^ right
        }
        return difference == 0
    }
}

/// AES-128-CBC with HMAC-SHA-256 (RFC 7518 §5.2.3).
public struct A128CBCHS256: AESCBCHMACContentEncryption {
    typealias Hash = SHA256
    public static let identifier: AlgorithmIdentifier = "A128CBC-HS256"
    public static let keyByteCount = 32
}

/// AES-192-CBC with HMAC-SHA-384 (RFC 7518 §5.2.4).
public struct A192CBCHS384: AESCBCHMACContentEncryption {
    typealias Hash = SHA384
    public static let identifier: AlgorithmIdentifier = "A192CBC-HS384"
    public static let keyByteCount = 48
}

/// AES-256-CBC with HMAC-SHA-512 (RFC 7518 §5.2.5).
public struct A256CBCHS512: AESCBCHMACContentEncryption {
    typealias Hash = SHA512
    public static let identifier: AlgorithmIdentifier = "A256CBC-HS512"
    public static let keyByteCount = 64
}

/// The content encryption algorithms this package implements.
public struct ContentEncryption {
    private init() {}

    public static let standard: [any ContentEncryptionAlgorithm.Type] = [
        A128GCM.self, A192GCM.self, A256GCM.self, A128CBCHS256.self, A192CBCHS384.self, A256CBCHS512.self,
    ]
}
