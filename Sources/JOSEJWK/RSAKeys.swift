import Foundation
import JOSECore

/// An RSA public key of an acceptable size.
public struct RSAPublicKey: Sendable, Hashable {
    /// RFC 7518 §3.3 and §3.5 require 2048 bits or more.
    public static let minimumBitCount = 2048
    /// The largest modulus accepted. The cost of an RSA operation grows steeply with key size and
    /// keys can come from an untrusted JWK Set; 16384 bits is also where OpenSSL stops.
    public static let maximumBitCount = 16384

    /// The modulus `n` as an unsigned big-endian integer with no leading zero bytes.
    public let modulus: Data
    /// The public exponent `e`, in the same form.
    public let exponent: Data

    /// The size of the modulus in bits.
    public var bitCount: Int {
        Self.bitCount(of: modulus)
    }

    /// `RSAPublicKey` as defined by PKCS#1. This is not SubjectPublicKeyInfo: a "BEGIN PUBLIC
    /// KEY" PEM has an extra wrapper around these bytes.
    public var pkcs1DERRepresentation: Data {
        RSAKeyDER.publicKey(modulus: modulus, exponent: exponent)
    }

    public init(modulus: Data, exponent: Data) throws(JWKError) {
        try Self.requireMinimal(modulus, member: "n")
        try Self.requireMinimal(exponent, member: "e")

        let bitCount = Self.bitCount(of: modulus)
        guard bitCount >= Self.minimumBitCount else {
            throw .rsaKeyTooSmall(bitCount: bitCount, minimum: Self.minimumBitCount)
        }
        guard bitCount <= Self.maximumBitCount else {
            throw .rsaKeyTooLarge(bitCount: bitCount, maximum: Self.maximumBitCount)
        }
        // A product of two odd primes is odd, and the exponent must be coprime to an even number.
        guard let lowModulus = modulus.last, lowModulus & 1 == 1 else {
            throw .invalidRSAKey(reason: "the modulus is even")
        }
        guard let lowExponent = exponent.last, lowExponent & 1 == 1 else {
            throw .invalidRSAKey(reason: "the public exponent is even")
        }
        guard exponent != Data([0x01]) else {
            throw .invalidRSAKey(reason: "the public exponent is 1")
        }

        self.modulus = Data(modulus)
        self.exponent = Data(exponent)
        // Let the platform's implementation have its say now, rather than when the key is first used.
        _ = try RSABackendPublicKey(pkcs1DER: pkcs1DERRepresentation)
    }

    public init(pkcs1DERRepresentation: Data) throws(JWKError) {
        let (modulus, exponent) = try RSAKeyDER.parsePublicKey(pkcs1DERRepresentation)
        try self.init(modulus: modulus, exponent: exponent)
    }

    static func requireMinimal(_ value: Data, member: String) throws(JWKError) {
        guard let first = value.first else {
            throw .wrongByteCount(member: member, curve: "RSA", expected: 1, found: 0)
        }
        guard first != 0 else {
            throw .nonMinimalInteger(member: member)
        }
    }

    private static func bitCount(of value: Data) -> Int {
        guard let first = value.first else {
            return 0
        }
        return (value.count - 1) * 8 + (8 - first.leadingZeroBitCount)
    }
}

/// An RSA private key held in memory, with its CRT values.
///
/// Not `Codable`, `Equatable` or `Hashable`, and its description is redacted; see ``ECPrivateKey``.
public struct RSAPrivateKey: Sendable {
    public let publicKey: RSAPublicKey
    let components: RSAPrivateKeyComponents

    /// `RSAPrivateKey` as defined by PKCS#1 (a "BEGIN RSA PRIVATE KEY" PEM, decoded). This output
    /// contains the private key.
    public var pkcs1DERRepresentation: Data {
        RSAKeyDER.privateKey(components)
    }

    /// Generates a new key.
    public init(bitCount: Int = 2048) throws(JWKError) {
        guard bitCount >= RSAPublicKey.minimumBitCount else {
            throw .rsaKeyTooSmall(bitCount: bitCount, minimum: RSAPublicKey.minimumBitCount)
        }
        guard bitCount <= RSAPublicKey.maximumBitCount else {
            throw .rsaKeyTooLarge(bitCount: bitCount, maximum: RSAPublicKey.maximumBitCount)
        }
        try self.init(pkcs1DERRepresentation: RSABackendPrivateKey.generatePKCS1DER(bitCount: bitCount))
    }

    public init(pkcs1DERRepresentation: Data) throws(JWKError) {
        try self.init(components: RSAKeyDER.parsePrivateKey(pkcs1DERRepresentation))
    }

    init(components: RSAPrivateKeyComponents) throws(JWKError) {
        publicKey = try RSAPublicKey(modulus: components.modulus, exponent: components.publicExponent)
        let privateValues: [(String, Data)] = [
            ("d", components.privateExponent), ("p", components.prime1), ("q", components.prime2),
            ("dp", components.exponent1), ("dq", components.exponent2), ("qi", components.coefficient),
        ]
        for (member, value) in privateValues {
            try RSAPublicKey.requireMinimal(value, member: member)
        }
        self.components = components

        // Checking that the private values belong to the public ones needs big-number arithmetic
        // this package does not have. Signing with the private half and verifying with the public
        // half establishes the same thing using the platform's implementation.
        let probe = Data("JOSEJWK RSA key consistency check".utf8)
        let signature: Data
        do {
            signature = try RSABackendPrivateKey(pkcs1DER: pkcs1DERRepresentation)
                .signature(for: probe, padding: .pkcs1v15, hash: .sha256)
        } catch let error as JWKError {
            throw error
        } catch {
            throw .invalidRSAKey(reason: String(describing: error))
        }
        let verifier = try RSABackendPublicKey(pkcs1DER: publicKey.pkcs1DERRepresentation)
        guard verifier.isValid(signature: signature, for: probe, padding: .pkcs1v15, hash: .sha256) else {
            throw .privateKeyDoesNotMatchPublicKey(curve: "RSA")
        }
    }
}

extension RSAPrivateKey: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "RSAPrivateKey(\(publicKey.bitCount) bits, redacted)"
    }

    public var debugDescription: String {
        description
    }
}

// MARK: - Algorithms

/// An RSA signature algorithm: a padding scheme and a hash.
public protocol RSASignatureAlgorithm: SignatureAlgorithm {
    static var padding: RSASignaturePadding { get }
    static var hash: RSASignatureHash { get }
}

extension RS256: RSASignatureAlgorithm {
    public static let padding = RSASignaturePadding.pkcs1v15
    public static let hash = RSASignatureHash.sha256
}

extension RS384: RSASignatureAlgorithm {
    public static let padding = RSASignaturePadding.pkcs1v15
    public static let hash = RSASignatureHash.sha384
}

extension RS512: RSASignatureAlgorithm {
    public static let padding = RSASignaturePadding.pkcs1v15
    public static let hash = RSASignatureHash.sha512
}

extension PS256: RSASignatureAlgorithm {
    public static let padding = RSASignaturePadding.pss
    public static let hash = RSASignatureHash.sha256
}

extension PS384: RSASignatureAlgorithm {
    public static let padding = RSASignaturePadding.pss
    public static let hash = RSASignatureHash.sha384
}

extension PS512: RSASignatureAlgorithm {
    public static let padding = RSASignaturePadding.pss
    public static let hash = RSASignatureHash.sha512
}

/// Signs with an in-memory RSA key. One key can sign under any of the six RSA algorithms; the
/// generic parameter says which.
public struct RSASigner<Algorithm: RSASignatureAlgorithm>: Signer {
    public let keyID: KeyID?
    public let publicKey: RSAPublicKey
    private let key: RSABackendPrivateKey

    public init(privateKey: RSAPrivateKey, keyID: KeyID? = nil) throws(JWKError) {
        key = try RSABackendPrivateKey(pkcs1DER: privateKey.pkcs1DERRepresentation)
        publicKey = privateKey.publicKey
        self.keyID = keyID
    }

    public func sign(_ message: Data) async throws(SigningError) -> Signature<Algorithm> {
        let raw: Data
        do {
            raw = try key.signature(for: message, padding: Algorithm.padding, hash: Algorithm.hash)
        } catch {
            throw .keyOperationFailed(algorithm: Algorithm.identifier, underlying: error)
        }
        do {
            return try Signature(rawRepresentation: raw)
        } catch {
            throw .invalidSignature(error)
        }
    }
}

/// Verifies RSA signatures with a public key.
public struct RSAVerifier<Algorithm: RSASignatureAlgorithm>: Verifier {
    public let keyID: KeyID?
    private let key: RSABackendPublicKey

    public init(publicKey: RSAPublicKey, keyID: KeyID? = nil) throws(JWKError) {
        key = try RSABackendPublicKey(pkcs1DER: publicKey.pkcs1DERRepresentation)
        self.keyID = keyID
    }

    /// Builds a verifier from a JWK, honouring its `use`, `key_ops` and `alg` restrictions.
    public init(jwk: JWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .verify, use: .signature, algorithm: Algorithm.identifier)
        guard case .rsa(let publicKey) = jwk.key else {
            throw .keyTypeMismatch(expected: "RSA", found: jwk.keyDescription)
        }
        try self.init(publicKey: publicKey, keyID: jwk.keyID)
    }

    public func verify(_ signature: Signature<Algorithm>, for message: Data) throws(VerificationError) {
        let isValid = key.isValid(
            signature: signature.rawRepresentation,
            for: message,
            padding: Algorithm.padding,
            hash: Algorithm.hash
        )
        guard isValid else {
            throw .signatureMismatch(algorithm: Algorithm.identifier)
        }
    }
}

// MARK: - Encryption

/// Encrypts short messages (in JOSE, a content encryption key) to an RSA public key with
/// RSAES-OAEP.
public struct RSAOAEPEncryptionKey: Sendable {
    public let publicKey: RSAPublicKey
    private let key: RSABackendPublicKey

    public init(publicKey: RSAPublicKey) throws(JWKError) {
        key = try RSABackendPublicKey(pkcs1DER: publicKey.pkcs1DERRepresentation)
        self.publicKey = publicKey
    }

    public func encrypt(_ plaintext: Data, hash: RSAOAEPHash) throws(JWKError) -> Data {
        try key.encryptOAEP(plaintext, hash: hash)
    }
}

/// Decrypts RSAES-OAEP ciphertexts with an RSA private key.
public struct RSAOAEPDecryptionKey: Sendable {
    public let publicKey: RSAPublicKey
    private let key: RSABackendPrivateKey

    public init(privateKey: RSAPrivateKey) throws(JWKError) {
        key = try RSABackendPrivateKey(pkcs1DER: privateKey.pkcs1DERRepresentation)
        publicKey = privateKey.publicKey
    }

    /// Fails with ``JWKError/rsaDecryptionFailed`` for any ciphertext that does not decrypt
    /// under this key, without saying why.
    public func decrypt(_ ciphertext: Data, hash: RSAOAEPHash) throws(JWKError) -> Data {
        try key.decryptOAEP(ciphertext, hash: hash)
    }
}
