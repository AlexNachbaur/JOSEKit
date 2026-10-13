import Foundation
import JOSECore
import JOSEJWK

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

// MARK: - ECDH-ES

/// An ECDH-ES algorithm (RFC 7518 §4.6): either the agreed key is the content encryption key
/// itself, or it wraps one with AES Key Wrap.
public protocol ECDHESAlgorithm: KeyManagementAlgorithm {
    /// The size of the AES Key Wrap key to derive, or `nil` when the derived key is used
    /// directly as the content encryption key.
    static var keyWrapByteCount: Int? { get }
}

/// ECDH-ES with the derived key used directly for content encryption.
public struct ECDHES: ECDHESAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ECDH-ES"
    public static let keyWrapByteCount: Int? = nil
}

public struct ECDHESA128KW: ECDHESAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ECDH-ES+A128KW"
    public static let keyWrapByteCount: Int? = 16
}

public struct ECDHESA192KW: ECDHESAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ECDH-ES+A192KW"
    public static let keyWrapByteCount: Int? = 24
}

public struct ECDHESA256KW: ECDHESAlgorithm {
    public static let identifier: AlgorithmIdentifier = "ECDH-ES+A256KW"
    public static let keyWrapByteCount: Int? = 32
}

/// A public key a JWE can be encrypted to with ECDH-ES.
public protocol ECDHRecipientPublicKey: Sendable {
    /// Generates an ephemeral key pair on the same curve and returns its public half as a JWK
    /// together with the shared secret `Z` with this key.
    func ephemeralAgreement() throws(JWKError) -> (ephemeralPublicKey: JWK, sharedSecret: Data)
}

/// A private key that can decrypt a JWE encrypted with ECDH-ES.
public protocol ECDHRecipientPrivateKey: Sendable {
    /// The name of the curve, for error messages.
    static var curveName: String { get }
    /// The shared secret `Z` with the sender's ephemeral public key, or `nil` if that key is for
    /// a different curve.
    func sharedSecret(withEphemeralKey ephemeralKey: JWK) throws(JWKError) -> Data?
}

extension ECPublicKey: ECDHRecipientPublicKey where Curve: KeyAgreementCurve {
    public func ephemeralAgreement() throws(JWKError) -> (ephemeralPublicKey: JWK, sharedSecret: Data) {
        let ephemeral = try ECPrivateKey<Curve>()
        let secret = try ephemeral.sharedSecret(with: self)
        return (try ECDHJSON.jwk(for: ephemeral.publicKey), secret)
    }
}

extension ECPrivateKey: ECDHRecipientPrivateKey where Curve: KeyAgreementCurve {
    public static var curveName: String {
        Curve.name
    }

    public func sharedSecret(withEphemeralKey ephemeralKey: JWK) throws(JWKError) -> Data? {
        var peer: ECPublicKey<Curve>?
        switch ephemeralKey.key {
        case .p256(let key):
            peer = key as? ECPublicKey<Curve>
        case .p384(let key):
            peer = key as? ECPublicKey<Curve>
        case .p521(let key):
            peer = key as? ECPublicKey<Curve>
        case .ed25519, .x25519, .rsa, .unrecognized:
            peer = nil
        }
        guard let peer else {
            return nil
        }
        return try sharedSecret(with: peer)
    }
}

extension X25519PublicKey: ECDHRecipientPublicKey {
    public func ephemeralAgreement() throws(JWKError) -> (ephemeralPublicKey: JWK, sharedSecret: Data) {
        let ephemeral = try X25519PrivateKey()
        return (JWK(.x25519(ephemeral.publicKey)), try ephemeral.sharedSecret(with: self))
    }
}

extension X25519PrivateKey: ECDHRecipientPrivateKey {
    public static var curveName: String {
        X25519PublicKey.curveName
    }

    public func sharedSecret(withEphemeralKey ephemeralKey: JWK) throws(JWKError) -> Data? {
        guard case .x25519(let peer) = ephemeralKey.key else {
            return nil
        }
        return try sharedSecret(with: peer)
    }
}

struct ECDHJSON {
    private init() {}

    /// A typed public key as a `JWK`. The curves this package knows have their own case; a curve
    /// added outside it goes through JSON, which is the only form every curve shares.
    static func jwk<Curve: EllipticCurve>(for key: ECPublicKey<Curve>) throws(JWKError) -> JWK {
        if let key = key as? ECPublicKey<P256Curve> {
            return JWK(.p256(key))
        }
        if let key = key as? ECPublicKey<P384Curve> {
            return JWK(.p384(key))
        }
        if let key = key as? ECPublicKey<P521Curve> {
            return JWK(.p521(key))
        }
        return try JWK(json: try ecPublicKey(key))
    }

    static func ecPublicKey<Curve: EllipticCurve>(_ key: ECPublicKey<Curve>) throws(JWKError) -> Data {
        let members: [String: JSONValue] = [
            "kty": "EC",
            "crv": .string(Curve.name),
            "x": .string(Base64URL.encode(key.x)),
            "y": .string(Base64URL.encode(key.y)),
        ]
        do {
            return try JSONEncoder().encode(members)
        } catch {
            throw .invalidJSON(description: String(describing: error))
        }
    }
}

/// The Concat KDF of NIST SP 800-56A with SHA-256, as profiled by RFC 7518 §4.6.2.
struct ConcatKDF {
    private init() {}

    static func derive(
        sharedSecret: Data,
        algorithmID: String,
        partyUInfo: Data,
        partyVInfo: Data,
        keyByteCount: Int
    ) -> Data {
        var otherInfo = lengthPrefixed(Data(algorithmID.utf8))
        otherInfo += lengthPrefixed(partyUInfo)
        otherInfo += lengthPrefixed(partyVInfo)
        // SuppPubInfo: the length of the derived key in bits.
        otherInfo += bigEndian(UInt32(keyByteCount * 8))

        var derived = Data()
        var counter: UInt32 = 1
        while derived.count < keyByteCount {
            var hash = SHA256()
            hash.update(data: bigEndian(counter))
            hash.update(data: sharedSecret)
            hash.update(data: otherInfo)
            derived += Data(hash.finalize())
            counter += 1
        }
        return derived.prefix(keyByteCount)
    }

    private static func bigEndian(_ value: UInt32) -> Data {
        Data([UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)])
    }

    private static func lengthPrefixed(_ data: Data) -> Data {
        bigEndian(UInt32(data.count)) + data
    }
}

/// The key size and algorithm name that go into the KDF. With direct agreement the derived key
/// is the content encryption key and is bound to `enc`; with key wrapping it is the wrapping key
/// and is bound to `alg`.
private func derivationParameters<Algorithm: ECDHESAlgorithm>(
    _ algorithm: Algorithm.Type,
    contentEncryption: AlgorithmIdentifier,
    contentKeyByteCount: Int
) -> (algorithmID: String, keyByteCount: Int) {
    if let wrapByteCount = Algorithm.keyWrapByteCount {
        return (Algorithm.identifier.rawValue, wrapByteCount)
    }
    return (contentEncryption.rawValue, contentKeyByteCount)
}

/// Key agreement is permitted by `key_ops` `deriveKey` or `deriveBits` (RFC 7517 §4.3), since
/// both describe what ECDH-ES does with the key.
private func requireAgreementPermission(
    _ metadata: JWKMetadata,
    algorithm: AlgorithmIdentifier
) throws(JWKError) {
    if let use = metadata.use {
        guard use == .encryption else {
            throw .useNotPermitted(use: use.rawValue, required: KeyUse.encryption.rawValue)
        }
    }
    if let operations = metadata.keyOperations {
        guard operations.contains(.deriveKey) || operations.contains(.deriveBits) else {
            throw .keyOperationNotPermitted(
                operations: operations.map(\.rawValue),
                required: KeyOperation.deriveKey.rawValue
            )
        }
    }
    if let keyAlgorithm = metadata.algorithm {
        guard keyAlgorithm == algorithm else {
            throw .algorithmMismatch(keyAlgorithm: keyAlgorithm, required: algorithm)
        }
    }
}

extension ECDHESAlgorithm {
    /// A decrypter for a private EC or X25519 JWK, honouring its `use`, `key_ops` and `alg`.
    public static func decrypter(for jwk: PrivateJWK) throws(JWKError) -> AnyKeyDecrypter {
        try requireAgreementPermission(jwk.metadata, algorithm: identifier)
        let keyID = jwk.metadata.keyID
        switch jwk.key {
        case .p256(let key):
            return AnyKeyDecrypter(ECDHESDecrypter<Self, ECPrivateKey<P256Curve>>(privateKey: key, keyID: keyID))
        case .p384(let key):
            return AnyKeyDecrypter(ECDHESDecrypter<Self, ECPrivateKey<P384Curve>>(privateKey: key, keyID: keyID))
        case .p521(let key):
            return AnyKeyDecrypter(ECDHESDecrypter<Self, ECPrivateKey<P521Curve>>(privateKey: key, keyID: keyID))
        case .x25519(let key):
            return AnyKeyDecrypter(ECDHESDecrypter<Self, X25519PrivateKey>(privateKey: key, keyID: keyID))
        case .ed25519, .rsa:
            throw .keyTypeMismatch(expected: "EC or OKP X25519", found: jwk.publicJWK.keyType)
        }
    }
}

extension ECDHES: JWKDecryptableAlgorithm {}
extension ECDHESA128KW: JWKDecryptableAlgorithm {}
extension ECDHESA192KW: JWKDecryptableAlgorithm {}
extension ECDHESA256KW: JWKDecryptableAlgorithm {}

/// Encrypts to a recipient's EC or X25519 public key with ECDH-ES.
public struct ECDHESEncrypter<Algorithm: ECDHESAlgorithm>: KeyEncrypter {
    public let keyID: KeyID?
    private let recipient: any ECDHRecipientPublicKey
    private let partyUInfo: Data
    private let partyVInfo: Data

    /// - Parameters:
    ///   - partyUInfo: Information about the sender, written to `apu`. Empty to omit.
    ///   - partyVInfo: Information about the recipient, written to `apv`. Empty to omit.
    public init(
        recipient: some ECDHRecipientPublicKey,
        keyID: KeyID? = nil,
        partyUInfo: Data = Data(),
        partyVInfo: Data = Data()
    ) {
        self.recipient = recipient
        self.keyID = keyID
        self.partyUInfo = partyUInfo
        self.partyVInfo = partyVInfo
    }

    /// Builds an encrypter from a recipient's published JWK, honouring its `use`, `key_ops` and
    /// `alg` restrictions.
    public init(jwk: JWK) throws(JWKError) {
        try requireAgreementPermission(jwk.metadata, algorithm: Algorithm.identifier)
        switch jwk.key {
        case .p256(let key):
            self.init(recipient: key, keyID: jwk.keyID)
        case .p384(let key):
            self.init(recipient: key, keyID: jwk.keyID)
        case .p521(let key):
            self.init(recipient: key, keyID: jwk.keyID)
        case .x25519(let key):
            self.init(recipient: key, keyID: jwk.keyID)
        case .ed25519, .rsa, .unrecognized:
            throw .keyTypeMismatch(expected: "EC or OKP X25519", found: jwk.keyType)
        }
    }

    public func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        if Algorithm.keyWrapByteCount == nil {
            guard request.contentEncryptionKey == nil else {
                throw .algorithmRequiresSingleRecipient(algorithm: Algorithm.identifier)
            }
        }
        let agreement: (ephemeralPublicKey: JWK, sharedSecret: Data)
        var headerParameters: [String: JSONValue] = [:]
        do {
            agreement = try recipient.ephemeralAgreement()
            headerParameters["epk"] = try JSONDecoder().decode(
                JSONValue.self,
                from: try agreement.ephemeralPublicKey.jsonRepresentation()
            )
        } catch let error as JWKError {
            throw .keyEncryptionFailed(algorithm: Algorithm.identifier, error)
        } catch {
            throw .headerEncodingFailed(description: String(describing: error))
        }
        if !partyUInfo.isEmpty {
            headerParameters["apu"] = .string(Base64URL.encode(partyUInfo))
        }
        if !partyVInfo.isEmpty {
            headerParameters["apv"] = .string(Base64URL.encode(partyVInfo))
        }

        let parameters = derivationParameters(
            Algorithm.self,
            contentEncryption: request.contentEncryption,
            contentKeyByteCount: request.keyByteCount
        )
        let derived = ConcatKDF.derive(
            sharedSecret: agreement.sharedSecret,
            algorithmID: parameters.algorithmID,
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo,
            keyByteCount: parameters.keyByteCount
        )

        guard Algorithm.keyWrapByteCount != nil else {
            return KeyEncryptionResult(
                contentEncryptionKey: derived,
                encryptedKey: Data(),
                headerParameters: headerParameters
            )
        }
        let contentKey = request.keyToWrap()
        do {
            return KeyEncryptionResult(
                contentEncryptionKey: contentKey,
                encryptedKey: try AESKeyWrapping.wrap(contentKey, with: derived),
                headerParameters: headerParameters
            )
        } catch {
            throw .contentEncryptionFailed(description: "\(Algorithm.identifier) key wrap failed: \(error)")
        }
    }
}

/// Decrypts with an EC or X25519 private key and ECDH-ES.
public struct ECDHESDecrypter<Algorithm: ECDHESAlgorithm, Key: ECDHRecipientPrivateKey>: KeyDecrypter {
    public let keyID: KeyID?
    private let key: Key

    public init(privateKey: Key, keyID: KeyID? = nil) {
        key = privateKey
        self.keyID = keyID
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        guard let epk = request.header["epk"] else {
            throw .missingHeaderParameter(name: "epk", algorithm: Algorithm.identifier)
        }
        guard case .object = epk else {
            throw .headerParameterWrongType(name: "epk", expected: "an object")
        }
        // Parsing as a `JWK` refuses a private key in `epk` and, for EC keys, a point that is
        // not on the curve.
        let ephemeralKey: JWK
        do {
            ephemeralKey = try JWK(json: try JSONEncoder().encode(epk))
        } catch let error as JWKError {
            throw .invalidEphemeralKey(error)
        } catch {
            throw .invalidHeaderJSON(description: String(describing: error))
        }
        let partyUInfo = try request.optionalBytes("apu") ?? Data()
        let partyVInfo = try request.optionalBytes("apv") ?? Data()

        let sharedSecret: Data
        do {
            guard let secret = try key.sharedSecret(withEphemeralKey: ephemeralKey) else {
                throw JWEError.ephemeralKeyCurveMismatch(expected: Key.curveName, found: Self.describe(ephemeralKey))
            }
            sharedSecret = secret
        } catch let error as JWEError {
            throw error
        } catch {
            // The agreement itself failed (an X25519 point of small order, for instance).
            throw .decryptionFailed
        }

        let parameters = derivationParameters(
            Algorithm.self,
            contentEncryption: request.contentEncryption,
            contentKeyByteCount: request.keyByteCount
        )
        let derived = ConcatKDF.derive(
            sharedSecret: sharedSecret,
            algorithmID: parameters.algorithmID,
            partyUInfo: partyUInfo,
            partyVInfo: partyVInfo,
            keyByteCount: parameters.keyByteCount
        )
        guard Algorithm.keyWrapByteCount != nil else {
            guard request.encryptedKey.isEmpty else {
                throw .encryptedKeyNotEmpty(algorithm: Algorithm.identifier)
            }
            return derived
        }
        return try AESKeyWrapping.unwrap(request.encryptedKey, with: derived)
    }

    private static func describe(_ jwk: JWK) -> String {
        switch jwk.key {
        case .p256:
            return P256Curve.name
        case .p384:
            return P384Curve.name
        case .p521:
            return P521Curve.name
        case .x25519:
            return X25519PublicKey.curveName
        case .ed25519:
            return Ed25519PublicKey.curveName
        case .rsa, .unrecognized:
            return jwk.keyType
        }
    }
}

// MARK: - RSA-OAEP

/// RSAES-OAEP key encryption (RFC 7518 §4.3).
public protocol RSAOAEPAlgorithm: KeyManagementAlgorithm {
    static var hash: RSAOAEPHash { get }
}

/// RSAES-OAEP with SHA-1 and MGF1 with SHA-1.
public struct RSAOAEP: RSAOAEPAlgorithm {
    public static let identifier: AlgorithmIdentifier = "RSA-OAEP"
    public static let hash = RSAOAEPHash.sha1
}

/// RSAES-OAEP with SHA-256 and MGF1 with SHA-256.
public struct RSAOAEP256: RSAOAEPAlgorithm {
    public static let identifier: AlgorithmIdentifier = "RSA-OAEP-256"
    public static let hash = RSAOAEPHash.sha256
}

extension RSAOAEPAlgorithm {
    /// A decrypter for a private RSA JWK, honouring its `use`, `key_ops` and `alg`.
    public static func decrypter(for jwk: PrivateJWK) throws(JWKError) -> AnyKeyDecrypter {
        AnyKeyDecrypter(try RSAOAEPDecrypter<Self>(jwk: jwk))
    }
}

extension RSAOAEP: JWKDecryptableAlgorithm {}
extension RSAOAEP256: JWKDecryptableAlgorithm {}

/// Encrypts the content encryption key to a recipient's RSA public key.
public struct RSAOAEPEncrypter<Algorithm: RSAOAEPAlgorithm>: KeyEncrypter {
    public let keyID: KeyID?
    private let key: RSAOAEPEncryptionKey

    public init(publicKey: RSAPublicKey, keyID: KeyID? = nil) throws(JWKError) {
        key = try RSAOAEPEncryptionKey(publicKey: publicKey)
        self.keyID = keyID
    }

    /// Builds an encrypter from a recipient's published JWK, honouring its `use`, `key_ops` and
    /// `alg` restrictions.
    public init(jwk: JWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .wrapKey, use: .encryption, algorithm: Algorithm.identifier)
        guard case .rsa(let publicKey) = jwk.key else {
            throw .keyTypeMismatch(expected: "RSA", found: jwk.keyType)
        }
        try self.init(publicKey: publicKey, keyID: jwk.keyID)
    }

    public func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
        let contentKey = request.keyToWrap()
        do {
            return KeyEncryptionResult(
                contentEncryptionKey: contentKey,
                encryptedKey: try key.encrypt(contentKey, hash: Algorithm.hash)
            )
        } catch {
            throw .keyEncryptionFailed(algorithm: Algorithm.identifier, error)
        }
    }
}

/// Recovers the content encryption key with an RSA private key.
public struct RSAOAEPDecrypter<Algorithm: RSAOAEPAlgorithm>: KeyDecrypter {
    public let keyID: KeyID?
    private let key: RSAOAEPDecryptionKey

    public init(privateKey: RSAPrivateKey, keyID: KeyID? = nil) throws(JWKError) {
        key = try RSAOAEPDecryptionKey(privateKey: privateKey)
        self.keyID = keyID
    }

    /// Builds a decrypter from a private JWK, honouring its `use`, `key_ops` and `alg`.
    public init(jwk: PrivateJWK) throws(JWKError) {
        try jwk.metadata.requirePermission(for: .unwrapKey, use: .encryption, algorithm: Algorithm.identifier)
        guard case .rsa(let privateKey) = jwk.key else {
            throw .keyTypeMismatch(expected: "RSA", found: jwk.publicJWK.keyType)
        }
        try self.init(privateKey: privateKey, keyID: jwk.metadata.keyID)
    }

    public func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
        do {
            return try key.decrypt(request.encryptedKey, hash: Algorithm.hash)
        } catch {
            throw .decryptionFailed
        }
    }
}
