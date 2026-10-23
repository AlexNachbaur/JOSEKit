import JOSECore
import JOSEJWK

/// Why a JWE could not be parsed, decrypted or produced.
///
/// Everything that can be known without a key is reported precisely: malformed input, a missing
/// or unsupported algorithm, no key for a key ID, a key of the wrong size. A failure of the
/// cryptography itself is always the single case ``decryptionFailed``, because telling a failed
/// key unwrap apart from a failed authentication tag gives an attacker who can submit
/// ciphertexts an oracle (RFC 7516 §11.5).
public enum JWEError: Error, Sendable, Equatable {
    // MARK: Parsing

    /// A compact JWE is exactly five segments separated by `.`.
    case invalidCompactSerialization(segmentCount: Int)
    case invalidBase64URL(part: String, Base64URLError)
    /// The part contains `=`. JWE uses base64url without padding.
    case paddingNotAllowed(part: String)
    case invalidJSONStructure(JSONStructureError)
    case invalidJSONSerialization(reason: String)
    case invalidHeaderStructure(JSONStructureError)
    case invalidHeaderJSON(description: String)
    /// No header has `alg`.
    case missingAlgorithm
    /// No header has `enc`.
    case missingContentEncryption
    case headerParameterWrongType(name: String, expected: String)
    /// The same parameter appears in more than one of the protected, shared unprotected and
    /// per-recipient headers (RFC 7516 §7.2.1).
    case headerParameterInMultipleHeaders(name: String)
    case headerParameterNotProtected(name: String)
    case invalidCritical(reason: String)
    case unsupportedCriticalParameter(name: String)
    /// The JWE's `zip` names a compression this package does not implement on this platform.
    /// `DEF` is the only one RFC 7516 defines, and it is not available on Windows.
    case unsupportedCompression(algorithm: String)
    case invalidCustomParameters(description: String)
    /// The `jwk` header parameter is not a valid public JWK.
    case invalidJWKParameter(JWKError)
    /// A parameter the key management algorithm needs (`epk`, `iv`, `tag`) is absent.
    case missingHeaderParameter(name: String, algorithm: AlgorithmIdentifier)
    /// The `epk` header parameter is not a usable public key.
    case invalidEphemeralKey(JWKError)
    /// The `epk` is for a different curve from the recipient's key.
    case ephemeralKeyCurveMismatch(expected: String, found: String)
    /// A PBES2 iteration count is below 1 or above the configured maximum. The maximum exists
    /// because a token chooses the count, and so the work a recipient does.
    case invalidIterationCount(found: Int, maximum: Int)
    /// A PBES2 salt input is shorter than RFC 7518 §4.8.1.1 allows.
    case saltTooShort(algorithm: AlgorithmIdentifier, minimum: Int, found: Int)

    // MARK: Decryption

    /// The JWE is compressed, and the decryption was asked to accept no compressed content
    /// (`maximumDecompressedByteCount` of 0).
    case compressionNotAllowed
    /// The decompressed plaintext would be larger than the decryption allows. Decompression
    /// stopped at the limit.
    case decompressedSizeExceedsLimit(maximum: Int)
    /// The decrypted content is not valid raw DEFLATE. The ciphertext authenticated, so this is
    /// a fault of whoever made the JWE, not an attack on the key.
    case invalidCompressedContent

    /// The JWE's `enc` is not among the content encryption algorithms the caller allows.
    case unsupportedContentEncryption(algorithm: AlgorithmIdentifier, allowed: [AlgorithmIdentifier])
    /// No decrypter was supplied for the algorithm the JWE names.
    case noDecrypterForAlgorithm(algorithm: AlgorithmIdentifier, offered: [AlgorithmIdentifier])
    /// Decrypters for the algorithm exist, but all of them are for other key IDs.
    case noDecrypterForKeyID(keyID: KeyID, algorithm: AlgorithmIdentifier)
    /// A `dir` key is not the size the content encryption algorithm requires. Keys whose size
    /// the key management algorithm alone fixes are checked when they are constructed instead.
    case keyWrongSize(algorithm: AlgorithmIdentifier, expected: Int, found: Int)
    /// The algorithm defines the encrypted key as empty, and this JWE has one.
    case encryptedKeyNotEmpty(algorithm: AlgorithmIdentifier)
    /// A `dir` key's JWK restricts it to one content encryption algorithm, and the JWE uses
    /// another.
    case contentEncryptionNotPermitted(keyAlgorithm: AlgorithmIdentifier, contentEncryption: AlgorithmIdentifier)
    case wrongInitializationVectorSize(algorithm: AlgorithmIdentifier, expected: Int, found: Int)
    case wrongAuthenticationTagSize(algorithm: AlgorithmIdentifier, expected: Int, found: Int)
    /// The key could not be unwrapped or the content did not authenticate. Deliberately carries
    /// no further detail.
    case decryptionFailed
    /// The JWE has several recipients and none could be decrypted. One reason per recipient.
    case noRecipientDecrypted(reasons: [JWEError])
    /// The JWE has several recipients and none of their headers could be read, so none could
    /// ever be decrypted. One reason per recipient.
    case noUsableRecipient(reasons: [JWEError])

    // MARK: Encryption

    /// `dir` and `ECDH-ES` fix the content encryption key themselves, so a JWE using one of them
    /// can have no other recipient.
    case algorithmRequiresSingleRecipient(algorithm: AlgorithmIdentifier)
    case noRecipients
    /// A `kid` was set in the shared header of a JWE with several recipients. Each recipient's
    /// key ID goes in its own header, taken from its encrypter.
    case sharedKeyIDWithMultipleRecipients
    case keyEncryptionFailed(algorithm: AlgorithmIdentifier, JWKError)
    case contentEncryptionFailed(description: String)
    case headerEncodingFailed(description: String)
    case customParameterCollision(name: String)
    case customParametersNotObject
    /// The JWE has features the requested serialization cannot carry.
    case notRepresentable(serialization: String, reason: String)
}

extension JWEError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidCompactSerialization(let segmentCount):
            return "compact JWE has \(segmentCount) segments; exactly 5 are required"
        case .invalidBase64URL(let part, let error):
            return "JWE \(part) is not valid base64url: \(error)"
        case .paddingNotAllowed(let part):
            return "JWE \(part) contains '='; JWE base64url is unpadded"
        case .invalidJSONStructure(let error):
            return "JWE JSON serialization is not a well-formed JSON object: \(error)"
        case .invalidJSONSerialization(let reason):
            return "JWE JSON serialization is invalid: \(reason)"
        case .invalidHeaderStructure(let error):
            return "JWE header is not a well-formed JSON object: \(error)"
        case .invalidHeaderJSON(let description):
            return "JWE header could not be decoded: \(description)"
        case .missingAlgorithm:
            return "JWE header has no \"alg\" parameter"
        case .missingContentEncryption:
            return "JWE header has no \"enc\" parameter"
        case .headerParameterWrongType(let name, let expected):
            return "JWE header parameter \"\(name)\" must be \(expected)"
        case .headerParameterInMultipleHeaders(let name):
            return "JWE header parameter \"\(name)\" appears in more than one header"
        case .headerParameterNotProtected(let name):
            return "JWE header parameter \"\(name)\" must be in the protected header"
        case .invalidCritical(let reason):
            return "JWE \"crit\" header parameter is invalid: \(reason)"
        case .unsupportedCriticalParameter(let name):
            return "JWE marks header parameter \"\(name)\" as critical, and it is not understood"
        case .unsupportedCompression(let algorithm):
            return "JWE \"zip\" is \(algorithm), which is not supported on this platform"
        case .compressionNotAllowed:
            return "JWE is compressed, and this decryption accepts no compressed content"
        case .decompressedSizeExceedsLimit(let maximum):
            return "JWE decompressed plaintext is larger than the \(maximum) bytes allowed"
        case .invalidCompressedContent:
            return "JWE decrypted content is not valid raw DEFLATE"
        case .invalidCustomParameters(let description):
            return "JWE header could not be decoded as the custom header type: \(description)"
        case .invalidJWKParameter(let error):
            return "JWE \"jwk\" header parameter is not a valid public key: \(error)"
        case .missingHeaderParameter(let name, let algorithm):
            return "JWE header has no \"\(name)\" parameter, which \(algorithm) requires"
        case .invalidEphemeralKey(let error):
            return "JWE \"epk\" header parameter is not a usable public key: \(error)"
        case .ephemeralKeyCurveMismatch(let expected, let found):
            return "JWE \"epk\" is a \(found) key; the recipient key is \(expected)"
        case .invalidIterationCount(let found, let maximum):
            return "PBES2 iteration count \(found) is outside the accepted range 1...\(maximum)"
        case .saltTooShort(let algorithm, let minimum, let found):
            return "\(algorithm) salt input is \(found) bytes; at least \(minimum) are required"
        case .unsupportedContentEncryption(let algorithm, let allowed):
            return "JWE content encryption \(algorithm) is not allowed "
                + "(allowed: \(allowed.map(\.rawValue).joined(separator: ", ")))"
        case .noDecrypterForAlgorithm(let algorithm, let offered):
            return "JWE key management algorithm is \(algorithm), for which no decrypter was supplied "
                + "(supplied: \(offered.map(\.rawValue).sorted().joined(separator: ", ")))"
        case .noDecrypterForKeyID(let keyID, let algorithm):
            return "no \(algorithm) decrypter was supplied for key ID \"\(keyID)\""
        case .keyWrongSize(let algorithm, let expected, let found):
            return "\(algorithm) needs a key of \(expected) bytes; the key supplied is \(found)"
        case .encryptedKeyNotEmpty(let algorithm):
            return "JWE has an encrypted key, which \(algorithm) does not use"
        case .contentEncryptionNotPermitted(let keyAlgorithm, let contentEncryption):
            return "the dir key is restricted to \(keyAlgorithm); the JWE uses \(contentEncryption)"
        case .wrongInitializationVectorSize(let algorithm, let expected, let found):
            return "JWE initialization vector is \(found) bytes; \(algorithm) requires \(expected)"
        case .wrongAuthenticationTagSize(let algorithm, let expected, let found):
            return "JWE authentication tag is \(found) bytes; \(algorithm) requires \(expected)"
        case .decryptionFailed:
            return "JWE decryption failed"
        case .noRecipientDecrypted(let reasons):
            return "none of the JWE's \(reasons.count) recipients could be decrypted: "
                + reasons.map(\.description).joined(separator: "; ")
        case .noUsableRecipient(let reasons):
            return "none of the JWE's \(reasons.count) recipients has a usable header: "
                + reasons.map(\.description).joined(separator: "; ")
        case .algorithmRequiresSingleRecipient(let algorithm):
            return "\(algorithm) determines the content encryption key and cannot be combined with other recipients"
        case .noRecipients:
            return "a JWE needs at least one recipient"
        case .sharedKeyIDWithMultipleRecipients:
            return "a JWE with several recipients cannot have a shared \"kid\"; each recipient's key ID is its own"
        case .keyEncryptionFailed(let algorithm, let error):
            return "\(algorithm) key encryption failed: \(error)"
        case .contentEncryptionFailed(let description):
            return "JWE content encryption failed: \(description)"
        case .headerEncodingFailed(let description):
            return "JWE header could not be encoded: \(description)"
        case .customParameterCollision(let name):
            return "custom header type encodes \"\(name)\", which is a parameter this package sets"
        case .customParametersNotObject:
            return "custom header type did not encode to a JSON object"
        case .notRepresentable(let serialization, let reason):
            return "this JWE cannot be written in the \(serialization) serialization: \(reason)"
        }
    }
}
