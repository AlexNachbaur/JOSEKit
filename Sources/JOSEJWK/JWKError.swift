import JOSECore

/// Why a key could not be read, built or used.
public enum JWKError: Error, Sendable, Equatable {
    /// The JWK is not a JSON object with unique member names.
    case invalidJSONStructure(JSONStructureError)
    /// The JSON could not be decoded for a reason not covered by a more specific case.
    case invalidJSON(description: String)
    /// A member the key type requires is absent. `keyType` is the `kty` value, if it was readable.
    case missingMember(name: String, keyType: String?)
    /// A member is present but is not the JSON type its definition requires.
    case wrongMemberType(name: String, expected: String)
    /// A member that must be base64url is not.
    case invalidBase64URL(member: String, Base64URLError)
    /// A key value has the wrong number of bytes. RFC 7518 §6.2.1 requires coordinates to be
    /// the full size of the curve, with leading zeros kept.
    case wrongByteCount(member: String, curve: String, expected: Int, found: Int)
    /// The `x`/`y` pair is not a point on the named curve.
    case pointNotOnCurve(curve: String)
    case x963WrongLength(curve: String, expected: Int, found: Int)
    /// The X9.63 buffer does not begin with `0x04`. Compressed and hybrid points are not accepted,
    /// and a buffer of the right length with another first byte is not a point at all.
    case x963NotUncompressed(curve: String, marker: UInt8)
    /// The private value is not a valid private key for the curve (zero, or not below the order).
    case invalidPrivateKey(curve: String)
    /// RFC 7518 §3.3 and §3.5: an RSA key of 2048 bits or larger must be used.
    case rsaKeyTooSmall(bitCount: Int, minimum: Int)
    /// The modulus is larger than this package will process. Verification cost grows steeply
    /// with key size, and a key can arrive from an untrusted JWK Set.
    case rsaKeyTooLarge(bitCount: Int, maximum: Int)
    /// An RSA value has a leading zero byte. RFC 7518 §6.3.1 (Base64urlUInt) requires the
    /// minimum number of octets, so that equal keys have equal JWKs and thumbprints.
    case nonMinimalInteger(member: String)
    /// The RSA key's values cannot form a key: an even modulus or exponent, an exponent of 1,
    /// or values the platform's RSA implementation refuses.
    case invalidRSAKey(reason: String)
    /// A private RSA JWK in a form this package does not handle: without the CRT values
    /// (`p`, `q`, `dp`, `dq`, `qi`), or with more than two primes (`oth`).
    case unsupportedRSAPrivateKey(reason: String)
    /// A PKCS#1 DER key could not be read.
    case invalidDER(reason: String)
    /// ECDH could not produce a usable shared secret with the given public key.
    case keyAgreementFailed(curve: String)
    /// RSA encryption failed. The plaintext may be too long for the key.
    case rsaEncryptionFailed(reason: String)
    /// RSA decryption failed. Deliberately carries no detail: saying why would help an attacker
    /// who can submit ciphertexts.
    case rsaDecryptionFailed
    /// A private JWK's `d` does not correspond to its public members.
    case privateKeyDoesNotMatchPublicKey(curve: String)
    /// A JWK being read as a public key carries a private member.
    case privateMemberInPublicKey(member: String, keyType: String)
    /// `kty` is `oct`. A symmetric key is never a public key.
    case symmetricKeyInPublicKey
    /// The JWK's `kty`/`crv` is not the one this operation needs.
    case keyTypeMismatch(expected: String, found: String)
    /// The JWK's `use` does not allow the operation.
    case useNotPermitted(use: String, required: String)
    /// The JWK's `key_ops` does not include the operation.
    case keyOperationNotPermitted(operations: [String], required: String)
    /// The JWK's `alg` names a different algorithm from the one it is being used with.
    case algorithmMismatch(keyAlgorithm: AlgorithmIdentifier, required: AlgorithmIdentifier)
    /// RFC 7518 §3.2: an HMAC key must be at least as long as the hash output.
    case keyTooShort(algorithm: AlgorithmIdentifier, minimumByteCount: Int, found: Int)
    /// The algorithm needs a symmetric key of exactly one size, such as 32 bytes for A256KW.
    case keyWrongSize(algorithm: AlgorithmIdentifier, expectedByteCount: Int, found: Int)
    /// `key_ops` lists the same operation twice, which RFC 7517 §4.3 forbids.
    case duplicateKeyOperation(String)
    /// The top-level `keys` member of a JWK Set is absent or is not an array.
    case invalidKeySet
    /// A thumbprint needs the key type's required members, which are unknown for this `kty`.
    case thumbprintUnavailable(keyType: String)
    /// An additional parameter uses a name that the JWK's typed properties already own.
    case reservedParameterName(String)
}

extension JWKError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidJSONStructure(let error):
            return "JWK is not a well-formed JSON object: \(error)"
        case .invalidJSON(let description):
            return "JWK could not be decoded: \(description)"
        case .missingMember(let name, let keyType):
            if let keyType {
                return "JWK of type \(keyType) is missing required member \"\(name)\""
            }
            return "JWK is missing required member \"\(name)\""
        case .wrongMemberType(let name, let expected):
            return "JWK member \"\(name)\" must be \(expected)"
        case .invalidBase64URL(let member, let error):
            return "JWK member \"\(member)\" is not valid base64url: \(error)"
        case .wrongByteCount(let member, let curve, let expected, let found):
            return "JWK member \"\(member)\" is \(found) bytes; \(curve) requires exactly \(expected)"
        case .pointNotOnCurve(let curve):
            return "public key is not a point on \(curve)"
        case .x963WrongLength(let curve, let expected, let found):
            return "X9.63 public key is \(found) bytes; an uncompressed \(curve) point is \(expected)"
        case .x963NotUncompressed(let curve, let marker):
            return "X9.63 public key for \(curve) starts with 0x\(String(marker, radix: 16)); "
                + "only uncompressed points (0x04) are accepted"
        case .invalidPrivateKey(let curve):
            return "private key value is not valid for \(curve)"
        case .rsaKeyTooSmall(let bitCount, let minimum):
            return "RSA key is \(bitCount) bits; at least \(minimum) are required"
        case .rsaKeyTooLarge(let bitCount, let maximum):
            return "RSA key is \(bitCount) bits; at most \(maximum) are supported"
        case .nonMinimalInteger(let member):
            return "JWK member \"\(member)\" has a leading zero byte; RSA values must be minimally encoded"
        case .invalidRSAKey(let reason):
            return "RSA key is not valid: \(reason)"
        case .unsupportedRSAPrivateKey(let reason):
            return "RSA private key is not supported: \(reason)"
        case .invalidDER(let reason):
            return "PKCS#1 DER key could not be read: \(reason)"
        case .keyAgreementFailed(let curve):
            return "\(curve) key agreement did not produce a usable shared secret"
        case .rsaEncryptionFailed(let reason):
            return "RSA encryption failed: \(reason)"
        case .rsaDecryptionFailed:
            return "RSA decryption failed"
        case .privateKeyDoesNotMatchPublicKey(let curve):
            return "\(curve) private key does not correspond to the public key it was supplied with"
        case .privateMemberInPublicKey(let member, let keyType):
            return "JWK of type \(keyType) carries private member \"\(member)\" where a public key is required"
        case .symmetricKeyInPublicKey:
            return "JWK of type oct is a symmetric key and cannot be used as a public key"
        case .keyTypeMismatch(let expected, let found):
            return "JWK is a \(found) key; a \(expected) key is required"
        case .useNotPermitted(let use, let required):
            return "JWK has use \"\(use)\"; \"\(required)\" is required"
        case .keyOperationNotPermitted(let operations, let required):
            return "JWK key_ops \(operations) does not include \"\(required)\""
        case .algorithmMismatch(let keyAlgorithm, let required):
            return "JWK is restricted to algorithm \(keyAlgorithm); it cannot be used with \(required)"
        case .keyTooShort(let algorithm, let minimumByteCount, let found):
            return "\(algorithm) key is \(found) bytes; at least \(minimumByteCount) are required"
        case .keyWrongSize(let algorithm, let expectedByteCount, let found):
            return "\(algorithm) key is \(found) bytes; exactly \(expectedByteCount) are required"
        case .duplicateKeyOperation(let name):
            return "JWK key_ops lists \"\(name)\" more than once"
        case .invalidKeySet:
            return "JWK Set has no \"keys\" array"
        case .thumbprintUnavailable(let keyType):
            return "cannot compute a thumbprint for unrecognised key type \(keyType)"
        case .reservedParameterName(let name):
            return "\"\(name)\" is a registered JWK member and cannot be set as an additional parameter"
        }
    }
}
