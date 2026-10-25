import Foundation
import JOSECore

/// A private asymmetric key in JWK form.
///
/// A separate type from ``JWK`` so that private material cannot be placed anywhere a public key
/// is expected. Not `Codable`: writing one out is the explicit ``jsonRepresentation()`` call.
public struct PrivateJWK: Sendable {
    public enum Key: Sendable {
        case p256(ECPrivateKey<P256Curve>)
        case p384(ECPrivateKey<P384Curve>)
        case p521(ECPrivateKey<P521Curve>)
        case ed25519(Ed25519PrivateKey)
        case x25519(X25519PrivateKey)
        case rsa(RSAPrivateKey)
        /// A key of a type another module adds, such as a secp256k1 key from JOSESecp256k1.
        case external(any ExternalPrivateKey)
    }

    public let key: Key
    public var metadata: JWKMetadata

    public init(_ key: Key, metadata: JWKMetadata = JWKMetadata()) {
        self.key = key
        self.metadata = metadata
    }

    /// The corresponding public JWK, with the same metadata.
    public var publicJWK: JWK {
        switch key {
        case .p256(let key):
            return JWK(.p256(key.publicKey), metadata: metadata)
        case .p384(let key):
            return JWK(.p384(key.publicKey), metadata: metadata)
        case .p521(let key):
            return JWK(.p521(key.publicKey), metadata: metadata)
        case .ed25519(let key):
            return JWK(.ed25519(key.publicKey), metadata: metadata)
        case .x25519(let key):
            return JWK(.x25519(key.publicKey), metadata: metadata)
        case .rsa(let key):
            return JWK(.rsa(key.publicKey), metadata: metadata)
        case .external(let key):
            return JWK(.external(JWK.ExternalKey(key.publicKey)), metadata: metadata)
        }
    }

    /// Parses a private JWK, checking that `d` corresponds to the public members beside it.
    ///
    /// A key whose type is listed in `keyTypes` is read as ``Key/external(_:)``.
    public init(json: Data, keyTypes: [any ExternalKeyType] = []) throws(JWKError) {
        let members = try JWKMembers(json: json)
        let keyType = try members.requiredString("kty", keyType: nil)
        metadata = try members.metadata()

        switch keyType {
        case "EC":
            let curve = try members.requiredString("crv", keyType: keyType)
            switch curve {
            case P256Curve.name:
                key = .p256(try Self.ecPrivateKey(members, keyType: keyType))
            case P384Curve.name:
                key = .p384(try Self.ecPrivateKey(members, keyType: keyType))
            case P521Curve.name:
                key = .p521(try Self.ecPrivateKey(members, keyType: keyType))
            default:
                key = try Self.external(
                    members,
                    keyTypes: keyTypes,
                    otherwise: .keyTypeMismatch(expected: "EC P-256, P-384 or P-521", found: "EC \(curve)")
                )
            }
        case "OKP":
            let curve = try members.requiredString("crv", keyType: keyType)
            guard curve == Ed25519PublicKey.curveName || curve == X25519PublicKey.curveName else {
                key = try Self.external(
                    members,
                    keyTypes: keyTypes,
                    otherwise: .keyTypeMismatch(expected: "OKP Ed25519 or X25519", found: "OKP \(curve)")
                )
                return
            }
            let publicBytes = try members.requiredBytes("x", keyType: keyType)
            let privateBytes = try members.requiredBytes("d", keyType: keyType)
            switch curve {
            case Ed25519PublicKey.curveName:
                let declared = try Ed25519PublicKey(rawRepresentation: publicBytes)
                let privateKey = try Ed25519PrivateKey(rawRepresentation: privateBytes)
                guard privateKey.publicKey == declared else {
                    throw .privateKeyDoesNotMatchPublicKey(curve: curve)
                }
                key = .ed25519(privateKey)
            case X25519PublicKey.curveName:
                let declared = try X25519PublicKey(rawRepresentation: publicBytes)
                let privateKey = try X25519PrivateKey(rawRepresentation: privateBytes)
                guard privateKey.publicKey == declared else {
                    throw .privateKeyDoesNotMatchPublicKey(curve: curve)
                }
                key = .x25519(privateKey)
            default:
                throw .keyTypeMismatch(expected: "OKP Ed25519 or X25519", found: "OKP \(curve)")
            }
        case "RSA":
            // RFC 7518 §6.3.2 lets a producer omit the CRT values or add further primes. Both
            // platform implementations need the two-prime CRT form.
            guard members.values["oth"] == nil else {
                throw .unsupportedRSAPrivateKey(reason: "keys with more than two primes (\"oth\") are not supported")
            }
            for name in ["p", "q", "dp", "dq", "qi"] where members.values[name] == nil {
                throw .unsupportedRSAPrivateKey(reason: "the CRT value \"\(name)\" is missing")
            }
            let components = RSAPrivateKeyComponents(
                modulus: try members.requiredBytes("n", keyType: keyType),
                publicExponent: try members.requiredBytes("e", keyType: keyType),
                privateExponent: try members.requiredBytes("d", keyType: keyType),
                prime1: try members.requiredBytes("p", keyType: keyType),
                prime2: try members.requiredBytes("q", keyType: keyType),
                exponent1: try members.requiredBytes("dp", keyType: keyType),
                exponent2: try members.requiredBytes("dq", keyType: keyType),
                coefficient: try members.requiredBytes("qi", keyType: keyType)
            )
            key = .rsa(try RSAPrivateKey(components: components))
        default:
            key = try Self.external(
                members,
                keyTypes: keyTypes,
                otherwise: .keyTypeMismatch(expected: "EC, OKP or RSA", found: keyType)
            )
        }
    }

    /// The key one of `keyTypes` reads from `members`, or `error` if none of them does.
    private static func external(
        _ members: JWKMembers,
        keyTypes: [any ExternalKeyType],
        otherwise error: JWKError
    ) throws(JWKError) -> Key {
        for externalType in keyTypes {
            if let key = try externalType.privateKey(from: members.values) {
                return .external(key)
            }
        }
        throw error
    }

    static func ecPrivateKey<Curve: EllipticCurve>(
        _ members: JWKMembers,
        keyType: String
    ) throws(JWKError) -> ECPrivateKey<Curve> {
        let declared = try ECPublicKey<Curve>(
            x: members.requiredBytes("x", keyType: keyType),
            y: members.requiredBytes("y", keyType: keyType)
        )
        let privateKey = try ECPrivateKey<Curve>(rawRepresentation: members.requiredBytes("d", keyType: keyType))
        // Without this, a JWK could pair one key's `d` with another key's `x`/`y`, and the public
        // half published from it would not verify anything the private half signs.
        guard privateKey.publicKey == declared else {
            throw .privateKeyDoesNotMatchPublicKey(curve: Curve.name)
        }
        return privateKey
    }

    /// The private JWK as JSON. This output contains the private key.
    public func jsonRepresentation() throws(JWKError) -> Data {
        var members = publicJWK.members
        switch key {
        case .p256(let key):
            members.values["d"] = .string(String(base64URLEncoding: key.rawRepresentation))
        case .p384(let key):
            members.values["d"] = .string(String(base64URLEncoding: key.rawRepresentation))
        case .p521(let key):
            members.values["d"] = .string(String(base64URLEncoding: key.rawRepresentation))
        case .ed25519(let key):
            members.values["d"] = .string(String(base64URLEncoding: key.rawRepresentation))
        case .x25519(let key):
            members.values["d"] = .string(String(base64URLEncoding: key.rawRepresentation))
        case .rsa(let key):
            members.values["d"] = .string(String(base64URLEncoding: key.components.privateExponent))
            members.values["p"] = .string(String(base64URLEncoding: key.components.prime1))
            members.values["q"] = .string(String(base64URLEncoding: key.components.prime2))
            members.values["dp"] = .string(String(base64URLEncoding: key.components.exponent1))
            members.values["dq"] = .string(String(base64URLEncoding: key.components.exponent2))
            members.values["qi"] = .string(String(base64URLEncoding: key.components.coefficient))
        case .external(let key):
            members.values.merge(key.privateJWKMembers) { _, privateMember in privateMember }
        }
        return try members.jsonRepresentation()
    }
}

extension PrivateJWK: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "PrivateJWK(\(publicJWK.keyType), redacted)"
    }

    public var debugDescription: String {
        description
    }
}

/// A symmetric key in JWK form (`kty` `oct`). Not `Codable`, for the same reason as ``PrivateJWK``.
public struct SymmetricJWK: Sendable {
    public let key: SymmetricKeyMaterial
    public var metadata: JWKMetadata

    public init(_ key: SymmetricKeyMaterial, metadata: JWKMetadata = JWKMetadata()) {
        self.key = key
        self.metadata = metadata
    }

    public init(json: Data) throws(JWKError) {
        let members = try JWKMembers(json: json)
        let keyType = try members.requiredString("kty", keyType: nil)
        guard keyType == "oct" else {
            throw .keyTypeMismatch(expected: "oct", found: keyType)
        }
        metadata = try members.metadata()
        key = SymmetricKeyMaterial(rawRepresentation: try members.requiredBytes("k", keyType: keyType))
    }

    /// The symmetric JWK as JSON. This output contains the key.
    public func jsonRepresentation() throws(JWKError) -> Data {
        var members = JWKMembers(values: [
            "kty": "oct",
            "k": .string(String(base64URLEncoding: key.rawRepresentation)),
        ])
        members.set(metadata)
        return try members.jsonRepresentation()
    }
}

extension SymmetricJWK: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "SymmetricJWK(redacted)"
    }

    public var debugDescription: String {
        description
    }
}
