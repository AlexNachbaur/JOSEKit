import Foundation
import JOSECore

/// A public key in JWK form (RFC 7517).
///
/// A `JWK` only ever holds public material. Private and symmetric keys have their own types
/// (``PrivateJWK``, ``SymmetricJWK``), so nothing that takes a `JWK` — a ``JWKSet``, the `jwk`
/// header parameter — can be handed a secret.
public struct JWK: Sendable, Hashable {
    public enum Key: Sendable, Hashable {
        case p256(ECPublicKey<P256Curve>)
        case p384(ECPublicKey<P384Curve>)
        case p521(ECPublicKey<P521Curve>)
        case ed25519(Ed25519PublicKey)
        case x25519(X25519PublicKey)
        case rsa(RSAPublicKey)
        /// A key type or curve this package does not implement. Its members are kept as they
        /// were read so that an add-on can interpret them.
        case unrecognized(UnrecognizedKey)
    }

    /// A key whose `kty` (or `crv`) is not one this package implements.
    public struct UnrecognizedKey: Sendable, Hashable {
        public let keyType: String
        /// Every member of the JWK except `kty` and the metadata members.
        public let parameters: [String: JSONValue]

        public init(keyType: String, parameters: [String: JSONValue]) {
            self.keyType = keyType
            self.parameters = parameters
        }
    }

    /// Member names that are owned by typed properties, or that would carry private material.
    static let reservedNames: Set<String> = [
        "kty", "crv", "x", "y", "d", "k", "n", "e", "p", "q", "dp", "dq", "qi", "oth", "kid", "use", "key_ops", "alg",
    ]

    public var key: Key
    public var metadata: JWKMetadata
    /// Members that are neither key material nor metadata, such as `x5c`. Carried, not interpreted.
    public private(set) var additionalParameters: [String: JSONValue] = [:]

    public init(_ key: Key, metadata: JWKMetadata = JWKMetadata()) {
        self.key = key
        self.metadata = metadata
    }

    public var keyID: KeyID? {
        metadata.keyID
    }

    /// The `kty` value.
    public var keyType: String {
        switch key {
        case .p256, .p384, .p521:
            return "EC"
        case .ed25519, .x25519:
            return "OKP"
        case .rsa:
            return "RSA"
        case .unrecognized(let unrecognized):
            return unrecognized.keyType
        }
    }

    /// Sets a member that is carried alongside the key, refusing names the typed properties own.
    public mutating func setAdditionalParameter(_ name: String, to value: JSONValue?) throws(JWKError) {
        guard !Self.reservedNames.contains(name) else {
            throw .reservedParameterName(name)
        }
        additionalParameters[name] = value
    }

    /// Parses a JWK from JSON, rejecting duplicate member names.
    public init(json: Data) throws(JWKError) {
        try self.init(members: JWKMembers(json: json))
    }

    init(members: JWKMembers) throws(JWKError) {
        let keyType = try members.requiredString("kty", keyType: nil)
        metadata = try members.metadata()

        var recognizedNames: Set<String> = ["kty"]
        switch keyType {
        case "EC":
            let curve = try members.requiredString("crv", keyType: keyType)
            switch curve {
            case P256Curve.name:
                key = .p256(try Self.ecPublicKey(members, keyType: keyType))
            case P384Curve.name:
                key = .p384(try Self.ecPublicKey(members, keyType: keyType))
            case P521Curve.name:
                key = .p521(try Self.ecPublicKey(members, keyType: keyType))
            default:
                key = Self.unrecognized(members, keyType: keyType)
                return
            }
            recognizedNames.formUnion(["crv", "x", "y"])
        case "OKP":
            let curve = try members.requiredString("crv", keyType: keyType)
            switch curve {
            case Ed25519PublicKey.curveName:
                try members.requireAbsent("d", keyType: keyType)
                key = .ed25519(try Ed25519PublicKey(rawRepresentation: members.requiredBytes("x", keyType: keyType)))
            case X25519PublicKey.curveName:
                try members.requireAbsent("d", keyType: keyType)
                key = .x25519(try X25519PublicKey(rawRepresentation: members.requiredBytes("x", keyType: keyType)))
            default:
                key = Self.unrecognized(members, keyType: keyType)
                return
            }
            recognizedNames.formUnion(["crv", "x"])
        case "RSA":
            for privateMember in RSAPrivateMembers.names {
                try members.requireAbsent(privateMember, keyType: keyType)
            }
            key = .rsa(
                try RSAPublicKey(
                    modulus: members.requiredBytes("n", keyType: keyType),
                    exponent: members.requiredBytes("e", keyType: keyType)
                )
            )
            recognizedNames.formUnion(["n", "e"])
        case "oct":
            throw .symmetricKeyInPublicKey
        default:
            key = Self.unrecognized(members, keyType: keyType)
            return
        }

        additionalParameters = members.values.filter { name, _ in
            !recognizedNames.contains(name) && !JWKMembers.metadataNames.contains(name)
        }
    }

    private static func ecPublicKey<Curve: EllipticCurve>(
        _ members: JWKMembers,
        keyType: String
    ) throws(JWKError) -> ECPublicKey<Curve> {
        try members.requireAbsent("d", keyType: keyType)
        return try ECPublicKey(
            x: members.requiredBytes("x", keyType: keyType),
            y: members.requiredBytes("y", keyType: keyType)
        )
    }

    private static func unrecognized(_ members: JWKMembers, keyType: String) -> Key {
        let parameters = members.values.filter { name, _ in
            name != "kty" && !JWKMembers.metadataNames.contains(name)
        }
        return .unrecognized(UnrecognizedKey(keyType: keyType, parameters: parameters))
    }

    var members: JWKMembers {
        var members = JWKMembers(values: additionalParameters)
        switch key {
        case .p256(let key):
            members.setECPublicKey(key)
        case .p384(let key):
            members.setECPublicKey(key)
        case .p521(let key):
            members.setECPublicKey(key)
        case .ed25519(let key):
            members.setOctetKeyPair(curve: Ed25519PublicKey.curveName, x: key.rawRepresentation)
        case .x25519(let key):
            members.setOctetKeyPair(curve: X25519PublicKey.curveName, x: key.rawRepresentation)
        case .rsa(let key):
            members.setRSAPublicKey(key)
        case .unrecognized(let unrecognized):
            members.values = unrecognized.parameters
            members.values["kty"] = .string(unrecognized.keyType)
        }
        members.set(metadata)
        return members
    }

    /// The JWK as JSON, with members in lexical order.
    public func jsonRepresentation() throws(JWKError) -> Data {
        try members.jsonRepresentation()
    }
}

extension JWKMembers {
    mutating func setECPublicKey<Curve: EllipticCurve>(_ key: ECPublicKey<Curve>) {
        values["kty"] = "EC"
        values["crv"] = .string(Curve.name)
        values["x"] = .string(Base64URL.encode(key.x))
        values["y"] = .string(Base64URL.encode(key.y))
    }

    mutating func setOctetKeyPair(curve: String, x: Data) {
        values["kty"] = "OKP"
        values["crv"] = .string(curve)
        values["x"] = .string(Base64URL.encode(x))
    }
}

/// The members that make an RSA JWK a private key (RFC 7518 §6.3.2).
struct RSAPrivateMembers {
    private init() {}

    static let names = ["d", "p", "q", "dp", "dq", "qi", "oth"]
}

extension JWKMembers {
    mutating func setRSAPublicKey(_ key: RSAPublicKey) {
        values["kty"] = "RSA"
        values["n"] = .string(Base64URL.encode(key.modulus))
        values["e"] = .string(Base64URL.encode(key.exponent))
    }
}

// Codable so that a JWK can sit inside another Codable type, such as a JOSE header. Decoding this
// way cannot see the raw bytes, so it does not check for duplicate member names; whoever decodes
// the enclosing document is responsible for running `JSONMemberUniqueness` over it first.
extension JWK: Codable {
    public init(from decoder: any Decoder) throws {
        let values = try decoder.singleValueContainer().decode([String: JSONValue].self)
        try self.init(members: JWKMembers(values: values))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(members.values)
    }
}

/// A set of public keys (RFC 7517 §5).
public struct JWKSet: Sendable {
    /// A member of the `keys` array that could not be used, and why.
    public struct RejectedKey: Sendable, Equatable {
        public let index: Int
        public let error: JWKError
    }

    public var keys: [JWK]
    /// Entries skipped while parsing. RFC 7517 §5 says a set should still be usable when some of
    /// its keys are malformed or out of range; they are recorded here rather than dropped
    /// silently, so that a missing key can be diagnosed.
    public let rejected: [RejectedKey]

    public init(keys: [JWK]) {
        self.keys = keys
        self.rejected = []
    }

    /// Parses a JWK Set, rejecting duplicate member names anywhere in the document.
    public init(json: Data) throws(JWKError) {
        let members = try JWKMembers(json: json)
        guard case .array(let entries) = members.values["keys"] else {
            throw .invalidKeySet
        }
        var keys: [JWK] = []
        var rejected: [RejectedKey] = []
        for (index, entry) in entries.enumerated() {
            guard case .object(let values) = entry else {
                rejected.append(RejectedKey(index: index, error: .wrongMemberType(name: "keys", expected: "objects")))
                continue
            }
            do {
                keys.append(try JWK(members: JWKMembers(values: values)))
            } catch {
                rejected.append(RejectedKey(index: index, error: error))
            }
        }
        self.keys = keys
        self.rejected = rejected
    }

    /// The keys whose `kid` is `keyID`. More than one key may share an identifier.
    public func keys(withID keyID: KeyID) -> [JWK] {
        keys.filter { $0.keyID == keyID }
    }

    public func jsonRepresentation() throws(JWKError) -> Data {
        let members = JWKMembers(values: ["keys": .array(keys.map { .object($0.members.values) })])
        return try members.jsonRepresentation()
    }
}
