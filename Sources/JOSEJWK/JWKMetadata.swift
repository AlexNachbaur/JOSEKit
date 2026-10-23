import Foundation
import JOSECore

/// The intended use of a public key (`use`, RFC 7517 §4.2).
public struct KeyUse: RawRepresentable, Sendable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let signature = KeyUse(rawValue: "sig")
    public static let encryption = KeyUse(rawValue: "enc")
}

/// An operation a key may be used for (`key_ops`, RFC 7517 §4.3).
public struct KeyOperation: RawRepresentable, Sendable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let sign = KeyOperation(rawValue: "sign")
    public static let verify = KeyOperation(rawValue: "verify")
    public static let encrypt = KeyOperation(rawValue: "encrypt")
    public static let decrypt = KeyOperation(rawValue: "decrypt")
    public static let wrapKey = KeyOperation(rawValue: "wrapKey")
    public static let unwrapKey = KeyOperation(rawValue: "unwrapKey")
    public static let deriveKey = KeyOperation(rawValue: "deriveKey")
    public static let deriveBits = KeyOperation(rawValue: "deriveBits")
}

/// The JWK members that describe a key rather than define it.
public struct JWKMetadata: Sendable, Hashable {
    public var keyID: KeyID?
    public var use: KeyUse?
    public var keyOperations: [KeyOperation]?
    /// The single algorithm this key is restricted to, if any (`alg`).
    public var algorithm: AlgorithmIdentifier?

    public init(
        keyID: KeyID? = nil,
        use: KeyUse? = nil,
        keyOperations: [KeyOperation]? = nil,
        algorithm: AlgorithmIdentifier? = nil
    ) {
        self.keyID = keyID
        self.use = use
        self.keyOperations = keyOperations
        self.algorithm = algorithm
    }

    /// Throws unless every restriction the key declares allows `operation` with `algorithm`.
    /// A restriction that is absent allows everything.
    public func requirePermission(
        for operation: KeyOperation,
        use requiredUse: KeyUse,
        algorithm required: AlgorithmIdentifier
    ) throws(JWKError) {
        if let use {
            guard use == requiredUse else {
                throw .useNotPermitted(use: use.rawValue, required: requiredUse.rawValue)
            }
        }
        if let keyOperations {
            guard keyOperations.contains(operation) else {
                throw .keyOperationNotPermitted(
                    operations: keyOperations.map(\.rawValue),
                    required: operation.rawValue
                )
            }
        }
        if let algorithm {
            guard algorithm == required else {
                throw .algorithmMismatch(keyAlgorithm: algorithm, required: required)
            }
        }
    }
}

/// The members of a JWK as parsed JSON, with accessors that report which member was wrong.
struct JWKMembers {
    static let metadataNames: Set<String> = ["kid", "use", "key_ops", "alg"]

    var values: [String: JSONValue]

    init(json: Data) throws(JWKError) {
        do {
            try json.requireUniqueJSONMembers()
        } catch {
            throw .invalidJSONStructure(error)
        }
        do {
            values = try JSONDecoder().decode([String: JSONValue].self, from: json)
        } catch {
            throw .invalidJSON(description: String(describing: error))
        }
    }

    init(values: [String: JSONValue]) {
        self.values = values
    }

    func optionalString(_ name: String) throws(JWKError) -> String? {
        guard let value = values[name] else {
            return nil
        }
        guard case .string(let string) = value else {
            throw .wrongMemberType(name: name, expected: "a string")
        }
        return string
    }

    func requiredString(_ name: String, keyType: String?) throws(JWKError) -> String {
        guard let string = try optionalString(name) else {
            throw .missingMember(name: name, keyType: keyType)
        }
        return string
    }

    func requiredBytes(_ name: String, keyType: String) throws(JWKError) -> Data {
        let string = try requiredString(name, keyType: keyType)
        do {
            return try Data(base64URLEncoded: string)
        } catch {
            throw .invalidBase64URL(member: name, error)
        }
    }

    func requireAbsent(_ name: String, keyType: String) throws(JWKError) {
        guard values[name] == nil else {
            throw .privateMemberInPublicKey(member: name, keyType: keyType)
        }
    }

    func metadata() throws(JWKError) -> JWKMetadata {
        var metadata = JWKMetadata()
        if let keyID = try optionalString("kid") {
            metadata.keyID = KeyID(rawValue: keyID)
        }
        if let use = try optionalString("use") {
            metadata.use = KeyUse(rawValue: use)
        }
        if let algorithm = try optionalString("alg") {
            metadata.algorithm = AlgorithmIdentifier(rawValue: algorithm)
        }
        if let operations = values["key_ops"] {
            guard case .array(let elements) = operations else {
                throw .wrongMemberType(name: "key_ops", expected: "an array of strings")
            }
            var parsed: [KeyOperation] = []
            for element in elements {
                guard case .string(let name) = element else {
                    throw .wrongMemberType(name: "key_ops", expected: "an array of strings")
                }
                let operation = KeyOperation(rawValue: name)
                // RFC 7517 §4.3: duplicate values must not be present.
                guard !parsed.contains(operation) else {
                    throw .duplicateKeyOperation(name)
                }
                parsed.append(operation)
            }
            metadata.keyOperations = parsed
        }
        return metadata
    }

    mutating func set(_ metadata: JWKMetadata) {
        if let keyID = metadata.keyID {
            values["kid"] = .string(keyID.rawValue)
        }
        if let use = metadata.use {
            values["use"] = .string(use.rawValue)
        }
        if let algorithm = metadata.algorithm {
            values["alg"] = .string(algorithm.rawValue)
        }
        if let operations = metadata.keyOperations {
            values["key_ops"] = .array(operations.map { .string($0.rawValue) })
        }
    }

    func jsonRepresentation() throws(JWKError) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        do {
            return try encoder.encode(values)
        } catch {
            throw .invalidJSON(description: String(describing: error))
        }
    }
}
