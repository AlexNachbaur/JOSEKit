import Foundation
import JOSECore
import JOSEJWK

/// The header parameters a caller may set. `alg`, `enc`, `crit` and the parameters a key
/// management algorithm adds (`epk`, `iv`, `tag`, ...) are not among them.
public struct JWEHeaderParameters<Custom: HeaderParameters>: Sendable {
    /// `kid`. When encrypting to a single recipient, a `nil` here is filled from the recipient's
    /// key ID.
    public var keyID: KeyID?
    /// `typ`
    public var type: MediaType?
    /// `cty`. Set to `JWT` when the plaintext is itself a JWT (RFC 7519 §5.2).
    public var contentType: MediaType?
    public var custom: Custom

    public init(keyID: KeyID? = nil, type: MediaType? = nil, contentType: MediaType? = nil, custom: Custom) {
        self.keyID = keyID
        self.type = type
        self.contentType = contentType
        self.custom = custom
    }
}

extension JWEHeaderParameters where Custom == EmptyHeaderParameters {
    public init(keyID: KeyID? = nil, type: MediaType? = nil, contentType: MediaType? = nil) {
        self.init(keyID: keyID, type: type, contentType: contentType, custom: EmptyHeaderParameters())
    }
}

/// The header that applies to one recipient: the union of the protected header, the shared
/// unprotected header and that recipient's own header.
public struct JWEHeader<Custom: HeaderParameters>: Sendable {
    /// The key management algorithm, `alg`.
    public let algorithm: AlgorithmIdentifier
    /// The content encryption algorithm, `enc`.
    public let contentEncryption: AlgorithmIdentifier
    public let parameters: JWEHeaderParameters<Custom>
    /// The contents of `crit`, empty if absent.
    public let critical: [String]
    /// Every parameter as it was read, including ones no typed property covers.
    public let rawParameters: [String: JSONValue]
    /// Names of parameters that came from an unprotected header and so are not authenticated.
    public let unprotectedParameterNames: Set<String>

    public var keyID: KeyID? {
        parameters.keyID
    }

    public var type: MediaType? {
        parameters.type
    }

    public var contentType: MediaType? {
        parameters.contentType
    }

    public var custom: Custom {
        parameters.custom
    }
}

/// Names defined by RFC 7516 and RFC 7518. They may not appear in `crit`, and a custom header
/// type may not encode them.
let registeredJWEHeaderNames: Set<String> = [
    "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
    "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
]

struct JWEJSON {
    private init() {}

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        // Sorted so that the same header always produces the same bytes.
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    static func decodeBase64URL(_ text: String, part: String) throws(JWEError) -> Data {
        guard !text.utf8.contains(UInt8(ascii: "=")) else {
            throw .paddingNotAllowed(part: part)
        }
        do {
            return try Base64URL.decode(text)
        } catch {
            throw .invalidBase64URL(part: part, error)
        }
    }

    /// Reads the protected header's JSON, rejecting duplicate member names.
    static func protectedValues(_ json: Data) throws(JWEError) -> [String: JSONValue] {
        do {
            try JSONMemberUniqueness.validate(json)
        } catch {
            throw .invalidHeaderStructure(error)
        }
        do {
            return try JSONDecoder().decode([String: JSONValue].self, from: json)
        } catch {
            throw .invalidHeaderJSON(description: String(describing: error))
        }
    }
}

extension JWEHeader {
    /// Combines the three headers that apply to a recipient and checks the result.
    static func parse(
        protectedJSON: Data?,
        protected: [String: JSONValue],
        sharedUnprotected: [String: JSONValue],
        recipientUnprotected: [String: JSONValue]
    ) throws(JWEError) -> JWEHeader<Custom> {
        var values = protected
        var unprotectedNames: Set<String> = []
        for unprotected in [sharedUnprotected, recipientUnprotected] {
            for (name, value) in unprotected {
                // RFC 7516 §7.2.1: the three headers must be disjoint.
                guard values[name] == nil else {
                    throw .headerParameterInMultipleHeaders(name: name)
                }
                values[name] = value
                unprotectedNames.insert(name)
            }
        }

        guard values["zip"] == nil else {
            throw .compressionNotSupported
        }
        guard let algorithm = try string("alg", in: values) else {
            throw .missingAlgorithm
        }
        guard let contentEncryption = try string("enc", in: values) else {
            throw .missingContentEncryption
        }
        let critical = try parseCritical(values: values, unprotectedNames: unprotectedNames)

        let custom: Custom
        do {
            // Decoded from the protected header's own bytes whenever that is the whole header,
            // so that the custom type sees exactly what was authenticated.
            if let protectedJSON, unprotectedNames.isEmpty {
                custom = try JSONDecoder().decode(Custom.self, from: protectedJSON)
            } else {
                custom = try JSONDecoder().decode(Custom.self, from: try JWEJSON.encoder().encode(values))
            }
        } catch {
            throw .invalidCustomParameters(description: String(describing: error))
        }

        var parameters = JWEHeaderParameters(custom: custom)
        if let keyID = try string("kid", in: values) {
            parameters.keyID = KeyID(rawValue: keyID)
        }
        if let type = try string("typ", in: values) {
            parameters.type = MediaType(rawValue: type)
        }
        if let contentType = try string("cty", in: values) {
            parameters.contentType = MediaType(rawValue: contentType)
        }
        return JWEHeader(
            algorithm: AlgorithmIdentifier(rawValue: algorithm),
            contentEncryption: AlgorithmIdentifier(rawValue: contentEncryption),
            parameters: parameters,
            critical: critical,
            rawParameters: values,
            unprotectedParameterNames: unprotectedNames
        )
    }

    private static func string(_ name: String, in values: [String: JSONValue]) throws(JWEError) -> String? {
        guard let value = values[name] else {
            return nil
        }
        guard case .string(let string) = value else {
            throw .headerParameterWrongType(name: name, expected: "a string")
        }
        return string
    }

    /// Applies RFC 7515 §4.1.11, which RFC 7516 §4.1.13 adopts for JWE.
    private static func parseCritical(
        values: [String: JSONValue],
        unprotectedNames: Set<String>
    ) throws(JWEError) -> [String] {
        guard let crit = values["crit"] else {
            return []
        }
        guard !unprotectedNames.contains("crit") else {
            throw .headerParameterNotProtected(name: "crit")
        }
        guard case .array(let elements) = crit else {
            throw .headerParameterWrongType(name: "crit", expected: "an array of strings")
        }
        guard !elements.isEmpty else {
            throw .invalidCritical(reason: "the list is empty")
        }
        var names: [String] = []
        for element in elements {
            guard case .string(let name) = element else {
                throw .headerParameterWrongType(name: "crit", expected: "an array of strings")
            }
            guard !names.contains(name) else {
                throw .invalidCritical(reason: "\"\(name)\" is listed more than once")
            }
            guard !registeredJWEHeaderNames.contains(name) else {
                throw .invalidCritical(reason: "\"\(name)\" is defined by the JWE specification and cannot be critical")
            }
            guard values[name] != nil else {
                throw .invalidCritical(reason: "\"\(name)\" is listed but is not in the header")
            }
            guard Custom.criticalParameterNames.contains(name) else {
                throw .unsupportedCriticalParameter(name: name)
            }
            names.append(name)
        }
        return names
    }
}

extension JWEHeaderParameters {
    /// The caller's parameters as header members, including `crit` for any critical custom
    /// parameter that is present.
    func values() throws(JWEError) -> [String: JSONValue] {
        var values: [String: JSONValue]
        do {
            let customJSON = try JWEJSON.encoder().encode(custom)
            guard case .object(let object) = try JSONDecoder().decode(JSONValue.self, from: customJSON) else {
                throw JWEError.customParametersNotObject
            }
            values = object
        } catch let error as JWEError {
            throw error
        } catch {
            throw .headerEncodingFailed(description: String(describing: error))
        }
        for name in values.keys {
            guard !registeredJWEHeaderNames.contains(name) else {
                throw .customParameterCollision(name: name)
            }
        }
        let critical = Custom.criticalParameterNames.filter { values[$0] != nil }.sorted()
        if !critical.isEmpty {
            values["crit"] = .array(critical.map { .string($0) })
        }
        if let keyID {
            values["kid"] = .string(keyID.rawValue)
        }
        if let type {
            values["typ"] = .string(type.rawValue)
        }
        if let contentType {
            values["cty"] = .string(contentType.rawValue)
        }
        return values
    }
}
