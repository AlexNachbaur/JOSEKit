import Foundation
import JOSECore
import JOSEJWK

/// How the plaintext is compressed before encryption, the `zip` header parameter
/// (RFC 7516 §4.1.3).
public enum JWECompression: String, Sendable, Equatable {
    /// Raw DEFLATE (RFC 1951), `zip` value `DEF`.
    case deflate = "DEF"

    /// The largest decompressed plaintext a decryption accepts by default, in bytes. The same as
    /// panva/jose's default. Compression lets a small token expand into a large plaintext, so a
    /// decryption refuses anything larger.
    public static let defaultMaximumDecompressedByteCount = 250_000

    /// Whether this platform can compress and decompress this way. `deflate` needs the system
    /// zlib, which Windows does not have; there a JWE with `zip` is refused with
    /// ``JWEError/unsupportedCompression(algorithm:)``, whether it is being read or written.
    public var isAvailable: Bool {
        switch self {
        case .deflate:
            return Deflate.isAvailable
        }
    }
}

/// The header parameters a caller may set. `alg`, `enc`, `crit` and the parameters a key
/// management algorithm adds (`epk`, `iv`, `tag`, ...) are not among them.
public struct JWEHeaderParameters<Custom: HeaderParameters>: Sendable {
    /// `kid`. When encrypting to a single recipient, a `nil` here is filled from the recipient's
    /// key ID. It must be `nil` when encrypting to several recipients, because each recipient's
    /// own key ID goes in that recipient's header.
    public var keyID: KeyID?
    /// `typ`
    public var type: MediaType?
    /// `cty`. Set to `JWT` when the plaintext is itself a JWT (RFC 7519 §5.2).
    public var contentType: MediaType?
    /// `jwk`: the public key the JWE was encrypted to. Only public keys can be carried.
    public var jwk: JWK?
    /// `jku`
    public var jwkSetURL: String?
    /// `x5u`
    public var x509URL: String?
    /// `x5c`: standard base64 (not base64url) DER certificates, the recipient's first.
    public var x509CertificateChain: [String]?
    /// `x5t`
    public var x509CertificateSHA1Thumbprint: String?
    /// `x5t#S256`
    public var x509CertificateSHA256Thumbprint: String?
    /// `zip`: compress the plaintext before encrypting it. Always written to the protected
    /// header, as RFC 7516 §4.1.3 requires. Compressing secrets alongside data an attacker
    /// controls can reveal them through the ciphertext's length (as in CRIME), so leave this off
    /// unless the plaintext is entirely yours.
    public var compression: JWECompression?
    public var custom: Custom

    public init(
        keyID: KeyID? = nil,
        type: MediaType? = nil,
        contentType: MediaType? = nil,
        jwk: JWK? = nil,
        jwkSetURL: String? = nil,
        x509URL: String? = nil,
        x509CertificateChain: [String]? = nil,
        x509CertificateSHA1Thumbprint: String? = nil,
        x509CertificateSHA256Thumbprint: String? = nil,
        compression: JWECompression? = nil,
        custom: Custom
    ) {
        self.keyID = keyID
        self.type = type
        self.contentType = contentType
        self.jwk = jwk
        self.jwkSetURL = jwkSetURL
        self.x509URL = x509URL
        self.x509CertificateChain = x509CertificateChain
        self.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
        self.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
        self.compression = compression
        self.custom = custom
    }
}

extension JWEHeaderParameters where Custom == EmptyHeaderParameters {
    public init(
        keyID: KeyID? = nil,
        type: MediaType? = nil,
        contentType: MediaType? = nil,
        jwk: JWK? = nil,
        jwkSetURL: String? = nil,
        x509URL: String? = nil,
        x509CertificateChain: [String]? = nil,
        x509CertificateSHA1Thumbprint: String? = nil,
        x509CertificateSHA256Thumbprint: String? = nil,
        compression: JWECompression? = nil
    ) {
        self.init(
            keyID: keyID,
            type: type,
            contentType: contentType,
            jwk: jwk,
            jwkSetURL: jwkSetURL,
            x509URL: x509URL,
            x509CertificateChain: x509CertificateChain,
            x509CertificateSHA1Thumbprint: x509CertificateSHA1Thumbprint,
            x509CertificateSHA256Thumbprint: x509CertificateSHA256Thumbprint,
            compression: compression,
            custom: EmptyHeaderParameters()
        )
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

    /// `zip`, always from the protected header.
    public var compression: JWECompression? {
        parameters.compression
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

        let compression = try parseCompression(in: values, unprotectedNames: unprotectedNames)
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
        parameters.jwk = try jwk(in: values)
        parameters.jwkSetURL = try string("jku", in: values)
        parameters.x509URL = try string("x5u", in: values)
        parameters.x509CertificateChain = try stringArray("x5c", in: values)
        parameters.x509CertificateSHA1Thumbprint = try string("x5t", in: values)
        parameters.x509CertificateSHA256Thumbprint = try string("x5t#S256", in: values)
        parameters.compression = compression
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

    /// The `zip` parameter, which must be protected (RFC 7516 §4.1.3) and must name a compression
    /// this package implements and this platform supports. Encryption parses its own header
    /// through here too, so it refuses the same `zip` values.
    private static func parseCompression(
        in values: [String: JSONValue],
        unprotectedNames: Set<String>
    ) throws(JWEError) -> JWECompression? {
        guard let name = try string("zip", in: values) else {
            return nil
        }
        guard !unprotectedNames.contains("zip") else {
            throw .headerParameterNotProtected(name: "zip")
        }
        guard let compression = JWECompression(rawValue: name), compression.isAvailable else {
            throw .unsupportedCompression(algorithm: name)
        }
        return compression
    }

    private static func stringArray(_ name: String, in values: [String: JSONValue]) throws(JWEError) -> [String]? {
        guard let value = values[name] else {
            return nil
        }
        guard case .array(let elements) = value else {
            throw .headerParameterWrongType(name: name, expected: "an array of strings")
        }
        var strings: [String] = []
        for element in elements {
            guard case .string(let string) = element else {
                throw .headerParameterWrongType(name: name, expected: "an array of strings")
            }
            strings.append(string)
        }
        return strings
    }

    /// The `jwk` parameter, which must be a public key.
    private static func jwk(in values: [String: JSONValue]) throws(JWEError) -> JWK? {
        guard let value = values["jwk"] else {
            return nil
        }
        guard case .object = value else {
            throw .headerParameterWrongType(name: "jwk", expected: "an object")
        }
        do {
            return try JWK(json: try JWEJSON.encoder().encode(value))
        } catch let error as JWKError {
            throw .invalidJWKParameter(error)
        } catch {
            throw .invalidHeaderJSON(description: String(describing: error))
        }
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
        if let compression {
            values["zip"] = .string(compression.rawValue)
        }
        if let jwk {
            do {
                values["jwk"] = try JSONDecoder().decode(JSONValue.self, from: try jwk.jsonRepresentation())
            } catch {
                throw .headerEncodingFailed(description: String(describing: error))
            }
        }
        let strings: [(String, String?)] = [
            ("jku", jwkSetURL), ("x5u", x509URL), ("x5t", x509CertificateSHA1Thumbprint),
            ("x5t#S256", x509CertificateSHA256Thumbprint),
        ]
        for case (let name, let value?) in strings {
            values[name] = .string(value)
        }
        if let x509CertificateChain {
            values["x5c"] = .array(x509CertificateChain.map { .string($0) })
        }
        return values
    }
}
