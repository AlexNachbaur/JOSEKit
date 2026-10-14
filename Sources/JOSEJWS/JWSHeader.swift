import Foundation
import JOSECore
import JOSEJWK

/// The header parameters a caller may set. `alg`, `crit` and `b64` are not among them: the first
/// comes from the signer, the others from the custom type and the payload encoding.
public struct JWSHeaderParameters<Custom: HeaderParameters>: Sendable {
    /// `kid`. When signing, a `nil` here is filled from the signer's key ID.
    public var keyID: KeyID?
    /// `typ`
    public var type: MediaType?
    /// `cty`
    public var contentType: MediaType?
    /// `jwk`. A public key by construction.
    public var jwk: JWK?
    /// `jku`
    public var jwkSetURL: String?
    /// `x5u`
    public var x509URL: String?
    /// `x5c`: certificates as standard (not URL-safe) base64 DER. Carried, not validated.
    public var x509CertificateChain: [String]?
    /// `x5t`
    public var x509CertificateSHA1Thumbprint: String?
    /// `x5t#S256`
    public var x509CertificateSHA256Thumbprint: String?
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
        self.custom = custom
    }
}

extension JWSHeaderParameters where Custom == EmptyHeaderParameters {
    public init(
        keyID: KeyID? = nil,
        type: MediaType? = nil,
        contentType: MediaType? = nil,
        jwk: JWK? = nil,
        jwkSetURL: String? = nil,
        x509URL: String? = nil,
        x509CertificateChain: [String]? = nil,
        x509CertificateSHA1Thumbprint: String? = nil,
        x509CertificateSHA256Thumbprint: String? = nil
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
            custom: EmptyHeaderParameters()
        )
    }
}

/// The header of one signature: the union of its protected and unprotected headers.
///
/// Only produced by this package, by parsing or by signing, so ``algorithm`` always reflects
/// what was actually signed or received.
public struct JWSHeader<Custom: HeaderParameters>: Sendable {
    public let algorithm: AlgorithmIdentifier
    public let parameters: JWSHeaderParameters<Custom>
    /// The contents of `crit`, empty if absent. Every entry is understood, or the header would
    /// not have parsed.
    public let critical: [String]
    /// `false` when the header carries `b64: false` (RFC 7797).
    public let isPayloadBase64URLEncoded: Bool
    /// Every parameter as it was read, including ones no typed property covers.
    public let rawParameters: [String: JSONValue]
    /// Names of parameters that came from the unprotected header and so are not covered by the
    /// signature. Empty for anything in compact form.
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

/// Names defined by RFC 7515 and RFC 7518. They may not appear in `crit`, and a custom header
/// type may not encode them.
let registeredHeaderNames: Set<String> = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
]

let unencodedPayloadName = "b64"

struct HeaderJSON {
    private init() {}

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        // Sorted so that the same header always produces the same bytes.
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}

extension JWSHeader {
    /// Reads a header from its protected bytes and, for the JSON serializations, its unprotected
    /// members.
    static func parse(
        protected protectedJSON: Data?,
        unprotected: [String: JSONValue]?
    ) throws(JWSError) -> JWSHeader<Custom> {
        var protectedValues: [String: JSONValue] = [:]
        if let protectedJSON {
            do {
                try JSONMemberUniqueness.validate(protectedJSON)
            } catch {
                throw .invalidHeaderStructure(error)
            }
            do {
                protectedValues = try JSONDecoder().decode([String: JSONValue].self, from: protectedJSON)
            } catch {
                throw .invalidHeaderJSON(description: String(describing: error))
            }
        }

        var values = protectedValues
        for (name, value) in unprotected ?? [:] {
            guard values[name] == nil else {
                throw .headerParameterInBothHeaders(name: name)
            }
            values[name] = value
        }
        let unprotectedNames = Set((unprotected ?? [:]).keys)

        guard let algorithm = try string("alg", in: values) else {
            throw .missingAlgorithm
        }

        let critical = try parseCritical(values: values, unprotectedNames: unprotectedNames)

        var isPayloadEncoded = true
        if let b64 = values[unencodedPayloadName] {
            guard case .bool(let flag) = b64 else {
                throw .headerParameterWrongType(name: unencodedPayloadName, expected: "a boolean")
            }
            guard !unprotectedNames.contains(unencodedPayloadName) else {
                throw .headerParameterNotProtected(name: unencodedPayloadName)
            }
            guard critical.contains(unencodedPayloadName) else {
                throw .unencodedPayloadNotCritical
            }
            isPayloadEncoded = flag
        }

        var jwk: JWK?
        if let jwkValue = values["jwk"] {
            guard case .object = jwkValue else {
                throw .headerParameterWrongType(name: "jwk", expected: "an object")
            }
            do {
                jwk = try JWK(json: try HeaderJSON.encoder().encode(jwkValue))
            } catch let error as JWKError {
                throw .invalidJWKParameter(error)
            } catch {
                throw .invalidHeaderJSON(description: String(describing: error))
            }
        }

        var certificateChain: [String]?
        if let chain = values["x5c"] {
            guard case .array(let elements) = chain else {
                throw .headerParameterWrongType(name: "x5c", expected: "an array of strings")
            }
            var certificates: [String] = []
            for element in elements {
                guard case .string(let certificate) = element else {
                    throw .headerParameterWrongType(name: "x5c", expected: "an array of strings")
                }
                certificates.append(certificate)
            }
            certificateChain = certificates
        }

        let custom: Custom
        do {
            // The custom type is decoded from the protected header's own bytes whenever that is
            // the whole header, so that it sees exactly what was signed.
            if let protectedJSON, unprotectedNames.isEmpty {
                custom = try JSONDecoder().decode(Custom.self, from: protectedJSON)
            } else {
                custom = try JSONDecoder().decode(Custom.self, from: try HeaderJSON.encoder().encode(values))
            }
        } catch {
            throw .invalidCustomParameters(description: String(describing: error))
        }

        var parameters = JWSHeaderParameters(custom: custom)
        parameters.jwk = jwk
        parameters.x509CertificateChain = certificateChain
        if let keyID = try string("kid", in: values) {
            parameters.keyID = KeyID(rawValue: keyID)
        }
        if let type = try string("typ", in: values) {
            parameters.type = MediaType(rawValue: type)
        }
        if let contentType = try string("cty", in: values) {
            parameters.contentType = MediaType(rawValue: contentType)
        }
        parameters.jwkSetURL = try string("jku", in: values)
        parameters.x509URL = try string("x5u", in: values)
        parameters.x509CertificateSHA1Thumbprint = try string("x5t", in: values)
        parameters.x509CertificateSHA256Thumbprint = try string("x5t#S256", in: values)

        return JWSHeader(
            algorithm: AlgorithmIdentifier(rawValue: algorithm),
            parameters: parameters,
            critical: critical,
            isPayloadBase64URLEncoded: isPayloadEncoded,
            rawParameters: values,
            unprotectedParameterNames: unprotectedNames
        )
    }

    private static func string(_ name: String, in values: [String: JSONValue]) throws(JWSError) -> String? {
        guard let value = values[name] else {
            return nil
        }
        guard case .string(let string) = value else {
            throw .headerParameterWrongType(name: name, expected: "a string")
        }
        return string
    }

    /// Applies RFC 7515 §4.1.11 and returns the names listed in `crit`.
    private static func parseCritical(
        values: [String: JSONValue],
        unprotectedNames: Set<String>
    ) throws(JWSError) -> [String] {
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
            guard !registeredHeaderNames.contains(name) else {
                throw .invalidCritical(reason: "\"\(name)\" is defined by the JWS specification and cannot be critical")
            }
            guard values[name] != nil else {
                throw .invalidCritical(reason: "\"\(name)\" is listed but is not in the header")
            }
            // A parameter the application must understand is one it will act on, so it has to be
            // covered by the signature.
            guard !unprotectedNames.contains(name) else {
                throw .headerParameterNotProtected(name: name)
            }
            guard name == unencodedPayloadName || Custom.criticalParameterNames.contains(name) else {
                throw .unsupportedCriticalParameter(name: name)
            }
            names.append(name)
        }
        return names
    }
}

extension JWSHeaderParameters {
    /// The protected header as JSON, with `alg` taken from the signer.
    func protectedJSON(
        algorithm: AlgorithmIdentifier,
        signerKeyID: KeyID?,
        isPayloadBase64URLEncoded: Bool
    ) throws(JWSError) -> Data {
        var values: [String: JSONValue]
        do {
            let customJSON = try HeaderJSON.encoder().encode(custom)
            guard case .object(let object) = try JSONDecoder().decode(JSONValue.self, from: customJSON) else {
                throw JWSError.customParametersNotObject
            }
            values = object
        } catch let error as JWSError {
            throw error
        } catch {
            throw .headerEncodingFailed(description: String(describing: error))
        }
        for name in values.keys {
            guard !registeredHeaderNames.contains(name), name != unencodedPayloadName else {
                throw .customParameterCollision(name: name)
            }
        }

        var critical = Custom.criticalParameterNames.filter { values[$0] != nil }.sorted()
        if !isPayloadBase64URLEncoded {
            values[unencodedPayloadName] = false
            critical.append(unencodedPayloadName)
        }
        if !critical.isEmpty {
            values["crit"] = .array(critical.map { .string($0) })
        }

        values["alg"] = .string(algorithm.rawValue)
        if let keyID = keyID ?? signerKeyID {
            values["kid"] = .string(keyID.rawValue)
        }
        if let type {
            values["typ"] = .string(type.rawValue)
        }
        if let contentType {
            values["cty"] = .string(contentType.rawValue)
        }
        if let jwkSetURL {
            values["jku"] = .string(jwkSetURL)
        }
        if let x509URL {
            values["x5u"] = .string(x509URL)
        }
        if let x509CertificateChain {
            values["x5c"] = .array(x509CertificateChain.map { .string($0) })
        }
        if let x509CertificateSHA1Thumbprint {
            values["x5t"] = .string(x509CertificateSHA1Thumbprint)
        }
        if let x509CertificateSHA256Thumbprint {
            values["x5t#S256"] = .string(x509CertificateSHA256Thumbprint)
        }

        do {
            if let jwk {
                values["jwk"] = try JSONDecoder().decode(JSONValue.self, from: try jwk.jsonRepresentation())
            }
            return try HeaderJSON.encoder().encode(values)
        } catch {
            throw .headerEncodingFailed(description: String(describing: error))
        }
    }
}
