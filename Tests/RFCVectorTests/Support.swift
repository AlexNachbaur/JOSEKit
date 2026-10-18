import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import JOSEJWS
import Testing

struct VectorError: Error, CustomStringConvertible {
    let description: String
}

/// One file of the JOSE cookbook, read as plain JSON so that the file's own shape is what the
/// tests navigate, with no intermediate model that could drift from it.
struct Vector {
    let name: String
    let root: JSONValue

    /// Loads `Fixtures/cookbook/<path>`.
    init(_ path: String) throws {
        guard
            let url = Bundle.module.url(
                forResource: path,
                withExtension: nil,
                subdirectory: "Fixtures/cookbook"
            )
        else {
            throw VectorError(description: "cookbook file \(path) is missing from the test bundle")
        }
        name = path
        root = try JSONDecoder().decode(JSONValue.self, from: Data(contentsOf: url))
    }

    /// The value at a path of member names, such as `value("output", "compact")`.
    func value(_ path: String...) throws -> JSONValue {
        guard let found = lookup(path) else {
            throw VectorError(description: "\(name) has no \(path.joined(separator: "."))")
        }
        return found
    }

    /// Whether the path exists.
    func has(_ path: String...) -> Bool {
        lookup(path) != nil
    }

    func string(_ path: String...) throws -> String {
        guard let found = lookup(path) else {
            throw VectorError(description: "\(name) has no \(path.joined(separator: "."))")
        }
        return try found.text
    }

    /// Base64url-decoded bytes at a path.
    func bytes(_ path: String...) throws -> Data {
        guard let found = lookup(path) else {
            throw VectorError(description: "\(name) has no \(path.joined(separator: "."))")
        }
        return try Base64URL.decode(try found.text)
    }

    private func lookup(_ path: [String]) -> JSONValue? {
        var current = root
        for name in path {
            guard case .object(let members) = current, let next = members[name] else {
                return nil
            }
            current = next
        }
        return current
    }
}

extension JSONValue {
    /// The value as JSON text, for parsers that take bytes.
    var json: Data {
        get throws {
            try JSONEncoder().encode(self)
        }
    }

    var elements: [JSONValue] {
        get throws {
            guard case .array(let elements) = self else {
                throw VectorError(description: "expected an array, found \(self)")
            }
            return elements
        }
    }

    var text: String {
        get throws {
            guard case .string(let text) = self else {
                throw VectorError(description: "expected a string, found \(self)")
            }
            return text
        }
    }

    /// One value, or each element of an array of them. The cookbook writes a single key or
    /// algorithm as a value and several as an array.
    var oneOrMany: [JSONValue] {
        if case .array(let elements) = self {
            return elements
        }
        return [self]
    }
}

struct VectorKeys {
    private init() {}

    /// A verifier for `algorithm` from a cookbook key, public or private.
    static func verifier(algorithm: String, key: JSONValue) throws -> AnyVerifier {
        let json = try key.json
        if algorithm.hasPrefix("HS") {
            let symmetric = try SymmetricJWK(json: json)
            switch algorithm {
            case "HS256":
                return AnyVerifier(try HMACVerifier<HS256>(jwk: symmetric))
            case "HS384":
                return AnyVerifier(try HMACVerifier<HS384>(jwk: symmetric))
            case "HS512":
                return AnyVerifier(try HMACVerifier<HS512>(jwk: symmetric))
            default:
                throw VectorError(description: "no verifier for \(algorithm)")
            }
        }
        // The cookbook's signing keys are private; verification needs only the public half.
        let publicKey = try PrivateJWK(json: json).publicJWK
        let types: [String: any JWKVerifiableAlgorithm.Type] = [
            "RS256": RS256.self, "RS384": RS384.self, "RS512": RS512.self,
            "PS256": PS256.self, "PS384": PS384.self, "PS512": PS512.self,
            "ES256": ES256.self, "ES384": ES384.self, "ES512": ES512.self,
            "EdDSA": EdDSA.self, "Ed25519": JOSECore.Ed25519.self,
        ]
        guard let type = types[algorithm] else {
            throw VectorError(description: "no verifier for \(algorithm)")
        }
        return try type.verifier(for: publicKey)
    }

    /// A decrypter for `algorithm` from a cookbook key.
    static func decrypter(algorithm: String, key: JSONValue) throws -> AnyKeyDecrypter {
        let json = try key.json
        switch algorithm {
        case "dir":
            return AnyKeyDecrypter(try DirectDecrypter(jwk: try SymmetricJWK(json: json)))
        case "A128KW":
            return AnyKeyDecrypter(try AESKeyWrapDecrypter<A128KW>(jwk: try SymmetricJWK(json: json)))
        case "A192KW":
            return AnyKeyDecrypter(try AESKeyWrapDecrypter<A192KW>(jwk: try SymmetricJWK(json: json)))
        case "A256KW":
            return AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(jwk: try SymmetricJWK(json: json)))
        case "A128GCMKW":
            return AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A128GCMKW>(jwk: try SymmetricJWK(json: json)))
        case "A192GCMKW":
            return AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A192GCMKW>(jwk: try SymmetricJWK(json: json)))
        case "A256GCMKW":
            return AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A256GCMKW>(jwk: try SymmetricJWK(json: json)))
        case "RSA-OAEP":
            return AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP>(jwk: try PrivateJWK(json: json)))
        case "RSA-OAEP-256":
            return AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP256>(jwk: try PrivateJWK(json: json)))
        case "ECDH-ES":
            return try ECDHES.decrypter(for: try PrivateJWK(json: json))
        case "ECDH-ES+A128KW":
            return try ECDHESA128KW.decrypter(for: try PrivateJWK(json: json))
        case "ECDH-ES+A192KW":
            return try ECDHESA192KW.decrypter(for: try PrivateJWK(json: json))
        case "ECDH-ES+A256KW":
            return try ECDHESA256KW.decrypter(for: try PrivateJWK(json: json))
        default:
            throw VectorError(description: "no decrypter for \(algorithm)")
        }
    }
}
