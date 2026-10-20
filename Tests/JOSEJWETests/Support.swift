import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import Testing

struct FixtureError: Error, CustomStringConvertible {
    let description: String
}

extension Decodable {
    /// Loads a fixture written by `interop/jwe/generate-fixtures.mjs`.
    init(fixture name: String) throws {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") else {
            throw FixtureError(description: "fixture \(name).json is missing from the test bundle")
        }
        self = try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }
}

extension Data {
    init(hex: String) throws {
        let digits = Array(hex.utf8)
        guard digits.count.isMultiple(of: 2) else {
            throw FixtureError(description: "hex string has odd length \(digits.count)")
        }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[index..<(index + 2)], as: UTF8.self), radix: 16) else {
                throw FixtureError(description: "invalid hex at offset \(index)")
            }
            bytes.append(byte)
        }
        self.init(bytes)
    }

    var hex: String {
        map { byte in
            let digits = String(byte, radix: 16)
            if digits.count == 1 {
                return "0" + digits
            }
            return digits
        }
        .joined()
    }
}

/// A custom header with one ordinary and one critical extension parameter.
struct ExampleHeader: HeaderParameters, Equatable {
    static let criticalParameterNames: Set<String> = ["urn:example:must"]

    var level: Int?
    var must: String?

    enum CodingKeys: String, CodingKey {
        case level = "urn:example:level"
        case must = "urn:example:must"
    }
}

extension AnyKeyDecrypter {
    private init<Algorithm: ECDHESAlgorithm>(
        ecdh algorithm: Algorithm.Type,
        _ jwk: PrivateJWK,
        keyID: KeyID?
    ) throws {
        switch jwk.key {
        case .p256(let key):
            self.init(ECDHESDecrypter<Algorithm, ECPrivateKey<P256Curve>>(privateKey: key, keyID: keyID))
        case .p384(let key):
            self.init(ECDHESDecrypter<Algorithm, ECPrivateKey<P384Curve>>(privateKey: key, keyID: keyID))
        case .p521(let key):
            self.init(ECDHESDecrypter<Algorithm, ECPrivateKey<P521Curve>>(privateKey: key, keyID: keyID))
        case .x25519(let key):
            self.init(ECDHESDecrypter<Algorithm, X25519PrivateKey>(privateKey: key, keyID: keyID))
        case .ed25519, .rsa:
            throw FixtureError(description: "not an ECDH key")
        }
    }

    /// A decrypter for `algorithm` from the private or symmetric JWK the counterpart exported.
    init(algorithm: String, jwk: String, keyID: KeyID? = nil) throws {
        let json = Data(jwk.utf8)
        func secret() throws -> SymmetricKeyMaterial {
            try SymmetricJWK(json: json).key
        }
        func rsa() throws -> RSAPrivateKey {
            guard case .rsa(let key) = try PrivateJWK(json: json).key else {
                throw FixtureError(description: "not an RSA key")
            }
            return key
        }
        switch algorithm {
        case "dir":
            self.init(DirectDecrypter(key: try secret(), keyID: keyID))
        case "A128KW":
            self.init(try AESKeyWrapDecrypter<A128KW>(key: try secret(), keyID: keyID))
        case "A192KW":
            self.init(try AESKeyWrapDecrypter<A192KW>(key: try secret(), keyID: keyID))
        case "A256KW":
            self.init(try AESKeyWrapDecrypter<A256KW>(key: try secret(), keyID: keyID))
        case "A128GCMKW":
            self.init(try AESGCMKeyWrapDecrypter<A128GCMKW>(key: try secret(), keyID: keyID))
        case "A192GCMKW":
            self.init(try AESGCMKeyWrapDecrypter<A192GCMKW>(key: try secret(), keyID: keyID))
        case "A256GCMKW":
            self.init(try AESGCMKeyWrapDecrypter<A256GCMKW>(key: try secret(), keyID: keyID))
        case "ECDH-ES":
            try self.init(ecdh: ECDHES.self, try PrivateJWK(json: json), keyID: keyID)
        case "ECDH-ES+A128KW":
            try self.init(ecdh: ECDHESA128KW.self, try PrivateJWK(json: json), keyID: keyID)
        case "ECDH-ES+A192KW":
            try self.init(ecdh: ECDHESA192KW.self, try PrivateJWK(json: json), keyID: keyID)
        case "ECDH-ES+A256KW":
            try self.init(ecdh: ECDHESA256KW.self, try PrivateJWK(json: json), keyID: keyID)
        case "RSA-OAEP":
            self.init(try RSADecrypter<RSAOAEP>(privateKey: try rsa(), keyID: keyID))
        case "RSA-OAEP-256":
            self.init(try RSADecrypter<RSAOAEP256>(privateKey: try rsa(), keyID: keyID))
        case "PBES2-HS256+A128KW":
            self.init(PBES2Decrypter<PBES2HS256A128KW>(password: try secret().rawRepresentation, keyID: keyID))
        case "PBES2-HS384+A192KW":
            self.init(PBES2Decrypter<PBES2HS384A192KW>(password: try secret().rawRepresentation, keyID: keyID))
        case "PBES2-HS512+A256KW":
            self.init(PBES2Decrypter<PBES2HS512A256KW>(password: try secret().rawRepresentation, keyID: keyID))
        default:
            throw FixtureError(description: "no decrypter for \(algorithm)")
        }
    }
}

/// Runs `body` and returns the error it threw, or `nil` if it returned.
func thrown<T>(_ body: () async throws(JWEError) -> T) async -> JWEError? {
    do {
        _ = try await body()
        return nil
    } catch {
        return error
    }
}
