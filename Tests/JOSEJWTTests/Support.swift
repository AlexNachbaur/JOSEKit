import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import JOSEJWT
import Testing

struct FixtureError: Error, CustomStringConvertible {
    let description: String
}

extension Decodable {
    /// Loads a fixture written by `interop/jwt/generate-fixtures.mjs`.
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

extension AnyVerifier {
    /// A verifier for `algorithm` from a JWK produced by the counterpart.
    init(algorithm: String, jwk: String) throws {
        let json = Data(jwk.utf8)
        switch algorithm {
        case "ES256":
            self = try ES256.verifier(for: try JWK(json: json))
        case "ES384":
            self = try ES384.verifier(for: try JWK(json: json))
        case "ES512":
            self = try ES512.verifier(for: try JWK(json: json))
        case "Ed25519":
            self = try JOSECore.Ed25519.verifier(for: try JWK(json: json))
        case "EdDSA":
            self = try EdDSA.verifier(for: try JWK(json: json))
        case "RS256":
            self = try RS256.verifier(for: try JWK(json: json))
        case "RS384":
            self = try RS384.verifier(for: try JWK(json: json))
        case "RS512":
            self = try RS512.verifier(for: try JWK(json: json))
        case "PS256":
            self = try PS256.verifier(for: try JWK(json: json))
        case "PS384":
            self = try PS384.verifier(for: try JWK(json: json))
        case "PS512":
            self = try PS512.verifier(for: try JWK(json: json))
        case "HS256":
            self = AnyVerifier(try HMACVerifier<HS256>(jwk: try SymmetricJWK(json: json)))
        case "HS384":
            self = AnyVerifier(try HMACVerifier<HS384>(jwk: try SymmetricJWK(json: json)))
        case "HS512":
            self = AnyVerifier(try HMACVerifier<HS512>(jwk: try SymmetricJWK(json: json)))
        default:
            throw FixtureError(description: "no verifier for \(algorithm)")
        }
    }
}
