import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import Testing

struct FixtureError: Error, CustomStringConvertible {
    let description: String
}

struct Fixtures {
    private init() {}

    /// Loads a fixture written by `interop/generate-fixtures.mjs`.
    static func load<T: Decodable>(_ type: T.Type, named name: String) throws -> T {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") else {
            throw FixtureError(description: "fixture \(name).json is missing from the test bundle")
        }
        return try JSONDecoder().decode(type, from: Data(contentsOf: url))
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

/// The name of an error's enum case, so that tests can assert which case was thrown without
/// `JWSError` having to be `Equatable` (it carries underlying errors that are not).
func caseName(_ error: JWSError) -> String {
    // Cases without associated values have no mirror children, and every string conversion of
    // the error goes through its message, so they are named here by hand.
    switch error {
    case .missingProtectedHeader:
        return "missingProtectedHeader"
    case .missingAlgorithm:
        return "missingAlgorithm"
    case .unencodedPayloadNotCritical:
        return "unencodedPayloadNotCritical"
    case .inconsistentPayloadEncoding:
        return "inconsistentPayloadEncoding"
    case .payloadMissing:
        return "payloadMissing"
    case .payloadSuppliedTwice:
        return "payloadSuppliedTwice"
    case .customParametersNotObject:
        return "customParametersNotObject"
    default:
        return Mirror(reflecting: error).children.first?.label ?? "unnamed case: \(error)"
    }
}

/// Runs `body` and returns the name of the `JWSError` case it threw, or `nil` if it returned.
func thrownCase<T>(_ body: () throws(JWSError) -> T) -> String? {
    do {
        _ = try body()
        return nil
    } catch {
        return caseName(error)
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

struct ValidFixture: Decodable {
    struct Token: Decodable {
        let algorithm: String
        let symmetric: Bool
        let jwk: String
        let payload: String
        let compact: String
        let compactDetached: String
        let flattened: String
        let unencodedPayload: String
        let unencodedFlattened: String
        let unencodedFlattenedDetached: String
    }
    struct General: Decodable {
        struct SignerKey: Decodable {
            let algorithm: String
            let jwk: String
        }
        let payload: String
        let json: String
        let signers: [SignerKey]
    }
    let tokens: [Token]
    let general: General
}

struct TestKeys {
    private init() {}

    /// A verifier for `algorithm` from a JWK produced by the counterpart.
    static func verifier(algorithm: String, jwk: String) throws -> AnyVerifier {
        let json = Data(jwk.utf8)
        switch algorithm {
        case "ES256":
            return try ES256.verifier(for: try JWK(json: json))
        case "ES384":
            return try ES384.verifier(for: try JWK(json: json))
        case "ES512":
            return try ES512.verifier(for: try JWK(json: json))
        case "Ed25519":
            return try JOSECore.Ed25519.verifier(for: try JWK(json: json))
        case "EdDSA":
            return try EdDSA.verifier(for: try JWK(json: json))
        case "RS256":
            return try RS256.verifier(for: try JWK(json: json))
        case "RS384":
            return try RS384.verifier(for: try JWK(json: json))
        case "RS512":
            return try RS512.verifier(for: try JWK(json: json))
        case "PS256":
            return try PS256.verifier(for: try JWK(json: json))
        case "PS384":
            return try PS384.verifier(for: try JWK(json: json))
        case "PS512":
            return try PS512.verifier(for: try JWK(json: json))
        case "HS256":
            return AnyVerifier(try HMACVerifier<HS256>(jwk: try SymmetricJWK(json: json)))
        case "HS384":
            return AnyVerifier(try HMACVerifier<HS384>(jwk: try SymmetricJWK(json: json)))
        case "HS512":
            return AnyVerifier(try HMACVerifier<HS512>(jwk: try SymmetricJWK(json: json)))
        default:
            throw FixtureError(description: "no verifier for \(algorithm)")
        }
    }
}
