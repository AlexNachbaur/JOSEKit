import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import Testing

struct FixtureError: Error, CustomStringConvertible {
    let description: String
}

extension Decodable {
    /// Loads a fixture written by `interop/jws/generate-fixtures.mjs` or `interop/jws/generate-certificates.mjs`.
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

/// The name of an error's enum case, so that tests can assert which case was thrown without
/// having to spell out the case's associated values.
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
func thrownCase<T>(_ body: () async throws(JWSError) -> T) async -> String? {
    do {
        _ = try await body()
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
