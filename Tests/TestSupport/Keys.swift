import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS

/// A custom header with one ordinary and one critical extension parameter.
public struct ExampleHeader: HeaderParameters, Equatable {
    public static let criticalParameterNames: Set<String> = ["urn:example:must"]

    public var level: Int?
    public var must: String?

    public init(level: Int? = nil, must: String? = nil) {
        self.level = level
        self.must = must
    }

    enum CodingKeys: String, CodingKey {
        case level = "urn:example:level"
        case must = "urn:example:must"
    }
}

extension AnyVerifier {
    /// A verifier for `algorithm` from a JWK produced by the counterpart.
    public init(algorithm: String, jwk: String) throws {
        let json = Data(jwk.utf8)
        if let named = JWSAlgorithm.allCases.first(where: { $0.identifier.rawValue == algorithm }) {
            self = try named.verifier(for: try JWK(json: json))
            return
        }
        switch algorithm {
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
