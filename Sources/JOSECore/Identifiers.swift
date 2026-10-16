/// A JOSE algorithm name as it appears in the `alg` header parameter, such as `"ES256"`.
///
/// Comparison is exact and case-sensitive, as RFC 7515 §4.1.1 requires.
public struct AlgorithmIdentifier: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }
}

extension AlgorithmIdentifier: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        rawValue = value
    }
}

extension AlgorithmIdentifier: CustomStringConvertible {
    public var description: String {
        rawValue
    }
}

/// A key identifier as it appears in the `kid` header parameter and JWK member.
///
/// A distinct type so that a key ID cannot be passed where an algorithm, issuer or other string
/// is expected. Comparison is exact and case-sensitive.
public struct KeyID: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }
}

extension KeyID: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        rawValue = value
    }
}

extension KeyID: CustomStringConvertible {
    public var description: String {
        rawValue
    }
}
