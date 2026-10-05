/// A media type as carried in the `typ` and `cty` header parameters.
///
/// Two values are equal when they name the same media type under RFC 7515 §4.1.9 and RFC 2045
/// §5.1, not when their text is identical:
///
/// - a value with no `/` is read as if `application/` were prepended, so `JWT` and
///   `application/jwt` are the same type;
/// - the type and subtype are compared without regard to case;
/// - anything after the first `;` (parameters) is compared exactly, apart from surrounding
///   whitespace, because parameter values can be case-sensitive.
///
/// ``rawValue`` is preserved as written and is what gets encoded.
public struct MediaType: Sendable, Codable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(from decoder: any Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// The value in the form used for comparison: full type and subtype in lowercase, followed
    /// by any parameters as written.
    public var canonicalValue: String {
        var essence = Substring(rawValue)
        var parameters: Substring?
        if let separator = rawValue.firstIndex(of: ";") {
            essence = rawValue[..<separator]
            parameters = rawValue[rawValue.index(after: separator)...]
        }

        var canonical = Self.trimmed(essence).lowercased()
        // RFC 7515 §4.1.9: the prefix may only have been omitted when no other "/" appears in
        // the value, so its absence anywhere means the prefix is implied.
        if !rawValue.contains("/") {
            canonical = "application/" + canonical
        }
        if let parameters {
            canonical += ";" + Self.trimmed(parameters)
        }
        return canonical
    }

    private static func trimmed(_ text: Substring) -> String {
        var result = text
        while let first = result.first, first == " " || first == "\t" {
            result = result.dropFirst()
        }
        while let last = result.last, last == " " || last == "\t" {
            result = result.dropLast()
        }
        return String(result)
    }
}

extension MediaType: Hashable {
    public static func == (lhs: MediaType, rhs: MediaType) -> Bool {
        lhs.canonicalValue == rhs.canonicalValue
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(canonicalValue)
    }
}

extension MediaType: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        rawValue = value
    }
}

extension MediaType: CustomStringConvertible {
    public var description: String {
        rawValue
    }
}
