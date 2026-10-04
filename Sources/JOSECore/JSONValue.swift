import Foundation

/// Any JSON value. Used for header parameters and claims that have no dedicated Swift type.
///
/// Numbers keep integers and floating-point values apart so that 64-bit integers survive without
/// passing through `Double`. A number is decoded as ``integer(_:)`` whenever `JSONDecoder` will
/// produce it as an `Int64`, and as ``double(_:)`` otherwise.
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case integer(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

extension JSONValue: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
            return
        }
        if let value = try Self.decodeIfMatching(Bool.self, from: container) {
            self = .bool(value)
            return
        }
        if let value = try Self.decodeIfMatching(Double.self, from: container) {
            // It is a number. Whether it is also an Int64 can only be found by asking, and
            // Foundation signals "no" with an error type that is not public (measured on macOS:
            // `numberIsNotRepresentableInSwift`, not a DecodingError), so any failure here means
            // "not an integer" and the Double already in hand is the answer.
            do {
                self = .integer(try container.decode(Int64.self))
            } catch {
                self = .double(value)
            }
            return
        }
        if let value = try Self.decodeIfMatching(String.self, from: container) {
            self = .string(value)
            return
        }
        if let value = try Self.decodeIfMatching([JSONValue].self, from: container) {
            self = .array(value)
            return
        }
        self = .object(try container.decode([String: JSONValue].self))
    }

    /// Returns `nil` when the value at this position is of a different JSON type.
    private static func decodeIfMatching<T: Decodable>(
        _ type: T.Type,
        from container: any SingleValueDecodingContainer
    ) throws -> T? {
        do {
            return try container.decode(type)
        } catch DecodingError.typeMismatch {
            return nil
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null:
            try container.encodeNil()
        case .bool(let value):
            try container.encode(value)
        case .integer(let value):
            try container.encode(value)
        case .double(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

extension JSONValue: ExpressibleByNilLiteral {
    public init(nilLiteral: ()) {
        self = .null
    }
}

extension JSONValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) {
        self = .bool(value)
    }
}

extension JSONValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int64) {
        self = .integer(value)
    }
}

extension JSONValue: ExpressibleByFloatLiteral {
    public init(floatLiteral value: Double) {
        self = .double(value)
    }
}

extension JSONValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        self = .string(value)
    }
}

extension JSONValue: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: JSONValue...) {
        self = .array(elements)
    }
}

extension JSONValue: ExpressibleByDictionaryLiteral {
    /// If the literal repeats a key, the last value is kept.
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
}
