import Foundation
import JOSECore

/// A point in time as JWT writes it: seconds since 1970-01-01T00:00:00Z (RFC 7519 §2).
public struct NumericDate: Sendable, Hashable, Comparable {
    public let secondsSince1970: Double

    public init(secondsSince1970: Double) {
        self.secondsSince1970 = secondsSince1970
    }

    public init(_ date: Date) {
        secondsSince1970 = date.timeIntervalSince1970
    }

    public var date: Date {
        Date(timeIntervalSince1970: secondsSince1970)
    }

    public static func < (lhs: NumericDate, rhs: NumericDate) -> Bool {
        lhs.secondsSince1970 < rhs.secondsSince1970
    }

    /// The value as JSON: an integer when it is a whole number of seconds, which is what other
    /// implementations write and expect, and a fraction otherwise.
    var jsonValue: JSONValue {
        if secondsSince1970 == secondsSince1970.rounded(), let whole = Int64(exactly: secondsSince1970) {
            return .integer(whole)
        }
        return .double(secondsSince1970)
    }
}

extension NumericDate: CustomStringConvertible {
    public var description: String {
        if case .integer(let whole) = jsonValue {
            return String(whole)
        }
        return String(secondsSince1970)
    }
}

/// The `aud` claim: one or more recipients. JSON allows either a single string or an array
/// (RFC 7519 §4.1.3); both are read, and a single value is written as a string.
public struct Audience: Sendable, Hashable {
    public let values: [String]

    public init(_ values: [String]) {
        self.values = values
    }

    public init(_ values: String...) {
        self.values = values
    }

    public func contains(_ value: String) -> Bool {
        values.contains(value)
    }

    var jsonValue: JSONValue {
        if values.count == 1 {
            return .string(values[0])
        }
        return .array(values.map { .string($0) })
    }
}

/// For tokens with registered claims only.
public struct EmptyClaims: Codable, Sendable, Hashable {
    public init() {}
}

/// A JWT claims set: the registered claims (RFC 7519 §4.1), the application's own typed claims,
/// and any further claims set by name.
public struct JWTClaims<Custom: Codable & Sendable>: Sendable {
    /// `iss`
    public var issuer: String?
    /// `sub`
    public var subject: String?
    /// `aud`
    public var audience: Audience?
    /// `exp`
    public var expiration: NumericDate?
    /// `nbf`
    public var notBefore: NumericDate?
    /// `iat`
    public var issuedAt: NumericDate?
    /// `jti`
    public var jwtID: String?
    public var custom: Custom
    /// Claims set by name when building a token. Not populated when a token is read: there, every
    /// claim as received is available from the token's `rawClaims`.
    public var additionalClaims: [String: JSONValue] = [:]

    public init(
        issuer: String? = nil,
        subject: String? = nil,
        audience: Audience? = nil,
        expiration: NumericDate? = nil,
        notBefore: NumericDate? = nil,
        issuedAt: NumericDate? = nil,
        jwtID: String? = nil,
        custom: Custom
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.expiration = expiration
        self.notBefore = notBefore
        self.issuedAt = issuedAt
        self.jwtID = jwtID
        self.custom = custom
    }
}

extension JWTClaims where Custom == EmptyClaims {
    public init(
        issuer: String? = nil,
        subject: String? = nil,
        audience: Audience? = nil,
        expiration: NumericDate? = nil,
        notBefore: NumericDate? = nil,
        issuedAt: NumericDate? = nil,
        jwtID: String? = nil
    ) {
        self.init(
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiration: expiration,
            notBefore: notBefore,
            issuedAt: issuedAt,
            jwtID: jwtID,
            custom: EmptyClaims()
        )
    }
}

let registeredClaimNames: Set<String> = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

struct ClaimsJSON {
    private init() {}

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        // Sorted so that the same claims always produce the same bytes.
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}

extension JWTClaims {
    /// The claims set as JSON, with members in lexical order.
    func jsonRepresentation() throws(JWTError) -> Data {
        var values: [String: JSONValue]
        do {
            let customJSON = try ClaimsJSON.encoder().encode(custom)
            guard case .object(let object) = try JSONDecoder().decode(JSONValue.self, from: customJSON) else {
                throw JWTError.customClaimsNotObject
            }
            values = object
        } catch let error as JWTError {
            throw error
        } catch {
            throw .claimsEncodingFailed(description: String(describing: error))
        }
        // Registered claims come only from the typed properties, so that what was validated or
        // intended is what is written.
        for name in values.keys {
            guard !registeredClaimNames.contains(name) else {
                throw .claimCollision(name: name)
            }
        }
        for (name, value) in additionalClaims {
            guard !registeredClaimNames.contains(name), values[name] == nil else {
                throw .claimCollision(name: name)
            }
            values[name] = value
        }

        if let issuer {
            values["iss"] = .string(issuer)
        }
        if let subject {
            values["sub"] = .string(subject)
        }
        if let audience {
            values["aud"] = audience.jsonValue
        }
        if let jwtID {
            values["jti"] = .string(jwtID)
        }
        let dates: [(String, NumericDate?)] = [("exp", expiration), ("nbf", notBefore), ("iat", issuedAt)]
        for (name, date) in dates {
            guard let date else {
                continue
            }
            guard date.secondsSince1970.isFinite else {
                throw .invalidNumericDate(name: name)
            }
            values[name] = date.jsonValue
        }

        do {
            return try ClaimsJSON.encoder().encode(values)
        } catch {
            throw .claimsEncodingFailed(description: String(describing: error))
        }
    }

    /// Reads a claims set, rejecting duplicate member names. Returns the typed claims and every
    /// member as received.
    static func parse(_ json: Data) throws(JWTError) -> (claims: JWTClaims<Custom>, raw: [String: JSONValue]) {
        do {
            try JSONMemberUniqueness.validate(json)
        } catch {
            throw .invalidClaimsStructure(error)
        }
        let values: [String: JSONValue]
        do {
            values = try JSONDecoder().decode([String: JSONValue].self, from: json)
        } catch {
            throw .invalidClaimsJSON(description: String(describing: error))
        }

        var audience: Audience?
        if let value = values["aud"] {
            switch value {
            case .string(let single):
                audience = Audience([single])
            case .array(let elements):
                var recipients: [String] = []
                for element in elements {
                    guard case .string(let recipient) = element else {
                        throw .claimWrongType(name: "aud", expected: "a string or an array of strings")
                    }
                    recipients.append(recipient)
                }
                audience = Audience(recipients)
            default:
                throw .claimWrongType(name: "aud", expected: "a string or an array of strings")
            }
        }

        let custom: Custom
        do {
            custom = try JSONDecoder().decode(Custom.self, from: json)
        } catch {
            throw .invalidCustomClaims(description: String(describing: error))
        }

        let claims = JWTClaims(
            issuer: try string("iss", in: values),
            subject: try string("sub", in: values),
            audience: audience,
            expiration: try numericDate("exp", in: values),
            notBefore: try numericDate("nbf", in: values),
            issuedAt: try numericDate("iat", in: values),
            jwtID: try string("jti", in: values),
            custom: custom
        )
        return (claims, values)
    }

    private static func string(_ name: String, in values: [String: JSONValue]) throws(JWTError) -> String? {
        guard let value = values[name] else {
            return nil
        }
        guard case .string(let string) = value else {
            throw .claimWrongType(name: name, expected: "a string")
        }
        return string
    }

    private static func numericDate(
        _ name: String,
        in values: [String: JSONValue]
    ) throws(JWTError) -> NumericDate? {
        guard let value = values[name] else {
            return nil
        }
        switch value {
        case .integer(let seconds):
            return NumericDate(secondsSince1970: Double(seconds))
        case .double(let seconds):
            guard seconds.isFinite else {
                throw .invalidNumericDate(name: name)
            }
            return NumericDate(secondsSince1970: seconds)
        default:
            // In particular a numeric string such as "1700000000" is not a NumericDate.
            throw .claimWrongType(name: name, expected: "a number")
        }
    }
}
