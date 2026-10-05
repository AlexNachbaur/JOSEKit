import JOSECore
import JOSEJWS

/// Why a JWT could not be parsed, verified or produced. Claim validation failures have their
/// own type, ``JWTValidationError``.
public enum JWTError: Error, Sendable {
    /// The JWS layer refused the token: malformed, wrong algorithm, bad signature, and so on.
    case jws(JWSError)
    /// The token uses an unencoded payload (`b64: false`), which RFC 7797 §7 forbids for JWTs.
    case unencodedPayloadNotAllowed
    /// The claims set is not a JSON object with unique member names (RFC 7519 §4).
    case invalidClaimsStructure(JSONStructureError)
    case invalidClaimsJSON(description: String)
    /// A registered claim has the wrong JSON type.
    case claimWrongType(name: String, expected: String)
    /// A NumericDate is not a finite number.
    case invalidNumericDate(name: String)
    /// The claims set could not be decoded as the custom claims type.
    case invalidCustomClaims(description: String)
    /// The custom claims type, or an ad-hoc claim, uses the name of a registered claim or of
    /// another claim already present.
    case claimCollision(name: String)
    /// The custom claims type did not encode to a JSON object.
    case customClaimsNotObject
    /// A claims builder set the same claim twice.
    case duplicateClaim(name: String)
    case claimsEncodingFailed(description: String)
}

extension JWTError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .jws(let error):
            return "JWT is not a valid JWS: \(error)"
        case .unencodedPayloadNotAllowed:
            return "JWT uses an unencoded payload (\"b64\": false), which is not allowed for JWTs"
        case .invalidClaimsStructure(let error):
            return "JWT claims set is not a well-formed JSON object: \(error)"
        case .invalidClaimsJSON(let description):
            return "JWT claims set could not be decoded: \(description)"
        case .claimWrongType(let name, let expected):
            return "JWT claim \"\(name)\" must be \(expected)"
        case .invalidNumericDate(let name):
            return "JWT claim \"\(name)\" is not a finite number"
        case .invalidCustomClaims(let description):
            return "JWT claims set could not be decoded as the custom claims type: \(description)"
        case .claimCollision(let name):
            return "claim \"\(name)\" is set more than one way: it is a registered claim or is already present"
        case .customClaimsNotObject:
            return "custom claims type did not encode to a JSON object"
        case .duplicateClaim(let name):
            return "the claims builder sets \"\(name)\" more than once"
        case .claimsEncodingFailed(let description):
            return "JWT claims set could not be encoded: \(description)"
        }
    }
}

/// Why the claims of a correctly signed JWT were not accepted.
public enum JWTValidationError: Error, Sendable, Equatable {
    /// `exp` has passed. Per RFC 7519 §4.1.4 the token is unusable on and after `exp`.
    case expired(expiration: NumericDate, now: NumericDate, leeway: Duration)
    /// `nbf` is still in the future.
    case notYetValid(notBefore: NumericDate, now: NumericDate, leeway: Duration)
    /// The policy requires `exp` and the token has none.
    case missingExpiration
    case issuerMismatch(expected: [String], found: String?)
    /// None of the token's audiences is one the policy accepts.
    case audienceMismatch(expected: [String], found: [String])
    case typeMismatch(expected: String, found: String?)
}

extension JWTValidationError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .expired(let expiration, let now, let leeway):
            return "JWT expired at \(expiration) (now \(now), leeway \(leeway))"
        case .notYetValid(let notBefore, let now, let leeway):
            return "JWT is not valid before \(notBefore) (now \(now), leeway \(leeway))"
        case .missingExpiration:
            return "JWT has no \"exp\" claim and the validation policy requires one"
        case .issuerMismatch(let expected, let found):
            return "JWT issuer is \(found.map { "\"\($0)\"" } ?? "absent"); expected \(Self.list(expected))"
        case .audienceMismatch(let expected, let found):
            if found.isEmpty {
                return "JWT has no audience; expected \(Self.list(expected))"
            }
            return "JWT audience is \(Self.list(found)); expected \(Self.list(expected))"
        case .typeMismatch(let expected, let found):
            return "JWT \"typ\" is \(found.map { "\"\($0)\"" } ?? "absent"); expected \"\(expected)\""
        }
    }

    private static func list(_ values: [String]) -> String {
        if values.count == 1 {
            return "\"\(values[0])\""
        }
        return "one of " + values.map { "\"\($0)\"" }.joined(separator: ", ")
    }
}
