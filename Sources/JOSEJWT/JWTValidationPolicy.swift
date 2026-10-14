import Foundation
import JOSECore

/// What a JWT's claims must satisfy before the token is accepted.
///
/// There is no default policy. The issuer, audience and type rules have to be written out, even
/// if only as `.unchecked`, so that skipping a check is a visible decision rather than an omission.
public struct JWTValidationPolicy: Sendable {
    public enum IssuerRule: Sendable {
        case exactly(String)
        case anyOf(Set<String>)
        /// Accept any issuer, or none.
        case unchecked
    }

    public enum AudienceRule: Sendable {
        /// The token's audience must include this value (RFC 7519 §4.1.3).
        case contains(String)
        /// The token's audience must include at least one of these values.
        case containsAny(Set<String>)
        /// Accept any audience, or none.
        case unchecked
    }

    public enum TypeRule: Sendable {
        /// The header's `typ` must be this media type. Comparison follows RFC 7515 §4.1.9, so
        /// `JWT` and `application/jwt` match. Explicit typing is what stops one kind of JWT
        /// being accepted as another (RFC 8725 §3.11).
        case exactly(MediaType)
        /// Accept any `typ`, or none.
        case unchecked
    }

    public var issuer: IssuerRule
    public var audience: AudienceRule
    public var type: TypeRule
    /// Whether a token without `exp` is refused. On by default: a token that never expires is
    /// rarely intended.
    public var requiresExpiration: Bool
    /// How far the local clock may differ from the issuer's when checking `exp` and `nbf`. A
    /// negative leeway is treated as zero rather than as a stricter rule.
    public var leeway: Duration
    public var clock: JWTClock

    public init(
        issuer: IssuerRule,
        audience: AudienceRule,
        type: TypeRule,
        requiresExpiration: Bool = true,
        leeway: Duration = .zero,
        clock: JWTClock = .system
    ) {
        self.issuer = issuer
        self.audience = audience
        self.type = type
        self.requiresExpiration = requiresExpiration
        self.leeway = leeway
        self.clock = clock
    }

    package func validate<Custom>(_ claims: JWTClaims<Custom>, type headerType: MediaType?) throws(JWTValidationError) {
        switch type {
        case .exactly(let expected):
            guard headerType == expected else {
                throw .typeMismatch(expected: expected.rawValue, found: headerType?.rawValue)
            }
        case .unchecked:
            break
        }

        switch issuer {
        case .exactly(let expected):
            guard claims.issuer == expected else {
                throw .issuerMismatch(expected: [expected], found: claims.issuer)
            }
        case .anyOf(let expected):
            guard let found = claims.issuer, expected.contains(found) else {
                throw .issuerMismatch(expected: expected.sorted(), found: claims.issuer)
            }
        case .unchecked:
            break
        }

        let audiences = claims.audience?.values ?? []
        switch audience {
        case .contains(let expected):
            guard audiences.contains(expected) else {
                throw .audienceMismatch(expected: [expected], found: audiences)
            }
        case .containsAny(let expected):
            guard audiences.contains(where: { expected.contains($0) }) else {
                throw .audienceMismatch(expected: expected.sorted(), found: audiences)
            }
        case .unchecked:
            break
        }

        let now = NumericDate(clock.now)
        let tolerance = max(leeway.seconds, 0)
        if let expiration = claims.expiration {
            // RFC 7519 §4.1.4: the current time must be before `exp`, so `exp` itself is too late.
            guard now.secondsSince1970 < expiration.secondsSince1970 + tolerance else {
                throw .expired(expiration: expiration, now: now, leeway: leeway)
            }
        } else if requiresExpiration {
            throw .missingExpiration
        }
        if let notBefore = claims.notBefore {
            // RFC 7519 §4.1.5: the current time must be after or equal to `nbf`.
            guard now.secondsSince1970 >= notBefore.secondsSince1970 - tolerance else {
                throw .notYetValid(notBefore: notBefore, now: now, leeway: leeway)
            }
        }
    }
}
