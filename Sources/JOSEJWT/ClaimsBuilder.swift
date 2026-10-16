import Foundation
import JOSECore

/// The source of "now" for building and validating tokens. Inject a fixed one in tests.
public struct JWTClock: Sendable {
    private let current: @Sendable () -> Date

    public init(_ current: @escaping @Sendable () -> Date) {
        self.current = current
    }

    public var now: Date {
        current()
    }

    /// The system clock.
    public static let system = JWTClock { Date() }

    /// A clock that always reports `date`.
    public static func fixed(_ date: Date) -> JWTClock {
        JWTClock { date }
    }
}

extension Duration {
    /// The duration in seconds, as a floating-point value.
    var seconds: Double {
        Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
}

/// The claims being assembled by a ``JWTClaimsBuilder``.
///
/// A component of your own sets what it needs here, calling ``claim(_:)`` first for each claim
/// so that a block cannot set the same claim twice.
public struct JWTClaimsDraft: Sendable {
    public var issuer: String?
    public var subject: String?
    public var audience: Audience?
    public var expiration: NumericDate?
    public var notBefore: NumericDate?
    public var issuedAt: NumericDate?
    public var jwtID: String?
    /// Claims other than the registered ones, by name.
    public var additional: [String: JSONValue] = [:]
    /// The names of the claims set so far.
    public private(set) var names: Set<String> = []

    /// Records that `name` is being set, refusing a second setting of the same claim.
    public mutating func claim(_ name: String) throws(JWTError) {
        guard names.insert(name).inserted else {
            throw .duplicateClaim(name: name)
        }
    }
}

/// One entry in a claims builder block. Conform your own types to add components, such as one
/// that sets several related claims at once.
public protocol JWTClaimComponent: Sendable {
    func apply(to draft: inout JWTClaimsDraft) throws(JWTError)
}

/// Sets `iss`.
public struct Issuer: JWTClaimComponent {
    let value: String

    public init(_ value: String) {
        self.value = value
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("iss")
        draft.issuer = value
    }
}

/// Sets `sub`.
public struct Subject: JWTClaimComponent {
    let value: String

    public init(_ value: String) {
        self.value = value
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("sub")
        draft.subject = value
    }
}

extension Audience: JWTClaimComponent {
    /// Sets `aud`.
    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("aud")
        draft.audience = self
    }
}

/// Sets `exp` to a specific time.
public struct ExpiresAt: JWTClaimComponent {
    let date: Date

    public init(_ date: Date) {
        self.date = date
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("exp")
        draft.expiration = NumericDate(date)
    }
}

/// Sets `exp` to a time after now.
public struct ExpiresIn: JWTClaimComponent {
    let duration: Duration
    let clock: JWTClock

    public init(_ duration: Duration, clock: JWTClock = .system) {
        self.duration = duration
        self.clock = clock
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("exp")
        draft.expiration = NumericDate(clock.now.addingTimeInterval(duration.seconds))
    }
}

/// Sets `nbf`.
public struct NotBefore: JWTClaimComponent {
    let date: Date

    public init(_ date: Date) {
        self.date = date
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("nbf")
        draft.notBefore = NumericDate(date)
    }
}

/// Sets `iat`, to now unless a time is given.
public struct IssuedAt: JWTClaimComponent {
    let date: Date

    public init(_ date: Date) {
        self.date = date
    }

    public init(clock: JWTClock = .system) {
        date = clock.now
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("iat")
        draft.issuedAt = NumericDate(date)
    }
}

/// Sets `jti`.
public struct JWTID: JWTClaimComponent {
    let value: String

    public init(_ value: String) {
        self.value = value
    }

    /// A random identifier (a UUID).
    public static func random() -> JWTID {
        JWTID(UUID().uuidString)
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        try draft.claim("jti")
        draft.jwtID = value
    }
}

/// Sets a claim by name. Registered claims have their own components and cannot be set this way.
public struct Claim: JWTClaimComponent {
    let name: String
    let value: JSONValue

    public init(_ name: String, _ value: JSONValue) {
        self.name = name
        self.value = value
    }

    public func apply(to draft: inout JWTClaimsDraft) throws(JWTError) {
        guard !registeredClaimNames.contains(name) else {
            throw .claimCollision(name: name)
        }
        try draft.claim(name)
        draft.additional[name] = value
    }
}

@resultBuilder
public struct JWTClaimsBuilder {
    public static func buildExpression(_ component: any JWTClaimComponent) -> [any JWTClaimComponent] {
        [component]
    }

    public static func buildBlock(_ components: [any JWTClaimComponent]...) -> [any JWTClaimComponent] {
        components.flatMap { $0 }
    }

    public static func buildOptional(_ component: [any JWTClaimComponent]?) -> [any JWTClaimComponent] {
        component ?? []
    }

    public static func buildEither(first component: [any JWTClaimComponent]) -> [any JWTClaimComponent] {
        component
    }

    public static func buildEither(second component: [any JWTClaimComponent]) -> [any JWTClaimComponent] {
        component
    }

    public static func buildArray(_ components: [[any JWTClaimComponent]]) -> [any JWTClaimComponent] {
        components.flatMap { $0 }
    }
}

extension JWTClaims {
    /// Builds a claims set from a block of components. Setting the same claim twice is an error.
    public init(
        custom: Custom,
        @JWTClaimsBuilder _ build: () -> [any JWTClaimComponent]
    ) throws(JWTError) {
        var draft = JWTClaimsDraft()
        for component in build() {
            try component.apply(to: &draft)
        }
        self.init(
            issuer: draft.issuer,
            subject: draft.subject,
            audience: draft.audience,
            expiration: draft.expiration,
            notBefore: draft.notBefore,
            issuedAt: draft.issuedAt,
            jwtID: draft.jwtID,
            custom: custom
        )
        additionalClaims = draft.additional
    }
}

extension JWTClaims where Custom == EmptyClaims {
    public init(@JWTClaimsBuilder _ build: () -> [any JWTClaimComponent]) throws(JWTError) {
        try self.init(custom: EmptyClaims(), build)
    }
}
