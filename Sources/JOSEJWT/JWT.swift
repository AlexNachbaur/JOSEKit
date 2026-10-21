import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS

/// JSON Web Token (RFC 7519), signed. Parameterised by the application's claims type and header
/// type; see ``SignedJWT`` for the common case of registered header parameters only.
///
/// Signing gives you a ``Signed``. A received token moves through three types. ``Unverified`` is
/// what parsing gives you. ``Verified``
/// means the signature is good and says nothing about the claims. ``Validated`` means the claims
/// also satisfied a ``JWTValidationPolicy``. Code that acts on a token should take a
/// `Validated`, which cannot be made any other way.
public struct JWT<Custom: Codable & Sendable, Header: HeaderParameters>: Sendable {
    private init() {}

    /// A parsed JWT whose signature has not been checked.
    public struct Unverified: Sendable {
        let jws: JWS<Header>.Unverified
        /// The header as received. Readable before verification because choosing a key depends
        /// on it; nothing in it is trustworthy yet.
        public let header: JWSHeader<Header>

        /// Parses a JWT. JWTs are always in the JWS Compact Serialization (RFC 7519 §1).
        public init(compact: String) throws(JWTError) {
            do {
                jws = try JWS<Header>.Unverified(compact: compact)
            } catch {
                throw .jws(error)
            }
            guard jws.header.isPayloadBase64URLEncoded else {
                throw .unencodedPayloadNotAllowed
            }
            header = jws.header
        }

        /// The claims **without any assurance that they are authentic**, for the rare case where
        /// something in them is needed to decide how to verify the token (which issuer's keys to
        /// use, say). Never act on these.
        public func unverifiedClaims() throws(JWTError) -> JWTClaims<Custom> {
            let payload: Data?
            do {
                payload = try jws.unverifiedPayload
            } catch {
                throw .jws(error)
            }
            return try JWTClaims<Custom>.parse(payload ?? Data()).claims
        }

        /// Checks the signature. The result's claims have still not been validated.
        public func verify(with keys: VerificationKeys) async throws(JWTError) -> Verified {
            let verified: JWS<Header>.Verified
            do {
                verified = try await jws.verify(with: keys)
            } catch {
                throw .jws(error)
            }
            let (claims, raw) = try JWTClaims<Custom>.parse(verified.payload)
            return Verified(header: verified.header, unvalidatedClaims: claims, rawClaims: raw)
        }

        /// Resolves keys from the header's `jku`, `x5c` or `jwk` with `resolver`, then verifies.
        public func verify(resolving resolver: HeaderKeyResolver) async throws(JWTError) -> Verified {
            let verified: JWS<Header>.Verified
            do {
                verified = try await jws.verify(resolving: resolver)
            } catch {
                throw .jws(error)
            }
            let (claims, raw) = try JWTClaims<Custom>.parse(verified.payload)
            return Verified(header: verified.header, unvalidatedClaims: claims, rawClaims: raw)
        }
    }

    /// A JWT whose signature is good. Whether it is expired, or meant for you, is not yet known.
    public struct Verified: Sendable {
        public let header: JWSHeader<Header>
        /// The claims, authentic but not yet checked against any policy.
        public let unvalidatedClaims: JWTClaims<Custom>
        /// Every claim as it was received, including ones no typed property covers. Authentic,
        /// but not yet checked against any policy.
        public let rawClaims: [String: JSONValue]

        /// Checks the claims against `policy`.
        public func validate(_ policy: JWTValidationPolicy) throws(JWTValidationError) -> Validated {
            try policy.validate(unvalidatedClaims, type: header.type)
            return Validated(header: header, claims: unvalidatedClaims, rawClaims: rawClaims)
        }
    }

    /// A JWT whose signature is good and whose claims satisfied a validation policy.
    public struct Validated: Sendable {
        public let header: JWSHeader<Header>
        public let claims: JWTClaims<Custom>
        /// Every claim as it was received, including ones no typed property covers.
        public let rawClaims: [String: JSONValue]
    }

    /// A JWT produced by signing.
    public struct Signed: Sendable {
        /// The header, as signed.
        public let header: JWSHeader<Header>
        private let compact: String

        /// The JWT in the JWS Compact Serialization, the only one a JWT uses (RFC 7519 §7.1).
        public func compactSerialization() -> String {
            compact
        }
    }
}

extension JWT.Signed {
    /// Signs `claims`.
    ///
    /// The header's `alg` is taken from the signer's type and cannot be supplied separately.
    public init<S: Signer>(
        signing claims: JWTClaims<Custom>,
        with signer: S,
        header: JWSHeaderParameters<Header>
    ) async throws(JWTError) {
        let payload = try claims.jsonRepresentation()
        do {
            let signed = try await JWS<Header>.Signed(signing: payload, with: signer, header: header)
            self.init(header: signed.header, compact: try signed.compactSerialization())
        } catch {
            throw .jws(error)
        }
    }
}

/// A JWT with registered header parameters only.
public typealias SignedJWT<Custom: Codable & Sendable> = JWT<Custom, EmptyHeaderParameters>

/// A JWT with registered claims and registered header parameters only.
public typealias SimpleJWT = JWT<EmptyClaims, EmptyHeaderParameters>

extension JWT.Signed where Header == EmptyHeaderParameters {
    /// Signs `claims`.
    ///
    /// - Parameter type: The header's `typ`. Defaults to `JWT`; use a specific type such as
    ///   `at+jwt` for tokens with a defined purpose (RFC 8725 §3.11).
    public init<S: Signer>(
        signing claims: JWTClaims<Custom>,
        with signer: S,
        type: MediaType? = "JWT"
    ) async throws(JWTError) {
        try await self.init(signing: claims, with: signer, header: JWSHeaderParameters(type: type))
    }

    /// Builds the claims from a block and signs them.
    public init<S: Signer>(
        signingWith signer: S,
        type: MediaType? = "JWT",
        custom: Custom,
        @JWTClaimsBuilder _ build: () -> [any JWTClaimComponent]
    ) async throws(JWTError) {
        try await self.init(signing: try JWTClaims(custom: custom, build), with: signer, type: type)
    }
}

extension JWT.Signed where Header == EmptyHeaderParameters, Custom == EmptyClaims {
    /// Builds the claims from a block and signs them.
    public init<S: Signer>(
        signingWith signer: S,
        type: MediaType? = "JWT",
        @JWTClaimsBuilder _ build: () -> [any JWTClaimComponent]
    ) async throws(JWTError) {
        try await self.init(signing: try JWTClaims(build), with: signer, type: type)
    }
}
