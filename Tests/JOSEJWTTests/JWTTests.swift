import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import Testing

@testable import JOSEJWT

private struct AppClaims: Codable, Sendable, Equatable {
    var scope: String
    var tenant: Int?
}

private struct AppHeader: HeaderParameters, Equatable {
    var nonce: String?
}

@Suite("JWT")
struct JWTTests {
    typealias Plain = SignedJWT<EmptyClaims>

    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let clock = JWTClock.fixed(now)

    private struct Keys {
        let signer: ECDSASigner<P256Curve>
        let verification: VerificationKeys

        init() throws {
            let privateKey = try ECPrivateKey<P256Curve>()
            signer = try ECDSASigner(privateKey: privateKey, keyID: "k1")
            verification = VerificationKeys([
                AnyVerifier(try ECDSAVerifier(publicKey: privateKey.publicKey, keyID: "k1"))
            ])
        }
    }

    private func policy(
        issuer: JWTValidationPolicy.IssuerRule = .unchecked,
        audience: JWTValidationPolicy.AudienceRule = .unchecked,
        type: JWTValidationPolicy.TypeRule = .unchecked,
        requiresExpiration: Bool = true,
        leeway: Duration = .zero
    ) -> JWTValidationPolicy {
        JWTValidationPolicy(
            issuer: issuer,
            audience: audience,
            type: type,
            requiresExpiration: requiresExpiration,
            leeway: leeway,
            clock: Self.clock
        )
    }

    /// Signs an exact payload, so that tests can present claims this package would not write.
    private func token(payload: String, keys: Keys) async throws -> String {
        try await JWS<EmptyHeaderParameters>.sign(Data(payload.utf8), with: keys.signer).compactSerialization()
    }

    private func payloadJSON(of token: String) throws -> String {
        let segment = String(token.split(separator: ".")[1])
        return String(decoding: try Base64URL.decode(segment), as: UTF8.self)
    }

    private func headerJSON(of token: String) throws -> String {
        let segment = String(token.split(separator: ".")[0])
        return String(decoding: try Base64URL.decode(segment), as: UTF8.self)
    }

    // MARK: Building and signing

    @Test("a token built with the claims builder round-trips through verify and validate")
    func builderRoundTrip() async throws {
        let keys = try Keys()
        let token = try await Plain.sign(with: keys.signer, type: "at+jwt") {
            Issuer("https://issuer.example")
            Subject("user-1")
            Audience("https://api.example")
            ExpiresIn(.seconds(300), clock: Self.clock)
            NotBefore(Self.now)
            IssuedAt(clock: Self.clock)
            JWTID("id-1")
            Claim("scope", "read write")
        }

        #expect(try headerJSON(of: token) == #"{"alg":"ES256","kid":"k1","typ":"at+jwt"}"#)
        #expect(
            try payloadJSON(of: token)
                == #"{"aud":"https://api.example","exp":1800000300,"iat":1800000000,"iss":"https://issuer.example","#
                + #""jti":"id-1","nbf":1800000000,"scope":"read write","sub":"user-1"}"#
        )

        let validated = try Plain.Unverified(compact: token)
            .verify(with: keys.verification)
            .validate(
                policy(
                    issuer: .exactly("https://issuer.example"),
                    audience: .contains("https://api.example"),
                    type: .exactly("application/at+jwt")
                )
            )
        #expect(validated.claims.subject == "user-1")
        #expect(validated.claims.expiration == NumericDate(secondsSince1970: 1_800_000_300))
        #expect(validated.rawClaims["scope"] == "read write")
        #expect(validated.header.algorithm == "ES256")
    }

    @Test("typed custom claims and a custom header type round-trip")
    func customTypes() async throws {
        let keys = try Keys()
        var claims = JWTClaims(
            issuer: "i",
            expiration: NumericDate(Self.now.addingTimeInterval(60)),
            custom: AppClaims(scope: "admin", tenant: 7)
        )
        claims.additionalClaims["extra"] = ["a": 1]
        let header = JWSHeaderParameters(type: "JWT", custom: AppHeader(nonce: "n-1"))
        let token = try await JWT<AppClaims, AppHeader>.sign(claims, with: keys.signer, header: header)

        let validated = try JWT<AppClaims, AppHeader>.Unverified(compact: token)
            .verify(with: keys.verification)
            .validate(policy(issuer: .exactly("i")))
        #expect(validated.claims.custom == AppClaims(scope: "admin", tenant: 7))
        #expect(validated.header.custom == AppHeader(nonce: "n-1"))
        #expect(validated.rawClaims["extra"] == ["a": 1])
        #expect(validated.claims.additionalClaims.isEmpty)

        // The same token read without the custom types still verifies; the claims are in rawClaims.
        let plain = try Plain.Unverified(compact: token).verify(with: keys.verification).validate(policy())
        #expect(plain.rawClaims["tenant"] == 7)
    }

    @Test("typ defaults to JWT and can be omitted")
    func typeDefault() async throws {
        let keys = try Keys()
        let withDefault = try await Plain.sign(JWTClaims(), with: keys.signer)
        #expect(try headerJSON(of: withDefault) == #"{"alg":"ES256","kid":"k1","typ":"JWT"}"#)
        let without = try await Plain.sign(JWTClaims(), with: keys.signer, type: nil)
        #expect(try headerJSON(of: without) == #"{"alg":"ES256","kid":"k1"}"#)
    }

    @Test("the builder supports conditionals and loops, and refuses a claim set twice")
    func builderControlFlow() throws {
        let includeSubject = true
        let claims = try JWTClaims {
            Issuer("i")
            if includeSubject {
                Subject("s")
            } else {
                Subject("other")
            }
            if !includeSubject {
                JWTID("never")
            }
            for index in 0..<2 {
                Claim("item\(index)", .integer(Int64(index)))
            }
        }
        #expect(claims.issuer == "i")
        #expect(claims.subject == "s")
        #expect(claims.jwtID == nil)
        #expect(claims.additionalClaims == ["item0": 0, "item1": 1])

        func duplicate(@JWTClaimsBuilder _ build: () -> [any JWTClaimComponent]) -> String? {
            do {
                _ = try JWTClaims(build)
                return nil
            } catch {
                guard case .duplicateClaim(let name) = error else {
                    return "other: \(error)"
                }
                return name
            }
        }
        #expect(
            duplicate {
                Issuer("a")
                Issuer("b")
            } == "iss"
        )
        #expect(
            duplicate {
                Subject("a")
                Subject("b")
            } == "sub"
        )
        #expect(
            duplicate {
                Audience("a")
                Audience("b")
            } == "aud"
        )
        #expect(
            duplicate {
                ExpiresAt(Self.now)
                ExpiresIn(.seconds(1))
            } == "exp"
        )
        #expect(
            duplicate {
                NotBefore(Self.now)
                NotBefore(Self.now)
            } == "nbf"
        )
        #expect(
            duplicate {
                IssuedAt(Self.now)
                IssuedAt()
            } == "iat"
        )
        #expect(
            duplicate {
                JWTID("a")
                JWTID.random()
            } == "jti"
        )
        #expect(
            duplicate {
                Claim("x", 1)
                Claim("x", 2)
            } == "x"
        )
        #expect(
            duplicate {
                Issuer("a")
                Subject("b")
                Claim("x", 1)
            } == nil
        )
    }

    @Test("registered claims cannot be set by name, by a custom claims type, or as additional claims")
    func registeredClaimsAreProtected() async throws {
        let keys = try Keys()
        for name in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] {
            do {
                _ = try JWTClaims { Claim(name, "x") }
                Issue.record("Claim(\"\(name)\") was accepted")
            } catch {
                guard case .claimCollision(let collided) = error else {
                    Issue.record("unexpected error \(error)")
                    continue
                }
                #expect(collided == name)
            }

            var claims = JWTClaims()
            claims.additionalClaims[name] = "x"
            do {
                _ = try await Plain.sign(claims, with: keys.signer)
                Issue.record("additional claim \(name) was accepted")
            } catch {
                guard case .claimCollision = error else {
                    Issue.record("unexpected error \(error)")
                    continue
                }
            }
        }

        struct Hostile: Codable, Sendable {
            var exp = 9_999_999_999
        }
        do {
            _ = try await SignedJWT<Hostile>.sign(JWTClaims(custom: Hostile()), with: keys.signer)
            Issue.record("a custom claims type was allowed to write exp")
        } catch {
            guard case .claimCollision(let name) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(name == "exp")
        }

        // An additional claim that repeats a custom claim is a collision too.
        var overlapping = JWTClaims(custom: AppClaims(scope: "a"))
        overlapping.additionalClaims["scope"] = "b"
        do {
            _ = try await SignedJWT<AppClaims>.sign(overlapping, with: keys.signer)
            Issue.record("an additional claim overrode a custom claim")
        } catch {
            guard case .claimCollision(let name) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(name == "scope")
        }

        struct NotAnObject: Codable, Sendable {
            init() {}
            init(from decoder: any Decoder) throws {}
            func encode(to encoder: any Encoder) throws {
                var container = encoder.singleValueContainer()
                try container.encode([1])
            }
        }
        do {
            _ = try await SignedJWT<NotAnObject>.sign(JWTClaims(custom: NotAnObject()), with: keys.signer)
            Issue.record("non-object custom claims were accepted")
        } catch {
            guard case .customClaimsNotObject = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
    }

    @Test("dates are written as integers when whole and as fractions otherwise; audiences as string or array")
    func claimEncoding() async throws {
        let keys = try Keys()
        let claims = JWTClaims(
            audience: Audience("a", "b"),
            expiration: NumericDate(secondsSince1970: 1_800_000_000.5),
            issuedAt: NumericDate(secondsSince1970: 1_800_000_000)
        )
        let token = try await Plain.sign(claims, with: keys.signer)
        #expect(try payloadJSON(of: token) == #"{"aud":["a","b"],"exp":1800000000.5,"iat":1800000000}"#)

        let read = try Plain.Unverified(compact: token).verify(with: keys.verification)
        #expect(read.unvalidatedClaims.audience == Audience("a", "b"))
        #expect(read.unvalidatedClaims.expiration?.secondsSince1970 == 1_800_000_000.5)
        #expect(NumericDate(secondsSince1970: 1_800_000_000).description == "1800000000")
        #expect(NumericDate(Self.now).date == Self.now)

        do {
            _ = try await Plain.sign(JWTClaims(expiration: NumericDate(secondsSince1970: .infinity)), with: keys.signer)
            Issue.record("an infinite exp was written")
        } catch {
            guard case .invalidNumericDate(let name) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(name == "exp")
        }
    }

    // MARK: Reading

    @Test("unverified claims are only reachable under a name that says so, and verified claims are not yet validated")
    func typeStates() async throws {
        let keys = try Keys()
        let token = try await Plain.sign(
            JWTClaims(issuer: "i", expiration: NumericDate(Self.now.addingTimeInterval(-1))),
            with: keys.signer
        )
        let unverified = try Plain.Unverified(compact: token)
        #expect(unverified.header.algorithm == "ES256")
        #expect(try unverified.unverifiedClaims().issuer == "i")

        // The signature is good, so verification succeeds even though the token has expired.
        let verified = try unverified.verify(with: keys.verification)
        #expect(verified.unvalidatedClaims.issuer == "i")
        #expect(throws: JWTValidationError.self) { try verified.validate(policy()) }
    }

    @Test("a bad signature, wrong key or unsupported algorithm stops at verification")
    func verificationFailures() async throws {
        let keys = try Keys()
        let other = try Keys()
        let token = try await Plain.sign(JWTClaims(issuer: "i"), with: keys.signer)
        _ = try Plain.Unverified(compact: token).verify(with: keys.verification)

        func failure(_ token: String, _ verification: VerificationKeys) -> String {
            do {
                _ = try Plain.Unverified(compact: token).verify(with: verification)
                return "accepted"
            } catch {
                guard case .jws(let underlying) = error else {
                    return "not a JWS error: \(error)"
                }
                return Mirror(reflecting: underlying).children.first?.label ?? "\(underlying)"
            }
        }
        #expect(failure(token, other.verification) == "signatureInvalid")
        let parts = token.split(separator: ".").map(String.init)
        let forgedClaims = Base64URL.encode(Data(#"{"iss":"mallory"}"#.utf8))
        #expect(failure("\(parts[0]).\(forgedClaims).\(parts[2])", keys.verification) == "signatureInvalid")
        let noneHeader = Base64URL.encode(Data(#"{"alg":"none"}"#.utf8))
        #expect(failure("\(noneHeader).\(parts[1]).", keys.verification) == "noVerifierForAlgorithm")
        #expect(failure("\(parts[0]).\(parts[1])", keys.verification) == "invalidCompactSerialization")
    }

    @Test("malformed claims sets are refused with the claim named")
    func malformedClaims() async throws {
        let keys = try Keys()
        func failure(_ payload: String) async throws -> String {
            let token = try await token(payload: payload, keys: keys)
            do {
                _ = try Plain.Unverified(compact: token).verify(with: keys.verification)
                return "accepted"
            } catch {
                return error.description
            }
        }
        #expect(try await failure(#"{"iss":"i"}"#) == "accepted")
        #expect(try await failure(#"{"iss":1}"#) == #"JWT claim "iss" must be a string"#)
        #expect(try await failure(#"{"sub":[]}"#) == #"JWT claim "sub" must be a string"#)
        #expect(try await failure(#"{"jti":true}"#) == #"JWT claim "jti" must be a string"#)
        #expect(try await failure(#"{"aud":1}"#) == #"JWT claim "aud" must be a string or an array of strings"#)
        #expect(try await failure(#"{"aud":["a",1]}"#) == #"JWT claim "aud" must be a string or an array of strings"#)
        #expect(try await failure(#"{"exp":"1800000000"}"#) == #"JWT claim "exp" must be a number"#)
        #expect(try await failure(#"{"nbf":null}"#) == #"JWT claim "nbf" must be a number"#)
        #expect(try await failure(#"{"iat":{}}"#) == #"JWT claim "iat" must be a number"#)
        #expect(try await failure("[]").contains("not a well-formed JSON object"))
        #expect(try await failure("").contains("not a well-formed JSON object"))
        #expect(try await failure(#"{"exp":1,"exp":2}"#).contains(#"duplicate member "exp""#))
        #expect(try await failure(#"{"a":{"b":1,"b":2}}"#).contains(#"duplicate member "b""#))
    }

    @Test("claims that do not fit the custom claims type are refused")
    func customClaimsMismatch() async throws {
        let keys = try Keys()
        let token = try await token(payload: #"{"scope":5}"#, keys: keys)
        do {
            _ = try SignedJWT<AppClaims>.Unverified(compact: token).verify(with: keys.verification)
            Issue.record("mismatched custom claims were accepted")
        } catch {
            guard case .invalidCustomClaims = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
        _ = try Plain.Unverified(compact: token).verify(with: keys.verification)
    }

    @Test("a JWT with an unencoded payload is refused")
    func unencodedPayload() async throws {
        let keys = try Keys()
        let jws = try await JWS<EmptyHeaderParameters>.sign(
            Data(#"{"iss":"i"}"#.utf8),
            with: keys.signer,
            payloadEncoding: .unencoded
        )
        let compact = try jws.compactSerialization()
        do {
            _ = try Plain.Unverified(compact: compact)
            Issue.record("an unencoded JWT was accepted")
        } catch {
            guard case .unencodedPayloadNotAllowed = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
    }

    // MARK: Validation policy

    private func validate(
        _ claims: JWTClaims<EmptyClaims>,
        type: MediaType? = "JWT",
        _ policy: JWTValidationPolicy
    ) -> JWTValidationError? {
        do {
            try policy.validate(claims, type: type)
            return nil
        } catch {
            return error
        }
    }

    private var valid: JWTClaims<EmptyClaims> {
        JWTClaims(
            issuer: "https://issuer.example",
            audience: Audience("https://api.example", "https://other.example"),
            expiration: NumericDate(Self.now.addingTimeInterval(60))
        )
    }

    @Test("issuer rules")
    func issuerRules() {
        #expect(validate(valid, policy(issuer: .exactly("https://issuer.example"))) == nil)
        #expect(validate(valid, policy(issuer: .anyOf(["https://a.example", "https://issuer.example"]))) == nil)
        #expect(validate(valid, policy(issuer: .unchecked)) == nil)
        #expect(
            validate(valid, policy(issuer: .exactly("https://ISSUER.example")))
                == .issuerMismatch(expected: ["https://ISSUER.example"], found: "https://issuer.example")
        )
        #expect(
            validate(valid, policy(issuer: .anyOf(["b", "a"])))
                == .issuerMismatch(expected: ["a", "b"], found: "https://issuer.example")
        )
        var noIssuer = valid
        noIssuer.issuer = nil
        #expect(validate(noIssuer, policy(issuer: .exactly("x"))) == .issuerMismatch(expected: ["x"], found: nil))
        #expect(validate(noIssuer, policy(issuer: .anyOf(["x"]))) == .issuerMismatch(expected: ["x"], found: nil))
        #expect(validate(noIssuer, policy(issuer: .unchecked)) == nil)
    }

    @Test("audience rules")
    func audienceRules() {
        #expect(validate(valid, policy(audience: .contains("https://other.example"))) == nil)
        #expect(validate(valid, policy(audience: .containsAny(["x", "https://api.example"]))) == nil)
        #expect(validate(valid, policy(audience: .unchecked)) == nil)
        let found = ["https://api.example", "https://other.example"]
        #expect(validate(valid, policy(audience: .contains("x"))) == .audienceMismatch(expected: ["x"], found: found))
        #expect(
            validate(valid, policy(audience: .containsAny(["y", "x"])))
                == .audienceMismatch(expected: ["x", "y"], found: found)
        )
        var noAudience = valid
        noAudience.audience = nil
        #expect(validate(noAudience, policy(audience: .contains("x"))) == .audienceMismatch(expected: ["x"], found: []))
        noAudience.audience = Audience([])
        #expect(
            validate(noAudience, policy(audience: .containsAny(["x"]))) == .audienceMismatch(expected: ["x"], found: [])
        )
        #expect(validate(noAudience, policy(audience: .unchecked)) == nil)
    }

    @Test("type rules compare as media types")
    func typeRules() {
        #expect(validate(valid, type: "JWT", policy(type: .exactly("application/jwt"))) == nil)
        #expect(validate(valid, type: "at+JWT", policy(type: .exactly("at+jwt"))) == nil)
        #expect(validate(valid, type: nil, policy(type: .unchecked)) == nil)
        #expect(
            validate(valid, type: "JWT", policy(type: .exactly("at+jwt")))
                == .typeMismatch(expected: "at+jwt", found: "JWT")
        )
        #expect(validate(valid, type: nil, policy(type: .exactly("JWT"))) == .typeMismatch(expected: "JWT", found: nil))
    }

    @Test("exp is exclusive, nbf is inclusive, and leeway widens both")
    func timeRules() {
        func claims(exp: Double? = 60, nbf: Double? = nil) -> JWTClaims<EmptyClaims> {
            var claims = JWTClaims()
            if let exp {
                claims.expiration = NumericDate(Self.now.addingTimeInterval(exp))
            }
            if let nbf {
                claims.notBefore = NumericDate(Self.now.addingTimeInterval(nbf))
            }
            return claims
        }
        let now = NumericDate(Self.now)
        func expired(_ offset: Double, _ leeway: Duration = .zero) -> JWTValidationError {
            .expired(expiration: NumericDate(Self.now.addingTimeInterval(offset)), now: now, leeway: leeway)
        }
        func early(_ offset: Double, _ leeway: Duration = .zero) -> JWTValidationError {
            .notYetValid(notBefore: NumericDate(Self.now.addingTimeInterval(offset)), now: now, leeway: leeway)
        }

        #expect(validate(claims(exp: 1), policy()) == nil)
        #expect(validate(claims(exp: 0.5), policy()) == nil)
        #expect(validate(claims(exp: 0), policy()) == expired(0))
        #expect(validate(claims(exp: -1), policy()) == expired(-1))
        #expect(validate(claims(exp: -5), policy(leeway: .seconds(5))) == expired(-5, .seconds(5)))
        #expect(validate(claims(exp: -5), policy(leeway: .seconds(6))) == nil)
        #expect(validate(claims(exp: -5), policy(leeway: .milliseconds(5500))) == nil)

        #expect(validate(claims(nbf: 0), policy()) == nil)
        #expect(validate(claims(nbf: -1), policy()) == nil)
        #expect(validate(claims(nbf: 1), policy()) == early(1))
        #expect(validate(claims(nbf: 5), policy(leeway: .seconds(5))) == nil)
        #expect(validate(claims(nbf: 5), policy(leeway: .seconds(4))) == early(5, .seconds(4)))

        #expect(validate(claims(exp: nil), policy()) == .missingExpiration)
        #expect(validate(claims(exp: nil), policy(requiresExpiration: false)) == nil)
        // An expired token is expired whether or not expiry is required.
        #expect(validate(claims(exp: -1), policy(requiresExpiration: false)) == expired(-1))
    }

    @Test("the clock is injectable, and the system clock is the default")
    func clocks() {
        let fixed = JWTClock.fixed(Self.now)
        #expect(fixed.now == Self.now)
        #expect(abs(JWTClock.system.now.timeIntervalSinceNow) < 5)
        let defaultPolicy = JWTValidationPolicy(issuer: .unchecked, audience: .unchecked, type: .unchecked)
        #expect(defaultPolicy.requiresExpiration)
        #expect(defaultPolicy.leeway == .zero)
        // A token that expired at the fixed instant, long ago, is expired by the real clock.
        #expect(validate(JWTClaims(expiration: NumericDate(Self.now)), defaultPolicy) != nil || Date() < Self.now)
        #expect(Duration.milliseconds(1500).seconds == 1.5)
    }

    @Test("every error has a message naming what was wrong")
    func descriptions() {
        let errors: [(JWTError, String)] = [
            (.jws(.missingAlgorithm), "alg"),
            (.unencodedPayloadNotAllowed, "b64"),
            (.invalidClaimsStructure(.rootNotObject), "object"),
            (.invalidClaimsJSON(description: "boom"), "boom"),
            (.claimWrongType(name: "exp", expected: "a number"), "exp"),
            (.invalidNumericDate(name: "nbf"), "nbf"),
            (.invalidCustomClaims(description: "bad"), "bad"),
            (.claimCollision(name: "iss"), "iss"),
            (.customClaimsNotObject, "object"),
            (.duplicateClaim(name: "sub"), "sub"),
            (.claimsEncodingFailed(description: "enc"), "enc"),
        ]
        for (error, fragment) in errors {
            #expect(error.description.contains(fragment), "\(error.description)")
        }
        let now = NumericDate(secondsSince1970: 100)
        let validation: [(JWTValidationError, String)] = [
            (.expired(expiration: NumericDate(secondsSince1970: 90), now: now, leeway: .zero), "90"),
            (.notYetValid(notBefore: NumericDate(secondsSince1970: 110), now: now, leeway: .zero), "110"),
            (.missingExpiration, "exp"),
            (.issuerMismatch(expected: ["a"], found: "b"), "\"b\""),
            (.issuerMismatch(expected: ["a", "c"], found: nil), "absent"),
            (.audienceMismatch(expected: ["a"], found: ["b"]), "\"b\""),
            (.audienceMismatch(expected: ["a"], found: []), "no audience"),
            (.typeMismatch(expected: "JWT", found: nil), "absent"),
        ]
        for (error, fragment) in validation {
            #expect(error.description.contains(fragment), "\(error.description)")
        }
    }
}
