import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import Testing

@testable import JOSEJWT

private struct ValidFixture: Decodable {
    struct Token: Decodable {
        let algorithm: String
        let jwk: String
        let token: String
        let payload: String
        let audience: [String]
    }
    let now: Double
    let tokens: [Token]
}

private struct ValidationFixture: Decodable {
    struct Options: Decodable {
        let issuer: OneOrMany?
        let audience: OneOrMany?
        let typ: String?
        let clockTolerance: Int?
    }
    struct OneOrMany: Decodable {
        let values: [String]

        init(from decoder: any Decoder) throws {
            let container = try decoder.singleValueContainer()
            do {
                values = [try container.decode(String.self)]
            } catch DecodingError.typeMismatch {
                values = try container.decode([String].self)
            }
        }
    }
    struct Case: Decodable {
        struct Jose: Decodable {
            let accepted: Bool
        }
        let name: String
        let token: String
        let options: Options
        let jose: Jose
    }
    let now: Double
    let jwk: String
    let cases: [Case]
}

/// The application claims jose wrote into the fixture tokens.
private struct ExampleClaims: Codable, Sendable, Equatable {
    struct Nested: Codable, Sendable, Equatable {
        let flag: Bool
    }
    let scope: String
    let level: Int
    let nested: Nested
    let namespaced: String

    enum CodingKeys: String, CodingKey {
        case scope
        case level
        case nested
        case namespaced = "https://example.com/claim"
    }
}

@Suite("Against jose")
struct CounterpartTests {
    /// Tokens jose 6.2.12 accepts and this package refuses.
    ///
    /// - `iss`, `sub`, `jti` and `aud` of the wrong JSON type: jose only looks at a claim's type
    ///   when asked to check that claim. RFC 7519 §4.1 defines their types, and a claims set
    ///   that violates them is refused here when it is read.
    /// - Duplicate `exp`: jose takes the last. RFC 7519 §4 allows that or rejection; this package
    ///   rejects, because Foundation would take the first.
    static let stricterThanJose: Set<String> = [
        "iss is a number", "sub is a number", "jti is a number", "aud is a number", "aud array has a number",
        "claims have a duplicate exp, the last one valid",
    ]

    @Test("JWTs from jose verify and validate, and their claims read back as jose reads them")
    func validTokens() async throws {
        let fixture = try Fixtures.load(ValidFixture.self, named: "valid")
        #expect(fixture.tokens.map(\.algorithm) == ["ES256", "ES384", "Ed25519", "EdDSA", "RS256", "PS256", "HS256"])
        let policy = JWTValidationPolicy(
            issuer: .exactly("https://issuer.example"),
            audience: .contains("https://api.example"),
            type: .exactly("JWT"),
            clock: .fixed(Date(timeIntervalSince1970: fixture.now))
        )
        for (index, token) in fixture.tokens.enumerated() {
            let label = Comment(rawValue: token.algorithm)
            let keys = VerificationKeys([try TestKeys.verifier(algorithm: token.algorithm, jwk: token.jwk)])
            let validated = try await SignedJWT<ExampleClaims>.Unverified(compact: token.token)
                .verify(with: keys)
                .validate(policy)

            let claims = validated.claims
            #expect(claims.issuer == "https://issuer.example", label)
            #expect(claims.subject == "user-123", label)
            #expect(claims.audience?.values == token.audience, label)
            #expect(claims.issuedAt == NumericDate(secondsSince1970: fixture.now - 10), label)
            #expect(claims.notBefore == NumericDate(secondsSince1970: fixture.now - 10), label)
            #expect(claims.expiration == NumericDate(secondsSince1970: fixture.now + 300), label)
            #expect(claims.jwtID == "id-\(index)", label)
            #expect(
                claims.custom
                    == ExampleClaims(scope: "read write", level: 3, nested: .init(flag: true), namespaced: "namespaced"),
                label
            )
            #expect(validated.header.keyID == KeyID(rawValue: "\(token.algorithm)-key"), label)

            // Every claim, exactly as jose itself decodes the payload.
            let josePayload = try JSONDecoder().decode([String: JSONValue].self, from: Data(token.payload.utf8))
            #expect(validated.rawClaims == josePayload, label)
        }
    }

    @Test("validation verdicts match jose's at the same instant, apart from the documented stricter cases")
    func validationVerdictsAgree() async throws {
        let fixture = try Fixtures.load(ValidationFixture.self, named: "validation")
        let keys = VerificationKeys([try TestKeys.verifier(algorithm: "ES256", jwk: fixture.jwk)])
        var accepted = 0
        var rejected = 0
        var stricter = 0
        for testCase in fixture.cases {
            // The policy equivalent of the options jose was given. jose does not require `exp`.
            var issuer = JWTValidationPolicy.IssuerRule.unchecked
            if let values = testCase.options.issuer?.values {
                issuer = .anyOf(Set(values))
            }
            var audience = JWTValidationPolicy.AudienceRule.unchecked
            if let values = testCase.options.audience?.values {
                audience = .containsAny(Set(values))
            }
            var type = JWTValidationPolicy.TypeRule.unchecked
            if let typ = testCase.options.typ {
                type = .exactly(MediaType(rawValue: typ))
            }
            let policy = JWTValidationPolicy(
                issuer: issuer,
                audience: audience,
                type: type,
                requiresExpiration: false,
                leeway: .seconds(testCase.options.clockTolerance ?? 0),
                clock: .fixed(Date(timeIntervalSince1970: fixture.now))
            )

            var isAccepted = true
            do {
                _ = try await SimpleJWT.Unverified(compact: testCase.token).verify(with: keys).validate(policy)
            } catch {
                isAccepted = false
            }

            if Self.stricterThanJose.contains(testCase.name) {
                #expect(testCase.jose.accepted, "listed as a deviation, but jose rejects it too: \(testCase.name)")
                #expect(!isAccepted, "accepted: \(testCase.name)")
                stricter += 1
            } else {
                #expect(isAccepted == testCase.jose.accepted, "\(testCase.name): jose \(testCase.jose.accepted)")
                if testCase.jose.accepted {
                    accepted += 1
                } else {
                    rejected += 1
                }
            }
        }
        #expect(accepted >= 15)
        #expect(rejected >= 20)
        #expect(stricter == Self.stricterThanJose.count)
    }
}
