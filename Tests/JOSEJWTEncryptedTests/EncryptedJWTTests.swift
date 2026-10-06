import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import JOSEJWS
import JOSEJWT
import Testing

@testable import JOSEJWTEncrypted

private struct Fixture: Decodable {
    struct Encrypted: Decodable {
        let algorithm: String
        let jwk: String
        let token: String
        let payload: String
    }
    struct Options: Decodable {
        let issuer: String?
        let audience: String?
        let typ: String?
    }
    struct Verdict: Decodable {
        let accepted: Bool
    }
    struct ValidationCase: Decodable {
        let name: String
        let token: String
        let options: Options
        let wrongKey: Bool
        let jose: Verdict
    }
    struct NestedCase: Decodable {
        let name: String
        let token: String
        let jose: Verdict
    }
    let now: Double
    let encrypted: [Encrypted]
    let validationJwk: String
    let validationWrongJwk: String
    let validation: [ValidationCase]
    let nestedSignerJwk: String
    let nested: [NestedCase]

    static func load() throws -> Fixture {
        guard let url = Bundle.module.url(forResource: "encrypted", withExtension: "json", subdirectory: "Fixtures")
        else {
            throw FixtureError(description: "encrypted.json is missing from the test bundle")
        }
        return try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    }
}

struct FixtureError: Error, CustomStringConvertible {
    let description: String
}

private struct AppClaims: Codable, Sendable, Equatable {
    let scope: String
    let level: Int
}

typealias PlainEncrypted = EncryptedJWT<EmptyClaims, EmptyHeaderParameters>
typealias PlainNested = NestedJWT<EmptyClaims, EmptyHeaderParameters>

/// A decrypter for the fixture's recipient key.
private func decrypter(algorithm: String, jwk: String) throws -> AnyKeyDecrypter {
    let json = Data(jwk.utf8)
    switch algorithm {
    case "dir":
        return AnyKeyDecrypter(DirectKey(key: try SymmetricJWK(json: json).key))
    case "A256KW":
        return AnyKeyDecrypter(try AESKeyWrapKey<A256KW>(key: try SymmetricJWK(json: json).key))
    case "ECDH-ES":
        guard case .p256(let key) = try PrivateJWK(json: json).key else {
            throw FixtureError(description: "not a P-256 key")
        }
        return AnyKeyDecrypter(ECDHESDecrypter<ECDHES, ECPrivateKey<P256Curve>>(privateKey: key))
    case "RSA-OAEP-256":
        guard case .rsa(let key) = try PrivateJWK(json: json).key else {
            throw FixtureError(description: "not an RSA key")
        }
        return AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP256>(privateKey: key))
    default:
        throw FixtureError(description: "no decrypter for \(algorithm)")
    }
}

@Suite("Encrypted and nested JWTs")
struct EncryptedJWTTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func policy(
        issuer: JWTValidationPolicy.IssuerRule = .exactly("https://issuer.example"),
        audience: JWTValidationPolicy.AudienceRule = .contains("https://api.example"),
        type: JWTValidationPolicy.TypeRule = .unchecked,
        requiresExpiration: Bool = true,
        at date: Date = EncryptedJWTTests.now
    ) -> JWTValidationPolicy {
        JWTValidationPolicy(
            issuer: issuer,
            audience: audience,
            type: type,
            requiresExpiration: requiresExpiration,
            clock: .fixed(date)
        )
    }

    // MARK: Against jose

    @Test("encrypted JWTs from jose decrypt and validate, with the claims jose reads")
    func counterpartEncryptedTokens() async throws {
        let fixture = try Fixture.load()
        #expect(fixture.encrypted.map(\.algorithm) == ["dir", "A256KW", "ECDH-ES", "RSA-OAEP-256"])
        for item in fixture.encrypted {
            let keys = DecryptionKeys([try decrypter(algorithm: item.algorithm, jwk: item.jwk)])
            let validated = try await EncryptedJWT<AppClaims, EmptyHeaderParameters>.Encrypted(compact: item.token)
                .decrypt(with: keys)
                .validate(policy(type: .exactly("JWT"), at: Date(timeIntervalSince1970: fixture.now)))
            #expect(validated.claims.subject == "user-123", "\(item.algorithm)")
            #expect(validated.claims.custom == AppClaims(scope: "read write", level: 3), "\(item.algorithm)")
            let josePayload = try JSONDecoder().decode([String: JSONValue].self, from: Data(item.payload.utf8))
            #expect(validated.rawClaims == josePayload, "\(item.algorithm)")
            #expect(validated.header.algorithm.rawValue == item.algorithm)
        }
    }

    /// Tokens jose accepts and this package refuses: a duplicate claim (jose takes the last).
    static let stricterThanJose: Set<String> = ["claims have a duplicate exp, the last one valid"]

    @Test("verdicts on encrypted JWTs match jose's, apart from the documented stricter case")
    func counterpartVerdicts() async throws {
        let fixture = try Fixture.load()
        let right = DecryptionKeys([try decrypter(algorithm: "A256KW", jwk: fixture.validationJwk)])
        let wrong = DecryptionKeys([try decrypter(algorithm: "A256KW", jwk: fixture.validationWrongJwk)])
        var accepted = 0
        var rejected = 0
        for testCase in fixture.validation {
            var issuer = JWTValidationPolicy.IssuerRule.unchecked
            if let expected = testCase.options.issuer {
                issuer = .exactly(expected)
            }
            var audience = JWTValidationPolicy.AudienceRule.unchecked
            if let expected = testCase.options.audience {
                audience = .contains(expected)
            }
            var type = JWTValidationPolicy.TypeRule.unchecked
            if let expected = testCase.options.typ {
                type = .exactly(MediaType(rawValue: expected))
            }
            let policy = JWTValidationPolicy(
                issuer: issuer,
                audience: audience,
                type: type,
                requiresExpiration: false,
                clock: .fixed(Date(timeIntervalSince1970: fixture.now))
            )
            var keys = right
            if testCase.wrongKey {
                keys = wrong
            }
            var isAccepted = true
            do {
                _ = try await PlainEncrypted.Encrypted(compact: testCase.token).decrypt(with: keys).validate(policy)
            } catch {
                isAccepted = false
            }
            if Self.stricterThanJose.contains(testCase.name) {
                #expect(testCase.jose.accepted, "listed as a deviation, but jose rejects it too: \(testCase.name)")
                #expect(!isAccepted, "accepted: \(testCase.name)")
            } else {
                #expect(isAccepted == testCase.jose.accepted, "\(testCase.name): jose \(testCase.jose.accepted)")
                if testCase.jose.accepted {
                    accepted += 1
                } else {
                    rejected += 1
                }
            }
        }
        #expect(accepted >= 5)
        #expect(rejected >= 11)
    }

    @Test("a replicated claim in the header that differs from the claims set is refused by name")
    func replicatedClaims() async throws {
        let fixture = try Fixture.load()
        let keys = DecryptionKeys([try decrypter(algorithm: "A256KW", jwk: fixture.validationJwk)])
        func outcome(_ name: String) async throws -> EncryptedJWTError? {
            let token = try #require(fixture.validation.first { $0.name == name }).token
            do {
                _ = try await PlainEncrypted.Encrypted(compact: token).decrypt(with: keys)
                return nil
            } catch {
                return error
            }
        }
        #expect(try await outcome("issuer replicated in the header, matching") == nil)
        guard case .replicatedClaimMismatch(let name) = try await outcome("issuer replicated in the header, different")
        else {
            Issue.record("mismatched replicated issuer was not reported")
            return
        }
        #expect(name == "iss")
        guard
            case .replicatedClaimMismatch(let missing) = try await outcome(
                "subject replicated in the header, but no sub claim"
            )
        else {
            Issue.record("replicated subject without a claim was not reported")
            return
        }
        #expect(missing == "sub")
    }

    @Test("nested JWTs from jose decrypt to a signed JWT that must still verify and validate")
    func counterpartNestedTokens() async throws {
        let fixture = try Fixture.load()
        let decryption = DecryptionKeys([try decrypter(algorithm: "A256KW", jwk: fixture.validationJwk)])
        let verification = VerificationKeys([try ES256.verifier(for: try JWK(json: Data(fixture.nestedSignerJwk.utf8)))]
        )
        let policy = policy(at: Date(timeIntervalSince1970: fixture.now))
        var accepted = 0
        var rejected = 0
        for testCase in fixture.nested {
            var isAccepted = true
            do {
                let inner = try await PlainNested.decrypt(testCase.token, with: decryption)
                _ = try inner.verify(with: verification).validate(policy)
            } catch {
                isAccepted = false
            }
            #expect(isAccepted == testCase.jose.accepted, "\(testCase.name): jose \(testCase.jose.accepted)")
            if testCase.jose.accepted {
                accepted += 1
            } else {
                rejected += 1
            }
        }
        #expect(accepted == 2)
        #expect(rejected == 5)
    }

    // MARK: Round trips

    @Test("an encrypted JWT round-trips, and its typ defaults to JWT")
    func encryptedRoundTrip() async throws {
        let secret = SymmetricKeyMaterial(randomByteCount: 32)
        let key = try AESKeyWrapKey<A256KW>(key: secret, keyID: "k")
        var claims = JWTClaims(
            issuer: "https://issuer.example",
            audience: Audience("https://api.example"),
            expiration: NumericDate(Self.now.addingTimeInterval(60)),
            custom: AppClaims(scope: "s", level: 1)
        )
        claims.additionalClaims["extra"] = true
        let token = try EncryptedJWT<AppClaims, EmptyHeaderParameters>.encrypt(claims, to: key, using: A256GCM.self)
        #expect(token.split(separator: ".").count == 5)

        let encrypted = try EncryptedJWT<AppClaims, EmptyHeaderParameters>.Encrypted(compact: token)
        #expect(encrypted.header.type == "JWT")
        #expect(encrypted.header.keyID == "k")
        let decrypted = try await encrypted.decrypt(with: DecryptionKeys([AnyKeyDecrypter(key)]))
        #expect(decrypted.unvalidatedClaims.custom == AppClaims(scope: "s", level: 1))
        let validated = try decrypted.validate(policy(type: .exactly("JWT")))
        #expect(validated.claims.issuer == "https://issuer.example")
        #expect(validated.rawClaims["extra"] == true)

        // The policy's type rule reads the JWE header's typ.
        #expect(throws: JWTValidationError.typeMismatch(expected: "at+jwt", found: "JWT")) {
            try decrypted.validate(policy(type: .exactly("at+jwt")))
        }
        let untyped = try PlainEncrypted.encrypt(JWTClaims(), to: key, using: A256GCM.self, type: nil)
        #expect(try PlainEncrypted.Encrypted(compact: untyped).header.type == nil)

        // A token typed as something other than JWT validates against that type, and not against JWT.
        let typedClaims = JWTClaims(
            issuer: "https://issuer.example",
            audience: Audience("https://api.example"),
            expiration: NumericDate(Self.now.addingTimeInterval(60))
        )
        let typed = try PlainEncrypted.encrypt(typedClaims, to: key, using: A256GCM.self, type: "at+jwt")
        let typedDecrypted = try await PlainEncrypted.Encrypted(compact: typed).decrypt(
            with: DecryptionKeys([AnyKeyDecrypter(key)])
        )
        _ = try typedDecrypted.validate(policy(type: .exactly("application/at+jwt")))
        #expect(throws: JWTValidationError.typeMismatch(expected: "JWT", found: "at+jwt")) {
            try typedDecrypted.validate(policy(type: .exactly("JWT")))
        }
    }

    @Test("an encrypted JWT cannot claim to be nested, and a nested one cannot be read as plain")
    func contentTypeRules() async throws {
        let secret = SymmetricKeyMaterial(randomByteCount: 32)
        let key = try AESKeyWrapKey<A256KW>(key: secret)
        // A caller asking for cty JWT on a plain encrypted JWT gets it dropped, not a misleading token.
        let token = try PlainEncrypted.encrypt(
            JWTClaims(),
            to: key,
            using: A256GCM.self,
            header: JWEHeaderParameters(contentType: "JWT")
        )
        #expect(try PlainEncrypted.Encrypted(compact: token).header.contentType == nil)

        let signer = try ECDSASigner(privateKey: try ECPrivateKey<P256Curve>())
        let nested = try await PlainNested.signThenEncrypt(
            JWTClaims(),
            signedBy: signer,
            encryptedTo: key,
            using: A256GCM.self
        )
        do {
            _ = try PlainEncrypted.Encrypted(compact: nested)
            Issue.record("a nested JWT was accepted as a plain encrypted JWT")
        } catch {
            guard case .contentIsNestedJWT = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
        do {
            _ = try await PlainNested.decrypt(token, with: DecryptionKeys([AnyKeyDecrypter(key)]))
            Issue.record("a plain encrypted JWT was accepted as nested")
        } catch {
            guard case .contentIsNotNestedJWT(let contentType) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(contentType == nil)
        }
    }

    @Test("a nested JWT's claims are reachable only after decrypting, verifying and validating")
    func nestedRoundTrip() async throws {
        let signingKey = try ECPrivateKey<P256Curve>()
        let signer = try ECDSASigner(privateKey: signingKey, keyID: "sig")
        let verification = VerificationKeys([
            AnyVerifier(try ECDSAVerifier(publicKey: signingKey.publicKey, keyID: "sig"))
        ])
        let recipientKey = try RSAPrivateKey()
        let recipient = try RSAOAEPEncrypter<RSAOAEP256>(publicKey: recipientKey.publicKey)
        let decryption = DecryptionKeys([AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP256>(privateKey: recipientKey))])

        let claims = JWTClaims(
            issuer: "https://issuer.example",
            audience: Audience("https://api.example"),
            expiration: NumericDate(Self.now.addingTimeInterval(60)),
            custom: AppClaims(scope: "admin", level: 9)
        )
        let token = try await NestedJWT<AppClaims, EmptyHeaderParameters>.signThenEncrypt(
            claims,
            signedBy: signer,
            header: JWSHeaderParameters(type: "JWT"),
            encryptedTo: recipient,
            using: A256CBCHS512.self,
            type: "JWT"
        )
        let outer = try JWE<EmptyHeaderParameters>.Encrypted(compact: token)
        #expect(outer.header?.contentType == "JWT")
        #expect(outer.header?.type == "JWT")
        #expect(outer.header?.algorithm == "RSA-OAEP-256")

        // Decrypting yields the ordinary Unverified type: the same gate every signed JWT goes through.
        let inner: JWT<AppClaims, EmptyHeaderParameters>.Unverified = try await NestedJWT<
            AppClaims, EmptyHeaderParameters
        >.decrypt(token, with: decryption)
        #expect(inner.header.algorithm == "ES256")
        #expect(inner.header.keyID == "sig")
        let validated = try inner.verify(with: verification).validate(policy(type: .exactly("JWT")))
        #expect(validated.claims.custom == AppClaims(scope: "admin", level: 9))

        // A stranger's key does not verify the inner token even though it decrypted.
        let stranger = VerificationKeys([
            AnyVerifier(try ECDSAVerifier(publicKey: (try ECPrivateKey<P256Curve>()).publicKey))
        ])
        #expect(throws: JWTError.self) { try inner.verify(with: stranger) }
        // And an expired inner token decrypts and verifies but does not validate.
        let expired = try await PlainNested.signThenEncrypt(
            JWTClaims(
                issuer: "https://issuer.example",
                audience: Audience("https://api.example"),
                expiration: NumericDate(Self.now)
            ),
            signedBy: signer,
            encryptedTo: recipient,
            using: A256GCM.self
        )
        let verified = try await PlainNested.decrypt(expired, with: decryption).verify(with: verification)
        #expect(throws: JWTValidationError.self) { try verified.validate(policy()) }
    }

    @Test("a nested JWT whose decrypted content is not text or not a JWT is refused")
    func nestedContentRules() async throws {
        let secret = SymmetricKeyMaterial(randomByteCount: 32)
        let key = try AESKeyWrapKey<A256KW>(key: secret)
        let keys = DecryptionKeys([AnyKeyDecrypter(key)])
        func wrap(_ content: Data) throws -> String {
            try JWE<EmptyHeaderParameters>.encrypt(
                content,
                to: key,
                using: A256GCM.self,
                header: JWEHeaderParameters(contentType: "JWT")
            ).compactSerialization()
        }
        // The wrapped tokens are made outside the `do` blocks so that each block throws only
        // `EncryptedJWTError` and the `catch` can match its cases.
        let binary = try wrap(Data([0xFF, 0xFE, 0x00]))
        do {
            _ = try await PlainNested.decrypt(binary, with: keys)
            Issue.record("non-UTF-8 content was accepted")
        } catch {
            guard case .nestedTokenNotUTF8 = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
        let text = try wrap(Data("not a jwt".utf8))
        do {
            _ = try await PlainNested.decrypt(text, with: keys)
            Issue.record("non-JWT content was accepted")
        } catch {
            guard case .jwt(.jws(.invalidCompactSerialization(let count))) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(count == 1)
        }
        // Decryption failures surface as JWE errors, uniformly.
        let other = DecryptionKeys([
            AnyKeyDecrypter(try AESKeyWrapKey<A256KW>(key: SymmetricKeyMaterial(randomByteCount: 32)))
        ])
        let short = try wrap(Data("x".utf8))
        do {
            _ = try await PlainNested.decrypt(short, with: other)
            Issue.record("wrong key was accepted")
        } catch {
            guard case .jwe(.decryptionFailed) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
    }

    @Test("every error has a message naming what was wrong")
    func descriptions() {
        let errors: [(EncryptedJWTError, String)] = [
            (.jwe(.decryptionFailed), "decryption failed"),
            (.jwt(.unencodedPayloadNotAllowed), "b64"),
            (.contentIsNestedJWT, "nested"),
            (.contentIsNotNestedJWT(contentType: "text"), "\"text\""),
            (.contentIsNotNestedJWT(contentType: nil), "absent"),
            (.nestedTokenNotUTF8, "UTF-8"),
            (.replicatedClaimMismatch(name: "iss"), "iss"),
        ]
        for (error, fragment) in errors {
            #expect(error.description.contains(fragment), "\(error.description)")
        }
    }
}
