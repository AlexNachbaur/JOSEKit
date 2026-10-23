import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import JOSEJWS
import JOSEJWT
import TestSupport
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
}

private struct AppClaims: Codable, Sendable, Equatable {
    let scope: String
    let level: Int
}

/// A decrypter for the fixture's recipient key.
private func decrypter(algorithm: String, jwk: String) throws -> AnyKeyDecrypter {
    let json = Data(jwk.utf8)
    switch algorithm {
    case "dir":
        return AnyKeyDecrypter(try DirectDecrypter(jwk: try SymmetricJWK(json: json)))
    case "A256KW":
        return AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(jwk: try SymmetricJWK(json: json)))
    case "ECDH-ES":
        return try ECDHES().decrypter(for: try PrivateJWK(json: json))
    case "RSA-OAEP-256":
        return AnyKeyDecrypter(try RSADecrypter<RSAOAEP256>(jwk: try PrivateJWK(json: json)))
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
        let fixture = try Fixture(fixture: "encrypted", in: .module)
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
        let fixture = try Fixture(fixture: "encrypted", in: .module)
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
                _ = try await SimpleEncryptedJWT.Encrypted(compact: testCase.token).decrypt(with: keys).validate(policy)
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
        let fixture = try Fixture(fixture: "encrypted", in: .module)
        let keys = DecryptionKeys([try decrypter(algorithm: "A256KW", jwk: fixture.validationJwk)])
        func outcome(_ name: String) async throws -> EncryptedJWTError? {
            let token = try #require(fixture.validation.first { $0.name == name }).token
            do {
                _ = try await SimpleEncryptedJWT.Encrypted(compact: token).decrypt(with: keys)
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
        let fixture = try Fixture(fixture: "encrypted", in: .module)
        let decryption = DecryptionKeys([try decrypter(algorithm: "A256KW", jwk: fixture.validationJwk)])
        let verification = VerificationKeys([
            try ES256().verifier(for: try JWK(json: Data(fixture.nestedSignerJwk.utf8)))
        ]
        )
        let policy = policy(at: Date(timeIntervalSince1970: fixture.now))
        var accepted = 0
        var rejected = 0
        for testCase in fixture.nested {
            var isAccepted = true
            do {
                _ = try await SimpleNestedJWT.Encrypted(compact: testCase.token)
                    .decrypt(with: decryption)
                    .verify(with: verification)
                    .validate(policy)
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
        let key = try AESKeyWrapEncrypter<A256KW>(key: secret, keyID: "k")
        let keys = DecryptionKeys([AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: secret))])
        var claims = JWTClaims(
            issuer: "https://issuer.example",
            audience: Audience("https://api.example"),
            expiration: NumericDate(Self.now.addingTimeInterval(60)),
            custom: AppClaims(scope: "s", level: 1)
        )
        claims.additionalClaims["extra"] = true
        let token = try await EncryptedJWT<AppClaims, EmptyHeaderParameters>.Encrypted(
            encrypting: claims,
            to: key,
            using: .a256gcm
        ).compactSerialization()
        #expect(token.split(separator: ".").count == 5)

        let encrypted = try EncryptedJWT<AppClaims, EmptyHeaderParameters>.Encrypted(compact: token)
        #expect(encrypted.header.type == "JWT")
        #expect(encrypted.header.keyID == "k")
        let decrypted = try await encrypted.decrypt(with: keys)
        #expect(decrypted.unvalidatedClaims.custom == AppClaims(scope: "s", level: 1))
        #expect(decrypted.rawClaims["extra"] == true)
        let validated = try decrypted.validate(policy(type: .exactly("JWT")))
        #expect(validated.claims.issuer == "https://issuer.example")
        #expect(validated.rawClaims["extra"] == true)

        // The policy's type rule reads the JWE header's typ.
        #expect(throws: JWTValidationError.typeMismatch(expected: "at+jwt", found: "JWT")) {
            try decrypted.validate(policy(type: .exactly("at+jwt")))
        }
        let untyped = try await SimpleEncryptedJWT.Encrypted(
            encrypting: JWTClaims(),
            to: key,
            using: .a256gcm,
            type: nil
        ).compactSerialization()
        #expect(try SimpleEncryptedJWT.Encrypted(compact: untyped).header.type == nil)

        // A token typed as something other than JWT validates against that type, and not against JWT.
        let typedClaims = JWTClaims(
            issuer: "https://issuer.example",
            audience: Audience("https://api.example"),
            expiration: NumericDate(Self.now.addingTimeInterval(60))
        )
        let typed = try await SimpleEncryptedJWT.Encrypted(
            encrypting: typedClaims,
            to: key,
            using: .a256gcm,
            type: "at+jwt"
        ).compactSerialization()
        let typedDecrypted = try await SimpleEncryptedJWT.Encrypted(compact: typed).decrypt(with: keys)
        _ = try typedDecrypted.validate(policy(type: .exactly("application/at+jwt")))
        #expect(throws: JWTValidationError.typeMismatch(expected: "JWT", found: "at+jwt")) {
            try typedDecrypted.validate(policy(type: .exactly("JWT")))
        }
    }

    // `zip` does not exist on Windows, which has no system zlib.
    #if !os(Windows)
        @Test("an encrypted JWT can be compressed, and its decryption honours the decompressed size limit")
        func compressedEncryptedJWT() async throws {
            let secret = SymmetricKeyMaterial(randomByteCount: 32)
            let keys = DecryptionKeys([AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: secret))])
            var claims = JWTClaims(
                issuer: "https://issuer.example",
                audience: Audience("https://api.example"),
                expiration: NumericDate(Self.now.addingTimeInterval(60))
            )
            claims.additionalClaims["padding"] = .string(String(repeating: "x", count: 2_000))
            let token = try await SimpleEncryptedJWT.Encrypted(
                encrypting: claims,
                to: try AESKeyWrapEncrypter<A256KW>(key: secret),
                using: .a256gcm,
                header: JWEHeaderParameters(type: "JWT", compression: .deflate)
            ).compactSerialization()
            let encrypted = try SimpleEncryptedJWT.Encrypted(compact: token)
            #expect(encrypted.header.compression == .deflate)
            let validated = try await encrypted.decrypt(with: keys).validate(policy())
            #expect(validated.claims.issuer == "https://issuer.example")
            await #expect(throws: EncryptedJWTError.jwe(.decompressedSizeExceedsLimit(maximum: 1_000))) {
                try await encrypted.decrypt(with: keys, maximumDecompressedByteCount: 1_000)
            }

            // A nested JWT passes its limit through in the same way.
            let signer = try ECDSASigner(privateKey: try ECPrivateKey<P256Curve>())
            let nested = try await SimpleJWE.Encrypted(
                encrypting: Data(try await SimpleJWT.Signed(signing: claims, with: signer).compactSerialization().utf8),
                to: try AESKeyWrapEncrypter<A256KW>(key: secret),
                using: .a256gcm,
                header: JWEHeaderParameters(contentType: "JWT", compression: .deflate)
            ).compactSerialization()
            let outer = try SimpleNestedJWT.Encrypted(compact: nested)
            _ = try await outer.decrypt(with: keys)
            await #expect(throws: EncryptedJWTError.jwe(.compressionNotAllowed)) {
                try await outer.decrypt(with: keys, maximumDecompressedByteCount: 0)
            }
        }
    #endif

    @Test("an encrypted JWT cannot claim to be nested, and a nested one cannot be read as plain")
    func contentTypeRules() async throws {
        let secret = SymmetricKeyMaterial(randomByteCount: 32)
        let key = try AESKeyWrapEncrypter<A256KW>(key: secret)
        // A caller asking for cty JWT on a plain encrypted JWT gets it dropped, not a misleading token.
        let token = try await SimpleEncryptedJWT.Encrypted(
            encrypting: JWTClaims(),
            to: key,
            using: .a256gcm,
            header: JWEHeaderParameters(contentType: "JWT")
        ).compactSerialization()
        #expect(try SimpleEncryptedJWT.Encrypted(compact: token).header.contentType == nil)

        let signer = try ECDSASigner(privateKey: try ECPrivateKey<P256Curve>())
        let nested = try await SimpleNestedJWT.Encrypted(
            signing: JWTClaims(),
            signedBy: signer,
            encryptedTo: key,
            using: .a256gcm
        ).compactSerialization()
        do {
            _ = try SimpleEncryptedJWT.Encrypted(compact: nested)
            Issue.record("a nested JWT was accepted as a plain encrypted JWT")
        } catch {
            guard case .contentIsNestedJWT = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
        #expect(throws: EncryptedJWTError.contentIsNotNestedJWT(contentType: nil)) {
            try SimpleNestedJWT.Encrypted(compact: token)
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
        let recipient = try RSAEncrypter<RSAOAEP256>(publicKey: recipientKey.publicKey)
        let decryption = DecryptionKeys([AnyKeyDecrypter(try RSADecrypter<RSAOAEP256>(privateKey: recipientKey))])

        let claims = JWTClaims(
            issuer: "https://issuer.example",
            audience: Audience("https://api.example"),
            expiration: NumericDate(Self.now.addingTimeInterval(60)),
            custom: AppClaims(scope: "admin", level: 9)
        )
        let token = try await NestedJWT<AppClaims, EmptyHeaderParameters>.Encrypted(
            signing: claims,
            signedBy: signer,
            header: JWSHeaderParameters(type: "JWT"),
            encryptedTo: recipient,
            using: .a256cbcHS512,
            type: "JWT"
        ).compactSerialization()
        // The outer header is readable before decryption, as for any encrypted token.
        let outer = try NestedJWT<AppClaims, EmptyHeaderParameters>.Encrypted(compact: token)
        #expect(outer.header.contentType == "JWT")
        #expect(outer.header.type == "JWT")
        #expect(outer.header.algorithm == "RSA-OAEP-256")

        // Decrypting yields the ordinary Unverified type: the same gate every signed JWT goes through.
        let decrypted = try await outer.decrypt(with: decryption)
        #expect(decrypted.header.algorithm == "RSA-OAEP-256")
        let inner: JWT<AppClaims, EmptyHeaderParameters>.Unverified = decrypted.inner
        #expect(inner.header.algorithm == "ES256")
        #expect(inner.header.keyID == "sig")
        let validated = try await decrypted.verify(with: verification).validate(policy(type: .exactly("JWT")))
        #expect(validated.claims.custom == AppClaims(scope: "admin", level: 9))

        // A stranger's key does not verify the inner token even though it decrypted.
        let stranger = VerificationKeys([
            AnyVerifier(try ECDSAVerifier(publicKey: (try ECPrivateKey<P256Curve>()).publicKey))
        ])
        await #expect(throws: EncryptedJWTError.jwt(.jws(.signatureInvalid(algorithm: "ES256", keyID: nil)))) {
            try await decrypted.verify(with: stranger)
        }
        // And an expired inner token decrypts and verifies but does not validate.
        let expired = try await SimpleNestedJWT.Encrypted(
            signing: JWTClaims(
                issuer: "https://issuer.example",
                audience: Audience("https://api.example"),
                expiration: NumericDate(Self.now)
            ),
            signedBy: signer,
            encryptedTo: recipient,
            using: .a256gcm
        ).compactSerialization()
        let verified = try await SimpleNestedJWT.Encrypted(compact: expired).decrypt(with: decryption)
            .verify(with: verification)
        #expect(throws: JWTValidationError.self) { try verified.validate(policy()) }
    }

    @Test("a claim the outer header of a nested JWT repeats must equal the signed claim")
    func nestedReplicatedClaims() async throws {
        struct Replicated: HeaderParameters {
            var iss: String?
            var sub: String?
        }
        let signingKey = try ECPrivateKey<P256Curve>()
        let signer = try ECDSASigner(privateKey: signingKey)
        let verification = VerificationKeys([AnyVerifier(try ECDSAVerifier(publicKey: signingKey.publicKey))])
        let secret = SymmetricKeyMaterial(randomByteCount: 32)
        let decryption = DecryptionKeys([AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: secret))])
        // The inner token carries its key, for the resolver path below.
        let inner = try await SimpleJWT.Signed(
            signing: JWTClaims(issuer: "https://issuer.example"),
            with: signer,
            header: JWSHeaderParameters(jwk: JWK(.p256(signingKey.publicKey)))
        ).compactSerialization()
        let resolver = HeaderKeyResolver(algorithms: [.es256], allowsEmbeddedKey: true)

        func nested(_ replicated: Replicated) async throws -> SimpleNestedJWT.Decrypted {
            let token = try await JWE<Replicated>.Encrypted(
                encrypting: Data(inner.utf8),
                to: try AESKeyWrapEncrypter<A256KW>(key: secret),
                using: .a256gcm,
                header: JWEHeaderParameters(contentType: "JWT", custom: replicated)
            ).compactSerialization()
            return try await SimpleNestedJWT.Encrypted(compact: token).decrypt(with: decryption)
        }

        let matching = try await nested(Replicated(iss: "https://issuer.example"))
        #expect(matching.header.rawParameters["iss"] == "https://issuer.example")
        _ = try await matching.verify(with: verification)
        _ = try await matching.verify(resolving: resolver)

        let different = try await nested(Replicated(iss: "https://mallory.example"))
        await #expect(throws: EncryptedJWTError.replicatedClaimMismatch(name: "iss")) {
            try await different.verify(with: verification)
        }
        await #expect(throws: EncryptedJWTError.replicatedClaimMismatch(name: "iss")) {
            try await different.verify(resolving: resolver)
        }
        // A repeated claim the signed token does not have is a mismatch too.
        let absent = try await nested(Replicated(sub: "user-1"))
        await #expect(throws: EncryptedJWTError.replicatedClaimMismatch(name: "sub")) {
            try await absent.verify(with: verification)
        }
    }

    @Test("a nested JWT whose decrypted content is not text or not a JWT is refused")
    func nestedContentRules() async throws {
        let secret = SymmetricKeyMaterial(randomByteCount: 32)
        let keys = DecryptionKeys([AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: secret))])
        func outcome(_ content: Data, _ keys: DecryptionKeys) async throws -> EncryptedJWTError? {
            let token = try await SimpleJWE.Encrypted(
                encrypting: content,
                to: try AESKeyWrapEncrypter<A256KW>(key: secret),
                using: .a256gcm,
                header: JWEHeaderParameters(contentType: "JWT")
            ).compactSerialization()
            let encrypted = try SimpleNestedJWT.Encrypted(compact: token)
            do {
                _ = try await encrypted.decrypt(with: keys)
                return nil
            } catch {
                return error
            }
        }
        #expect(try await outcome(Data([0xFF, 0xFE, 0x00]), keys) == .nestedTokenNotUTF8)
        #expect(
            try await outcome(Data("not a jwt".utf8), keys) == .jwt(.jws(.invalidCompactSerialization(segmentCount: 1)))
        )
        // Decryption failures surface as JWE errors, uniformly.
        let other = DecryptionKeys([
            AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: SymmetricKeyMaterial(randomByteCount: 32)))
        ])
        #expect(try await outcome(Data("x".utf8), other) == .jwe(.decryptionFailed))
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
