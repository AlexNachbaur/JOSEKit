import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWS

private struct CertificateFixture: Decodable {
    struct Leaf: Decodable {
        let der: String
        let privateJwk: String
        let publicJwk: String
        let sha1: String
        let sha256: String
    }
    let root: String
    let otherRoot: String
    let ecLeaf: Leaf
    let rsaLeaf: Leaf
    let expiredLeaf: Leaf
    let leafUnderOtherRoot: Leaf

    static func load() throws -> CertificateFixture {
        try Fixtures.load(CertificateFixture.self, named: "certificates")
    }
}

/// Serves JWK Sets from memory and counts requests.
private final class MemoryJWKSetProvider: JWKSetProvider, @unchecked Sendable {
    struct Missing: Error {}
    private let lock = NSLock()
    private var sets: [URL: JWKSet]
    private(set) var requests: [URL] = []

    init(_ sets: [URL: JWKSet]) {
        self.sets = sets
    }

    func jwkSet(at url: URL) async throws -> JWKSet {
        let set: JWKSet? = lock.withLock {
            requests.append(url)
            return sets[url]
        }
        guard let set else {
            throw Missing()
        }
        return set
    }
}

/// Accepts any chain and returns a fixed key, or refuses everything.
private struct StubValidator: CertificateChainValidator {
    struct Refused: Error {}
    let result: JWK?

    func validate(chain: [Data]) async throws -> JWK {
        guard let result else {
            throw Refused()
        }
        return result
    }
}

@Suite("Key resolution")
struct KeyResolutionTests {
    typealias Plain = JWS<EmptyHeaderParameters>

    private let jwksURL = URL(string: "https://issuer.example/.well-known/jwks.json")!
    private let signingKey: ECPrivateKey<P256Curve>
    private let signer: ECDSASigner<P256Curve>
    private let publicJWK: JWK

    init() throws {
        signingKey = try ECPrivateKey<P256Curve>()
        signer = try ECDSASigner(privateKey: signingKey, keyID: "k1")
        publicJWK = JWK(.p256(signingKey.publicKey), metadata: JWKMetadata(keyID: "k1"))
    }

    private func token(header: JWSHeaderParameters<EmptyHeaderParameters>) async throws -> Plain.Unverified {
        let signed = try await Plain.sign(Data("payload".utf8), with: signer, header: header)
        return try Plain.Unverified(compact: try signed.compactSerialization())
    }

    private func caseName(_ error: KeyResolutionError) -> String {
        Mirror(reflecting: error).children.first?.label ?? "\(error)"
    }

    /// The number of verifiers resolved, or `nil` on failure. `KeyResolutionError` carries
    /// underlying errors and so is not `Equatable`; failures are pattern-matched instead.
    private func resolvedCount(_ resolver: HeaderKeyResolver, _ jws: Plain.Unverified) async -> Int? {
        guard case .success(let count) = await resolution(resolver, jws) else {
            return nil
        }
        return count
    }

    private func resolution(_ resolver: HeaderKeyResolver, _ jws: Plain.Unverified) async -> Result<
        Int, KeyResolutionError
    > {
        guard let header = jws.header else {
            return .success(-1)
        }
        do {
            return .success(try await resolver.verificationKeys(for: header).verifiers.count)
        } catch {
            return .failure(error)
        }
    }

    // MARK: jku

    @Test("jku is used only with a provider and an allow-listed HTTPS URL")
    func jwkSetURL() async throws {
        let provider = MemoryJWKSetProvider([jwksURL: JWKSet(keys: [publicJWK])])
        var header = JWSHeaderParameters<EmptyHeaderParameters>()
        header.jwkSetURL = jwksURL.absoluteString
        let jws = try await token(header: header)

        var resolver = HeaderKeyResolver(algorithms: [ES256.self])
        // No provider: jku is ignored, and nothing else is available.
        guard case .failure(.noUsableKeySource(let present)) = await resolution(resolver, jws) else {
            Issue.record("expected noUsableKeySource")
            return
        }
        #expect(present == ["jku"])

        resolver.jwkSetProvider = provider
        guard case .failure(.jwkSetURLNotAllowed) = await resolution(resolver, jws) else {
            Issue.record("a URL not on the allow-list was used")
            return
        }
        #expect(provider.requests.isEmpty)

        resolver.allowedJWKSetURLs = [jwksURL]
        #expect(await resolvedCount(resolver, jws) == 1)
        #expect(provider.requests == [jwksURL])
        let verified = try await jws.verify(resolving: resolver)
        #expect(verified.payload == Data("payload".utf8))

        // Exact match: a different path on the same host is not allowed.
        var otherPath = header
        otherPath.jwkSetURL = "https://issuer.example/jwks.json"
        guard case .failure(.jwkSetURLNotAllowed) = await resolution(resolver, try await token(header: otherPath))
        else {
            Issue.record("a different path was allowed")
            return
        }

        var http = header
        http.jwkSetURL = "http://issuer.example/.well-known/jwks.json"
        resolver.allowedJWKSetURLs.insert(URL(string: http.jwkSetURL!)!)
        guard case .failure(.jwkSetURLNotAllowed) = await resolution(resolver, try await token(header: http)) else {
            Issue.record("an http URL was allowed")
            return
        }

        var unavailable = header
        unavailable.jwkSetURL = "https://issuer.example/missing"
        resolver.allowedJWKSetURLs.insert(URL(string: unavailable.jwkSetURL!)!)
        guard case .failure(.jwkSetUnavailable) = await resolution(resolver, try await token(header: unavailable))
        else {
            Issue.record("a provider failure was not reported")
            return
        }

        // The algorithm list restricts what the fetched keys may be used for.
        let edOnly = HeaderKeyResolver(algorithms: [EdDSA.self], jwkSetProvider: provider, allowedJWKSetURLs: [jwksURL])
        guard case .failure(.noUsableKeySource) = await resolution(edOnly, jws) else {
            Issue.record("a P-256 key was offered for EdDSA")
            return
        }
    }

    // MARK: x5c and jwk

    @Test("x5c is used only with a validator; thumbprints and an embedded jwk must agree with it")
    func certificateChain() async throws {
        let leafDER = Data([0x30, 0x03, 0x02, 0x01, 0x01])
        var header = JWSHeaderParameters<EmptyHeaderParameters>()
        header.x509CertificateChain = [leafDER.base64EncodedString()]
        let jws = try await token(header: header)

        var resolver = HeaderKeyResolver(algorithms: [ES256.self])
        guard case .failure(.noUsableKeySource(let present)) = await resolution(resolver, jws) else {
            Issue.record("expected noUsableKeySource")
            return
        }
        #expect(present == ["x5c"])

        resolver.certificateChainValidator = StubValidator(result: publicJWK)
        #expect(await resolvedCount(resolver, jws) == 1)
        _ = try await jws.verify(resolving: resolver)

        resolver.certificateChainValidator = StubValidator(result: nil)
        guard case .failure(.certificateChainRejected) = await resolution(resolver, jws) else {
            Issue.record("a rejected chain was used")
            return
        }
        resolver.certificateChainValidator = StubValidator(result: publicJWK)

        var withThumbprints = header
        withThumbprints.x509CertificateSHA1Thumbprint = Base64URL.encode(CertificateDigest.sha1(leafDER))
        withThumbprints.x509CertificateSHA256Thumbprint = Base64URL.encode(CertificateDigest.sha256(leafDER))
        #expect(await resolvedCount(resolver, try await token(header: withThumbprints)) == 1)

        var wrongSHA1 = withThumbprints
        wrongSHA1.x509CertificateSHA1Thumbprint = Base64URL.encode(Data(count: 20))
        guard
            case .failure(.certificateThumbprintMismatch("x5t")) = await resolution(
                resolver,
                try await token(header: wrongSHA1)
            )
        else {
            Issue.record("a wrong x5t was accepted")
            return
        }
        var wrongSHA256 = withThumbprints
        wrongSHA256.x509CertificateSHA256Thumbprint = Base64URL.encode(Data(count: 32))
        guard
            case .failure(.certificateThumbprintMismatch("x5t#S256")) = await resolution(
                resolver,
                try await token(header: wrongSHA256)
            )
        else {
            Issue.record("a wrong x5t#S256 was accepted")
            return
        }

        var malformed = header
        malformed.x509CertificateChain = ["not base64!"]
        guard case .failure(.certificateChainMalformed) = await resolution(resolver, try await token(header: malformed))
        else {
            Issue.record("malformed x5c was accepted")
            return
        }
        malformed.x509CertificateChain = []
        guard case .failure(.certificateChainMalformed) = await resolution(resolver, try await token(header: malformed))
        else {
            Issue.record("an empty x5c was accepted")
            return
        }

        // jwk alongside x5c must be the same key.
        var matching = header
        matching.jwk = publicJWK
        #expect(await resolvedCount(resolver, try await token(header: matching)) == 1)
        var mismatching = header
        mismatching.jwk = JWK(.p256((try ECPrivateKey<P256Curve>()).publicKey))
        guard
            case .failure(.embeddedKeyDoesNotMatchCertificate) = await resolution(
                resolver,
                try await token(header: mismatching)
            )
        else {
            Issue.record("a jwk different from the certificate's key was accepted")
            return
        }
    }

    @Test("an embedded jwk is used only when explicitly allowed")
    func embeddedKey() async throws {
        var header = JWSHeaderParameters<EmptyHeaderParameters>()
        header.jwk = publicJWK
        let jws = try await token(header: header)
        var resolver = HeaderKeyResolver(algorithms: [ES256.self])
        guard case .failure(.noUsableKeySource(let present)) = await resolution(resolver, jws) else {
            Issue.record("an embedded key was used without permission")
            return
        }
        #expect(present == ["jwk"])
        resolver.allowsEmbeddedKey = true
        #expect(await resolvedCount(resolver, jws) == 1)
        _ = try await jws.verify(resolving: resolver)

        // The embedded key is still subject to the algorithm list and to the signature check.
        let other = try ECDSASigner(privateKey: try ECPrivateKey<P256Curve>(), keyID: "k1")
        let forged = try Plain.Unverified(
            compact: try await Plain.sign(Data("x".utf8), with: other, header: header).compactSerialization()
        )
        await #expect(throws: JWSError.self) { try await forged.verify(resolving: resolver) }
    }

    @Test("a header without any key source, and a JWT, report resolution failure as a JWS error")
    func noSource() async throws {
        let jws = try await token(header: JWSHeaderParameters())
        let resolver = HeaderKeyResolver(algorithms: [ES256.self], allowsEmbeddedKey: true)
        do {
            _ = try await jws.verify(resolving: resolver)
            Issue.record("verified with no key")
        } catch {
            guard case .keyResolutionFailed(.noUsableKeySource(let present)) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(present.isEmpty)
            #expect(error.description.contains("no key source"))
        }
    }

    // MARK: Caching and fetching

    @Test("the caching provider fetches once per URL until the entry expires, and shares in-flight fetches")
    func caching() async throws {
        let upstream = MemoryJWKSetProvider([jwksURL: JWKSet(keys: [publicJWK])])
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Clock(now)
        let cache = CachingJWKSetProvider(upstream, timeToLive: 60, clock: { clock.now })

        _ = try await cache.jwkSet(at: jwksURL)
        _ = try await cache.jwkSet(at: jwksURL)
        #expect(upstream.requests.count == 1)
        clock.now = now.addingTimeInterval(59)
        _ = try await cache.jwkSet(at: jwksURL)
        #expect(upstream.requests.count == 1)
        clock.now = now.addingTimeInterval(61)
        _ = try await cache.jwkSet(at: jwksURL)
        #expect(upstream.requests.count == 2)
        await cache.invalidate()
        _ = try await cache.jwkSet(at: jwksURL)
        #expect(upstream.requests.count == 3)

        let fresh = CachingJWKSetProvider(upstream, timeToLive: 60, clock: { clock.now })
        let url = jwksURL
        async let first = fresh.jwkSet(at: url)
        async let second = fresh.jwkSet(at: url)
        _ = try await (first, second)
        #expect(upstream.requests.count == 4)
    }

    @Test("the URLSession provider refuses non-HTTPS URLs before any request")
    func urlSessionProviderPolicy() async {
        let provider = URLSessionJWKSetProvider()
        do {
            _ = try await provider.jwkSet(at: URL(string: "http://issuer.example/jwks")!)
            Issue.record("an http URL was fetched")
        } catch {
            guard case JWKSetFetchError.notHTTPS = error else {
                Issue.record("unexpected error \(error)")
                return
            }
        }
    }

    @Test("every error has a message naming what was wrong")
    func descriptions() {
        struct Underlying: Error {}
        let errors: [(KeyResolutionError, String)] = [
            (.noUsableKeySource(headerParameters: ["jku"]), "jku"),
            (.jwkSetURLNotAllowed("https://x"), "https://x"),
            (.jwkSetURLInvalid("::"), "::"),
            (.jwkSetUnavailable(url: "https://y", underlying: Underlying()), "https://y"),
            (.certificateChainRejected(underlying: Underlying()), "rejected"),
            (.certificateChainMalformed(reason: "empty"), "empty"),
            (.certificateThumbprintMismatch(parameter: "x5t"), "x5t"),
            (.embeddedKeyDoesNotMatchCertificate, "different keys"),
            (.keyNotUsable(.symmetricKeyInPublicKey), "oct"),
        ]
        for (error, fragment) in errors {
            #expect(error.description.contains(fragment), "\(error.description)")
        }
        #expect(JWKSetFetchError.unexpectedStatus(URL(string: "https://x")!, status: 503).description.contains("503"))
        #expect(
            JWKSetFetchError.responseTooLarge(URL(string: "https://x")!, byteCount: 9, maximum: 8).description.contains(
                "9"
            )
        )
    }
}

/// A settable clock for the cache test.
private final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(_ value: Date) {
        self.value = value
    }

    var now: Date {
        get {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            value = newValue
        }
    }
}

#if canImport(Security)
    @Suite("SecTrust certificate validation")
    struct SecTrustValidatorTests {
        typealias Plain = JWS<EmptyHeaderParameters>

        private func der(_ hex: String) throws -> Data {
            try Data(hex: hex)
        }

        @Test("a leaf under the trusted CA yields its key, for EC and RSA, with or without the CA in the chain")
        func validChains() async throws {
            let fixture = try CertificateFixture.load()
            let validator = try SecTrustCertificateChainValidator(anchors: [try der(fixture.root)])
            for leaf in [fixture.ecLeaf, fixture.rsaLeaf] {
                let expected = try JWK(json: Data(leaf.publicJwk.utf8))
                #expect(try await validator.validate(chain: [try der(leaf.der)]) == expected)
                #expect(try await validator.validate(chain: [try der(leaf.der), try der(fixture.root)]) == expected)
            }
        }

        @Test("chains to another CA, expired leaves, and unreadable data are refused")
        func invalidChains() async throws {
            let fixture = try CertificateFixture.load()
            let validator = try SecTrustCertificateChainValidator(anchors: [try der(fixture.root)])
            await #expect(throws: CertificateValidationError.self) {
                try await validator.validate(chain: [try der(fixture.leafUnderOtherRoot.der)])
            }
            await #expect(throws: CertificateValidationError.self) {
                try await validator.validate(chain: [
                    try der(fixture.leafUnderOtherRoot.der), try der(fixture.otherRoot),
                ])
            }
            await #expect(throws: CertificateValidationError.self) {
                try await validator.validate(chain: [try der(fixture.expiredLeaf.der)])
            }
            // The same expired leaf is fine when the clock is inside its validity period.
            let backThen = try SecTrustCertificateChainValidator(
                anchors: [try der(fixture.root)],
                clock: { Date(timeIntervalSince1970: 1_593_000_000) }
            )
            _ = try await backThen.validate(chain: [try der(fixture.expiredLeaf.der)])

            await #expect(throws: CertificateValidationError.self) {
                try await validator.validate(chain: [Data("garbage".utf8)])
            }
            await #expect(throws: CertificateValidationError.self) {
                try await validator.validate(chain: [])
            }
            // Positive control for the anchor itself: the other CA trusts its own leaf.
            let other = try SecTrustCertificateChainValidator(anchors: [try der(fixture.otherRoot)])
            _ = try await other.validate(chain: [try der(fixture.leafUnderOtherRoot.der)])

            #expect(throws: CertificateValidationError.self) { try SecTrustCertificateChainValidator(anchors: []) }
            #expect(throws: CertificateValidationError.self) {
                try SecTrustCertificateChainValidator(anchors: [Data("garbage".utf8)])
            }
        }

        @Test("a JWS with x5c and x5t#S256 verifies end to end against the CA, and not against another")
        func endToEnd() async throws {
            let fixture = try CertificateFixture.load()
            guard case .p256(let privateKey) = try PrivateJWK(json: Data(fixture.ecLeaf.privateJwk.utf8)).key else {
                Issue.record("leaf key is not P-256")
                return
            }
            let signer = try ECDSASigner(privateKey: privateKey)
            var header = JWSHeaderParameters<EmptyHeaderParameters>()
            header.x509CertificateChain = [try der(fixture.ecLeaf.der).base64EncodedString()]
            header.x509CertificateSHA256Thumbprint = fixture.ecLeaf.sha256
            header.x509CertificateSHA1Thumbprint = fixture.ecLeaf.sha1
            let jws = try Plain.Unverified(
                compact: try await Plain.sign(Data("signed".utf8), with: signer, header: header).compactSerialization()
            )

            let trusted = HeaderKeyResolver(
                algorithms: [ES256.self],
                certificateChainValidator: try SecTrustCertificateChainValidator(anchors: [try der(fixture.root)])
            )
            #expect(try await jws.verify(resolving: trusted).payload == Data("signed".utf8))

            let untrusting = HeaderKeyResolver(
                algorithms: [ES256.self],
                certificateChainValidator: try SecTrustCertificateChainValidator(anchors: [try der(fixture.otherRoot)])
            )
            await #expect(throws: JWSError.self) { try await jws.verify(resolving: untrusting) }

            // The certificate is trusted, but the token was not signed by its key.
            let impostor = try ECDSASigner(privateKey: try ECPrivateKey<P256Curve>())
            let forged = try Plain.Unverified(
                compact: try await Plain.sign(Data("signed".utf8), with: impostor, header: header)
                    .compactSerialization()
            )
            await #expect(throws: JWSError.self) { try await forged.verify(resolving: trusted) }
        }
    }
#endif
