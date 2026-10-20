import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWS

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

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
        try CertificateFixture(fixture: "certificates")
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

/// Serves canned responses by URL and records every URL requested.
///
/// - ``directURL``: an empty JWK Set.
/// - ``movedURL``: an empty JWK Set whose response names ``elsewhereURL``, which is how a
///   followed redirect looks to the caller.
/// - ``redirectingURL``: a 302 to ``redirectTargetURL``, which serves an empty JWK Set.
/// - ``declaredLargeURL``: a small body whose `Content-Length` claims 4096 bytes.
/// - ``largeURL``: 3000 bytes with no `Content-Length`.
private final class StubJWKSetProtocol: URLProtocol {
    static let directURL = URL(string: "https://issuer.example/direct")!
    static let movedURL = URL(string: "https://issuer.example/moved")!
    static let elsewhereURL = URL(string: "https://elsewhere.example/jwks")!
    static let redirectingURL = URL(string: "https://issuer.example/redirecting")!
    static let redirectTargetURL = URL(string: "https://target.example/jwks")!
    static let declaredLargeURL = URL(string: "https://issuer.example/declared-large")!
    static let largeURL = URL(string: "https://issuer.example/large")!
    static let emptySet = Data(#"{"keys":[]}"#.utf8)

    private static let lock = NSLock()
    nonisolated(unsafe) private static var requested: [URL] = []

    static var requestedURLs: [URL] {
        lock.withLock { requested }
    }

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubJWKSetProtocol.self]
        return URLSession(configuration: configuration)
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    private func respond(from url: URL, status: Int = 200, headers: [String: String] = [:], body: Data) {
        guard
            let client,
            let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)
        else {
            return
        }
        client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: body)
        client.urlProtocolDidFinishLoading(self)
    }

    override func startLoading() {
        guard let url = request.url, let client else {
            return
        }
        Self.lock.withLock { Self.requested.append(url) }
        switch url {
        case Self.movedURL:
            respond(from: Self.elsewhereURL, body: Self.emptySet)
        case Self.redirectingURL:
            guard
                let redirect = HTTPURLResponse(
                    url: url,
                    statusCode: 302,
                    httpVersion: "HTTP/1.1",
                    headerFields: ["Location": Self.redirectTargetURL.absoluteString]
                )
            else {
                return
            }
            client.urlProtocol(
                self,
                wasRedirectedTo: URLRequest(url: Self.redirectTargetURL),
                redirectResponse: redirect
            )
            respond(from: url, status: 302, body: Data())
        case Self.declaredLargeURL:
            respond(from: url, headers: ["Content-Length": "4096"], body: Self.emptySet)
        case Self.largeURL:
            respond(from: url, body: Data(repeating: 0x20, count: 3000))
        default:
            respond(from: url, body: Self.emptySet)
        }
    }

    override func stopLoading() {}
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
    private let jwksURL = URL(string: "https://issuer.example/.well-known/jwks.json")!
    private let signingKey: ECPrivateKey<P256Curve>
    private let signer: ECDSASigner<P256Curve>
    private let publicJWK: JWK

    init() throws {
        signingKey = try ECPrivateKey<P256Curve>()
        signer = try ECDSASigner(privateKey: signingKey, keyID: "k1")
        publicJWK = JWK(.p256(signingKey.publicKey), metadata: JWKMetadata(keyID: "k1"))
    }

    private func token(header: JWSHeaderParameters<EmptyHeaderParameters>) async throws -> SimpleJWS.Unverified {
        let signed = try await SimpleJWS.sign(Data("payload".utf8), with: signer, header: header)
        return try SimpleJWS.Unverified(compact: try signed.compactSerialization())
    }

    private func caseName(_ error: KeyResolutionError) -> String {
        Mirror(reflecting: error).children.first?.label ?? "\(error)"
    }

    /// The number of verifiers resolved, or `nil` on failure.
    private func resolvedCount(_ resolver: HeaderKeyResolver, _ jws: SimpleJWS.Unverified) async -> Int? {
        guard case .success(let count) = await resolution(resolver, jws) else {
            return nil
        }
        return count
    }

    private func resolution(_ resolver: HeaderKeyResolver, _ jws: SimpleJWS.Unverified) async -> Result<
        Int, KeyResolutionError
    > {
        do {
            return .success(try await resolver.verificationKeys(for: jws.header).verifiers.count)
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
        withThumbprints.x509CertificateSHA1Thumbprint = Base64URL.encode(CertificateDigest.sha1.digest(of: leafDER))
        withThumbprints.x509CertificateSHA256Thumbprint = Base64URL.encode(CertificateDigest.sha256.digest(of: leafDER))
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
        let forged = try SimpleJWS.Unverified(
            compact: try await SimpleJWS.sign(Data("x".utf8), with: other, header: header).compactSerialization()
        )
        await #expect(throws: JWSError.self) { try await forged.verify(resolving: resolver) }
    }

    @Test("with several signatures, each is verified with the keys its own header names")
    func perSignatureResolution() async throws {
        let otherKey = try ECPrivateKey<P256Curve>()
        let otherSigner = try ECDSASigner(privateKey: otherKey, keyID: "k2")
        let signed = try await SimpleJWS.sign(
            Data("payload".utf8),
            with: signer,
            header: JWSHeaderParameters(jwk: publicJWK)
        )
        .adding(
            signatureWith: otherSigner,
            header: JWSHeaderParameters(jwk: JWK(.p256(otherKey.publicKey), metadata: JWKMetadata(keyID: "k2")))
        )
        let jws = try SimpleJWS.Unverified(json: try signed.generalJSONSerialization())
        let resolver = HeaderKeyResolver(algorithms: [ES256.self], allowsEmbeddedKey: true)
        let verified = try await jws.verify(resolving: resolver)
        #expect(verified.verifiedHeaders.map(\.keyID) == ["k1", "k2"])

        // A signature whose own header names the wrong key fails on its own; the other still verifies.
        let swapped = try await SimpleJWS.sign(
            Data("payload".utf8),
            with: signer,
            header: JWSHeaderParameters(jwk: publicJWK)
        )
        .adding(signatureWith: otherSigner, header: JWSHeaderParameters(jwk: publicJWK))
        let partly = try await SimpleJWS.Unverified(json: try swapped.generalJSONSerialization()).verify(
            resolving: resolver
        )
        #expect(partly.verifiedHeaders.map(\.keyID) == ["k1"])
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

    @Test("the URLSession provider uses a response only when it comes from the URL requested")
    func urlSessionProviderResponseURL() async throws {
        let provider = URLSessionJWKSetProvider(session: StubJWKSetProtocol.session())
        let direct = try await provider.jwkSet(at: StubJWKSetProtocol.directURL)
        #expect(direct.keys.isEmpty)
        #expect(
            await fetchError(provider, StubJWKSetProtocol.movedURL)
                == .respondedFromDifferentURL(StubJWKSetProtocol.movedURL, actual: StubJWKSetProtocol.elsewhereURL)
        )
    }

    /// The error a fetch failed with, or `nil` if it succeeded.
    private func fetchError(_ provider: URLSessionJWKSetProvider, _ url: URL) async -> JWKSetFetchError? {
        do {
            _ = try await provider.jwkSet(at: url)
            return nil
        } catch let error as JWKSetFetchError {
            return error
        } catch {
            Issue.record("unexpected error \(error)")
            return nil
        }
    }

    @Test("the URLSession provider refuses a response above its size limit")
    func urlSessionProviderSizeLimit() async {
        let provider = URLSessionJWKSetProvider(session: StubJWKSetProtocol.session(), maximumByteCount: 1024)
        let url = StubJWKSetProtocol.largeURL
        #expect(await fetchError(provider, url) == .responseTooLarge(url, maximum: 1024))
        // The declared length alone is enough to refuse; the body here is small.
        let declared = StubJWKSetProtocol.declaredLargeURL
        #expect(await fetchError(provider, declared) == .responseTooLarge(declared, maximum: 1024))
    }

    #if !canImport(FoundationNetworking)
        @Test("on Apple platforms the URLSession provider does not follow redirects")
        func urlSessionProviderRedirect() async {
            let provider = URLSessionJWKSetProvider(session: StubJWKSetProtocol.session())
            let url = StubJWKSetProtocol.redirectingURL
            #expect(await fetchError(provider, url) == .unexpectedStatus(url, status: 302))
            #expect(!StubJWKSetProtocol.requestedURLs.contains(StubJWKSetProtocol.redirectTargetURL))
        }
    #endif

    @Test("verification keys can be built from a JWK Set URL known out of band")
    func keysFromConfiguredURL() async throws {
        let provider = MemoryJWKSetProvider([jwksURL: JWKSet(keys: [publicJWK])])
        let keys = try await VerificationKeys(jwksAt: jwksURL, provider: provider, allowing: [ES256.self, EdDSA.self])
        #expect(keys.algorithms == ["ES256"])
        let jws = try await token(header: JWSHeaderParameters(keyID: "k1"))
        #expect(try await jws.verify(with: keys).payload == Data("payload".utf8))

        let missing = URL(string: "https://issuer.example/missing")!
        do {
            _ = try await VerificationKeys(jwksAt: missing, provider: provider, allowing: [ES256.self])
            Issue.record("a missing JWK Set produced keys")
        } catch {
            #expect(
                error
                    == .jwkSetUnavailable(
                        url: missing.absoluteString,
                        underlying: UnderlyingError(MemoryJWKSetProvider.Missing())
                    )
            )
        }
    }

    @Test("every error has a message naming what was wrong")
    func descriptions() {
        struct Underlying: Error {}
        let errors: [(KeyResolutionError, String)] = [
            (.noUsableKeySource(headerParameters: ["jku"]), "jku"),
            (.jwkSetURLNotAllowed("https://x"), "https://x"),
            (.jwkSetURLInvalid("::"), "::"),
            (.jwkSetUnavailable(url: "https://y", underlying: UnderlyingError(Underlying())), "https://y"),
            (.certificateChainRejected(underlying: UnderlyingError(Underlying())), "rejected"),
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
            JWKSetFetchError.responseTooLarge(URL(string: "https://x")!, maximum: 8).description.contains("8 bytes")
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
            let jws = try SimpleJWS.Unverified(
                compact: try await SimpleJWS.sign(Data("signed".utf8), with: signer, header: header)
                    .compactSerialization()
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
            let forged = try SimpleJWS.Unverified(
                compact: try await SimpleJWS.sign(Data("signed".utf8), with: impostor, header: header)
                    .compactSerialization()
            )
            await #expect(throws: JWSError.self) { try await forged.verify(resolving: trusted) }
        }
    }
#endif
