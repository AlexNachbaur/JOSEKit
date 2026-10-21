import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWS

@Suite("JWS")
struct JWSTests {

    private struct Keys {
        let signer: ECDSASigner<P256Curve>
        let verification: VerificationKeys

        init(keyID: KeyID? = nil) throws {
            let privateKey = try ECPrivateKey<P256Curve>()
            signer = try ECDSASigner(privateKey: privateKey, keyID: keyID)
            verification = VerificationKeys([
                AnyVerifier(try ECDSAVerifier(publicKey: privateKey.publicKey, keyID: keyID))
            ])
        }
    }

    private func encoded(_ json: String) -> String {
        String(base64URLEncoding: Data(json.utf8))
    }

    /// Signs arbitrary header text, so that tests can present headers this package would not write.
    private func token(headerJSON: String, payload: String = "payload", signer: ECDSASigner<P256Curve>) async throws
        -> String
    {
        let input = encoded(headerJSON) + "." + String(base64URLEncoding: Data(payload.utf8))
        let signature = try await signer.sign(Data(input.utf8))
        return input + "." + String(base64URLEncoding: signature.rawRepresentation)
    }

    @Test("sign and verify round-trips in all three serializations")
    func roundTrip() async throws {
        let keys = try Keys(keyID: "k1")
        let payload = Data("hello".utf8)
        let signed = try await SimpleJWS.Signed(
            signing: payload,
            with: keys.signer,
            header: JWSHeaderParameters(type: "example")
        )

        #expect(signed.header.algorithm == "ES256")
        #expect(signed.header.keyID == "k1")
        #expect(signed.header.type == "application/EXAMPLE")
        #expect(signed.payload == payload)

        let compact = try signed.compactSerialization()
        #expect(compact.split(separator: ".").count == 3)
        #expect(try await SimpleJWS.Unverified(compact: compact).verify(with: keys.verification).payload == payload)

        let flattened = try SimpleJWS.Unverified(json: try signed.flattenedJSONSerialization())
        #expect(try await flattened.verify(with: keys.verification).payload == payload)

        let general = try SimpleJWS.Unverified(json: try signed.generalJSONSerialization())
        #expect(try await general.verify(with: keys.verification).payload == payload)
    }

    @Test("the protected header is written with sorted members and alg from the signer")
    func protectedHeaderBytes() async throws {
        let keys = try Keys(keyID: "k1")
        let signed = try await SimpleJWS.Signed(
            signing: Data(),
            with: keys.signer,
            header: JWSHeaderParameters(type: "JWT")
        )
        let headerSegment = String(try signed.compactSerialization().split(separator: ".")[0])
        let json = String(decoding: try Data(base64URLEncoded: headerSegment), as: UTF8.self)
        #expect(json == #"{"alg":"ES256","kid":"k1","typ":"JWT"}"#)
    }

    @Test("an explicit kid in the header wins over the signer's, and no kid is written when neither has one")
    func keyIDPrecedence() async throws {
        let withKeyID = try Keys(keyID: "from-signer")
        let explicit = try await SimpleJWS.Signed(
            signing: Data(),
            with: withKeyID.signer,
            header: JWSHeaderParameters(keyID: "explicit")
        )
        #expect(explicit.header.keyID == "explicit")

        let without = try Keys()
        let none = try await SimpleJWS.Signed(signing: Data(), with: without.signer)
        #expect(none.header.keyID == nil)
        #expect(none.header.rawParameters["kid"] == nil)
    }

    @Test("verification is over the bytes received, not a re-encoding of the header")
    func verifiesReceivedBytes() async throws {
        let keys = try Keys()
        // Whitespace and member order that this package would never produce.
        let unusual = try await token(headerJSON: "{ \"typ\" : \"x\",\n\t\"alg\" : \"ES256\" }", signer: keys.signer)
        let verified = try await SimpleJWS.Unverified(compact: unusual).verify(with: keys.verification)
        #expect(verified.payload == Data("payload".utf8))
        #expect(verified.header.type == "x")
    }

    @Test("the payload of an unverified JWS is only reachable under a name that says so")
    func unverifiedPayload() async throws {
        let keys = try Keys()
        let signed = try await SimpleJWS.Signed(signing: Data("secret?".utf8), with: keys.signer)
        let unverified = try SimpleJWS.Unverified(compact: try signed.compactSerialization())
        #expect(try unverified.unverifiedPayload == Data("secret?".utf8))
        #expect(unverified.header.algorithm == "ES256")
        let detached = try SimpleJWS.Unverified(json: try signed.flattenedJSONSerialization(detached: true))
        #expect(try detached.unverifiedPayload == nil)
    }

    @Test("a custom header type round-trips, and its critical parameters are listed in crit")
    func customHeader() async throws {
        let keys = try Keys()
        let header = JWSHeaderParameters(custom: ExampleHeader(level: 3, must: "understood"))
        let signed = try await JWS<ExampleHeader>.Signed(signing: Data("p".utf8), with: keys.signer, header: header)
        #expect(signed.header.critical == ["urn:example:must"])

        let compact = try signed.compactSerialization()
        let verified = try await JWS<ExampleHeader>.Unverified(compact: compact).verify(with: keys.verification)
        #expect(verified.header.custom == ExampleHeader(level: 3, must: "understood"))
        #expect(verified.header.critical == ["urn:example:must"])

        // A reader that does not know the critical extension must refuse the token.
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(compact: compact) }
                == "unsupportedCriticalParameter"
        )

        // Without the critical parameter present, nothing is listed and anyone can read it.
        let ordinary = try await JWS<ExampleHeader>.Signed(
            signing: Data(),
            with: keys.signer,
            header: JWSHeaderParameters(custom: ExampleHeader(level: 3, must: nil))
        )
        #expect(ordinary.header.critical.isEmpty)
        #expect(ordinary.header.rawParameters["crit"] == nil)
        _ = try await SimpleJWS.Unverified(compact: try ordinary.compactSerialization()).verify(with: keys.verification)
    }

    @Test("the compact form is split on the period byte, not on grapheme clusters")
    func compactSplitOnBytes() async {
        // A combining mark after the second period joins it into one grapheme cluster. Split by
        // character, the token has two segments; split by byte, three.
        let joined = "eyJhbGciOiJFUzI1NiJ9.\u{301}AA.AA"
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(compact: joined) }
                == "invalidBase64URL"
        )
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(compact: "a.b") }
                == "invalidCompactSerialization"
        )
    }

    @Test("a custom header type cannot set alg or any other parameter this package owns")
    func customHeaderCannotOverride() async throws {
        struct Hostile: HeaderParameters {
            var values: [String: String]

            init(_ values: [String: String]) {
                self.values = values
            }

            init(from decoder: any Decoder) throws {
                values = [:]
            }

            func encode(to encoder: any Encoder) throws {
                var container = encoder.singleValueContainer()
                try container.encode(values)
            }
        }
        let keys = try Keys()
        _ = try await JWS<Hostile>.Signed(
            signing: Data(),
            with: keys.signer,
            header: JWSHeaderParameters(custom: Hostile(["x": "y"]))
        )
        for name in ["alg", "kid", "typ", "cty", "crit", "jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256", "b64"] {
            do {
                _ = try await JWS<Hostile>.Signed(
                    signing: Data(),
                    with: keys.signer,
                    header: JWSHeaderParameters(custom: Hostile([name: "none"]))
                )
                Issue.record("custom header was allowed to set \(name)")
            } catch {
                #expect(caseName(error) == "customParameterCollision", "\(name)")
            }
        }

        struct NotAnObject: HeaderParameters {
            init() {}
            init(from decoder: any Decoder) throws {}
            func encode(to encoder: any Encoder) throws {
                var container = encoder.singleValueContainer()
                try container.encode("text")
            }
        }
        do {
            _ = try await JWS<NotAnObject>.Signed(
                signing: Data(),
                with: keys.signer,
                header: JWSHeaderParameters(custom: NotAnObject())
            )
            Issue.record("a non-object custom header was accepted")
        } catch {
            #expect(caseName(error) == "customParametersNotObject")
        }
    }

    @Test("registered header parameters are written and read back, including an embedded public JWK")
    func registeredParameters() async throws {
        let keys = try Keys()
        let header = JWSHeaderParameters(
            type: "t",
            contentType: "c",
            jwk: JWK(.p256(keys.signer.publicKey)),
            jwkSetURL: "https://example.com/jwks",
            x509URL: "https://example.com/cert",
            x509CertificateChain: ["MIIB", "MIIC"],
            x509CertificateSHA1Thumbprint: "sha1",
            x509CertificateSHA256Thumbprint: "sha256"
        )
        let signed = try await SimpleJWS.Signed(signing: Data(), with: keys.signer, header: header)
        let read = try await SimpleJWS.Unverified(compact: try signed.compactSerialization()).verify(
            with: keys.verification
        )
        let parameters = read.header.parameters
        #expect(parameters.type == "t")
        #expect(parameters.contentType == "c")
        #expect(parameters.jwk == JWK(.p256(keys.signer.publicKey)))
        #expect(parameters.jwkSetURL == "https://example.com/jwks")
        #expect(parameters.x509URL == "https://example.com/cert")
        #expect(parameters.x509CertificateChain == ["MIIB", "MIIC"])
        #expect(parameters.x509CertificateSHA1Thumbprint == "sha1")
        #expect(parameters.x509CertificateSHA256Thumbprint == "sha256")
    }

    @Test("a jwk header parameter carrying private or symmetric material is refused")
    func jwkHeaderMustBePublic() async throws {
        let keys = try Keys()
        let privateJSON = String(
            decoding: try PrivateJWK(.p256(try ECPrivateKey<P256Curve>())).jsonRepresentation(),
            as: UTF8.self
        )
        let withPrivate = try await token(headerJSON: #"{"alg":"ES256","jwk":\#(privateJSON)}"#, signer: keys.signer)
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(compact: withPrivate) }
                == "invalidJWKParameter"
        )
        let withSymmetric = try await token(
            headerJSON: #"{"alg":"ES256","jwk":{"kty":"oct","k":"AAAA"}}"#,
            signer: keys.signer
        )
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(compact: withSymmetric) }
                == "invalidJWKParameter"
        )
        let notObject = try await token(headerJSON: #"{"alg":"ES256","jwk":"x"}"#, signer: keys.signer)
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(compact: notObject) }
                == "headerParameterWrongType"
        )
    }

    @Test("header parameters of the wrong type are refused by name")
    func wrongParameterTypes() async throws {
        let keys = try Keys()
        for parameter in [
            #""kid":1"#, #""typ":true"#, #""cty":[]"#, #""jku":1"#, #""x5u":1"#, #""x5t":1"#, #""x5t#S256":1"#,
            #""x5c":"a""#, #""x5c":[1]"#,
        ] {
            let bad = try await token(headerJSON: #"{"alg":"ES256",\#(parameter)}"#, signer: keys.signer)
            #expect(
                await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(compact: bad) }
                    == "headerParameterWrongType",
                "\(parameter)"
            )
        }
        // Positive control: the same shape with valid types parses.
        let good = try await token(headerJSON: #"{"alg":"ES256","kid":"1","x5c":["a"]}"#, signer: keys.signer)
        _ = try SimpleJWS.Unverified(compact: good)
    }

    @Test("a custom header whose parameter has the wrong type is refused")
    func customDecodeFailure() async throws {
        let keys = try Keys()
        let bad = try await token(headerJSON: #"{"alg":"ES256","urn:example:level":"high"}"#, signer: keys.signer)
        #expect(
            await thrownCase { () async throws(JWSError) in try JWS<ExampleHeader>.Unverified(compact: bad) }
                == "invalidCustomParameters"
        )
        // The same token is fine for a reader that does not declare the parameter.
        _ = try await SimpleJWS.Unverified(compact: bad).verify(with: keys.verification)
    }

    // MARK: Detached and unencoded payloads

    @Test("a detached payload must be supplied exactly once")
    func detachedPayload() async throws {
        let keys = try Keys()
        let payload = Data("detached".utf8)
        let signed = try await SimpleJWS.Signed(signing: payload, with: keys.signer)

        let detached = try SimpleJWS.Unverified(compact: try signed.compactSerialization(detached: true))
        #expect(try await detached.verify(with: keys.verification, detachedPayload: payload).payload == payload)

        let attached = try SimpleJWS.Unverified(compact: try signed.compactSerialization())
        #expect(
            await thrownCase { () async throws(JWSError) in
                try await attached.verify(with: keys.verification, detachedPayload: payload)
            }
                == "payloadSuppliedTwice"
        )

        let detachedJSON = try SimpleJWS.Unverified(json: try signed.generalJSONSerialization(detached: true))
        #expect(
            await thrownCase { () async throws(JWSError) in try await detachedJSON.verify(with: keys.verification) }
                == "payloadMissing"
        )
        #expect(try await detachedJSON.verify(with: keys.verification, detachedPayload: payload).payload == payload)
    }

    @Test("an unencoded payload is signed as it is and marked critical")
    func unencodedPayload() async throws {
        let keys = try Keys()
        let payload = Data("$.02 paid to é".utf8)
        let signed = try await SimpleJWS.Signed(signing: payload, with: keys.signer, payloadEncoding: .unencoded)
        #expect(signed.header.critical == ["b64"])
        #expect(!signed.header.isPayloadBase64URLEncoded)
        #expect(signed.header.rawParameters["b64"] == false)

        // Non-ASCII and '.' cannot sit between the periods of the compact form.
        #expect(
            await thrownCase { () async throws(JWSError) in try signed.compactSerialization() }
                == "unencodedPayloadNotRepresentable"
        )
        let detached = try signed.compactSerialization(detached: true)
        #expect(detached.contains(".."))
        let verified = try await SimpleJWS.Unverified(compact: detached).verify(
            with: keys.verification,
            detachedPayload: payload
        )
        #expect(verified.payload == payload)

        let json = try SimpleJWS.Unverified(json: try signed.flattenedJSONSerialization())
        #expect(try await json.verify(with: keys.verification).payload == payload)

        // The signature really is over the raw payload, not its base64url form.
        let encodedInstead = try await SimpleJWS.Signed(signing: payload, with: keys.signer)
        let swapped =
            try signed.compactSerialization(detached: true).split(separator: ".", omittingEmptySubsequences: false)
        let forged = swapped[0] + "." + String(base64URLEncoding: payload) + "." + swapped[2]
        _ = encodedInstead
        #expect(
            await thrownCase { () async throws(JWSError) in
                try await SimpleJWS.Unverified(compact: String(forged)).verify(with: keys.verification)
            }
                == "signatureInvalid"
        )
    }

    @Test("an unencoded payload of printable ASCII without a period fits the compact form")
    func unencodedCompact() async throws {
        let keys = try Keys()
        let payload = Data("plain text payload".utf8)
        let signed = try await SimpleJWS.Signed(signing: payload, with: keys.signer, payloadEncoding: .unencoded)
        let compact = try signed.compactSerialization()
        #expect(compact.split(separator: ".", omittingEmptySubsequences: false)[1] == "plain text payload")
        #expect(try await SimpleJWS.Unverified(compact: compact).verify(with: keys.verification).payload == payload)

        for unrepresentable in ["a.b", "line\nbreak", "é"] {
            let other = try await SimpleJWS.Signed(
                signing: Data(unrepresentable.utf8),
                with: keys.signer,
                payloadEncoding: .unencoded
            )
            #expect(
                await thrownCase { () async throws(JWSError) in try other.compactSerialization() }
                    == "unencodedPayloadNotRepresentable"
            )
        }
    }

    @Test("an unencoded payload that is not UTF-8 can be signed and carried detached, but not written")
    func unencodedNotUTF8() async throws {
        let keys = try Keys()
        let binary = Data([0xFF, 0xFE, 0x00, 0x2E])
        let signed = try await SimpleJWS.Signed(signing: binary, with: keys.signer, payloadEncoding: .unencoded)
        #expect(
            await thrownCase { () async throws(JWSError) in try signed.compactSerialization() }
                == "unencodedPayloadNotRepresentable"
        )
        #expect(
            await thrownCase { () async throws(JWSError) in try signed.flattenedJSONSerialization() }
                == "unencodedPayloadNotRepresentable"
        )
        #expect(
            await thrownCase { () async throws(JWSError) in try signed.generalJSONSerialization() }
                == "unencodedPayloadNotRepresentable"
        )
        // Detached, the payload travels as bytes and is verified as bytes (RFC 7797 §5.2).
        let compact = try SimpleJWS.Unverified(compact: try signed.compactSerialization(detached: true))
        #expect(try await compact.verify(with: keys.verification, detachedPayload: binary).payload == binary)
        let json = try SimpleJWS.Unverified(json: try signed.flattenedJSONSerialization(detached: true))
        #expect(try await json.verify(with: keys.verification, detachedPayload: binary).payload == binary)
        #expect(
            await thrownCase { () async throws(JWSError) in
                try await json.verify(with: keys.verification, detachedPayload: binary + [0])
            } == "signatureInvalid"
        )
        // A byte order mark is content and survives.
        let withBOM = Data([0xEF, 0xBB, 0xBF]) + Data("x".utf8)
        let signedBOM = try await SimpleJWS.Signed(signing: withBOM, with: keys.signer, payloadEncoding: .unencoded)
        let carried = try SimpleJWS.Unverified(json: try signedBOM.flattenedJSONSerialization())
        #expect(try await carried.verify(with: keys.verification).payload == withBOM)
    }

    // MARK: Multiple signatures and the JSON serializations

    @Test("a JWS with several signatures serializes only in the general form")
    func multipleSignatures() async throws {
        let first = try Keys(keyID: "a")
        let edwards = try Ed25519PrivateKey()
        let second = try Ed25519Signer<JOSECore.Ed25519>(privateKey: edwards, keyID: "b")
        let secondVerifier = AnyVerifier(
            try Ed25519Verifier<JOSECore.Ed25519>(publicKey: edwards.publicKey, keyID: "b")
        )

        let payload = Data("two signers".utf8)
        let signed = try await SimpleJWS.Signed(signing: payload, with: first.signer)
            .adding(signatureWith: second, header: JWSHeaderParameters())
        #expect(signed.headers.map(\.algorithm) == ["ES256", "Ed25519"])

        #expect(
            await thrownCase { () async throws(JWSError) in try signed.compactSerialization() }
                == "singleSignatureRequired"
        )
        #expect(
            await thrownCase { () async throws(JWSError) in try signed.flattenedJSONSerialization() }
                == "singleSignatureRequired"
        )

        let jws = try SimpleJWS.Unverified(json: try signed.generalJSONSerialization())
        #expect(try await jws.verify(with: first.verification).header.keyID == "a")
        #expect(try await jws.verify(with: VerificationKeys([secondVerifier])).header.keyID == "b")
        let both = try await jws.verify(with: VerificationKeys(first.verification.verifiers + [secondVerifier]))
        #expect(both.verifiedHeaders.map(\.keyID) == ["a", "b"])
    }

    @Test("one unusable signature does not stop another from verifying")
    func unusableSignatureIsSkipped() async throws {
        let keys = try Keys()
        let signed = try await SimpleJWS.Signed(signing: Data("p".utf8), with: keys.signer)
        let parts = try signed.compactSerialization().split(separator: ".").map(String.init)
        let unknownCritical = encoded(#"{"alg":"ES256","crit":["x"],"x":1}"#)
        let json = """
            {"payload":"\(parts[1])","signatures":[
              {"protected":"\(unknownCritical)","signature":"AAAA"},
              {"protected":"\(parts[0])","signature":"\(parts[2])"}]}
            """
        let jws = try SimpleJWS.Unverified(json: Data(json.utf8))
        #expect(jws.headers.count == 1)
        #expect(try await jws.verify(with: keys.verification).payload == Data("p".utf8))

        // With only the unusable signature, the specific reason is reported.
        let alone = #"{"payload":"\#(parts[1])","signatures":[{"protected":"\#(unknownCritical)","signature":"AAAA"}]}"#
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(json: Data(alone.utf8)) }
                == "unsupportedCriticalParameter"
        )

        // With several signatures and none usable, the JWS is refused, with every reason.
        let noAlgorithm = encoded(#"{"kid":"k"}"#)
        let none = """
            {"payload":"\(parts[1])","signatures":[
              {"protected":"\(unknownCritical)","signature":"AAAA"},
              {"protected":"\(noAlgorithm)","signature":"AAAA"}]}
            """
        do {
            _ = try SimpleJWS.Unverified(json: Data(none.utf8))
            Issue.record("a JWS with no usable signature was accepted")
        } catch {
            #expect(
                error == .noUsableSignature(reasons: [.unsupportedCriticalParameter(name: "x"), .missingAlgorithm])
            )
        }
    }

    @Test("unprotected header parameters are read, flagged, and restricted")
    func unprotectedHeader() async throws {
        let keys = try Keys()
        let signed = try await SimpleJWS.Signed(signing: Data("p".utf8), with: keys.signer)
        let parts = try signed.compactSerialization().split(separator: ".").map(String.init)
        func flattened(protected: String?, header: String) -> Data {
            var members = [#""payload":"\#(parts[1])""#, #""signature":"\#(parts[2])""#, #""header":\#(header)"#]
            if let protected {
                members.append(#""protected":"\#(protected)""#)
            }
            return Data(("{" + members.joined(separator: ",") + "}").utf8)
        }

        let withExtra = try SimpleJWS.Unverified(
            json: flattened(protected: parts[0], header: #"{"kid":"u","typ":"t"}"#)
        )
        let verified = try await withExtra.verify(with: keys.verification)
        #expect(verified.header.unprotectedParameterNames == ["kid", "typ"])
        #expect(verified.header.keyID == "u")

        #expect(
            await thrownCase { () async throws(JWSError) in
                try SimpleJWS.Unverified(json: flattened(protected: parts[0], header: #"{"alg":"ES256"}"#))
            } == "headerParameterInBothHeaders"
        )
        let critProtected = encoded(#"{"alg":"ES256"}"#)
        #expect(
            await thrownCase { () async throws(JWSError) in
                try SimpleJWS.Unverified(
                    json: flattened(protected: critProtected, header: #"{"crit":["b64"],"b64":false}"#)
                )
            } == "headerParameterNotProtected"
        )
        #expect(
            await thrownCase { () async throws(JWSError) in
                try SimpleJWS.Unverified(
                    json: flattened(protected: encoded(#"{"alg":"ES256","crit":["b64"]}"#), header: #"{"b64":false}"#)
                )
            } == "headerParameterNotProtected"
        )

        // alg may come from the unprotected header alone (RFC 7515 §7.2.1), and is flagged as such.
        let unprotectedOnly = try SimpleJWS.Unverified(json: flattened(protected: nil, header: #"{"alg":"ES256"}"#))
        #expect(unprotectedOnly.header.unprotectedParameterNames == ["alg"])
        #expect(
            await thrownCase { () async throws(JWSError) in try await unprotectedOnly.verify(with: keys.verification) }
                == "signatureInvalid"
        )
    }

    @Test("a critical parameter must itself be protected, not only listed in a protected crit")
    func criticalParameterMustBeProtected() async throws {
        let keys = try Keys()
        let signed = try await SimpleJWS.Signed(signing: Data("p".utf8), with: keys.signer)
        let parts = try signed.compactSerialization().split(separator: ".").map(String.init)
        let protected = encoded(#"{"alg":"ES256","crit":["urn:example:must"]}"#)
        let json =
            #"{"payload":"\#(parts[1])","signature":"\#(parts[2])","protected":"\#(protected)","header":{"urn:example:must":"x"}}"#
        do {
            _ = try JWS<ExampleHeader>.Unverified(json: Data(json.utf8))
            Issue.record("an unprotected critical parameter was accepted")
        } catch {
            #expect(error == .headerParameterNotProtected(name: "urn:example:must"))
        }
    }

    @Test("crit itself must be protected, and may not list a name twice")
    func criticalRules() async throws {
        let keys = try Keys()
        let signed = try await SimpleJWS.Signed(signing: Data("p".utf8), with: keys.signer)
        let parts = try signed.compactSerialization().split(separator: ".").map(String.init)

        // The critical parameter is protected and understood; only `crit` sits in the unprotected header.
        let protected = encoded(#"{"alg":"ES256","urn:example:must":"x"}"#)
        let json =
            #"{"payload":"\#(parts[1])","signature":"\#(parts[2])","protected":"\#(protected)","header":{"crit":["urn:example:must"]}}"#
        do {
            _ = try JWS<ExampleHeader>.Unverified(json: Data(json.utf8))
            Issue.record("an unprotected crit was accepted")
        } catch {
            guard case .headerParameterNotProtected(let name) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(name == "crit")
        }
        // Positive control: the same header with crit protected parses.
        let allProtected = try await token(
            headerJSON: #"{"alg":"ES256","crit":["urn:example:must"],"urn:example:must":"x"}"#,
            signer: keys.signer
        )
        _ = try await JWS<ExampleHeader>.Unverified(compact: allProtected).verify(with: keys.verification)

        let repeated = try await token(
            headerJSON: #"{"alg":"ES256","crit":["urn:example:must","urn:example:must"],"urn:example:must":"x"}"#,
            signer: keys.signer
        )
        do {
            _ = try JWS<ExampleHeader>.Unverified(compact: repeated)
            Issue.record("a crit list with a repeated name was accepted")
        } catch {
            guard case .invalidCritical(let reason) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(reason.contains("more than once"))
        }
    }

    @Test("malformed JSON serializations report what is wrong")
    func invalidJSONSerialization() async {
        func parse(_ json: String) async -> String? {
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(json: Data(json.utf8)) }
        }
        #expect(await parse("[]") == "invalidJSONStructure")
        #expect(await parse(#"{"payload":"","payload":""}"#) == "invalidJSONStructure")
        #expect(await parse(#"{"payload":1,"signature":"AA"}"#) == "invalidJSONSerialization")
        #expect(await parse(#"{"payload":""}"#) == "invalidJSONSerialization")
        #expect(await parse(#"{"payload":"","signature":1}"#) == "invalidJSONSerialization")
        #expect(await parse(#"{"payload":"","signature":"AA","protected":1}"#) == "invalidJSONSerialization")
        #expect(await parse(#"{"payload":"","signature":"AA","header":"x"}"#) == "invalidJSONSerialization")
        #expect(await parse(#"{"payload":"","signatures":[]}"#) == "invalidJSONSerialization")
        #expect(await parse(#"{"payload":"","signatures":{}}"#) == "invalidJSONSerialization")
        #expect(await parse(#"{"payload":"","signatures":[1]}"#) == "invalidJSONSerialization")
        #expect(
            await parse(#"{"payload":"","signatures":[{"signature":"AA"}],"signature":"AA"}"#)
                == "invalidJSONSerialization"
        )
        #expect(await parse(#"{"payload":"","signature":"AA"}"#) == "missingAlgorithm")
        #expect(await parse(#"{"payload":"!","signature":"AA","header":{"alg":"ES256"}}"#) == "invalidBase64URL")
        #expect(await parse(#"{"payload":"","signature":"AA","header":{"alg":"ES256"}}"#) == nil)
    }

    @Test("signatures that disagree about b64 are refused")
    func inconsistentPayloadEncoding() async {
        let encodedHeader = encoded(#"{"alg":"ES256"}"#)
        let unencodedHeader = encoded(#"{"alg":"ES256","b64":false,"crit":["b64"]}"#)
        let json =
            #"{"payload":"AA","signatures":[{"protected":"\#(encodedHeader)","signature":"AA"},{"protected":"\#(unencodedHeader)","signature":"AA"}]}"#
        #expect(
            await thrownCase { () async throws(JWSError) in try SimpleJWS.Unverified(json: Data(json.utf8)) }
                == "inconsistentPayloadEncoding"
        )
    }

    // MARK: Key selection

    @Test("a signature is only tried against verifiers for its own algorithm and key ID")
    func keySelection() async throws {
        let signerKey = try ECPrivateKey<P256Curve>()
        let signer = try ECDSASigner(privateKey: signerKey, keyID: "right")
        let right = AnyVerifier(try ECDSAVerifier(publicKey: signerKey.publicKey, keyID: "right"))
        let unnamed = AnyVerifier(try ECDSAVerifier(publicKey: signerKey.publicKey))
        let sameKeyOtherID = AnyVerifier(try ECDSAVerifier(publicKey: signerKey.publicKey, keyID: "other"))
        let wrongKeyRightID = AnyVerifier(
            try ECDSAVerifier(publicKey: (try ECPrivateKey<P256Curve>()).publicKey, keyID: "right")
        )
        let hmac = AnyVerifier(try HMACVerifier<HS256>(key: SymmetricKeyMaterial(randomByteCount: 32)))

        let withKeyID = try SimpleJWS.Unverified(
            compact: try await SimpleJWS.Signed(signing: Data(), with: signer).compactSerialization()
        )
        func verify(_ jws: SimpleJWS.Unverified, _ verifiers: [AnyVerifier]) async -> String? {
            await thrownCase { () async throws(JWSError) in try await jws.verify(with: VerificationKeys(verifiers)) }
        }
        #expect(await verify(withKeyID, [right]) == nil)
        #expect(await verify(withKeyID, [unnamed]) == nil)
        #expect(await verify(withKeyID, [wrongKeyRightID, right]) == nil)
        // The right key under another ID is not tried: the token asked for a specific key.
        #expect(await verify(withKeyID, [sameKeyOtherID]) == "noVerifierForKeyID")
        #expect(await verify(withKeyID, [wrongKeyRightID]) == "signatureInvalid")
        #expect(await verify(withKeyID, [hmac]) == "noVerifierForAlgorithm")
        #expect(await verify(withKeyID, []) == "noVerifierForAlgorithm")

        // A token without a key ID is tried against every verifier for its algorithm.
        let anonymousSigner = try ECDSASigner(privateKey: signerKey)
        let withoutKeyID = try SimpleJWS.Unverified(
            compact: try await SimpleJWS.Signed(signing: Data(), with: anonymousSigner).compactSerialization()
        )
        #expect(await verify(withoutKeyID, [wrongKeyRightID, sameKeyOtherID]) == nil)
        #expect(await verify(withoutKeyID, [wrongKeyRightID]) == "signatureInvalid")
    }

    @Test("an RSA token cannot be re-labelled between RS256 and PS256, and is refused when only EC keys are offered")
    func rsaAlgorithmBinding() async throws {
        let key = try RSAPrivateKey()
        let signed = try await SimpleJWS.Signed(
            signing: Data("rsa".utf8),
            with: try RSASigner<RS256>(privateKey: key, keyID: "r")
        )
        let jws = try SimpleJWS.Unverified(compact: try signed.compactSerialization())
        let rs256 = AnyVerifier(try RSAVerifier<RS256>(publicKey: key.publicKey, keyID: "r"))
        let ps256 = AnyVerifier(try RSAVerifier<PS256>(publicKey: key.publicKey, keyID: "r"))
        #expect(try await jws.verify(with: VerificationKeys([rs256])).payload == Data("rsa".utf8))
        // The same key registered for a different RSA algorithm is not a verifier for this token.
        #expect(
            await thrownCase { () async throws(JWSError) in try await jws.verify(with: VerificationKeys([ps256])) }
                == "noVerifierForAlgorithm"
        )
        let ecOnly = try Keys().verification
        #expect(
            await thrownCase { () async throws(JWSError) in try await jws.verify(with: ecOnly) }
                == "noVerifierForAlgorithm"
        )
    }

    @Test("the error for an unsupported algorithm lists what was offered")
    func noVerifierMessage() async throws {
        let keys = try Keys()
        let signed = try await SimpleJWS.Signed(
            signing: Data(),
            with: try HMACSigner<HS256>(key: SymmetricKeyMaterial(randomByteCount: 32))
        )
        do {
            _ = try await SimpleJWS.Unverified(compact: try signed.compactSerialization()).verify(
                with: keys.verification
            )
            Issue.record("an HS256 token verified with only an ES256 key")
        } catch {
            guard case .noVerifierForAlgorithm(let algorithm, let offered) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(algorithm == "HS256")
            #expect(offered == ["ES256"])
            #expect(error.description.contains("HS256"))
            #expect(error.description.contains("ES256"))
        }
    }

    @Test("verification keys can be assembled with the result builder")
    func keysBuilder() throws {
        let p256 = (try ECPrivateKey<P256Curve>()).publicKey
        let edwards = (try Ed25519PrivateKey()).publicKey
        let includeLegacy = true
        let keys = try VerificationKeys {
            try ECDSAVerifier(publicKey: p256, keyID: "a")
            if includeLegacy {
                try Ed25519Verifier<EdDSA>(publicKey: edwards)
            }
            for keyID in ["x", "y"] {
                try Ed25519Verifier<JOSECore.Ed25519>(publicKey: edwards, keyID: KeyID(rawValue: keyID))
            }
            VerificationKeys([AnyVerifier(try HMACVerifier<HS512>(key: SymmetricKeyMaterial(randomByteCount: 64)))])
        }
        #expect(keys.verifiers.count == 5)
        #expect(keys.algorithms == ["ES256", "EdDSA", "Ed25519", "HS512"])
    }

    @Test("each JWSAlgorithm case delegates to its type, and each shorthand makes that type")
    func jwsAlgorithmCases() throws {
        let p256 = JWK(.p256((try ECPrivateKey<P256Curve>()).publicKey))
        let p384 = JWK(.p384((try ECPrivateKey<P384Curve>()).publicKey))
        let p521 = JWK(.p521((try ECPrivateKey<P521Curve>()).publicKey))
        let edwards = JWK(.ed25519((try Ed25519PrivateKey()).publicKey))
        let rsa = JWK(.rsa((try RSAPrivateKey()).publicKey))
        let types: [JWSAlgorithm: (any JWKVerifiableAlgorithm, JWK)] = [
            .es256: (ES256(), p256), .es384: (ES384(), p384), .es512: (ES512(), p521),
            .ed25519: (JOSECore.Ed25519(), edwards), .edDSA: (EdDSA(), edwards),
            .rs256: (RS256(), rsa), .rs384: (RS384(), rsa), .rs512: (RS512(), rsa),
            .ps256: (PS256(), rsa), .ps384: (PS384(), rsa), .ps512: (PS512(), rsa),
        ]
        #expect(Set(types.keys) == Set(JWSAlgorithm.allCases))
        for (named, (type, jwk)) in types {
            #expect(named.identifier == type.identifier)
            #expect(try named.verifier(for: jwk).algorithm == type.identifier)
            #expect(try type.verifier(for: jwk).algorithm == type.identifier)
        }
        func identifier(_ algorithm: some JWKVerifiableAlgorithm) -> AlgorithmIdentifier {
            algorithm.identifier
        }
        #expect(identifier(.es256) == "ES256")
        #expect(identifier(.es384) == "ES384")
        #expect(identifier(.es512) == "ES512")
        #expect(identifier(.ed25519) == "Ed25519")
        #expect(identifier(.edDSA) == "EdDSA")
        #expect(identifier(.rs256) == "RS256")
        #expect(identifier(.rs384) == "RS384")
        #expect(identifier(.rs512) == "RS512")
        #expect(identifier(.ps256) == "PS256")
        #expect(identifier(.ps384) == "PS384")
        #expect(identifier(.ps512) == "PS512")
    }

    @Test("verifiers built from a JWK Set cover only the allowed algorithms each key is suitable for")
    func keysFromJWKSet() throws {
        let p256 = JWK(.p256((try ECPrivateKey<P256Curve>()).publicKey), metadata: JWKMetadata(keyID: "p256"))
        let p384 = JWK(.p384((try ECPrivateKey<P384Curve>()).publicKey), metadata: JWKMetadata(keyID: "p384"))
        let edwards = JWK(.ed25519((try Ed25519PrivateKey()).publicKey), metadata: JWKMetadata(keyID: "ed"))
        let edwardsLegacyOnly = JWK(
            .ed25519((try Ed25519PrivateKey()).publicKey),
            metadata: JWKMetadata(keyID: "ed-legacy", algorithm: "EdDSA")
        )
        let encryptionOnly = JWK(
            .p256((try ECPrivateKey<P256Curve>()).publicKey),
            metadata: JWKMetadata(keyID: "enc", use: .encryption)
        )
        let set = JWKSet(keys: [p256, p384, edwards, edwardsLegacyOnly, encryptionOnly])

        let keys = VerificationKeys(jwks: set, allowing: [.es256, .ed25519, .edDSA])
        let summary = keys.verifiers.map { "\($0.algorithm):\($0.keyID?.rawValue ?? "-")" }
        #expect(summary == ["ES256:p256", "Ed25519:ed", "EdDSA:ed", "EdDSA:ed-legacy"])

        let rsa = JWK(.rsa(try RSAPrivateKey().publicKey), metadata: JWKMetadata(keyID: "rsa"))
        let rsaKeys = VerificationKeys(
            jwks: JWKSet(keys: [p256, rsa]),
            allowing: [JWSAlgorithm.rs256, .ps256, .es256]
        )
        #expect(
            rsaKeys.verifiers.map { "\($0.algorithm):\($0.keyID?.rawValue ?? "-")" }
                == ["ES256:p256", "RS256:rsa", "PS256:rsa"]
        )

        #expect(VerificationKeys(jwks: set, allowing: []).verifiers.isEmpty)
        #expect(VerificationKeys(jwks: set, allowing: [ES384(), ES512()]).algorithms == ["ES384"])
    }

    @Test("a verifier that cannot carry out the check is reported as such, not as a bad signature")
    func verifierFailure() async throws {
        struct Unavailable: Error {}
        struct BrokenVerifier: Verifier {
            typealias Algorithm = ES256
            let keyID: KeyID? = nil
            func verify(_ signature: Signature<ES256>, for message: Data) throws(VerificationError) {
                throw .keyOperationFailed(algorithm: "ES256", underlying: UnderlyingError(Unavailable()))
            }
        }
        let keys = try Keys()
        let jws = try SimpleJWS.Unverified(
            compact: try await SimpleJWS.Signed(signing: Data(), with: keys.signer).compactSerialization()
        )
        #expect(
            await thrownCase { () async throws(JWSError) in
                try await jws.verify(with: VerificationKeys([AnyVerifier(BrokenVerifier())]))
            }
                == "verificationFailed"
        )
    }

    @Test("a signer's failure surfaces as a signing error with its cause")
    func signerFailure() async throws {
        struct Unavailable: Error {}
        struct BrokenSigner: Signer {
            typealias Algorithm = ES256
            let keyID: KeyID? = nil
            func sign(_ message: Data) async throws(SigningError) -> Signature<ES256> {
                throw .keyOperationFailed(algorithm: "ES256", underlying: UnderlyingError(Unavailable()))
            }
        }
        do {
            _ = try await SimpleJWS.Signed(signing: Data(), with: BrokenSigner())
            Issue.record("signing should have failed")
        } catch {
            guard case .signingFailed(.keyOperationFailed(_, let underlying)) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(underlying == UnderlyingError(Unavailable()))
        }
    }

    @Test("every error has a message naming what was wrong")
    func descriptions() {
        #expect(JWSError.paddingNotAllowed(part: "payload") == .paddingNotAllowed(part: "payload"))
        #expect(JWSError.paddingNotAllowed(part: "payload") != .paddingNotAllowed(part: "signature"))
        let errors: [(JWSError, String)] = [
            (.invalidCompactSerialization(segmentCount: 2), "2 segments"),
            (.missingProtectedHeader, "empty protected header"),
            (.invalidBase64URL(part: "signature", .invalidLength(count: 1)), "signature"),
            (.paddingNotAllowed(part: "payload"), "payload"),
            (.invalidJSONStructure(.rootNotObject), "object"),
            (.invalidJSONSerialization(reason: "why"), "why"),
            (.invalidHeaderStructure(.duplicateMember(name: "alg", offset: 3)), "alg"),
            (.invalidHeaderJSON(description: "boom"), "boom"),
            (.missingAlgorithm, "alg"),
            (.headerParameterWrongType(name: "kid", expected: "a string"), "kid"),
            (.headerParameterInBothHeaders(name: "typ"), "typ"),
            (.headerParameterNotProtected(name: "crit"), "crit"),
            (.invalidCritical(reason: "empty"), "empty"),
            (.unsupportedCriticalParameter(name: "exp"), "exp"),
            (.unencodedPayloadNotCritical, "b64"),
            (.invalidJWKParameter(.symmetricKeyInPublicKey), "oct"),
            (.invalidCustomParameters(description: "bad"), "bad"),
            (.inconsistentPayloadEncoding, "b64"),
            (.payloadMissing, "detached"),
            (.payloadSuppliedTwice, "detached"),
            (.unencodedPayloadNotRepresentable(reason: "dots"), "dots"),
            (.noVerifierForAlgorithm(algorithm: "RS256", offered: ["ES256"]), "RS256"),
            (.noVerifierForKeyID(keyID: "k9", algorithm: "ES256"), "k9"),
            (.malformedSignature(.wrongLength(algorithm: "ES256", expected: 64, found: 70)), "70"),
            (.signatureInvalid(algorithm: "ES256", keyID: "k1"), "k1"),
            (.signatureInvalid(algorithm: "ES256", keyID: nil), "ES256"),
            (.verificationFailed(.signatureMismatch(algorithm: "ES256")), "ES256"),
            (.noSignatureVerified(reasons: [.payloadMissing, .missingAlgorithm]), "2 signatures"),
            (.noUsableSignature(reasons: [.missingAlgorithm, .missingAlgorithm]), "usable header"),
            (.signingFailed(.invalidSignature(.wrongLength(algorithm: "ES256", expected: 64, found: 1))), "64"),
            (.headerEncodingFailed(description: "enc"), "enc"),
            (.customParameterCollision(name: "alg"), "alg"),
            (.customParametersNotObject, "object"),
            (.singleSignatureRequired(serialization: "compact", count: 2), "compact"),
        ]
        for (error, fragment) in errors {
            #expect(error.description.contains(fragment), "\(error.description)")
        }
    }
}
