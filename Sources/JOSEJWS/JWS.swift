import Foundation
import JOSECore
import JOSEJWK

/// How the payload enters the signing input.
public enum PayloadEncoding: Sendable {
    /// The payload is base64url-encoded, as in every ordinary JWS.
    case base64URL
    /// The payload is signed and carried as it is (RFC 7797, `b64: false`). Meant for detached
    /// payloads, which may be any bytes. A carried payload must be UTF-8, and in the compact
    /// form printable ASCII without `.`.
    case unencoded
}

/// JSON Web Signature (RFC 7515), parameterised by the application's header type.
///
/// A JWS moves through distinct types: ``Unverified`` is what parsing gives you and has no
/// trustworthy payload; ``Verified`` is what a successful signature check gives you; ``Signed``
/// is what signing gives you.
public struct JWS<Custom: HeaderParameters>: Sendable {
    private init() {}

    /// One signature with its header, as received.
    struct SignatureEntry: Sendable {
        /// The protected header exactly as it appeared, still base64url-encoded. The signature is
        /// checked over these characters, never over a re-encoding of the parsed header.
        let protectedEncoded: String
        let header: JWSHeader<Custom>
        let signature: Data

        /// The JWS Signing Input: the protected header as received, a period, and the payload
        /// as it enters the signature: its base64url text, or the bytes themselves under RFC 7797.
        func signingInput(payload: Data) -> Data {
            Data((protectedEncoded + ".").utf8) + payload
        }
    }

    /// The bytes that stand for the payload in the signing input.
    static func signingPayload(_ payload: Data, isBase64URLEncoded: Bool) -> Data {
        guard isBase64URLEncoded else {
            return payload
        }
        return Data(Base64URL.encode(payload).utf8)
    }

    /// A parsed JWS whose signature has not been checked.
    public struct Unverified: Sendable {
        /// One element per signature. A signature whose header could not be accepted is kept as
        /// its error, so that the others can still be used.
        let entries: [Result<SignatureEntry, JWSError>]
        /// The payload as it appears in the serialization: base64url text, or the payload itself
        /// when `b64` is false. `nil` when detached.
        let payloadText: String?
        let isPayloadBase64URLEncoded: Bool

        /// The headers of the signatures that parsed. Readable before verification because
        /// choosing a key depends on them; nothing in them is trustworthy yet.
        public var headers: [JWSHeader<Custom>] {
            entries.compactMap { entry in
                guard case .success(let entry) = entry else {
                    return nil
                }
                return entry.header
            }
        }

        /// The header of the first signature that parsed. A JWS in which no signature's header
        /// parses is refused when it is parsed, so there always is one.
        public let header: JWSHeader<Custom>

        /// The payload **without any assurance that it is authentic**. `nil` when a JSON
        /// serialization has no `payload` member; empty when the compact form's payload segment
        /// is empty, which is how a detached compact JWS looks. Use
        /// ``verify(with:detachedPayload:)`` to obtain a payload that can be trusted.
        public var unverifiedPayload: Data? {
            get throws(JWSError) {
                guard let payloadText else {
                    return nil
                }
                return try JWS.decodePayload(payloadText, isBase64URLEncoded: isPayloadBase64URLEncoded)
            }
        }

        init(entries: [Result<SignatureEntry, JWSError>], payloadText: String?) throws(JWSError) {
            var headers: [JWSHeader<Custom>] = []
            var failures: [JWSError] = []
            for entry in entries {
                switch entry {
                case .success(let entry):
                    headers.append(entry.header)
                case .failure(let error):
                    failures.append(error)
                }
            }
            guard let first = headers.first else {
                throw .noUsableSignature(reasons: failures)
            }
            guard Set(headers.map(\.isPayloadBase64URLEncoded)).count == 1 else {
                throw .inconsistentPayloadEncoding
            }
            self.entries = entries
            self.header = first
            self.payloadText = payloadText
            self.isPayloadBase64URLEncoded = first.isPayloadBase64URLEncoded
            if let payloadText {
                // Fail at parse time rather than at verification for a payload that is not base64url.
                _ = try JWS.decodePayload(payloadText, isBase64URLEncoded: isPayloadBase64URLEncoded)
            }
        }

        /// Checks the signature and returns the JWS with a payload that can be trusted.
        ///
        /// Succeeds if at least one signature verifies with one of `keys`. A signature is only
        /// tried against verifiers for the algorithm its header names.
        ///
        /// - Parameter detachedPayload: The payload, when the JWS does not carry it.
        public func verify(
            with keys: VerificationKeys,
            detachedPayload: Data? = nil
        ) async throws(JWSError) -> Verified {
            let (payload, signingPayload) = try resolvePayload(detached: detachedPayload)
            var verifiedHeaders: [JWSHeader<Custom>] = []
            var failures: [JWSError] = []
            for entry in entries {
                do {
                    let entry = try entry.get()
                    try await JWS.verify(entry, signingPayload: signingPayload, with: keys)
                    verifiedHeaders.append(entry.header)
                } catch {
                    failures.append(error)
                }
            }
            return try Verified.first(of: verifiedHeaders, failures: failures, payload: payload)
        }

        /// The payload to return and the bytes that stand for it in the signing input, from the
        /// carried payload or the detached one. A detached payload is taken as bytes, so a binary
        /// `b64: false` payload needs no text form.
        private func resolvePayload(detached: Data?) throws(JWSError) -> (payload: Data, signingPayload: Data) {
            if let detached {
                guard payloadText == nil || payloadText == "" else {
                    throw .payloadSuppliedTwice
                }
                return (detached, JWS.signingPayload(detached, isBase64URLEncoded: isPayloadBase64URLEncoded))
            }
            guard let payloadText else {
                throw .payloadMissing
            }
            let payload = try JWS.decodePayload(payloadText, isBase64URLEncoded: isPayloadBase64URLEncoded)
            return (payload, Data(payloadText.utf8))
        }

        /// Resolves keys from each signature's own `jku`, `x5c` or `jwk` with `resolver`, then
        /// verifies that signature with them.
        public func verify(
            resolving resolver: HeaderKeyResolver,
            detachedPayload: Data? = nil
        ) async throws(JWSError) -> Verified {
            let (payload, signingPayload) = try resolvePayload(detached: detachedPayload)
            var verifiedHeaders: [JWSHeader<Custom>] = []
            var failures: [JWSError] = []
            for entry in entries {
                do {
                    let entry = try entry.get()
                    let keys = try await Self.keys(for: entry.header, resolving: resolver)
                    try await JWS.verify(entry, signingPayload: signingPayload, with: keys)
                    verifiedHeaders.append(entry.header)
                } catch {
                    failures.append(error)
                }
            }
            return try Verified.first(of: verifiedHeaders, failures: failures, payload: payload)
        }

        // Separate so that the loop above has one error type to catch.
        private static func keys(
            for header: JWSHeader<Custom>,
            resolving resolver: HeaderKeyResolver
        ) async throws(JWSError) -> VerificationKeys {
            do {
                return try await resolver.verificationKeys(for: header)
            } catch {
                throw .keyResolutionFailed(error)
            }
        }
    }

    /// A JWS with at least one signature that verified.
    public struct Verified: Sendable {
        /// The header of the first signature that verified.
        public let header: JWSHeader<Custom>
        /// The headers of every signature that verified. For a JWS with several signatures,
        /// compare this with what your application requires.
        public let verifiedHeaders: [JWSHeader<Custom>]
        public let payload: Data

        /// The result for the signatures that verified, or the reason none did: the single
        /// signature's own error, or one reason per signature.
        static func first(
            of verifiedHeaders: [JWSHeader<Custom>],
            failures: [JWSError],
            payload: Data
        ) throws(JWSError) -> Verified {
            guard let header = verifiedHeaders.first else {
                if failures.count == 1 {
                    throw failures[0]
                }
                throw .noSignatureVerified(reasons: failures)
            }
            return Verified(header: header, verifiedHeaders: verifiedHeaders, payload: payload)
        }
    }

    private static func verify(
        _ entry: SignatureEntry,
        signingPayload: Data,
        with keys: VerificationKeys
    ) async throws(JWSError) {
        let candidates = try keys.candidates(algorithm: entry.header.algorithm, keyID: entry.header.keyID)
        let message = entry.signingInput(payload: signingPayload)
        var lastError = JWSError.signatureInvalid(algorithm: entry.header.algorithm, keyID: entry.header.keyID)
        for candidate in candidates {
            do {
                try await candidate.verify(signature: entry.signature, message: message)
                return
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    static func decodePayload(_ text: String, isBase64URLEncoded: Bool) throws(JWSError) -> Data {
        guard isBase64URLEncoded else {
            return Data(text.utf8)
        }
        return try decodeBase64URL(text, part: "payload")
    }

    static func encodePayload(_ payload: Data, isBase64URLEncoded: Bool) throws(JWSError) -> String {
        guard isBase64URLEncoded else {
            guard let text = strictUTF8String(payload) else {
                throw .unencodedPayloadNotRepresentable(reason: "the payload is not valid UTF-8")
            }
            return text
        }
        return Base64URL.encode(payload)
    }

    static func decodeBase64URL(_ text: String, part: String) throws(JWSError) -> Data {
        // JOSECore accepts correct padding; JWS does not allow any (RFC 7515 §2).
        guard !text.utf8.contains(UInt8(ascii: "=")) else {
            throw .paddingNotAllowed(part: part)
        }
        do {
            return try Base64URL.decode(text)
        } catch {
            throw .invalidBase64URL(part: part, error)
        }
    }
}

/// A JWS with registered header parameters only, which is the common case.
public typealias SimpleJWS = JWS<EmptyHeaderParameters>

/// Decodes UTF-8 without repairing or dropping anything. Foundation's `String(data:encoding:)`
/// is not used because it removes a leading byte order mark, which would change a signed payload.
func strictUTF8String(_ data: Data) -> String? {
    var decoder = UTF8()
    var iterator = data.makeIterator()
    var scalars = String.UnicodeScalarView()
    while true {
        switch decoder.decode(&iterator) {
        case .scalarValue(let scalar):
            scalars.append(scalar)
        case .emptyInput:
            return String(scalars)
        case .error:
            return nil
        }
    }
}
