import Foundation
import JOSECore
import JOSEJWK

/// How the payload enters the signing input.
public enum PayloadEncoding: Sendable {
    /// The payload is base64url-encoded, as in every ordinary JWS.
    case base64URL
    /// The payload is signed and carried as it is (RFC 7797, `b64: false`). Meant for detached
    /// payloads; in the compact form it can only hold printable ASCII without `.`.
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

        func signingInput(payloadText: String) -> Data {
            Data((protectedEncoded + "." + payloadText).utf8)
        }
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

        /// The header of the first signature that parsed.
        public var header: JWSHeader<Custom>? {
            headers.first
        }

        /// The payload **without any assurance that it is authentic**. `nil` when the payload is
        /// detached. Use ``verify(with:detachedPayload:)`` to obtain a payload that can be trusted.
        public var unverifiedPayload: Data? {
            get throws(JWSError) {
                guard let payloadText else {
                    return nil
                }
                return try JWS.decodePayload(payloadText, isBase64URLEncoded: isPayloadBase64URLEncoded)
            }
        }

        init(entries: [Result<SignatureEntry, JWSError>], payloadText: String?) throws(JWSError) {
            var encodings: Set<Bool> = []
            for case .success(let entry) in entries {
                encodings.insert(entry.header.isPayloadBase64URLEncoded)
            }
            guard encodings.count <= 1 else {
                throw .inconsistentPayloadEncoding
            }
            self.entries = entries
            self.payloadText = payloadText
            self.isPayloadBase64URLEncoded = encodings.first ?? true
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
        ) throws(JWSError) -> Verified {
            let payload: Data
            let text: String
            if let detachedPayload {
                guard payloadText == nil || payloadText == "" else {
                    throw .payloadSuppliedTwice
                }
                payload = detachedPayload
                text = try JWS.encodePayload(detachedPayload, isBase64URLEncoded: isPayloadBase64URLEncoded)
            } else {
                guard let payloadText else {
                    throw .payloadMissing
                }
                payload = try JWS.decodePayload(payloadText, isBase64URLEncoded: isPayloadBase64URLEncoded)
                text = payloadText
            }

            var verifiedHeaders: [JWSHeader<Custom>] = []
            var failures: [JWSError] = []
            for entry in entries {
                do {
                    let entry = try entry.get()
                    try JWS.verify(entry, payloadText: text, with: keys)
                    verifiedHeaders.append(entry.header)
                } catch {
                    failures.append(error)
                }
            }

            guard let header = verifiedHeaders.first else {
                if failures.count == 1 {
                    throw failures[0]
                }
                throw .noSignatureVerified(reasons: failures)
            }
            return Verified(header: header, verifiedHeaders: verifiedHeaders, payload: payload)
        }

        /// Resolves keys from the header's `jku`, `x5c` or `jwk` with `resolver`, then verifies.
        ///
        /// Keys are resolved for the first signature's header. With several signatures, resolve and
        /// verify per header instead.
        public func verify(
            resolving resolver: HeaderKeyResolver,
            detachedPayload: Data? = nil
        ) async throws(JWSError) -> Verified {
            guard let header else {
                throw .missingAlgorithm
            }
            let keys: VerificationKeys
            do {
                keys = try await resolver.verificationKeys(for: header)
            } catch {
                throw .keyResolutionFailed(error)
            }
            return try verify(with: keys, detachedPayload: detachedPayload)
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
    }

    private static func verify(
        _ entry: SignatureEntry,
        payloadText: String,
        with keys: VerificationKeys
    ) throws(JWSError) {
        let candidates = try keys.candidates(algorithm: entry.header.algorithm, keyID: entry.header.keyID)
        let message = entry.signingInput(payloadText: payloadText)
        var lastError = JWSError.signatureInvalid(algorithm: entry.header.algorithm, keyID: entry.header.keyID)
        for candidate in candidates {
            do {
                try candidate.verify(signature: entry.signature, message: message)
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
        return try decodeBase64URL(text, part: .payload)
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

    static func decodeBase64URL(_ text: String, part: JWSError.Part) throws(JWSError) -> Data {
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
