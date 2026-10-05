import Foundation
import JOSECore
import JOSEJWK

extension JWS {
    /// A JWS produced by signing, ready to serialize.
    public struct Signed: Sendable {
        let entries: [SignatureEntry]
        public let payload: Data
        public let payloadEncoding: PayloadEncoding

        /// The headers, one per signature, in the order the signatures were added.
        public var headers: [JWSHeader<Custom>] {
            entries.map(\.header)
        }

        /// The header of the first signature.
        public var header: JWSHeader<Custom> {
            entries[0].header
        }

        var isPayloadBase64URLEncoded: Bool {
            switch payloadEncoding {
            case .base64URL:
                return true
            case .unencoded:
                return false
            }
        }

        /// Adds another signature over the same payload, for the general JSON serialization.
        public func adding<S: Signer>(
            signatureWith signer: S,
            header: JWSHeaderParameters<Custom>
        ) async throws(JWSError) -> Signed {
            let entry = try await JWS.makeEntry(
                payload: payload,
                signer: signer,
                header: header,
                isPayloadBase64URLEncoded: isPayloadBase64URLEncoded
            )
            return Signed(entries: entries + [entry], payload: payload, payloadEncoding: payloadEncoding)
        }

        /// The JWS Compact Serialization.
        ///
        /// - Parameter detached: Leave the payload out, for transmission by other means.
        public func compactSerialization(detached: Bool = false) throws(JWSError) -> String {
            guard entries.count == 1 else {
                throw .singleSignatureRequired(serialization: "compact", count: entries.count)
            }
            var payloadText = ""
            if !detached {
                payloadText = try JWS.encodePayload(payload, isBase64URLEncoded: isPayloadBase64URLEncoded)
                if !isPayloadBase64URLEncoded {
                    // RFC 7797 §5.2: without encoding, the payload itself sits between the
                    // periods, so it cannot contain one, and should be limited to printable ASCII.
                    let isRepresentable = payload.allSatisfy { byte in
                        byte >= 0x20 && byte <= 0x7E && byte != UInt8(ascii: ".")
                    }
                    guard isRepresentable else {
                        throw .unencodedPayloadNotRepresentable(
                            reason: "the compact form can only carry printable ASCII without '.'; detach the payload"
                        )
                    }
                }
            }
            let entry = entries[0]
            return entry.protectedEncoded + "." + payloadText + "." + Base64URL.encode(entry.signature)
        }

        /// The flattened JWS JSON Serialization, which holds exactly one signature.
        public func flattenedJSONSerialization(detached: Bool = false) throws(JWSError) -> Data {
            guard entries.count == 1 else {
                throw .singleSignatureRequired(serialization: "flattened JSON", count: entries.count)
            }
            var document = Self.signatureObject(entries[0])
            if !detached {
                document["payload"] = .string(
                    try JWS.encodePayload(payload, isBase64URLEncoded: isPayloadBase64URLEncoded)
                )
            }
            return try Self.encode(document)
        }

        /// The general JWS JSON Serialization, which holds any number of signatures.
        public func generalJSONSerialization(detached: Bool = false) throws(JWSError) -> Data {
            var document: [String: JSONValue] = [
                "signatures": .array(entries.map { .object(Self.signatureObject($0)) })
            ]
            if !detached {
                document["payload"] = .string(
                    try JWS.encodePayload(payload, isBase64URLEncoded: isPayloadBase64URLEncoded)
                )
            }
            return try Self.encode(document)
        }

        private static func signatureObject(_ entry: SignatureEntry) -> [String: JSONValue] {
            [
                "protected": .string(entry.protectedEncoded),
                "signature": .string(Base64URL.encode(entry.signature)),
            ]
        }

        private static func encode(_ document: [String: JSONValue]) throws(JWSError) -> Data {
            do {
                return try HeaderJSON.encoder().encode(document)
            } catch {
                throw .headerEncodingFailed(description: String(describing: error))
            }
        }
    }

    /// Signs `payload`.
    ///
    /// The header's `alg` is taken from the signer's type and cannot be supplied separately.
    /// Every header parameter is placed in the protected header.
    public static func sign<S: Signer>(
        _ payload: Data,
        with signer: S,
        header: JWSHeaderParameters<Custom>,
        payloadEncoding: PayloadEncoding = .base64URL
    ) async throws(JWSError) -> Signed {
        var isEncoded = true
        if case .unencoded = payloadEncoding {
            isEncoded = false
        }
        let entry = try await makeEntry(
            payload: payload,
            signer: signer,
            header: header,
            isPayloadBase64URLEncoded: isEncoded
        )
        return Signed(entries: [entry], payload: payload, payloadEncoding: payloadEncoding)
    }

    static func makeEntry<S: Signer>(
        payload: Data,
        signer: S,
        header: JWSHeaderParameters<Custom>,
        isPayloadBase64URLEncoded: Bool
    ) async throws(JWSError) -> SignatureEntry {
        let protectedJSON = try header.protectedJSON(
            algorithm: S.Algorithm.identifier,
            signerKeyID: signer.keyID,
            isPayloadBase64URLEncoded: isPayloadBase64URLEncoded
        )
        let protectedEncoded = Base64URL.encode(protectedJSON)
        // Parsing our own header back keeps one definition of what a header means, and refuses to
        // sign anything this package would not itself accept.
        let parsed = try JWSHeader<Custom>.parse(protected: protectedJSON, unprotected: nil)
        let payloadText = try encodePayload(payload, isBase64URLEncoded: isPayloadBase64URLEncoded)

        let unsigned = SignatureEntry(protectedEncoded: protectedEncoded, header: parsed, signature: Data())
        let signature: Signature<S.Algorithm>
        do {
            signature = try await signer.sign(unsigned.signingInput(payloadText: payloadText))
        } catch {
            throw .signingFailed(error)
        }
        return SignatureEntry(
            protectedEncoded: protectedEncoded,
            header: parsed,
            signature: signature.rawRepresentation
        )
    }
}

extension JWS where Custom == EmptyHeaderParameters {
    /// Signs `payload` with a header of registered parameters only.
    public static func sign<S: Signer>(
        _ payload: Data,
        with signer: S,
        payloadEncoding: PayloadEncoding = .base64URL
    ) async throws(JWSError) -> Signed {
        try await sign(payload, with: signer, header: JWSHeaderParameters(), payloadEncoding: payloadEncoding)
    }
}
