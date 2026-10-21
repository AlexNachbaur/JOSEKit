import Foundation
import JOSECore
import JOSEJWK

extension JWS.Unverified {
    /// Parses the JWS Compact Serialization: `header.payload.signature`.
    public init(compact: String) throws(JWSError) {
        // Split on the byte, not the Character: a period followed by a combining mark is one
        // Character to Swift but a separator to every other JWS implementation.
        let segments = compact.utf8.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
            .map { String(decoding: $0, as: UTF8.self) }
        guard segments.count == 3 else {
            throw .invalidCompactSerialization(segmentCount: segments.count)
        }
        let protectedEncoded = segments[0]
        guard !protectedEncoded.isEmpty else {
            throw .missingProtectedHeader
        }
        let entry = try JWS.SignatureEntry(
            protectedEncoded: protectedEncoded,
            unprotected: nil,
            signatureEncoded: String(segments[2])
        )
        try self.init(entries: [.success(entry)], payloadText: String(segments[1]))
    }

    /// Parses the JWS JSON Serialization, in either its flattened or its general form.
    public init(json: Data) throws(JWSError) {
        do {
            try json.requireUniqueJSONMembers()
        } catch {
            throw .invalidJSONStructure(error)
        }
        let document: [String: JSONValue]
        do {
            document = try JSONDecoder().decode([String: JSONValue].self, from: json)
        } catch {
            throw .invalidJSONSerialization(reason: String(describing: error))
        }

        var payloadText: String?
        if let payload = document["payload"] {
            guard case .string(let text) = payload else {
                throw .invalidJSONSerialization(reason: "\"payload\" must be a string")
            }
            payloadText = text
        }

        var signatureObjects: [[String: JSONValue]] = []
        if let signatures = document["signatures"] {
            // RFC 7515 §7.2.2: the flattened members must not be present alongside "signatures".
            for name in ["protected", "header", "signature"] where document[name] != nil {
                throw .invalidJSONSerialization(reason: "\"\(name)\" and \"signatures\" are both present")
            }
            guard case .array(let elements) = signatures, !elements.isEmpty else {
                throw .invalidJSONSerialization(reason: "\"signatures\" must be a non-empty array")
            }
            for element in elements {
                guard case .object(let object) = element else {
                    throw .invalidJSONSerialization(reason: "\"signatures\" must contain objects")
                }
                signatureObjects.append(object)
            }
        } else {
            signatureObjects = [document]
        }

        var entries: [Result<JWS.SignatureEntry, JWSError>] = []
        for object in signatureObjects {
            do {
                entries.append(.success(try JWS.SignatureEntry(jsonObject: object)))
            } catch {
                // With a single signature there is nothing else to fall back on, so report the
                // problem now, with its specific cause.
                guard signatureObjects.count > 1 else {
                    throw error
                }
                entries.append(.failure(error))
            }
        }
        try self.init(entries: entries, payloadText: payloadText)
    }
}

extension JWS.SignatureEntry {
    /// Reads one signature object of the JSON serializations.
    init(jsonObject object: [String: JSONValue]) throws(JWSError) {
        var protectedEncoded: String?
        if let protected = object["protected"] {
            guard case .string(let text) = protected else {
                throw .invalidJSONSerialization(reason: "\"protected\" must be a string")
            }
            protectedEncoded = text
        }
        var unprotected: [String: JSONValue]?
        if let header = object["header"] {
            guard case .object(let values) = header else {
                throw .invalidJSONSerialization(reason: "\"header\" must be an object")
            }
            unprotected = values
        }
        guard case .string(let signatureEncoded) = object["signature"] else {
            throw .invalidJSONSerialization(reason: "\"signature\" must be present and a string")
        }
        try self.init(
            protectedEncoded: protectedEncoded ?? "",
            unprotected: unprotected,
            signatureEncoded: signatureEncoded
        )
    }

    /// Reads one signature from its encoded parts.
    init(
        protectedEncoded: String,
        unprotected: [String: JSONValue]?,
        signatureEncoded: String
    ) throws(JWSError) {
        var protectedJSON: Data?
        if !protectedEncoded.isEmpty {
            protectedJSON = try Data(jwsPart: protectedEncoded, named: "protected header")
        }
        let header = try JWSHeader<Custom>.parse(protected: protectedJSON, unprotected: unprotected)
        let signature = try Data(jwsPart: signatureEncoded, named: "signature")
        self.init(protectedEncoded: protectedEncoded, header: header, signature: signature)
    }
}
