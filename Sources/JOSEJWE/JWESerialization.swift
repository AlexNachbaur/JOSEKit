import Foundation
import JOSECore
import JOSEJWK

extension JWE.Encrypted {
    // MARK: Parsing

    /// Parses the JWE Compact Serialization: `header.key.iv.ciphertext.tag`.
    public init(compact: String) throws(JWEError) {
        let segments = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard segments.count == 5 else {
            throw .invalidCompactSerialization(segmentCount: segments.count)
        }
        guard !segments[0].isEmpty else {
            throw .missingAlgorithm
        }
        let protectedJSON = try JWEJSON.decodeBase64URL(segments[0], part: "protected header")
        let protected = try JWEJSON.protectedValues(protectedJSON)
        let header = try JWEHeader<Custom>.parse(
            protectedJSON: protectedJSON,
            protected: protected,
            sharedUnprotected: [:],
            recipientUnprotected: [:]
        )
        let recipient = JWE.Recipient(
            header: header,
            encryptedKey: try JWEJSON.decodeBase64URL(segments[1], part: "encrypted key"),
            unprotected: [:]
        )
        try self.init(
            protectedEncoded: segments[0],
            sharedUnprotected: [:],
            recipients: [.success(recipient)],
            initializationVector: try JWEJSON.decodeBase64URL(segments[2], part: "initialization vector"),
            ciphertext: try JWEJSON.decodeBase64URL(segments[3], part: "ciphertext"),
            tag: try JWEJSON.decodeBase64URL(segments[4], part: "authentication tag"),
            additionalDataEncoded: nil
        )
    }

    /// Parses the JWE JSON Serialization, in either its flattened or its general form.
    public init(json: Data) throws(JWEError) {
        do {
            try JSONMemberUniqueness.validate(json)
        } catch {
            throw .invalidJSONStructure(error)
        }
        let document: [String: JSONValue]
        do {
            document = try JSONDecoder().decode([String: JSONValue].self, from: json)
        } catch {
            throw .invalidJSONSerialization(reason: String(describing: error))
        }

        func string(_ name: String) throws(JWEError) -> String? {
            guard let value = document[name] else {
                return nil
            }
            guard case .string(let text) = value else {
                throw .invalidJSONSerialization(reason: "\"\(name)\" must be a string")
            }
            return text
        }
        func object(_ name: String, in values: [String: JSONValue]) throws(JWEError) -> [String: JSONValue] {
            guard let value = values[name] else {
                return [:]
            }
            guard case .object(let members) = value else {
                throw .invalidJSONSerialization(reason: "\"\(name)\" must be an object")
            }
            return members
        }

        let protectedEncoded = try string("protected") ?? ""
        var protectedJSON: Data?
        var protected: [String: JSONValue] = [:]
        if !protectedEncoded.isEmpty {
            let decoded = try JWEJSON.decodeBase64URL(protectedEncoded, part: "protected header")
            protected = try JWEJSON.protectedValues(decoded)
            protectedJSON = decoded
        }
        let sharedUnprotected = try object("unprotected", in: document)

        guard let ciphertextEncoded = try string("ciphertext") else {
            throw .invalidJSONSerialization(reason: "\"ciphertext\" is missing")
        }

        var recipientObjects: [[String: JSONValue]] = []
        if let recipients = document["recipients"] {
            // RFC 7516 §7.2.2: the flattened members must not be present alongside "recipients".
            for name in ["header", "encrypted_key"] where document[name] != nil {
                throw .invalidJSONSerialization(reason: "\"\(name)\" and \"recipients\" are both present")
            }
            guard case .array(let elements) = recipients, !elements.isEmpty else {
                throw .invalidJSONSerialization(reason: "\"recipients\" must be a non-empty array")
            }
            for element in elements {
                guard case .object(let members) = element else {
                    throw .invalidJSONSerialization(reason: "\"recipients\" must contain objects")
                }
                recipientObjects.append(members)
            }
        } else {
            recipientObjects = [document]
        }

        var recipients: [Result<JWE.Recipient, JWEError>] = []
        for members in recipientObjects {
            do throws(JWEError) {
                let unprotected = try object("header", in: members)
                var encryptedKey = Data()
                if let value = members["encrypted_key"] {
                    guard case .string(let text) = value else {
                        throw JWEError.invalidJSONSerialization(reason: "\"encrypted_key\" must be a string")
                    }
                    encryptedKey = try JWEJSON.decodeBase64URL(text, part: "encrypted key")
                }
                let header = try JWEHeader<Custom>.parse(
                    protectedJSON: protectedJSON,
                    protected: protected,
                    sharedUnprotected: sharedUnprotected,
                    recipientUnprotected: unprotected
                )
                recipients.append(
                    .success(JWE.Recipient(header: header, encryptedKey: encryptedKey, unprotected: unprotected))
                )
            } catch {
                // With a single recipient there is nothing else to fall back on, so report the
                // problem now, with its specific cause.
                guard recipientObjects.count > 1 else {
                    throw error
                }
                recipients.append(.failure(error))
            }
        }

        let additionalDataEncoded = try string("aad")
        if let additionalDataEncoded {
            _ = try JWEJSON.decodeBase64URL(additionalDataEncoded, part: "aad")
        }
        try self.init(
            protectedEncoded: protectedEncoded,
            sharedUnprotected: sharedUnprotected,
            recipients: recipients,
            initializationVector: try JWEJSON.decodeBase64URL(try string("iv") ?? "", part: "initialization vector"),
            ciphertext: try JWEJSON.decodeBase64URL(ciphertextEncoded, part: "ciphertext"),
            tag: try JWEJSON.decodeBase64URL(try string("tag") ?? "", part: "authentication tag"),
            additionalDataEncoded: additionalDataEncoded
        )
    }

    // MARK: Writing

    private func usableRecipients() throws(JWEError) -> [JWE.Recipient] {
        var usable: [JWE.Recipient] = []
        for recipient in recipients {
            usable.append(try recipient.get())
        }
        return usable
    }

    /// The JWE Compact Serialization. Only a JWE with one recipient, a fully protected header and
    /// no additional authenticated data can be written this way.
    public func compactSerialization() throws(JWEError) -> String {
        let usable = try usableRecipients()
        guard usable.count == 1 else {
            throw .notRepresentable(serialization: "compact", reason: "it has \(usable.count) recipients")
        }
        guard sharedUnprotected.isEmpty, usable[0].unprotected.isEmpty else {
            throw .notRepresentable(serialization: "compact", reason: "it has unprotected header parameters")
        }
        guard additionalDataEncoded == nil else {
            throw .notRepresentable(serialization: "compact", reason: "it has additional authenticated data")
        }
        return [
            protectedEncoded,
            Base64URL.encode(usable[0].encryptedKey),
            Base64URL.encode(initializationVector),
            Base64URL.encode(ciphertext),
            Base64URL.encode(tag),
        ].joined(separator: ".")
    }

    private func commonMembers() -> [String: JSONValue] {
        var document: [String: JSONValue] = [
            "iv": .string(Base64URL.encode(initializationVector)),
            "ciphertext": .string(Base64URL.encode(ciphertext)),
            "tag": .string(Base64URL.encode(tag)),
        ]
        if !protectedEncoded.isEmpty {
            document["protected"] = .string(protectedEncoded)
        }
        if !sharedUnprotected.isEmpty {
            document["unprotected"] = .object(sharedUnprotected)
        }
        if let additionalDataEncoded {
            document["aad"] = .string(additionalDataEncoded)
        }
        return document
    }

    private static func recipientMembers(_ recipient: JWE.Recipient) -> [String: JSONValue] {
        var members: [String: JSONValue] = [:]
        if !recipient.unprotected.isEmpty {
            members["header"] = .object(recipient.unprotected)
        }
        if !recipient.encryptedKey.isEmpty {
            members["encrypted_key"] = .string(Base64URL.encode(recipient.encryptedKey))
        }
        return members
    }

    private static func encode(_ document: [String: JSONValue]) throws(JWEError) -> Data {
        do {
            return try JWEJSON.encoder().encode(document)
        } catch {
            throw .headerEncodingFailed(description: String(describing: error))
        }
    }

    /// The flattened JWE JSON Serialization, which holds exactly one recipient.
    public func flattenedJSONSerialization() throws(JWEError) -> Data {
        let usable = try usableRecipients()
        guard usable.count == 1 else {
            throw .notRepresentable(serialization: "flattened JSON", reason: "it has \(usable.count) recipients")
        }
        var document = commonMembers()
        for (name, value) in Self.recipientMembers(usable[0]) {
            document[name] = value
        }
        return try Self.encode(document)
    }

    /// The general JWE JSON Serialization, which holds any number of recipients.
    public func generalJSONSerialization() throws(JWEError) -> Data {
        var document = commonMembers()
        document["recipients"] = .array(try usableRecipients().map { .object(Self.recipientMembers($0)) })
        return try Self.encode(document)
    }
}
