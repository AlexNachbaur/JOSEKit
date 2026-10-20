import Foundation
import JOSECore
import JOSEJWK

/// JSON Web Encryption (RFC 7516), parameterised by the application's header type.
///
/// ``Encrypted`` is a JWE whose content is still sealed, whether it was just parsed or just
/// produced. ``Decrypted`` is what a successful decryption gives you; there is no other way to
/// reach the plaintext.
public struct JWE<Custom: HeaderParameters>: Sendable {
    private init() {}

    struct Recipient: Sendable {
        let header: JWEHeader<Custom>
        let encryptedKey: Data
        /// This recipient's own unprotected header, as it appears in the JSON serialization.
        let unprotected: [String: JSONValue]
    }

    /// A JWE whose content has not been decrypted.
    public struct Encrypted: Sendable {
        /// The protected header exactly as it appeared or was produced, still base64url-encoded.
        /// It is authenticated as these characters, never as a re-encoding.
        let protectedEncoded: String
        let sharedUnprotected: [String: JSONValue]
        /// One element per recipient. A recipient whose header could not be accepted is kept as
        /// its error, so that the others can still be used.
        let recipients: [Result<Recipient, JWEError>]
        let initializationVector: Data
        let ciphertext: Data
        let tag: Data
        /// The JSON serialization's `aad` member as it appeared, still base64url-encoded.
        let additionalDataEncoded: String?

        /// The headers of the recipients that parsed. Nothing in them is authenticated until the
        /// JWE has been decrypted.
        public var headers: [JWEHeader<Custom>] {
            recipients.compactMap { recipient in
                guard case .success(let recipient) = recipient else {
                    return nil
                }
                return recipient.header
            }
        }

        /// The header of the first recipient that parsed. A JWE in which no recipient's header
        /// parses is refused when it is parsed, so there always is one.
        public let header: JWEHeader<Custom>

        init(
            protectedEncoded: String,
            sharedUnprotected: [String: JSONValue],
            recipients: [Result<Recipient, JWEError>],
            initializationVector: Data,
            ciphertext: Data,
            tag: Data,
            additionalDataEncoded: String?
        ) throws(JWEError) {
            var failures: [JWEError] = []
            var first: JWEHeader<Custom>?
            for recipient in recipients {
                switch recipient {
                case .success(let recipient):
                    first = first ?? recipient.header
                case .failure(let error):
                    failures.append(error)
                }
            }
            guard let first else {
                throw .noUsableRecipient(reasons: failures)
            }
            self.header = first
            self.protectedEncoded = protectedEncoded
            self.sharedUnprotected = sharedUnprotected
            self.recipients = recipients
            self.initializationVector = initializationVector
            self.ciphertext = ciphertext
            self.tag = tag
            self.additionalDataEncoded = additionalDataEncoded
        }

        /// What the content encryption authenticates alongside the ciphertext (RFC 7516 §5.1
        /// step 14).
        var authenticatedData: Data {
            if let additionalDataEncoded {
                return Data((protectedEncoded + "." + additionalDataEncoded).utf8)
            }
            return Data(protectedEncoded.utf8)
        }

        /// Decrypts the JWE.
        ///
        /// - Parameters:
        ///   - keys: The keys to try. A recipient is only tried with decrypters for the `alg` it
        ///     names.
        ///   - contentEncryptions: The `enc` algorithms to accept. Defaults to those this package
        ///     implements.
        ///   - maximumDecompressedByteCount: For a compressed JWE (`zip`), the largest plaintext
        ///     accepted after decompression. 0 or less refuses compressed JWEs before any
        ///     cryptography is done.
        public func decrypt(
            with keys: DecryptionKeys,
            contentEncryptions: [any ContentEncryptionAlgorithm.Type] = ContentEncryption.standard,
            maximumDecompressedByteCount: Int = JWECompression.defaultMaximumDecompressedByteCount
        ) async throws(JWEError) -> Decrypted {
            var failures: [JWEError] = []
            for recipient in recipients {
                do throws(JWEError) {
                    let recipient = try recipient.get()
                    if recipient.header.compression != nil {
                        guard maximumDecompressedByteCount > 0 else {
                            throw JWEError.compressionNotAllowed
                        }
                    }
                    let decrypted = try await decrypt(recipient, with: keys, contentEncryptions: contentEncryptions)
                    let plaintext = try Self.decompress(
                        decrypted,
                        compression: recipient.header.compression,
                        limit: maximumDecompressedByteCount
                    )
                    var additionalData: Data?
                    if let additionalDataEncoded {
                        additionalData = try Data(jwePart: additionalDataEncoded, named: "aad")
                    }
                    return Decrypted(
                        header: recipient.header,
                        plaintext: plaintext,
                        additionalAuthenticatedData: additionalData
                    )
                } catch {
                    failures.append(error)
                }
            }
            if failures.count == 1 {
                throw failures[0]
            }
            throw .noRecipientDecrypted(reasons: failures)
        }

        /// The plaintext of an authenticated JWE, decompressed if its header says so.
        private static func decompress(
            _ content: Data,
            compression: JWECompression?,
            limit: Int
        ) throws(JWEError) -> Data {
            guard let compression else {
                return content
            }
            do {
                return try compression.decompress(content, limit: limit)
            } catch {
                switch error {
                case .tooLarge:
                    throw .decompressedSizeExceedsLimit(maximum: limit)
                case .malformed, .failed:
                    throw .invalidCompressedContent
                }
            }
        }

        private func decrypt(
            _ recipient: Recipient,
            with keys: DecryptionKeys,
            contentEncryptions: [any ContentEncryptionAlgorithm.Type]
        ) async throws(JWEError) -> Data {
            let header = recipient.header
            guard let encryption = contentEncryptions.first(where: { $0.identifier == header.contentEncryption })
            else {
                throw .unsupportedContentEncryption(
                    algorithm: header.contentEncryption,
                    allowed: contentEncryptions.map { $0.identifier }
                )
            }
            guard initializationVector.count == encryption.initializationVectorByteCount else {
                throw .wrongInitializationVectorSize(
                    algorithm: encryption.identifier,
                    expected: encryption.initializationVectorByteCount,
                    found: initializationVector.count
                )
            }
            guard tag.count == encryption.authenticationTagByteCount else {
                throw .wrongAuthenticationTagSize(
                    algorithm: encryption.identifier,
                    expected: encryption.authenticationTagByteCount,
                    found: tag.count
                )
            }
            let candidates = try keys.candidates(algorithm: header.algorithm, keyID: header.keyID)
            let request = KeyDecryptionRequest(
                encryptedKey: recipient.encryptedKey,
                contentEncryption: encryption.identifier,
                keyByteCount: encryption.keyByteCount,
                header: header.rawParameters
            )

            // Something knowable without the key, such as a missing `epk`, is reported in
            // preference to a cryptographic failure, whichever order the candidates are in.
            var structuralError: JWEError?
            for candidate in candidates {
                var contentKey: Data
                do {
                    contentKey = try await candidate.decryptKey(request)
                } catch {
                    guard error == .decryptionFailed else {
                        structuralError = structuralError ?? error
                        continue
                    }
                    // RFC 7516 §11.5: when the key cannot be unwrapped, carry on with a random
                    // key so that this failure looks the same, in outcome and in the work done,
                    // as a failure of the content's authentication tag.
                    contentKey = SymmetricKeyMaterial(randomByteCount: encryption.keyByteCount).rawRepresentation
                }
                if contentKey.count != encryption.keyByteCount {
                    contentKey = SymmetricKeyMaterial(randomByteCount: encryption.keyByteCount).rawRepresentation
                }
                do {
                    return try encryption.decrypt(
                        ciphertext,
                        tag: tag,
                        key: contentKey,
                        initializationVector: initializationVector,
                        additionalAuthenticatedData: authenticatedData
                    )
                } catch {
                    // Every content decryption failure is the same `.decryptionFailed`.
                    continue
                }
            }
            throw structuralError ?? .decryptionFailed
        }
    }

    /// The result of decrypting a JWE.
    public struct Decrypted: Sendable {
        /// The header of the recipient that was decrypted. Parameters named in its
        /// `unprotectedParameterNames` were not authenticated.
        public let header: JWEHeader<Custom>
        public let plaintext: Data
        /// The JSON serialization's additional authenticated data, if it had any.
        public let additionalAuthenticatedData: Data?
    }

    // MARK: Encryption

    /// Encrypts `plaintext` to one recipient.
    ///
    /// `alg` comes from the recipient's type and `enc` from `contentEncryption`; neither can be
    /// supplied separately. Every header parameter is placed in the protected header.
    public static func encrypt<Recipient: KeyEncrypter, Encryption: ContentEncryptionAlgorithm>(
        _ plaintext: Data,
        to recipient: Recipient,
        using contentEncryption: Encryption.Type,
        header: JWEHeaderParameters<Custom>,
        additionalAuthenticatedData: Data? = nil
    ) async throws(JWEError) -> Encrypted {
        try await encrypt(
            plaintext,
            to: [AnyKeyEncrypter(recipient)],
            using: contentEncryption,
            header: header,
            additionalAuthenticatedData: additionalAuthenticatedData
        )
    }

    /// Encrypts `plaintext` to several recipients, each of whom can decrypt it independently.
    ///
    /// With more than one recipient, `enc` and the caller's parameters are in the protected
    /// header and each recipient's `alg`, `kid` and key parameters are in that recipient's own
    /// header, which only the JSON serialization can carry. `header` may not then set `kid`.
    public static func encrypt<Encryption: ContentEncryptionAlgorithm>(
        _ plaintext: Data,
        to recipients: [AnyKeyEncrypter],
        using contentEncryption: Encryption.Type,
        header: JWEHeaderParameters<Custom>,
        additionalAuthenticatedData: Data? = nil
    ) async throws(JWEError) -> Encrypted {
        guard !recipients.isEmpty else {
            throw .noRecipients
        }
        guard recipients.count == 1 || header.keyID == nil else {
            throw .sharedKeyIDWithMultipleRecipients
        }
        var protected = try header.values()
        protected["enc"] = .string(Encryption.identifier.rawValue)

        var contentKey: Data?
        var results: [(AnyKeyEncrypter, KeyEncryptionResult)] = []
        for recipient in recipients {
            // A later `dir` or `ECDH-ES` recipient is handed the key already chosen and refuses it.
            let result = try await recipient.encryptKey(
                KeyEncryptionRequest(
                    contentEncryption: Encryption.identifier,
                    keyByteCount: Encryption.keyByteCount,
                    contentEncryptionKey: contentKey
                )
            )
            // A first `dir` or `ECDH-ES` recipient supplies the key itself, which shows as an
            // empty encrypted key. Its key must not be handed to anyone else, so this stops
            // before the next recipient is asked.
            guard recipients.count == 1 || !result.encryptedKey.isEmpty else {
                throw .algorithmRequiresSingleRecipient(algorithm: recipient.algorithm)
            }
            if let contentKey {
                guard result.contentEncryptionKey == contentKey else {
                    throw .algorithmRequiresSingleRecipient(algorithm: recipient.algorithm)
                }
            }
            contentKey = result.contentEncryptionKey
            results.append((recipient, result))
        }
        guard let contentKey, contentKey.count == Encryption.keyByteCount else {
            throw .contentEncryptionFailed(description: "the key encrypter did not supply a key of the right size")
        }

        var recipientHeaders: [[String: JSONValue]] = []
        for (recipient, result) in results {
            var values = result.headerParameters
            values["alg"] = .string(recipient.algorithm.rawValue)
            if let keyID = recipient.keyID, protected["kid"] == nil {
                values["kid"] = .string(keyID.rawValue)
            }
            recipientHeaders.append(values)
        }
        // A single recipient's parameters are all protected, which is also what makes the
        // compact serialization possible.
        if results.count == 1 {
            for (name, value) in recipientHeaders[0] {
                protected[name] = value
            }
            recipientHeaders[0] = [:]
        }

        let protectedJSON: Data
        do {
            protectedJSON = try JSONEncoder.deterministic().encode(protected)
        } catch {
            throw .headerEncodingFailed(description: String(describing: error))
        }
        let protectedEncoded = Base64URL.encode(protectedJSON)
        var additionalDataEncoded: String?
        if let additionalAuthenticatedData {
            additionalDataEncoded = Base64URL.encode(additionalAuthenticatedData)
        }

        var parsedRecipients: [Result<JWE.Recipient, JWEError>] = []
        for (index, (_, result)) in results.enumerated() {
            // Parsing our own header back keeps one definition of what a header means.
            let parsed = try JWEHeader<Custom>.parse(
                protectedJSON: protectedJSON,
                protected: protected,
                sharedUnprotected: [:],
                recipientUnprotected: recipientHeaders[index]
            )
            parsedRecipients.append(
                .success(
                    JWE.Recipient(
                        header: parsed,
                        encryptedKey: result.encryptedKey,
                        unprotected: recipientHeaders[index]
                    )
                )
            )
        }

        let initializationVector = SymmetricKeyMaterial(
            randomByteCount: Encryption.initializationVectorByteCount
        ).rawRepresentation
        var sealed = try Encrypted(
            protectedEncoded: protectedEncoded,
            sharedUnprotected: [:],
            recipients: parsedRecipients,
            initializationVector: initializationVector,
            ciphertext: Data(),
            tag: Data(),
            additionalDataEncoded: additionalDataEncoded
        )
        // `zip` is in the protected header, so it is authenticated along with the content.
        var content = plaintext
        if let compression = header.compression {
            do {
                content = try compression.compress(plaintext)
            } catch {
                throw .contentEncryptionFailed(description: "compression failed")
            }
        }
        let (ciphertext, tag) = try Encryption.encrypt(
            content,
            key: contentKey,
            initializationVector: initializationVector,
            additionalAuthenticatedData: sealed.authenticatedData
        )
        sealed = try Encrypted(
            protectedEncoded: protectedEncoded,
            sharedUnprotected: [:],
            recipients: parsedRecipients,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            tag: tag,
            additionalDataEncoded: additionalDataEncoded
        )
        return sealed
    }
}

extension JWE where Custom == EmptyHeaderParameters {
    /// Encrypts `plaintext` to one recipient, with a header of registered parameters only.
    public static func encrypt<Recipient: KeyEncrypter, Encryption: ContentEncryptionAlgorithm>(
        _ plaintext: Data,
        to recipient: Recipient,
        using contentEncryption: Encryption.Type
    ) async throws(JWEError) -> Encrypted {
        try await encrypt(plaintext, to: recipient, using: contentEncryption, header: JWEHeaderParameters())
    }
}

/// A JWE with registered header parameters only, which is the common case.
public typealias SimpleJWE = JWE<EmptyHeaderParameters>
