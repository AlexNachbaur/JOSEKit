import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWE

/// RFC 7520 §5 (JWE) and the RFC 8037 X25519 example, from the JOSE cookbook.
@Suite("RFC vectors: encryption")
struct EncryptionVectorTests {
    /// Examples with one recipient whose algorithms this package implements, keyed by a JWK.
    static let singleRecipient = [
        "jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json",
        "jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json",
        "jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json",
        "jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json",
        "jwe/5_6.direct_encryption_using_aes-gcm.json",
        "jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json",
        "jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json",
        "jwe/5_10.including_additional_authentication_data.json",
        "jwe/5_11.protecting_specific_header_fields.json",
        "jwe/5_12.protecting_content_only.json",
        "curve25519/ecdh-es.json",
    ]

    /// Every serialization the example gives, parsed.
    private func serializations(_ vector: Vector) throws -> [(String, SimpleJWE.Encrypted)] {
        var parsed: [(String, SimpleJWE.Encrypted)] = []
        for form in ["compact", "json", "json_flat"] where vector.has("output", form) {
            let serialization = try vector.value("output", form)
            if case .string(let compact) = serialization {
                parsed.append((form, try SimpleJWE.Encrypted(compact: compact)))
            } else {
                parsed.append((form, try SimpleJWE.Encrypted(json: try serialization.json)))
            }
        }
        return parsed
    }

    @Test("every serialization of each example decrypts to the plaintext", arguments: singleRecipient)
    func decrypts(file: String) async throws {
        let vector = try Vector(file)
        let keys = DecryptionKeys([
            try VectorKeys.decrypter(
                algorithm: try vector.string("input", "alg"),
                key: try vector.value("input", "key")
            )
        ])
        let plaintext = Data(try vector.string("input", "plaintext").utf8)
        let parsed = try serializations(vector)
        #expect(parsed.count >= 2, "\(file) has fewer serializations than expected")
        for (form, jwe) in parsed {
            #expect(try await jwe.decrypt(with: keys).plaintext == plaintext, "\(file) \(form)")
        }
    }

    @Test("RFC 7520 §5.3: PBES2 decrypts with the example's password")
    func passwordBased() async throws {
        let vector = try Vector("jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json")
        let decrypter = PBES2Decrypter<PBES2HS512A256KW>(password: try vector.string("input", "pwd"))
        let plaintext = Data(try vector.string("input", "plaintext").utf8)
        for (form, jwe) in try serializations(vector) {
            #expect(
                try await jwe.decrypt(with: DecryptionKeys([AnyKeyDecrypter(decrypter)])).plaintext == plaintext,
                "\(form)"
            )
        }
    }

    @Test("RFC 7520 §5.13: each of the three recipients decrypts the multi-recipient example")
    func multipleRecipients() async throws {
        let vector = try Vector("jwe/5_13.encrypting_to_multiple_recipients.json")
        let algorithms = try vector.value("input", "alg").elements.map { try $0.text }
        let keys = try vector.value("input", "key").elements
        let plaintext = Data(try vector.string("input", "plaintext").utf8)
        let jwe = try SimpleJWE.Encrypted(json: try vector.value("output", "json").json)
        #expect(jwe.headers.map(\.algorithm.rawValue) == algorithms)
        #expect(algorithms == ["RSA1_5", "ECDH-ES+A256KW", "A256GCMKW"])
        for (algorithm, key) in zip(algorithms, keys) {
            let keys = DecryptionKeys([try VectorKeys.decrypter(algorithm: algorithm, key: key)])
            let decrypted = try await jwe.decrypt(with: keys)
            #expect(decrypted.plaintext == plaintext, "\(algorithm)")
            #expect(decrypted.header.algorithm.rawValue == algorithm)
            #expect(decrypted.header.contentType == "text/plain")
        }
    }

    /// The protected header, and the AAD when there is one, as content encryption
    /// authenticates them (RFC 7516 §5.1 step 14).
    private func authenticatedData(_ vector: Vector) throws -> Data {
        var text = ""
        if vector.has("encrypting_content", "protected_b64u") {
            text = try vector.string("encrypting_content", "protected_b64u")
        }
        if vector.has("generated", "aad_b64u") {
            text += "." + (try vector.string("generated", "aad_b64u"))
        }
        return Data(text.utf8)
    }

    /// Content encryption is deterministic given the key and IV, so each example's ciphertext and
    /// tag must come out exactly.
    @Test("content encryption reproduces each example's ciphertext and tag")
    func reproducesContentEncryption() throws {
        let encryptions: [String: any ContentEncryptionAlgorithm.Type] = [
            "A128GCM": A128GCM.self, "A192GCM": A192GCM.self, "A256GCM": A256GCM.self,
            "A128CBC-HS256": A128CBCHS256.self, "A192CBC-HS384": A192CBCHS384.self,
            "A256CBC-HS512": A256CBCHS512.self,
        ]
        let reproducible =
            Self.singleRecipient.filter { $0.hasPrefix("jwe/") } + [
                "jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json"
            ]
        for file in reproducible {
            let vector = try Vector(file)
            let name = try vector.string("input", "enc")
            guard let encryption = encryptions[name] else {
                Issue.record("\(file): no content encryption \(name)")
                continue
            }
            // §5.5 derives the key by ECDH-ES and records it with the key agreement; §5.6 uses the
            // input key directly; the others generate it.
            let key: Data
            if vector.has("encrypting_key", "cek") {
                key = try vector.bytes("encrypting_key", "cek")
            } else if vector.has("generated", "cek") {
                key = try vector.bytes("generated", "cek")
            } else {
                key = try SymmetricJWK(json: try vector.value("input", "key").json).key.rawRepresentation
            }
            let (ciphertext, tag) = try encryption.encrypt(
                Data(try vector.string("input", "plaintext").utf8),
                key: key,
                initializationVector: try vector.bytes("generated", "iv"),
                additionalAuthenticatedData: try authenticatedData(vector)
            )
            #expect(ciphertext == (try vector.bytes("encrypting_content", "ciphertext")), "\(file)")
            #expect(tag == (try vector.bytes("encrypting_content", "tag")), "\(file)")
        }
    }

    /// AES Key Wrap is deterministic, so wrapping the example's content key must give exactly
    /// its encrypted key.
    @Test("AES Key Wrap reproduces each example's encrypted key")
    func reproducesKeyWrap() throws {
        for file in [
            "jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json",
            "jwe/5_10.including_additional_authentication_data.json",
            "jwe/5_11.protecting_specific_header_fields.json",
            "jwe/5_12.protecting_content_only.json",
        ] {
            let vector = try Vector(file)
            let wrappingKey = try SymmetricJWK(json: try vector.value("input", "key").json).key.rawRepresentation
            let wrapped = try AESKeyWrapping.wrap(try vector.bytes("generated", "cek"), with: wrappingKey)
            #expect(wrapped == (try vector.bytes("encrypting_key", "encrypted_key")), "\(file)")
        }
    }

    @Test("an altered tag is refused with the uniform decryption error", arguments: singleRecipient)
    func refusesTampering(file: String) async throws {
        let vector = try Vector(file)
        let keys = DecryptionKeys([
            try VectorKeys.decrypter(
                algorithm: try vector.string("input", "alg"),
                key: try vector.value("input", "key")
            )
        ])
        guard case .object(var flattened) = try vector.value("output", "json_flat") else {
            throw VectorError(description: "\(file): json_flat is not an object")
        }
        var tag = try vector.bytes("encrypting_content", "tag")
        tag[0] ^= 0x01
        flattened["tag"] = .string(Base64URL.encode(tag))
        let tampered = try SimpleJWE.Encrypted(json: try JSONValue.object(flattened).json)
        await #expect(throws: JWEError.decryptionFailed, "\(file)") {
            try await tampered.decrypt(with: keys)
        }
    }

    // MARK: Not yet supported

    /// RFC 7520 §5.9 uses `zip`, which this package does not implement yet. This records how it
    /// is refused today; it changes when support is added.
    @Test("the compressed example is refused, naming what is unsupported")
    func unsupported() async throws {
        let compressed = try Vector("jwe/5_9.compressed_content.json")
        #expect(throws: JWEError.compressionNotSupported) {
            try SimpleJWE.Encrypted(compact: try compressed.string("output", "compact"))
        }
    }
}
