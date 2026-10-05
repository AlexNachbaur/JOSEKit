import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWE

@Suite("JWE")
struct JWETests {
    typealias Plain = JWE<EmptyHeaderParameters>

    static let plaintext = Data("the quick brown fox".utf8)

    private func secret(_ byteCount: Int) -> SymmetricKeyMaterial {
        SymmetricKeyMaterial(randomByteCount: byteCount)
    }

    /// Encrypts with `encrypter`, round-trips through the compact form, and decrypts with `decrypter`.
    private func roundTrip<E: KeyEncrypter, D: KeyDecrypter, C: ContentEncryptionAlgorithm>(
        _ encrypter: E,
        _ decrypter: D,
        _ encryption: C.Type
    ) async throws {
        let sealed = try Plain.encrypt(Self.plaintext, to: encrypter, using: encryption)
        let compact = try sealed.compactSerialization()
        #expect(compact.split(separator: ".", omittingEmptySubsequences: false).count == 5)
        let parsed = try Plain.Encrypted(compact: compact)
        #expect(parsed.header?.algorithm == E.Algorithm.identifier)
        #expect(parsed.header?.contentEncryption == C.identifier)
        let decrypted = try await parsed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(decrypter)]))
        #expect(decrypted.plaintext == Self.plaintext, "\(E.Algorithm.identifier) / \(C.identifier)")
    }

    @Test("every key management algorithm round-trips")
    func keyManagementRoundTrips() async throws {
        let direct = DirectKey(key: secret(32))
        try await roundTrip(direct, direct, A256GCM.self)

        let kw128 = try AESKeyWrapKey<A128KW>(key: secret(16))
        try await roundTrip(kw128, kw128, A128GCM.self)
        let kw192 = try AESKeyWrapKey<A192KW>(key: secret(24))
        try await roundTrip(kw192, kw192, A192GCM.self)
        let kw256 = try AESKeyWrapKey<A256KW>(key: secret(32))
        try await roundTrip(kw256, kw256, A256CBCHS512.self)

        let gcm128 = try AESGCMKeyWrapKey<A128GCMKW>(key: secret(16))
        try await roundTrip(gcm128, gcm128, A128CBCHS256.self)
        let gcm192 = try AESGCMKeyWrapKey<A192GCMKW>(key: secret(24))
        try await roundTrip(gcm192, gcm192, A192CBCHS384.self)
        let gcm256 = try AESGCMKeyWrapKey<A256GCMKW>(key: secret(32))
        try await roundTrip(gcm256, gcm256, A256GCM.self)

        let p256 = try ECPrivateKey<P256Curve>()
        try await roundTrip(
            ECDHESEncrypter<ECDHES>(recipient: p256.publicKey),
            ECDHESDecrypter<ECDHES, ECPrivateKey<P256Curve>>(privateKey: p256),
            A128GCM.self
        )
        let p384 = try ECPrivateKey<P384Curve>()
        try await roundTrip(
            ECDHESEncrypter<ECDHESA128KW>(recipient: p384.publicKey),
            ECDHESDecrypter<ECDHESA128KW, ECPrivateKey<P384Curve>>(privateKey: p384),
            A256CBCHS512.self
        )
        let p521 = try ECPrivateKey<P521Curve>()
        try await roundTrip(
            ECDHESEncrypter<ECDHESA192KW>(recipient: p521.publicKey),
            ECDHESDecrypter<ECDHESA192KW, ECPrivateKey<P521Curve>>(privateKey: p521),
            A192GCM.self
        )
        let x25519 = try X25519PrivateKey()
        try await roundTrip(
            ECDHESEncrypter<ECDHESA256KW>(recipient: x25519.publicKey),
            ECDHESDecrypter<ECDHESA256KW, X25519PrivateKey>(privateKey: x25519),
            A256GCM.self
        )
        try await roundTrip(
            ECDHESEncrypter<ECDHES>(recipient: x25519.publicKey),
            ECDHESDecrypter<ECDHES, X25519PrivateKey>(privateKey: x25519),
            A256CBCHS512.self
        )

        let rsa = try RSAPrivateKey()
        try await roundTrip(
            try RSAOAEPEncrypter<RSAOAEP>(publicKey: rsa.publicKey),
            try RSAOAEPDecrypter<RSAOAEP>(privateKey: rsa),
            A128CBCHS256.self
        )
        try await roundTrip(
            try RSAOAEPEncrypter<RSAOAEP256>(publicKey: rsa.publicKey),
            try RSAOAEPDecrypter<RSAOAEP256>(privateKey: rsa),
            A256GCM.self
        )
    }

    @Test("the protected header is written with sorted members; alg and enc come from the types")
    func protectedHeader() throws {
        let key = try AESKeyWrapKey<A256KW>(key: secret(32), keyID: "k1")
        let sealed = try Plain.encrypt(
            Self.plaintext,
            to: key,
            using: A256GCM.self,
            header: JWEHeaderParameters(type: "JWT")
        )
        let headerSegment = String(try sealed.compactSerialization().split(separator: ".")[0])
        let json = String(decoding: try Base64URL.decode(headerSegment), as: UTF8.self)
        #expect(json == #"{"alg":"A256KW","enc":"A256GCM","kid":"k1","typ":"JWT"}"#)

        let explicit = try Plain.encrypt(
            Self.plaintext,
            to: key,
            using: A256GCM.self,
            header: JWEHeaderParameters(keyID: "explicit")
        )
        #expect(explicit.header?.keyID == "explicit")
    }

    @Test("encryption is randomised: the same input gives a different IV, key and ciphertext each time")
    func randomised() throws {
        let key = try AESKeyWrapKey<A256KW>(key: secret(32))
        let first = try Plain.encrypt(Self.plaintext, to: key, using: A256GCM.self)
        let second = try Plain.encrypt(Self.plaintext, to: key, using: A256GCM.self)
        #expect(first.initializationVector != second.initializationVector)
        #expect(first.ciphertext != second.ciphertext)
        #expect(first.initializationVector.count == 12)
        #expect(first.tag.count == 16)
        let cbc = try Plain.encrypt(Self.plaintext, to: key, using: A128CBCHS256.self)
        #expect(cbc.initializationVector.count == 16)
        #expect(cbc.tag.count == 16)
        #expect(cbc.ciphertext.count == 32)
        // AES-GCM-KW uses a fresh IV for the key wrap too.
        let gcmKey = try AESGCMKeyWrapKey<A256GCMKW>(key: secret(32))
        let a = try Plain.encrypt(Self.plaintext, to: gcmKey, using: A256GCM.self)
        let b = try Plain.encrypt(Self.plaintext, to: gcmKey, using: A256GCM.self)
        #expect(a.header?.rawParameters["iv"] != b.header?.rawParameters["iv"])
    }

    @Test("a wrong key and a tampered JWE fail identically")
    func uniformFailure() async throws {
        let rsa = try RSAPrivateKey()
        let sealed = try Plain.encrypt(
            Self.plaintext,
            to: try RSAOAEPEncrypter<RSAOAEP256>(publicKey: rsa.publicKey),
            using: A256GCM.self
        )
        let right = DecryptionKeys([AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP256>(privateKey: rsa))])
        let wrong = DecryptionKeys([AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP256>(privateKey: try RSAPrivateKey()))])
        #expect(try await sealed.decrypt(with: right).plaintext == Self.plaintext)
        #expect(
            await thrown { () async throws(JWEError) in try await sealed.decrypt(with: wrong) } == .decryptionFailed
        )

        var parts = try sealed.compactSerialization().split(separator: ".").map(String.init)
        var tag = try Base64URL.decode(parts[4])
        tag[0] ^= 0x01
        parts[4] = Base64URL.encode(tag)
        let tampered = try Plain.Encrypted(compact: parts.joined(separator: "."))
        #expect(
            await thrown { () async throws(JWEError) in try await tampered.decrypt(with: right) } == .decryptionFailed
        )
    }

    @Test("a decrypter that returns a key of the wrong size is treated as a failed decryption")
    func wrongSizeContentKey() async throws {
        struct ShortKey: KeyDecrypter {
            typealias Algorithm = A256KW
            let keyID: KeyID? = nil
            func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
                Data(count: 5)
            }
        }
        let key = try AESKeyWrapKey<A256KW>(key: secret(32))
        let sealed = try Plain.encrypt(Self.plaintext, to: key, using: A256GCM.self)
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(ShortKey())]))
            }
                == .decryptionFailed
        )
    }

    @Test("a content encryption algorithm is never handed a key of the wrong size")
    func contentEncryptionKeySizeIsEnforced() async throws {
        // An algorithm that, unlike the built-in ones, does not check its key size and "decrypts"
        // anything when given a short key. The engine must not rely on the algorithm to object.
        struct Careless: ContentEncryptionAlgorithm {
            static let identifier: AlgorithmIdentifier = "X-CARELESS"
            static let keyByteCount = 32
            static let initializationVectorByteCount = 12
            static let authenticationTagByteCount = 16

            static func encrypt(
                _ plaintext: Data,
                key: Data,
                initializationVector: Data,
                additionalAuthenticatedData: Data
            ) throws(JWEError) -> (ciphertext: Data, tag: Data) {
                try A256GCM.encrypt(
                    plaintext,
                    key: key,
                    initializationVector: initializationVector,
                    additionalAuthenticatedData: additionalAuthenticatedData
                )
            }

            static func decrypt(
                _ ciphertext: Data,
                tag: Data,
                key: Data,
                initializationVector: Data,
                additionalAuthenticatedData: Data
            ) throws(JWEError) -> Data {
                guard key.count == keyByteCount else {
                    return Data("accepted a short key".utf8)
                }
                return try A256GCM.decrypt(
                    ciphertext,
                    tag: tag,
                    key: key,
                    initializationVector: initializationVector,
                    additionalAuthenticatedData: additionalAuthenticatedData
                )
            }
        }
        struct ShortKey: KeyDecrypter {
            typealias Algorithm = A256KW
            let keyID: KeyID? = nil
            func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
                Data(count: 5)
            }
        }
        let key = try AESKeyWrapKey<A256KW>(key: secret(32))
        let sealed = try Plain.encrypt(Self.plaintext, to: key, using: Careless.self)
        // Positive control: the custom algorithm works with the right key.
        let opened = try await sealed.decrypt(
            with: DecryptionKeys([AnyKeyDecrypter(key)]),
            contentEncryptions: [Careless.self]
        )
        #expect(opened.plaintext == Self.plaintext)
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(
                    with: DecryptionKeys([AnyKeyDecrypter(ShortKey())]),
                    contentEncryptions: [Careless.self]
                )
            } == .decryptionFailed
        )
    }

    @Test("a key encrypter that ignores the key chosen for an earlier recipient is caught")
    func encrypterMustUseSharedKey() throws {
        struct OwnKey: KeyEncrypter {
            typealias Algorithm = A256KW
            let keyID: KeyID? = nil
            func encryptKey(_ request: KeyEncryptionRequest) throws(JWEError) -> KeyEncryptionResult {
                // Wrongly makes up its own content key instead of using `request.keyToWrap()`.
                KeyEncryptionResult(contentEncryptionKey: Data(repeating: 7, count: 32), encryptedKey: Data(count: 40))
            }
        }
        let wrap = AnyKeyEncrypter(try AESKeyWrapKey<A256KW>(key: secret(32)))
        _ = try Plain.encrypt(
            Self.plaintext,
            to: [AnyKeyEncrypter(OwnKey())],
            using: A256GCM.self,
            header: JWEHeaderParameters()
        )
        #expect(throws: JWEError.algorithmRequiresSingleRecipient(algorithm: "A256KW")) {
            try Plain.encrypt(
                Self.plaintext,
                to: [wrap, AnyKeyEncrypter(OwnKey())],
                using: A256GCM.self,
                header: JWEHeaderParameters()
            )
        }
    }

    @Test("keys of the wrong size are refused with the sizes named")
    func keySizes() async throws {
        #expect(throws: JWEError.keyWrongSize(algorithm: "A128KW", expected: 16, found: 32)) {
            try AESKeyWrapKey<A128KW>(key: secret(32))
        }
        #expect(throws: JWEError.keyWrongSize(algorithm: "A256GCMKW", expected: 32, found: 16)) {
            try AESGCMKeyWrapKey<A256GCMKW>(key: secret(16))
        }
        let direct = DirectKey(key: secret(16))
        #expect(throws: JWEError.keyWrongSize(algorithm: "dir", expected: 32, found: 16)) {
            try Plain.encrypt(Self.plaintext, to: direct, using: A256GCM.self)
        }
        // And on the way in: a dir token for A256GCM cannot be opened with a 16-byte key.
        let sealed = try Plain.encrypt(Self.plaintext, to: DirectKey(key: secret(32)), using: A256GCM.self)
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(direct)]))
            }
                == .keyWrongSize(algorithm: "dir", expected: 32, found: 16)
        )
    }

    @Test("a recipient is only tried with decrypters for its own algorithm and key ID")
    func keySelection() async throws {
        let material = secret(32)
        let encrypter = try AESKeyWrapKey<A256KW>(key: material, keyID: "right")
        let sealed = try Plain.encrypt(Self.plaintext, to: encrypter, using: A256GCM.self)
        func outcome(_ decrypters: [AnyKeyDecrypter]) async -> JWEError? {
            await thrown { () async throws(JWEError) in try await sealed.decrypt(with: DecryptionKeys(decrypters)) }
        }
        let right = AnyKeyDecrypter(try AESKeyWrapKey<A256KW>(key: material, keyID: "right"))
        let unnamed = AnyKeyDecrypter(try AESKeyWrapKey<A256KW>(key: material))
        let sameKeyOtherID = AnyKeyDecrypter(try AESKeyWrapKey<A256KW>(key: material, keyID: "other"))
        let wrongKeyRightID = AnyKeyDecrypter(try AESKeyWrapKey<A256KW>(key: secret(32), keyID: "right"))
        let otherAlgorithm = AnyKeyDecrypter(try AESGCMKeyWrapKey<A256GCMKW>(key: material, keyID: "right"))

        #expect(await outcome([right]) == nil)
        #expect(await outcome([unnamed]) == nil)
        #expect(await outcome([wrongKeyRightID, right]) == nil)
        #expect(await outcome([sameKeyOtherID]) == .noDecrypterForKeyID(keyID: "right", algorithm: "A256KW"))
        #expect(await outcome([wrongKeyRightID]) == .decryptionFailed)
        #expect(
            await outcome([otherAlgorithm]) == .noDecrypterForAlgorithm(algorithm: "A256KW", offered: ["A256GCMKW"])
        )
        #expect(await outcome([]) == .noDecrypterForAlgorithm(algorithm: "A256KW", offered: []))
    }

    @Test("content encryption can be restricted, and the default is everything this package implements")
    func contentEncryptionAllowList() async throws {
        let key = try AESKeyWrapKey<A256KW>(key: secret(32))
        let keys = DecryptionKeys([AnyKeyDecrypter(key)])
        let sealed = try Plain.encrypt(Self.plaintext, to: key, using: A128CBCHS256.self)
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)
        #expect(
            try await sealed.decrypt(with: keys, contentEncryptions: [A128CBCHS256.self]).plaintext == Self.plaintext
        )
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(with: keys, contentEncryptions: [A256GCM.self, A128GCM.self])
            } == .unsupportedContentEncryption(algorithm: "A128CBC-HS256", allowed: ["A256GCM", "A128GCM"])
        )
        #expect(ContentEncryption.standard.count == 6)
    }

    // MARK: Serializations and recipients

    @Test("a single-recipient JWE round-trips through all three serializations, with additional data in JSON")
    func serializations() async throws {
        let key = try AESKeyWrapKey<A256KW>(key: secret(32), keyID: "k")
        let keys = DecryptionKeys([AnyKeyDecrypter(key)])
        let sealed = try Plain.encrypt(Self.plaintext, to: key, using: A256GCM.self)
        #expect(
            try await Plain.Encrypted(json: try sealed.flattenedJSONSerialization()).decrypt(with: keys).plaintext
                == Self.plaintext
        )
        #expect(
            try await Plain.Encrypted(json: try sealed.generalJSONSerialization()).decrypt(with: keys).plaintext
                == Self.plaintext
        )

        let aad = Data("bound context".utf8)
        let withAAD = try Plain.encrypt(
            Self.plaintext,
            to: key,
            using: A256GCM.self,
            header: JWEHeaderParameters(),
            additionalAuthenticatedData: aad
        )
        #expect(
            throws: JWEError.notRepresentable(serialization: "compact", reason: "it has additional authenticated data")
        ) {
            try withAAD.compactSerialization()
        }
        let decrypted = try await Plain.Encrypted(json: try withAAD.flattenedJSONSerialization()).decrypt(with: keys)
        #expect(decrypted.plaintext == Self.plaintext)
        #expect(decrypted.additionalAuthenticatedData == aad)

        var document = try JSONDecoder().decode(
            [String: JSONValue].self,
            from: try withAAD.flattenedJSONSerialization()
        )
        document["aad"] = nil
        let stripped = try Plain.Encrypted(json: try JSONEncoder().encode(document))
        #expect(
            await thrown { () async throws(JWEError) in try await stripped.decrypt(with: keys) } == .decryptionFailed
        )
    }

    @Test("a JWE for several recipients can be opened by each, and only in the general form")
    func multipleRecipients() async throws {
        let rsa = try RSAPrivateKey()
        let ec = try ECPrivateKey<P256Curve>()
        let shared = secret(32)
        let recipients = [
            AnyKeyEncrypter(try RSAOAEPEncrypter<RSAOAEP256>(publicKey: rsa.publicKey, keyID: "rsa")),
            AnyKeyEncrypter(ECDHESEncrypter<ECDHESA256KW>(recipient: ec.publicKey, keyID: "ec")),
            AnyKeyEncrypter(try AESGCMKeyWrapKey<A256GCMKW>(key: shared, keyID: "shared")),
        ]
        let sealed = try Plain.encrypt(
            Self.plaintext,
            to: recipients,
            using: A256GCM.self,
            header: JWEHeaderParameters(type: "example")
        )
        #expect(sealed.headers.map(\.keyID) == ["rsa", "ec", "shared"])
        #expect(sealed.headers.map(\.algorithm) == ["RSA-OAEP-256", "ECDH-ES+A256KW", "A256GCMKW"])
        // enc and the caller's parameters are protected; each recipient's alg is its own.
        #expect(sealed.headers[1].unprotectedParameterNames == ["alg", "kid", "epk"])
        #expect(sealed.headers[2].unprotectedParameterNames == ["alg", "kid", "iv", "tag"])
        #expect(sealed.headers[0].type == "example")

        #expect(throws: JWEError.notRepresentable(serialization: "compact", reason: "it has 3 recipients")) {
            try sealed.compactSerialization()
        }
        #expect(throws: JWEError.notRepresentable(serialization: "flattened JSON", reason: "it has 3 recipients")) {
            try sealed.flattenedJSONSerialization()
        }

        let parsed = try Plain.Encrypted(json: try sealed.generalJSONSerialization())
        let decrypters = [
            AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP256>(privateKey: rsa)),
            AnyKeyDecrypter(ECDHESDecrypter<ECDHESA256KW, ECPrivateKey<P256Curve>>(privateKey: ec)),
            AnyKeyDecrypter(try AESGCMKeyWrapKey<A256GCMKW>(key: shared)),
        ]
        for (index, decrypter) in decrypters.enumerated() {
            let decrypted = try await parsed.decrypt(with: DecryptionKeys([decrypter]))
            #expect(decrypted.plaintext == Self.plaintext)
            #expect(decrypted.header.keyID == sealed.headers[index].keyID)
        }
    }

    @Test("dir and ECDH-ES cannot share a JWE with other recipients, in either position")
    func singleRecipientAlgorithms() throws {
        let wrap = AnyKeyEncrypter(try AESKeyWrapKey<A256KW>(key: secret(32)))
        let direct = AnyKeyEncrypter(DirectKey(key: secret(32)))
        let agreement = AnyKeyEncrypter(ECDHESEncrypter<ECDHES>(recipient: (try ECPrivateKey<P256Curve>()).publicKey))
        func attempt(_ recipients: [AnyKeyEncrypter]) -> JWEError? {
            do {
                _ = try Plain.encrypt(
                    Self.plaintext,
                    to: recipients,
                    using: A256GCM.self,
                    header: JWEHeaderParameters()
                )
                return nil
            } catch {
                return error
            }
        }
        #expect(attempt([wrap, wrap]) == nil)
        #expect(attempt([wrap, direct]) == .algorithmRequiresSingleRecipient(algorithm: "dir"))
        #expect(attempt([wrap, agreement]) == .algorithmRequiresSingleRecipient(algorithm: "ECDH-ES"))
        // First in line: the next recipient would be handed a key it did not choose, which a
        // wrapping algorithm accepts, so it is the direct one that has to object.
        #expect(attempt([direct, direct]) == .algorithmRequiresSingleRecipient(algorithm: "dir"))
        #expect(attempt([agreement, agreement]) == .algorithmRequiresSingleRecipient(algorithm: "ECDH-ES"))
        #expect(attempt([]) == .noRecipients)
    }

    @Test("one unusable recipient does not stop another from decrypting")
    func unusableRecipientIsSkipped() async throws {
        let key = try AESKeyWrapKey<A256KW>(key: secret(32))
        let sealed = try Plain.encrypt(
            Self.plaintext,
            to: [AnyKeyEncrypter(key), AnyKeyEncrypter(key)],
            using: A256GCM.self,
            header: JWEHeaderParameters()
        )
        var document = try JSONDecoder().decode([String: JSONValue].self, from: try sealed.generalJSONSerialization())
        guard case .array(var recipients) = document["recipients"], case .object(var first) = recipients[0] else {
            Issue.record("unexpected JSON shape")
            return
        }
        // The first recipient's header now repeats a protected parameter, which makes it unusable.
        first["header"] = ["alg": "A256KW", "enc": "A256GCM"]
        recipients[0] = .object(first)
        document["recipients"] = .array(recipients)
        let parsed = try Plain.Encrypted(json: try JSONEncoder().encode(document))
        #expect(parsed.headers.count == 1)
        #expect(try await parsed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(key)])).plaintext == Self.plaintext)
    }

    @Test("malformed JSON serializations report what is wrong")
    func invalidJSON() {
        func parse(_ json: String) -> JWEError? {
            do {
                _ = try Plain.Encrypted(json: Data(json.utf8))
                return nil
            } catch {
                return error
            }
        }
        let header = Base64URL.encode(Data(#"{"alg":"dir","enc":"A256GCM"}"#.utf8))
        #expect(parse(#"{"protected":"\#(header)","iv":"AAAA","ciphertext":"AAAA","tag":"AAAA"}"#) == nil)
        #expect(parse("[]") == .invalidJSONStructure(.rootNotObject))
        #expect(
            parse(#"{"protected":"\#(header)","iv":"AAAA","tag":"AAAA"}"#)
                == .invalidJSONSerialization(reason: "\"ciphertext\" is missing")
        )
        #expect(
            parse(#"{"protected":1,"ciphertext":"AAAA"}"#)
                == .invalidJSONSerialization(reason: "\"protected\" must be a string")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","unprotected":1}"#)
                == .invalidJSONSerialization(reason: "\"unprotected\" must be an object")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","header":1}"#)
                == .invalidJSONSerialization(reason: "\"header\" must be an object")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","encrypted_key":1}"#)
                == .invalidJSONSerialization(reason: "\"encrypted_key\" must be a string")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","recipients":[]}"#)
                == .invalidJSONSerialization(reason: "\"recipients\" must be a non-empty array")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","recipients":[1]}"#)
                == .invalidJSONSerialization(reason: "\"recipients\" must contain objects")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","recipients":[{}],"encrypted_key":"AA"}"#)
                == .invalidJSONSerialization(reason: "\"encrypted_key\" and \"recipients\" are both present")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","header":{"alg":"dir"}}"#)
                == .headerParameterInMultipleHeaders(name: "alg")
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","unprotected":{"x":1},"header":{"x":2}}"#)
                == .headerParameterInMultipleHeaders(name: "x")
        )
        #expect(parse(#"{"ciphertext":"AAAA"}"#) == .missingAlgorithm)
        #expect(parse(#"{"protected":"\#(header)","ciphertext":"AA=A"}"#) == .paddingNotAllowed(part: "ciphertext"))
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","aad":"!!"}"#)
                == .invalidBase64URL(part: "aad", .invalidCharacter(byte: 0x21, offset: 0))
        )
        #expect(
            parse(#"{"protected":"\#(header)","ciphertext":"AAAA","unprotected":{"crit":["x"],"x":1}}"#)
                == .headerParameterNotProtected(name: "crit")
        )
    }

    // MARK: Headers

    @Test("a custom header type round-trips, and its critical parameters are enforced")
    func customHeader() async throws {
        let key = try AESKeyWrapKey<A256KW>(key: secret(32))
        let keys = DecryptionKeys([AnyKeyDecrypter(key)])
        let header = JWEHeaderParameters(contentType: "JWT", custom: ExampleHeader(level: 3, must: "understood"))
        let sealed = try JWE<ExampleHeader>.encrypt(Self.plaintext, to: key, using: A256GCM.self, header: header)
        #expect(sealed.header?.critical == ["urn:example:must"])
        let compact = try sealed.compactSerialization()

        let decrypted = try await JWE<ExampleHeader>.Encrypted(compact: compact).decrypt(with: keys)
        #expect(decrypted.header.custom == ExampleHeader(level: 3, must: "understood"))
        #expect(decrypted.header.contentType == "application/jwt")

        // A reader that does not know the critical extension must refuse the JWE.
        #expect(throws: JWEError.unsupportedCriticalParameter(name: "urn:example:must")) {
            try Plain.Encrypted(compact: compact)
        }
    }

    @Test("a custom header type cannot set alg, enc or any other parameter this package owns")
    func customHeaderCannotOverride() throws {
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
        let key = try AESKeyWrapKey<A256KW>(key: secret(32))
        _ = try JWE<Hostile>.encrypt(
            Self.plaintext,
            to: key,
            using: A256GCM.self,
            header: JWEHeaderParameters(custom: Hostile(["x": "y"]))
        )
        for name in [
            "alg", "enc", "zip", "kid", "typ", "cty", "crit", "epk", "apu", "apv", "iv", "tag", "jwk", "p2s", "p2c",
        ] {
            #expect(throws: JWEError.customParameterCollision(name: name), "\(name)") {
                try JWE<Hostile>.encrypt(
                    Self.plaintext,
                    to: key,
                    using: A256GCM.self,
                    header: JWEHeaderParameters(custom: Hostile([name: "dir"]))
                )
            }
        }
    }

    // MARK: ECDH-ES details

    private func ecdhToken(header: String, from sealed: Plain.Encrypted) throws -> Plain.Encrypted {
        var parts = try sealed.compactSerialization().split(separator: ".", omittingEmptySubsequences: false).map(
            String.init
        )
        parts[0] = Base64URL.encode(Data(header.utf8))
        return try Plain.Encrypted(compact: parts.joined(separator: "."))
    }

    @Test("a missing, malformed, private, off-curve or wrong-curve epk is refused with its cause")
    func ephemeralKeyValidation() async throws {
        let recipient = try ECPrivateKey<P256Curve>()
        let keys = DecryptionKeys([
            AnyKeyDecrypter(ECDHESDecrypter<ECDHES, ECPrivateKey<P256Curve>>(privateKey: recipient))
        ])
        let sealed = try Plain.encrypt(
            Self.plaintext,
            to: ECDHESEncrypter<ECDHES>(recipient: recipient.publicKey),
            using: A256GCM.self
        )
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)

        func outcome(epk: String?) async throws -> JWEError? {
            var header = #"{"alg":"ECDH-ES","enc":"A256GCM""#
            if let epk {
                header += #","epk":\#(epk)"#
            }
            let token = try ecdhToken(header: header + "}", from: sealed)
            return await thrown { () async throws(JWEError) in try await token.decrypt(with: keys) }
        }
        #expect(try await outcome(epk: nil) == .missingHeaderParameter(name: "epk", algorithm: "ECDH-ES"))
        #expect(try await outcome(epk: #""x""#) == .headerParameterWrongType(name: "epk", expected: "an object"))

        let privateJSON = String(
            decoding: try PrivateJWK(.p256(try ECPrivateKey<P256Curve>())).jsonRepresentation(),
            as: UTF8.self
        )
        #expect(
            try await outcome(epk: privateJSON)
                == .invalidEphemeralKey(.privateMemberInPublicKey(member: "d", keyType: "EC"))
        )

        let zeros = String(repeating: "A", count: 43)
        #expect(
            try await outcome(epk: #"{"kty":"EC","crv":"P-256","x":"\#(zeros)","y":"\#(zeros)"}"#)
                == .invalidEphemeralKey(.pointNotOnCurve(curve: "P-256"))
        )
        let p384 = String(
            decoding: try JWK(.p384((try ECPrivateKey<P384Curve>()).publicKey)).jsonRepresentation(),
            as: UTF8.self
        )
        #expect(try await outcome(epk: p384) == .ephemeralKeyCurveMismatch(expected: "P-256", found: "P-384"))
        let x25519 = String(
            decoding: try JWK(.x25519((try X25519PrivateKey()).publicKey)).jsonRepresentation(),
            as: UTF8.self
        )
        #expect(try await outcome(epk: x25519) == .ephemeralKeyCurveMismatch(expected: "P-256", found: "X25519"))

        // A valid epk from someone else decrypts to nothing, and says only that.
        let other = String(
            decoding: try JWK(.p256((try ECPrivateKey<P256Curve>()).publicKey)).jsonRepresentation(),
            as: UTF8.self
        )
        #expect(try await outcome(epk: other) == .decryptionFailed)
    }

    @Test("ECDH-ES direct agreement has no encrypted key, and refuses to follow another recipient")
    func directAgreementRules() async throws {
        let recipient = try ECPrivateKey<P256Curve>()
        let encrypter = ECDHESEncrypter<ECDHES>(recipient: recipient.publicKey)
        let keys = DecryptionKeys([
            AnyKeyDecrypter(ECDHESDecrypter<ECDHES, ECPrivateKey<P256Curve>>(privateKey: recipient))
        ])
        let sealed = try Plain.encrypt(Self.plaintext, to: encrypter, using: A256GCM.self)
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)

        // RFC 7516 §5.2 step 10: with direct key agreement the encrypted key must be empty.
        var parts = try sealed.compactSerialization().split(separator: ".", omittingEmptySubsequences: false).map(
            String.init
        )
        #expect(parts[1].isEmpty)
        parts[1] = Base64URL.encode(Data(count: 40))
        let withKey = try Plain.Encrypted(compact: parts.joined(separator: "."))
        #expect(
            await thrown { () async throws(JWEError) in try await withKey.decrypt(with: keys) }
                == .encryptedKeyNotEmpty(algorithm: "ECDH-ES")
        )

        // Asked directly to adopt a key someone else chose, the encrypter itself says no. The
        // key-wrapping variant accepts, and returns that same key.
        let existing = Data(repeating: 9, count: 32)
        let request = KeyEncryptionRequest(
            contentEncryption: "A256GCM",
            keyByteCount: 32,
            contentEncryptionKey: existing
        )
        #expect(throws: JWEError.algorithmRequiresSingleRecipient(algorithm: "ECDH-ES")) {
            try encrypter.encryptKey(request)
        }
        let wrapping = ECDHESEncrypter<ECDHESA256KW>(recipient: recipient.publicKey)
        #expect(try wrapping.encryptKey(request).contentEncryptionKey == existing)
        #expect(throws: JWEError.algorithmRequiresSingleRecipient(algorithm: "dir")) {
            try DirectKey(key: secret(32)).encryptKey(request)
        }
    }

    @Test("an X25519 epk of small order is refused as a failed decryption")
    func smallOrderEphemeralKey() async throws {
        let recipient = try X25519PrivateKey()
        let keys = DecryptionKeys([AnyKeyDecrypter(ECDHESDecrypter<ECDHES, X25519PrivateKey>(privateKey: recipient))])
        let sealed = try Plain.encrypt(
            Self.plaintext,
            to: ECDHESEncrypter<ECDHES>(recipient: recipient.publicKey),
            using: A256GCM.self
        )
        let zeroPoint = Base64URL.encode(Data(count: 32))
        let token = try ecdhToken(
            header: #"{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"OKP","crv":"X25519","x":"\#(zeroPoint)"}}"#,
            from: sealed
        )
        #expect(await thrown { () async throws(JWEError) in try await token.decrypt(with: keys) } == .decryptionFailed)
    }

    @Test("party information enters the key derivation: without the same apu and apv the key differs")
    func partyInfoIsBound() async throws {
        let recipient = try ECPrivateKey<P256Curve>()
        let keys = DecryptionKeys([
            AnyKeyDecrypter(ECDHESDecrypter<ECDHESA256KW, ECPrivateKey<P256Curve>>(privateKey: recipient))
        ])
        let encrypter = ECDHESEncrypter<ECDHESA256KW>(
            recipient: recipient.publicKey,
            partyUInfo: Data("Alice".utf8),
            partyVInfo: Data("Bob".utf8)
        )
        let sealed = try Plain.encrypt(Self.plaintext, to: encrypter, using: A256GCM.self)
        #expect(sealed.header?.rawParameters["apu"] == .string(Base64URL.encode(Data("Alice".utf8))))
        #expect(sealed.header?.rawParameters["apv"] == .string(Base64URL.encode(Data("Bob".utf8))))
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)

        var raw = try #require(sealed.header?.rawParameters)
        raw["apu"] = .string(Base64URL.encode(Data("Mallory".utf8)))
        let header = String(decoding: try JSONEncoder().encode(raw), as: UTF8.self)
        let altered = try ecdhToken(header: header, from: sealed)
        #expect(
            await thrown { () async throws(JWEError) in try await altered.decrypt(with: keys) } == .decryptionFailed
        )
    }

    @Test("the Concat KDF binds the algorithm name and key length, and spans more than one hash block")
    func concatKDF() {
        let secret = Data(repeating: 0x0B, count: 32)
        let base = ConcatKDF.derive(
            sharedSecret: secret,
            algorithmID: "A256GCM",
            partyUInfo: Data(),
            partyVInfo: Data(),
            keyByteCount: 32
        )
        #expect(base.count == 32)
        #expect(
            ConcatKDF.derive(
                sharedSecret: secret,
                algorithmID: "A256GCM",
                partyUInfo: Data(),
                partyVInfo: Data(),
                keyByteCount: 32
            ) == base
        )
        #expect(
            ConcatKDF.derive(
                sharedSecret: secret,
                algorithmID: "A128GCM",
                partyUInfo: Data(),
                partyVInfo: Data(),
                keyByteCount: 32
            ) != base
        )
        #expect(
            ConcatKDF.derive(
                sharedSecret: secret,
                algorithmID: "A256GCM",
                partyUInfo: Data([1]),
                partyVInfo: Data(),
                keyByteCount: 32
            ) != base
        )
        #expect(
            ConcatKDF.derive(
                sharedSecret: secret,
                algorithmID: "A256GCM",
                partyUInfo: Data(),
                partyVInfo: Data([1]),
                keyByteCount: 32
            ) != base
        )
        // The key length is itself an input, so a shorter key is not a prefix of a longer one.
        let short = ConcatKDF.derive(
            sharedSecret: secret,
            algorithmID: "A256GCM",
            partyUInfo: Data(),
            partyVInfo: Data(),
            keyByteCount: 16
        )
        #expect(short != base.prefix(16))
        let long = ConcatKDF.derive(
            sharedSecret: secret,
            algorithmID: "A256CBC-HS512",
            partyUInfo: Data(),
            partyVInfo: Data(),
            keyByteCount: 64
        )
        #expect(long.count == 64)
        #expect(long.prefix(32) != long.suffix(32))
    }

    @Test("encrypters built from a JWK honour its restrictions and key type")
    func jwkRestrictions() throws {
        let ec = JWK.Key.p256((try ECPrivateKey<P256Curve>()).publicKey)
        _ = try ECDHESEncrypter<ECDHES>(
            jwk: JWK(ec, metadata: JWKMetadata(keyID: "e", use: .encryption, keyOperations: [.deriveBits]))
        )
        _ = try ECDHESEncrypter<ECDHES>(jwk: JWK(.x25519((try X25519PrivateKey()).publicKey)))
        #expect(throws: JWKError.useNotPermitted(use: "sig", required: "enc")) {
            try ECDHESEncrypter<ECDHES>(jwk: JWK(ec, metadata: JWKMetadata(use: .signature)))
        }
        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["verify"], required: "deriveKey")) {
            try ECDHESEncrypter<ECDHES>(jwk: JWK(ec, metadata: JWKMetadata(keyOperations: [.verify])))
        }
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "ECDH-ES+A256KW", required: "ECDH-ES")) {
            try ECDHESEncrypter<ECDHES>(jwk: JWK(ec, metadata: JWKMetadata(algorithm: "ECDH-ES+A256KW")))
        }
        let rsa = JWK.Key.rsa(try RSAPrivateKey().publicKey)
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC or OKP X25519", found: "RSA")) {
            try ECDHESEncrypter<ECDHES>(jwk: JWK(rsa))
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC or OKP X25519", found: "OKP")) {
            try ECDHESEncrypter<ECDHES>(jwk: JWK(.ed25519((try Ed25519PrivateKey()).publicKey)))
        }

        #expect(
            try RSAOAEPEncrypter<RSAOAEP256>(jwk: JWK(rsa, metadata: JWKMetadata(keyID: "r", use: .encryption))).keyID
                == "r"
        )
        #expect(throws: JWKError.useNotPermitted(use: "sig", required: "enc")) {
            try RSAOAEPEncrypter<RSAOAEP256>(jwk: JWK(rsa, metadata: JWKMetadata(use: .signature)))
        }
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "RSA-OAEP", required: "RSA-OAEP-256")) {
            try RSAOAEPEncrypter<RSAOAEP256>(jwk: JWK(rsa, metadata: JWKMetadata(algorithm: "RSA-OAEP")))
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "RSA", found: "EC")) {
            try RSAOAEPEncrypter<RSAOAEP256>(jwk: JWK(ec))
        }
    }

    // MARK: Primitives

    @Test("AES-GCM-KW needs its iv and tag, of the right sizes")
    func gcmKeyWrapParameters() async throws {
        let key = try AESGCMKeyWrapKey<A256GCMKW>(key: secret(32))
        func outcome(_ header: [String: JSONValue]) async -> JWEError? {
            let request = KeyDecryptionRequest(
                encryptedKey: Data(count: 32),
                contentEncryption: "A256GCM",
                keyByteCount: 32,
                header: header
            )
            return await thrown { () async throws(JWEError) in try await key.decryptKey(request) }
        }
        let iv = JSONValue.string(Base64URL.encode(Data(count: 12)))
        let tag = JSONValue.string(Base64URL.encode(Data(count: 16)))
        #expect(await outcome(["iv": iv, "tag": tag]) == .decryptionFailed)
        #expect(await outcome(["tag": tag]) == .missingHeaderParameter(name: "iv", algorithm: "A256GCMKW"))
        #expect(await outcome(["iv": iv]) == .missingHeaderParameter(name: "tag", algorithm: "A256GCMKW"))
        #expect(
            await outcome(["iv": 5, "tag": tag])
                == .headerParameterWrongType(name: "iv", expected: "a base64url string")
        )
        #expect(
            await outcome(["iv": .string(Base64URL.encode(Data(count: 8))), "tag": tag])
                == .wrongInitializationVectorSize(algorithm: "A256GCMKW", expected: 12, found: 8)
        )
        #expect(
            await outcome(["iv": iv, "tag": .string(Base64URL.encode(Data(count: 8)))])
                == .wrongAuthenticationTagSize(algorithm: "A256GCMKW", expected: 16, found: 8)
        )
    }

    @Test("CBC-HMAC checks the tag before decrypting, over the additional data, IV and ciphertext")
    func cbcHMAC() throws {
        let key = secret(32).rawRepresentation
        let iv = Data(count: 16)
        let aad = Data("header".utf8)
        let (ciphertext, tag) = try A128CBCHS256.encrypt(
            Self.plaintext,
            key: key,
            initializationVector: iv,
            additionalAuthenticatedData: aad
        )
        #expect(ciphertext.count == 32)
        #expect(tag.count == 16)
        #expect(
            try A128CBCHS256.decrypt(
                ciphertext,
                tag: tag,
                key: key,
                initializationVector: iv,
                additionalAuthenticatedData: aad
            ) == Self.plaintext
        )

        func fails(_ ciphertext: Data, _ tag: Data, _ key: Data, _ iv: Data, _ aad: Data) -> Bool {
            do {
                _ = try A128CBCHS256.decrypt(
                    ciphertext,
                    tag: tag,
                    key: key,
                    initializationVector: iv,
                    additionalAuthenticatedData: aad
                )
                return false
            } catch {
                return error == .decryptionFailed
            }
        }
        var otherCiphertext = ciphertext
        otherCiphertext[0] ^= 1
        var otherTag = tag
        otherTag[15] ^= 1
        var otherIV = iv
        otherIV[0] ^= 1
        // The MAC key is the first half; changing only it must fail even though the AES key is right.
        var otherMACKey = key
        otherMACKey[0] ^= 1
        #expect(fails(otherCiphertext, tag, key, iv, aad))
        #expect(fails(ciphertext, otherTag, key, iv, aad))
        #expect(fails(ciphertext, tag, key, otherIV, aad))
        #expect(fails(ciphertext, tag, key, iv, Data("other".utf8)))
        #expect(fails(ciphertext, tag, otherMACKey, iv, aad))
        #expect(fails(ciphertext, tag.prefix(8), key, iv, aad))
        // A full, untruncated HMAC is not the tag.
        #expect(fails(ciphertext, tag + Data(count: 16), key, iv, aad))
    }

    @Test("AES-CBC pads with PKCS#7 and round-trips every length")
    func aesCBC() throws {
        let key = secret(16).rawRepresentation
        let iv = secret(16).rawRepresentation
        for length in 0...48 {
            let plaintext = Data((0..<length).map { UInt8($0) })
            let ciphertext = try AESCBC.encrypt(plaintext, key: key, iv: iv)
            #expect(ciphertext.count == (length / 16 + 1) * 16)
            #expect(try AESCBC.decrypt(ciphertext, key: key, iv: iv) == plaintext)
        }
        #expect(throws: (any Error).self) { try AESCBC.encrypt(Data(count: 16), key: key, iv: Data(count: 8)) }
    }

    @Test("constant-time comparison is correct")
    func constantTime() {
        #expect(ConstantTime.equal(Data([1, 2, 3]), Data([1, 2, 3])))
        #expect(!ConstantTime.equal(Data([1, 2, 3]), Data([1, 2, 4])))
        #expect(!ConstantTime.equal(Data([0, 2, 3]), Data([1, 2, 3])))
        #expect(!ConstantTime.equal(Data([1, 2, 3]), Data([1, 2])))
        #expect(ConstantTime.equal(Data(), Data()))
    }

    @Test("decryption keys can be assembled with the result builder")
    func keysBuilder() throws {
        let includeRSA = false
        let keys = try DecryptionKeys {
            DirectKey(key: secret(32))
            try AESKeyWrapKey<A256KW>(key: secret(32), keyID: "a")
            if includeRSA {
                try RSAOAEPDecrypter<RSAOAEP>(privateKey: try RSAPrivateKey())
            }
            for keyID in ["x", "y"] {
                try AESGCMKeyWrapKey<A128GCMKW>(key: secret(16), keyID: KeyID(rawValue: keyID))
            }
        }
        #expect(keys.decrypters.count == 4)
        #expect(keys.algorithms == ["dir", "A256KW", "A128GCMKW"])
    }

    @Test("every error has a message naming what was wrong")
    func descriptions() {
        let errors: [(JWEError, String)] = [
            (.invalidCompactSerialization(segmentCount: 3), "3 segments"),
            (.invalidBase64URL(part: "ciphertext", .invalidLength(count: 1)), "ciphertext"),
            (.paddingNotAllowed(part: "tag"), "tag"),
            (.invalidJSONStructure(.rootNotObject), "object"),
            (.invalidJSONSerialization(reason: "why"), "why"),
            (.invalidHeaderStructure(.rootNotObject), "object"),
            (.invalidHeaderJSON(description: "boom"), "boom"),
            (.missingAlgorithm, "alg"),
            (.missingContentEncryption, "enc"),
            (.headerParameterWrongType(name: "kid", expected: "a string"), "kid"),
            (.headerParameterInMultipleHeaders(name: "alg"), "alg"),
            (.headerParameterNotProtected(name: "crit"), "crit"),
            (.invalidCritical(reason: "empty"), "empty"),
            (.unsupportedCriticalParameter(name: "x"), "\"x\""),
            (.compressionNotSupported, "zip"),
            (.invalidCustomParameters(description: "bad"), "bad"),
            (.missingHeaderParameter(name: "epk", algorithm: "ECDH-ES"), "epk"),
            (.invalidEphemeralKey(.pointNotOnCurve(curve: "P-256")), "P-256"),
            (.ephemeralKeyCurveMismatch(expected: "P-256", found: "P-384"), "P-384"),
            (.unsupportedContentEncryption(algorithm: "X", allowed: ["A256GCM"]), "A256GCM"),
            (.noDecrypterForAlgorithm(algorithm: "RSA1_5", offered: ["dir"]), "RSA1_5"),
            (.noDecrypterForKeyID(keyID: "k9", algorithm: "dir"), "k9"),
            (.keyWrongSize(algorithm: "dir", expected: 32, found: 16), "16"),
            (.encryptedKeyNotEmpty(algorithm: "dir"), "dir"),
            (.wrongInitializationVectorSize(algorithm: "A256GCM", expected: 12, found: 8), "8"),
            (.wrongAuthenticationTagSize(algorithm: "A256GCM", expected: 16, found: 12), "12"),
            (.noRecipientDecrypted(reasons: [.decryptionFailed, .missingAlgorithm]), "2 recipients"),
            (.algorithmRequiresSingleRecipient(algorithm: "dir"), "dir"),
            (.noRecipients, "recipient"),
            (.keyEncryptionFailed(algorithm: "RSA-OAEP", .rsaDecryptionFailed), "RSA-OAEP"),
            (.contentEncryptionFailed(description: "x9"), "x9"),
            (.headerEncodingFailed(description: "enc7"), "enc7"),
            (.customParameterCollision(name: "alg"), "alg"),
            (.customParametersNotObject, "object"),
            (.notRepresentable(serialization: "compact", reason: "r5"), "r5"),
        ]
        for (error, fragment) in errors {
            #expect(error.description.contains(fragment), "\(error.description)")
        }
        // The one error that must say nothing more.
        #expect(JWEError.decryptionFailed.description == "JWE decryption failed")
    }
}
