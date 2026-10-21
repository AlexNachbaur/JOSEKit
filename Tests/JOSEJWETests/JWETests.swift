import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWE

@Suite("JWE")
struct JWETests {
    static let plaintext = Data("the quick brown fox".utf8)

    private func secret(_ byteCount: Int) -> SymmetricKeyMaterial {
        SymmetricKeyMaterial(randomByteCount: byteCount)
    }

    /// An A256KW encrypter and decrypter over the same new key.
    private func keyWrap(keyID: KeyID? = nil) throws -> (AESKeyWrapEncrypter<A256KW>, AESKeyWrapDecrypter<A256KW>) {
        let material = secret(32)
        return (
            try AESKeyWrapEncrypter<A256KW>(key: material, keyID: keyID),
            try AESKeyWrapDecrypter<A256KW>(key: material, keyID: keyID)
        )
    }

    /// Encrypts with `encrypter`, round-trips through the compact form, and decrypts with `decrypter`.
    private func roundTrip<E: KeyEncrypter, D: KeyDecrypter>(
        _ encrypter: E,
        _ decrypter: D,
        _ encryption: some ContentEncryptionAlgorithm
    ) async throws {
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: encryption)
        let compact = try sealed.compactSerialization()
        #expect(compact.split(separator: ".", omittingEmptySubsequences: false).count == 5)
        let parsed = try SimpleJWE.Encrypted(compact: compact)
        #expect(parsed.header.algorithm == E.Algorithm.identifier)
        #expect(parsed.header.contentEncryption == encryption.identifier)
        let decrypted = try await parsed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(decrypter)]))
        #expect(decrypted.plaintext == Self.plaintext, "\(E.Algorithm.identifier) / \(encryption.identifier)")
    }

    @Test("every key management algorithm round-trips")
    func keyManagementRoundTrips() async throws {
        let direct = secret(32)
        try await roundTrip(DirectEncrypter(key: direct), DirectDecrypter(key: direct), A256GCM())

        let kw128 = secret(16)
        try await roundTrip(
            try AESKeyWrapEncrypter<A128KW>(key: kw128),
            try AESKeyWrapDecrypter<A128KW>(key: kw128),
            A128GCM()
        )
        let kw192 = secret(24)
        try await roundTrip(
            try AESKeyWrapEncrypter<A192KW>(key: kw192),
            try AESKeyWrapDecrypter<A192KW>(key: kw192),
            A192GCM()
        )
        let (kw256Encrypter, kw256Decrypter) = try keyWrap()
        try await roundTrip(kw256Encrypter, kw256Decrypter, A256CBCHS512())

        let gcm128 = secret(16)
        try await roundTrip(
            try AESGCMKeyWrapEncrypter<A128GCMKW>(key: gcm128),
            try AESGCMKeyWrapDecrypter<A128GCMKW>(key: gcm128),
            A128CBCHS256()
        )
        let gcm192 = secret(24)
        try await roundTrip(
            try AESGCMKeyWrapEncrypter<A192GCMKW>(key: gcm192),
            try AESGCMKeyWrapDecrypter<A192GCMKW>(key: gcm192),
            A192CBCHS384()
        )
        let gcm256 = secret(32)
        try await roundTrip(
            try AESGCMKeyWrapEncrypter<A256GCMKW>(key: gcm256),
            try AESGCMKeyWrapDecrypter<A256GCMKW>(key: gcm256),
            A256GCM()
        )

        try await roundTrip(
            try PBES2Encrypter<PBES2HS384A192KW>(password: "pw"),
            PBES2Decrypter<PBES2HS384A192KW>(password: "pw"),
            A192GCM()
        )

        let p256 = try ECPrivateKey<P256Curve>()
        try await roundTrip(
            ECDHESEncrypter<ECDHES>(recipient: p256.publicKey),
            ECDHESDecrypter<ECDHES, ECPrivateKey<P256Curve>>(privateKey: p256),
            A128GCM()
        )
        let p384 = try ECPrivateKey<P384Curve>()
        try await roundTrip(
            ECDHESEncrypter<ECDHESA128KW>(recipient: p384.publicKey),
            ECDHESDecrypter<ECDHESA128KW, ECPrivateKey<P384Curve>>(privateKey: p384),
            A256CBCHS512()
        )
        let p521 = try ECPrivateKey<P521Curve>()
        try await roundTrip(
            ECDHESEncrypter<ECDHESA192KW>(recipient: p521.publicKey),
            ECDHESDecrypter<ECDHESA192KW, ECPrivateKey<P521Curve>>(privateKey: p521),
            A192GCM()
        )
        let x25519 = try X25519PrivateKey()
        try await roundTrip(
            ECDHESEncrypter<ECDHESA256KW>(recipient: x25519.publicKey),
            ECDHESDecrypter<ECDHESA256KW, X25519PrivateKey>(privateKey: x25519),
            A256GCM()
        )
        try await roundTrip(
            ECDHESEncrypter<ECDHES>(recipient: x25519.publicKey),
            ECDHESDecrypter<ECDHES, X25519PrivateKey>(privateKey: x25519),
            A256CBCHS512()
        )

        let rsa = try RSAPrivateKey()
        try await roundTrip(
            try RSAEncrypter<RSAOAEP>(publicKey: rsa.publicKey),
            try RSADecrypter<RSAOAEP>(privateKey: rsa),
            A128CBCHS256()
        )
        try await roundTrip(
            try RSAEncrypter<RSAOAEP256>(publicKey: rsa.publicKey),
            try RSADecrypter<RSAOAEP256>(privateKey: rsa),
            A256GCM()
        )
        try await roundTrip(
            try RSAEncrypter<RSA15>(publicKey: rsa.publicKey),
            try RSADecrypter<RSA15>(privateKey: rsa),
            A128CBCHS256()
        )
    }

    /// RFC 7516 §11.5: with RSA1_5, a ciphertext whose padding is wrong, one that decrypts to a
    /// key of the wrong size, a wrong key and a tampered tag must all be indistinguishable.
    @Test("every RSA1_5 failure is the same error, whatever went wrong")
    func rsa15FailsUniformly() async throws {
        let rsa = try RSAPrivateKey()
        let keys = DecryptionKeys([AnyKeyDecrypter(try RSADecrypter<RSA15>(privateKey: rsa))])
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: try RSAEncrypter<RSA15>(publicKey: rsa.publicKey),
            using: .a128cbcHS256
        )
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)
        let parts = try sealed.compactSerialization().split(separator: ".", omittingEmptySubsequences: false)
            .map(String.init)
        func outcome(encryptedKey: Data? = nil, tag: Data? = nil) async throws -> JWEError? {
            var altered = parts
            if let encryptedKey {
                altered[1] = String(base64URLEncoding: encryptedKey)
            }
            if let tag {
                altered[4] = String(base64URLEncoding: tag)
            }
            let jwe = try SimpleJWE.Encrypted(compact: altered.joined(separator: "."))
            return await thrown { () async throws(JWEError) in try await jwe.decrypt(with: keys) }
        }

        // Bad padding: one bit changed in the encrypted key.
        var flipped = try Data(base64URLEncoded: parts[1])
        flipped[flipped.count - 1] ^= 0x01
        #expect(try await outcome(encryptedKey: flipped) == .decryptionFailed)
        // Valid padding around a key of the wrong size for A128CBC-HS256 (16 bytes, not 32).
        let shortKey = try RSAEncryptionKey(publicKey: rsa.publicKey).encrypt(Data(count: 16), padding: .pkcs1v15)
        #expect(try await outcome(encryptedKey: shortKey) == .decryptionFailed)
        // Valid padding around a wrong key of the right size.
        let wrongKey = try RSAEncryptionKey(publicKey: rsa.publicKey).encrypt(Data(count: 32), padding: .pkcs1v15)
        #expect(try await outcome(encryptedKey: wrongKey) == .decryptionFailed)
        // The right key, and a tampered tag.
        var tag = try Data(base64URLEncoded: parts[4])
        tag[0] ^= 0x01
        #expect(try await outcome(tag: tag) == .decryptionFailed)
        // A key that is not this recipient's.
        let stranger = DecryptionKeys([AnyKeyDecrypter(try RSADecrypter<RSA15>(privateKey: try RSAPrivateKey()))])
        #expect(
            await thrown { () async throws(JWEError) in try await sealed.decrypt(with: stranger) } == .decryptionFailed
        )
    }

    @Test("the protected header is written with sorted members; alg and enc come from the types")
    func protectedHeader() async throws {
        let (key, _) = try keyWrap(keyID: "k1")
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: key,
            using: .a256gcm,
            header: JWEHeaderParameters(type: "JWT")
        )
        let headerSegment = String(try sealed.compactSerialization().split(separator: ".")[0])
        let json = String(decoding: try Data(base64URLEncoded: headerSegment), as: UTF8.self)
        #expect(json == #"{"alg":"A256KW","enc":"A256GCM","kid":"k1","typ":"JWT"}"#)

        let explicit = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: key,
            using: .a256gcm,
            header: JWEHeaderParameters(keyID: "explicit")
        )
        #expect(explicit.header.keyID == "explicit")
    }

    @Test("encryption is randomised: the same input gives a different IV, key and ciphertext each time")
    func randomised() async throws {
        let (key, _) = try keyWrap()
        let first = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: .a256gcm)
        let second = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: .a256gcm)
        #expect(first.initializationVector != second.initializationVector)
        #expect(first.ciphertext != second.ciphertext)
        #expect(first.initializationVector.count == 12)
        #expect(first.tag.count == 16)
        let cbc = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: .a128cbcHS256)
        #expect(cbc.initializationVector.count == 16)
        #expect(cbc.tag.count == 16)
        #expect(cbc.ciphertext.count == 32)
        // AES-GCM-KW uses a fresh IV for the key wrap too.
        let gcmKey = try AESGCMKeyWrapEncrypter<A256GCMKW>(key: secret(32))
        let a = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: gcmKey, using: .a256gcm)
        let b = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: gcmKey, using: .a256gcm)
        #expect(a.header.rawParameters["iv"] != b.header.rawParameters["iv"])
    }

    @Test("a wrong key and a tampered JWE fail identically")
    func uniformFailure() async throws {
        let rsa = try RSAPrivateKey()
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: try RSAEncrypter<RSAOAEP256>(publicKey: rsa.publicKey),
            using: .a256gcm
        )
        let right = DecryptionKeys([AnyKeyDecrypter(try RSADecrypter<RSAOAEP256>(privateKey: rsa))])
        let wrong = DecryptionKeys([AnyKeyDecrypter(try RSADecrypter<RSAOAEP256>(privateKey: try RSAPrivateKey()))])
        #expect(try await sealed.decrypt(with: right).plaintext == Self.plaintext)
        #expect(
            await thrown { () async throws(JWEError) in try await sealed.decrypt(with: wrong) } == .decryptionFailed
        )

        var parts = try sealed.compactSerialization().split(separator: ".").map(String.init)
        var tag = try Data(base64URLEncoded: parts[4])
        tag[0] ^= 0x01
        parts[4] = String(base64URLEncoding: tag)
        let tampered = try SimpleJWE.Encrypted(compact: parts.joined(separator: "."))
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
        let (key, _) = try keyWrap()
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: .a256gcm)
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(ShortKey())]))
            }
                == .decryptionFailed
        )
    }

    @Test("an error knowable without the key is reported over a failed decryption, in either order")
    func structuralErrorPreferred() async throws {
        struct MissingParameter: KeyDecrypter {
            typealias Algorithm = A256KW
            let keyID: KeyID? = nil
            func decryptKey(_ request: KeyDecryptionRequest) async throws(JWEError) -> Data {
                throw .missingHeaderParameter(name: "x", algorithm: "A256KW")
            }
        }
        let (key, _) = try keyWrap()
        let (_, wrongKey) = try keyWrap()
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: .a256gcm)
        let structural = JWEError.missingHeaderParameter(name: "x", algorithm: "A256KW")
        for decrypters in [
            [AnyKeyDecrypter(MissingParameter()), AnyKeyDecrypter(wrongKey)],
            [AnyKeyDecrypter(wrongKey), AnyKeyDecrypter(MissingParameter())],
        ] {
            #expect(
                await thrown { () async throws(JWEError) in try await sealed.decrypt(with: DecryptionKeys(decrypters)) }
                    == structural
            )
        }
    }

    @Test("a content encryption algorithm is never handed a key of the wrong size")
    func contentEncryptionKeySizeIsEnforced() async throws {
        // An algorithm that, unlike the built-in ones, does not check its key size and "decrypts"
        // anything when given a short key. The engine must not rely on the algorithm to object.
        struct Careless: ContentEncryptionAlgorithm {
            let identifier: AlgorithmIdentifier = "X-CARELESS"
            let keyByteCount = 32
            let initializationVectorByteCount = 12
            let authenticationTagByteCount = 16

            func encrypt(
                _ plaintext: Data,
                key: Data,
                initializationVector: Data,
                additionalAuthenticatedData: Data
            ) throws(JWEError) -> (ciphertext: Data, tag: Data) {
                try A256GCM().encrypt(
                    plaintext,
                    key: key,
                    initializationVector: initializationVector,
                    additionalAuthenticatedData: additionalAuthenticatedData
                )
            }

            func decrypt(
                _ ciphertext: Data,
                tag: Data,
                key: Data,
                initializationVector: Data,
                additionalAuthenticatedData: Data
            ) throws(JWEError) -> Data {
                guard key.count == keyByteCount else {
                    return Data("accepted a short key".utf8)
                }
                return try A256GCM().decrypt(
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
        let (key, unwrapKey) = try keyWrap()
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: Careless())
        // Positive control: the custom algorithm works with the right key.
        let opened = try await sealed.decrypt(
            with: DecryptionKeys([AnyKeyDecrypter(unwrapKey)]),
            contentEncryptions: [Careless()]
        )
        #expect(opened.plaintext == Self.plaintext)
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(
                    with: DecryptionKeys([AnyKeyDecrypter(ShortKey())]),
                    contentEncryptions: [Careless()]
                )
            } == .decryptionFailed
        )
    }

    @Test("a key encrypter that ignores the key chosen for an earlier recipient is caught")
    func encrypterMustUseSharedKey() async throws {
        struct OwnKey: KeyEncrypter {
            typealias Algorithm = A256KW
            let keyID: KeyID? = nil
            func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
                // Wrongly makes up its own content key instead of using `request.keyToWrap()`.
                KeyEncryptionResult(contentEncryptionKey: Data(repeating: 7, count: 32), encryptedKey: Data(count: 40))
            }
        }
        let wrap = AnyKeyEncrypter(try keyWrap().0)
        _ = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: [AnyKeyEncrypter(OwnKey())],
            using: .a256gcm,
            header: JWEHeaderParameters()
        )
        await #expect(throws: JWEError.algorithmRequiresSingleRecipient(algorithm: "A256KW")) {
            try await SimpleJWE.Encrypted(
                encrypting: Self.plaintext,
                to: [wrap, AnyKeyEncrypter(OwnKey())],
                using: .a256gcm,
                header: JWEHeaderParameters()
            )
        }
    }

    @Test("keys of the wrong size are refused with the sizes named")
    func keySizes() async throws {
        #expect(throws: JWKError.keyWrongSize(algorithm: "A128KW", expectedByteCount: 16, found: 32)) {
            try AESKeyWrapEncrypter<A128KW>(key: secret(32))
        }
        #expect(throws: JWKError.keyWrongSize(algorithm: "A192KW", expectedByteCount: 24, found: 16)) {
            try AESKeyWrapDecrypter<A192KW>(key: secret(16))
        }
        #expect(throws: JWKError.keyWrongSize(algorithm: "A256GCMKW", expectedByteCount: 32, found: 16)) {
            try AESGCMKeyWrapEncrypter<A256GCMKW>(key: secret(16))
        }
        #expect(throws: JWKError.keyWrongSize(algorithm: "A128GCMKW", expectedByteCount: 16, found: 0)) {
            try AESGCMKeyWrapDecrypter<A128GCMKW>(key: secret(0))
        }
        let short = secret(16)
        await #expect(throws: JWEError.keyWrongSize(algorithm: "dir", expected: 32, found: 16)) {
            try await SimpleJWE.Encrypted(
                encrypting: Self.plaintext,
                to: DirectEncrypter(key: short),
                using: .a256gcm
            )
        }
        // And on the way in: a dir token for A256GCM cannot be opened with a 16-byte key.
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: DirectEncrypter(key: secret(32)),
            using: .a256gcm
        )
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(DirectDecrypter(key: short))]))
            }
                == .keyWrongSize(algorithm: "dir", expected: 32, found: 16)
        )
    }

    @Test("a recipient is only tried with decrypters for its own algorithm and key ID")
    func keySelection() async throws {
        let material = secret(32)
        let encrypter = try AESKeyWrapEncrypter<A256KW>(key: material, keyID: "right")
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: .a256gcm)
        func outcome(_ decrypters: [AnyKeyDecrypter]) async -> JWEError? {
            await thrown { () async throws(JWEError) in try await sealed.decrypt(with: DecryptionKeys(decrypters)) }
        }
        let right = AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: material, keyID: "right"))
        let unnamed = AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: material))
        let sameKeyOtherID = AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: material, keyID: "other"))
        let wrongKeyRightID = AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: secret(32), keyID: "right"))
        let otherAlgorithm = AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A256GCMKW>(key: material, keyID: "right"))

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
        let (key, unwrapKey) = try keyWrap()
        let keys = DecryptionKeys([AnyKeyDecrypter(unwrapKey)])
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: .a128cbcHS256)
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)
        #expect(
            try await sealed.decrypt(with: keys, contentEncryptions: [A128CBCHS256()]).plaintext == Self.plaintext
        )
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(with: keys, contentEncryptions: [A256GCM(), A128GCM()])
            } == .unsupportedContentEncryption(algorithm: "A128CBC-HS256", allowed: ["A256GCM", "A128GCM"])
        )
        #expect(ContentEncryption.allCases.count == 6)
        // The enum's cases are accepted in the list just as the types are.
        #expect(
            try await sealed.decrypt(with: keys, contentEncryptions: [ContentEncryption.a128cbcHS256]).plaintext
                == Self.plaintext
        )
    }

    @Test("each ContentEncryption case delegates to its type, and each shorthand makes that type")
    func contentEncryptionCases() throws {
        let types: [ContentEncryption: any ContentEncryptionAlgorithm] = [
            .a128gcm: A128GCM(), .a192gcm: A192GCM(), .a256gcm: A256GCM(),
            .a128cbcHS256: A128CBCHS256(), .a192cbcHS384: A192CBCHS384(), .a256cbcHS512: A256CBCHS512(),
        ]
        #expect(Set(types.keys) == Set(ContentEncryption.allCases))
        let key = secret(64).rawRepresentation
        for (encryption, type) in types {
            #expect(encryption.identifier == type.identifier)
            #expect(encryption.keyByteCount == type.keyByteCount)
            #expect(encryption.initializationVectorByteCount == type.initializationVectorByteCount)
            #expect(encryption.authenticationTagByteCount == type.authenticationTagByteCount)
            // What the case encrypts, the type decrypts, and the other way round.
            let iv = secret(type.initializationVectorByteCount).rawRepresentation
            let contentKey = key.prefix(type.keyByteCount)
            let (ciphertext, tag) = try encryption.encrypt(
                Self.plaintext,
                key: contentKey,
                initializationVector: iv,
                additionalAuthenticatedData: Data()
            )
            #expect(
                try type.decrypt(
                    ciphertext,
                    tag: tag,
                    key: contentKey,
                    initializationVector: iv,
                    additionalAuthenticatedData: Data()
                ) == Self.plaintext
            )
            let sealed = try type.encrypt(
                Self.plaintext,
                key: contentKey,
                initializationVector: iv,
                additionalAuthenticatedData: Data()
            )
            #expect(
                try encryption.decrypt(
                    sealed.ciphertext,
                    tag: sealed.tag,
                    key: contentKey,
                    initializationVector: iv,
                    additionalAuthenticatedData: Data()
                ) == Self.plaintext
            )
        }
        func identifier(_ encryption: some ContentEncryptionAlgorithm) -> AlgorithmIdentifier {
            encryption.identifier
        }
        #expect(identifier(.a128gcm) == "A128GCM")
        #expect(identifier(.a192gcm) == "A192GCM")
        #expect(identifier(.a256gcm) == "A256GCM")
        #expect(identifier(.a128cbcHS256) == "A128CBC-HS256")
        #expect(identifier(.a192cbcHS384) == "A192CBC-HS384")
        #expect(identifier(.a256cbcHS512) == "A256CBC-HS512")
    }

    // MARK: Serializations and recipients

    @Test("a single-recipient JWE round-trips through all three serializations, with additional data in JSON")
    func serializations() async throws {
        let (key, unwrapKey) = try keyWrap(keyID: "k")
        let keys = DecryptionKeys([AnyKeyDecrypter(unwrapKey)])
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: key, using: .a256gcm)
        #expect(
            try await SimpleJWE.Encrypted(json: try sealed.flattenedJSONSerialization()).decrypt(with: keys).plaintext
                == Self.plaintext
        )
        #expect(
            try await SimpleJWE.Encrypted(json: try sealed.generalJSONSerialization()).decrypt(with: keys).plaintext
                == Self.plaintext
        )

        let aad = Data("bound context".utf8)
        let withAAD = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: key,
            using: .a256gcm,
            header: JWEHeaderParameters(),
            additionalAuthenticatedData: aad
        )
        #expect(
            throws: JWEError.notRepresentable(serialization: "compact", reason: "it has additional authenticated data")
        ) {
            try withAAD.compactSerialization()
        }
        let decrypted = try await SimpleJWE.Encrypted(json: try withAAD.flattenedJSONSerialization()).decrypt(
            with: keys
        )
        #expect(decrypted.plaintext == Self.plaintext)
        #expect(decrypted.additionalAuthenticatedData == aad)

        var document = try JSONDecoder().decode(
            [String: JSONValue].self,
            from: try withAAD.flattenedJSONSerialization()
        )
        document["aad"] = nil
        let stripped = try SimpleJWE.Encrypted(json: try JSONEncoder().encode(document))
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
            AnyKeyEncrypter(try RSAEncrypter<RSAOAEP256>(publicKey: rsa.publicKey, keyID: "rsa")),
            AnyKeyEncrypter(ECDHESEncrypter<ECDHESA256KW>(recipient: ec.publicKey, keyID: "ec")),
            AnyKeyEncrypter(try AESGCMKeyWrapEncrypter<A256GCMKW>(key: shared, keyID: "shared")),
        ]
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: recipients,
            using: .a256gcm,
            header: JWEHeaderParameters(type: "example")
        )
        #expect(sealed.headers.map(\.keyID) == ["rsa", "ec", "shared"])
        #expect(sealed.headers.map(\.algorithm) == ["RSA-OAEP-256", "ECDH-ES+A256KW", "A256GCMKW"])
        // enc and the caller's parameters are protected; each recipient's alg is its own.
        #expect(sealed.headers[1].unprotectedParameterNames == ["alg", "kid", "epk"])
        #expect(sealed.headers[2].unprotectedParameterNames == ["alg", "kid", "iv", "tag"])
        #expect(sealed.headers[0].type == "example")

        // A shared kid would apply to every recipient, and each already names its own.
        await #expect(throws: JWEError.sharedKeyIDWithMultipleRecipients) {
            try await SimpleJWE.Encrypted(
                encrypting: Self.plaintext,
                to: recipients,
                using: .a256gcm,
                header: JWEHeaderParameters(keyID: "everyone")
            )
        }

        #expect(throws: JWEError.notRepresentable(serialization: "compact", reason: "it has 3 recipients")) {
            try sealed.compactSerialization()
        }
        #expect(throws: JWEError.notRepresentable(serialization: "flattened JSON", reason: "it has 3 recipients")) {
            try sealed.flattenedJSONSerialization()
        }

        let parsed = try SimpleJWE.Encrypted(json: try sealed.generalJSONSerialization())
        let decrypters = [
            AnyKeyDecrypter(try RSADecrypter<RSAOAEP256>(privateKey: rsa)),
            AnyKeyDecrypter(ECDHESDecrypter<ECDHESA256KW, ECPrivateKey<P256Curve>>(privateKey: ec)),
            AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A256GCMKW>(key: shared)),
        ]
        for (index, decrypter) in decrypters.enumerated() {
            let decrypted = try await parsed.decrypt(with: DecryptionKeys([decrypter]))
            #expect(decrypted.plaintext == Self.plaintext)
            #expect(decrypted.header.keyID == sealed.headers[index].keyID)
        }
    }

    @Test("dir and ECDH-ES cannot share a JWE with other recipients, in either position")
    func singleRecipientAlgorithms() async throws {
        /// Fails loudly if it is ever handed a key.
        struct Tripwire: KeyEncrypter {
            typealias Algorithm = A256KW
            let keyID: KeyID? = nil
            func encryptKey(_ request: KeyEncryptionRequest) async throws(JWEError) -> KeyEncryptionResult {
                throw .contentEncryptionFailed(description: "a recipient was handed the key")
            }
        }
        let wrap = AnyKeyEncrypter(try keyWrap().0)
        let direct = AnyKeyEncrypter(DirectEncrypter(key: secret(32)))
        let agreement = AnyKeyEncrypter(ECDHESEncrypter<ECDHES>(recipient: (try ECPrivateKey<P256Curve>()).publicKey))
        let tripwire = AnyKeyEncrypter(Tripwire())
        func attempt(_ recipients: [AnyKeyEncrypter]) async -> JWEError? {
            await thrown { () async throws(JWEError) in
                try await SimpleJWE.Encrypted(
                    encrypting: Self.plaintext,
                    to: recipients,
                    using: .a256gcm,
                    header: JWEHeaderParameters()
                )
            }
        }
        #expect(await attempt([wrap, wrap]) == nil)
        // Second in line: handed a key it did not choose, the direct recipient refuses it.
        #expect(await attempt([wrap, direct]) == .algorithmRequiresSingleRecipient(algorithm: "dir"))
        #expect(await attempt([wrap, agreement]) == .algorithmRequiresSingleRecipient(algorithm: "ECDH-ES"))
        // First in line: its key would be wrapped for the others, so encryption stops before
        // any other recipient sees it.
        #expect(await attempt([direct, tripwire]) == .algorithmRequiresSingleRecipient(algorithm: "dir"))
        #expect(await attempt([agreement, tripwire]) == .algorithmRequiresSingleRecipient(algorithm: "ECDH-ES"))
        #expect(await attempt([direct, direct]) == .algorithmRequiresSingleRecipient(algorithm: "dir"))
        #expect(await attempt([]) == .noRecipients)
    }

    @Test("one unusable recipient does not stop another from decrypting")
    func unusableRecipientIsSkipped() async throws {
        let (key, unwrapKey) = try keyWrap()
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: [AnyKeyEncrypter(key), AnyKeyEncrypter(key)],
            using: .a256gcm,
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
        let parsed = try SimpleJWE.Encrypted(json: try JSONEncoder().encode(document))
        #expect(parsed.headers.count == 1)
        #expect(
            try await parsed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(unwrapKey)])).plaintext == Self.plaintext
        )

        // With every recipient unusable, the JWE is refused, with every reason.
        recipients[1] = .object(first)
        document["recipients"] = .array(recipients)
        #expect(
            throws: JWEError.noUsableRecipient(reasons: [
                .headerParameterInMultipleHeaders(name: "enc"), .headerParameterInMultipleHeaders(name: "enc"),
            ])
        ) {
            try SimpleJWE.Encrypted(json: try JSONEncoder().encode(document))
        }
    }

    @Test("malformed JSON serializations report what is wrong")
    func invalidJSON() {
        func parse(_ json: String) -> JWEError? {
            do {
                _ = try SimpleJWE.Encrypted(json: Data(json.utf8))
                return nil
            } catch {
                return error
            }
        }
        let header = String(base64URLEncoding: Data(#"{"alg":"dir","enc":"A256GCM"}"#.utf8))
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
        let (key, unwrapKey) = try keyWrap()
        let keys = DecryptionKeys([AnyKeyDecrypter(unwrapKey)])
        let header = JWEHeaderParameters(contentType: "JWT", custom: ExampleHeader(level: 3, must: "understood"))
        let sealed = try await JWE<ExampleHeader>.Encrypted(
            encrypting: Self.plaintext,
            to: key,
            using: .a256gcm,
            header: header
        )
        #expect(sealed.header.critical == ["urn:example:must"])
        let compact = try sealed.compactSerialization()

        let decrypted = try await JWE<ExampleHeader>.Encrypted(compact: compact).decrypt(with: keys)
        #expect(decrypted.header.custom == ExampleHeader(level: 3, must: "understood"))
        #expect(decrypted.header.contentType == "application/jwt")

        // A reader that does not know the critical extension must refuse the JWE.
        #expect(throws: JWEError.unsupportedCriticalParameter(name: "urn:example:must")) {
            try SimpleJWE.Encrypted(compact: compact)
        }
    }

    @Test("registered header parameters are written and read back, including an embedded public JWK")
    func registeredParameters() async throws {
        let recipient = try ECPrivateKey<P256Curve>()
        let publicJWK = JWK(.p256(recipient.publicKey))
        let header = JWEHeaderParameters(
            jwk: publicJWK,
            jwkSetURL: "https://example.com/jwks",
            x509URL: "https://example.com/cert",
            x509CertificateChain: ["MIIB", "MIIC"],
            x509CertificateSHA1Thumbprint: "sha1",
            x509CertificateSHA256Thumbprint: "sha256"
        )
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: ECDHESEncrypter<ECDHESA256KW>(recipient: recipient.publicKey),
            using: .a256gcm,
            header: header
        )
        let parameters = try SimpleJWE.Encrypted(compact: try sealed.compactSerialization()).header.parameters
        #expect(parameters.jwk == publicJWK)
        #expect(parameters.jwkSetURL == "https://example.com/jwks")
        #expect(parameters.x509URL == "https://example.com/cert")
        #expect(parameters.x509CertificateChain == ["MIIB", "MIIC"])
        #expect(parameters.x509CertificateSHA1Thumbprint == "sha1")
        #expect(parameters.x509CertificateSHA256Thumbprint == "sha256")

        func parse(_ members: String) -> JWEError? {
            let protected = String(base64URLEncoding: Data(#"{"alg":"dir","enc":"A256GCM",\#(members)}"#.utf8))
            do {
                _ = try SimpleJWE.Encrypted(json: Data(#"{"protected":"\#(protected)","ciphertext":"AAAA"}"#.utf8))
                return nil
            } catch {
                return error
            }
        }
        let privateJSON = String(decoding: try PrivateJWK(.p256(recipient)).jsonRepresentation(), as: UTF8.self)
        #expect(
            parse(#""jwk":\#(privateJSON)"#)
                == .invalidJWKParameter(.privateMemberInPublicKey(member: "d", keyType: "EC"))
        )
        #expect(parse(#""jwk":"key""#) == .headerParameterWrongType(name: "jwk", expected: "an object"))
        #expect(parse(#""x5c":"MIIB""#) == .headerParameterWrongType(name: "x5c", expected: "an array of strings"))
        #expect(parse(#""x5c":[1]"#) == .headerParameterWrongType(name: "x5c", expected: "an array of strings"))
        #expect(parse(#""jku":1"#) == .headerParameterWrongType(name: "jku", expected: "a string"))
    }

    @Test("a custom header type cannot set alg, enc or any other parameter this package owns")
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
        let (key, _) = try keyWrap()
        _ = try await JWE<Hostile>.Encrypted(
            encrypting: Self.plaintext,
            to: key,
            using: .a256gcm,
            header: JWEHeaderParameters(custom: Hostile(["x": "y"]))
        )
        for name in [
            "alg", "enc", "zip", "kid", "typ", "cty", "crit", "epk", "apu", "apv", "iv", "tag", "jwk", "p2s", "p2c",
        ] {
            await #expect(throws: JWEError.customParameterCollision(name: name), "\(name)") {
                try await JWE<Hostile>.Encrypted(
                    encrypting: Self.plaintext,
                    to: key,
                    using: .a256gcm,
                    header: JWEHeaderParameters(custom: Hostile([name: "dir"]))
                )
            }
        }
    }

    // MARK: ECDH-ES details

    private func ecdhToken(header: String, from sealed: SimpleJWE.Encrypted) throws -> SimpleJWE.Encrypted {
        var parts = try sealed.compactSerialization().split(separator: ".", omittingEmptySubsequences: false).map(
            String.init
        )
        parts[0] = String(base64URLEncoding: Data(header.utf8))
        return try SimpleJWE.Encrypted(compact: parts.joined(separator: "."))
    }

    @Test("a missing, malformed, private, off-curve or wrong-curve epk is refused with its cause")
    func ephemeralKeyValidation() async throws {
        let recipient = try ECPrivateKey<P256Curve>()
        let keys = DecryptionKeys([
            AnyKeyDecrypter(ECDHESDecrypter<ECDHES, ECPrivateKey<P256Curve>>(privateKey: recipient))
        ])
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: ECDHESEncrypter<ECDHES>(recipient: recipient.publicKey),
            using: .a256gcm
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
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: .a256gcm)
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)

        // RFC 7516 §5.2 step 10: with direct key agreement the encrypted key must be empty.
        var parts = try sealed.compactSerialization().split(separator: ".", omittingEmptySubsequences: false).map(
            String.init
        )
        #expect(parts[1].isEmpty)
        parts[1] = String(base64URLEncoding: Data(count: 40))
        let withKey = try SimpleJWE.Encrypted(compact: parts.joined(separator: "."))
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
        await #expect(throws: JWEError.algorithmRequiresSingleRecipient(algorithm: "ECDH-ES")) {
            try await encrypter.encryptKey(request)
        }
        let wrapping = ECDHESEncrypter<ECDHESA256KW>(recipient: recipient.publicKey)
        #expect(try await wrapping.encryptKey(request).contentEncryptionKey == existing)
        await #expect(throws: JWEError.algorithmRequiresSingleRecipient(algorithm: "dir")) {
            try await DirectEncrypter(key: secret(32)).encryptKey(request)
        }
    }

    @Test("an X25519 epk of small order is refused as a failed decryption")
    func smallOrderEphemeralKey() async throws {
        let recipient = try X25519PrivateKey()
        let keys = DecryptionKeys([AnyKeyDecrypter(ECDHESDecrypter<ECDHES, X25519PrivateKey>(privateKey: recipient))])
        let sealed = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: ECDHESEncrypter<ECDHES>(recipient: recipient.publicKey),
            using: .a256gcm
        )
        let zeroPoint = String(base64URLEncoding: Data(count: 32))
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
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: .a256gcm)
        #expect(sealed.header.rawParameters["apu"] == .string(String(base64URLEncoding: Data("Alice".utf8))))
        #expect(sealed.header.rawParameters["apv"] == .string(String(base64URLEncoding: Data("Bob".utf8))))
        #expect(try await sealed.decrypt(with: keys).plaintext == Self.plaintext)

        var raw = sealed.header.rawParameters
        raw["apu"] = .string(String(base64URLEncoding: Data("Mallory".utf8)))
        let header = String(decoding: try JSONEncoder().encode(raw), as: UTF8.self)
        let altered = try ecdhToken(header: header, from: sealed)
        #expect(
            await thrown { () async throws(JWEError) in try await altered.decrypt(with: keys) } == .decryptionFailed
        )
    }

    @Test("the Concat KDF binds the algorithm name and key length, and spans more than one hash block")
    func concatKDF() {
        let secret = Data(repeating: 0x0B, count: 32)
        func derive(
            _ algorithmID: String,
            partyUInfo: Data = Data(),
            partyVInfo: Data = Data(),
            keyByteCount: Int = 32
        ) -> Data {
            ConcatKDF(
                algorithmID: algorithmID,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                keyByteCount: keyByteCount
            ).deriveKey(from: secret)
        }
        let base = derive("A256GCM")
        #expect(base.count == 32)
        #expect(derive("A256GCM") == base)
        #expect(derive("A128GCM") != base)
        #expect(derive("A256GCM", partyUInfo: Data([1])) != base)
        #expect(derive("A256GCM", partyVInfo: Data([1])) != base)
        // The key length is itself an input, so a shorter key is not a prefix of a longer one.
        let short = derive("A256GCM", keyByteCount: 16)
        #expect(short != base.prefix(16))
        let long = derive("A256CBC-HS512", keyByteCount: 64)
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
            try RSAEncrypter<RSAOAEP256>(jwk: JWK(rsa, metadata: JWKMetadata(keyID: "r", use: .encryption))).keyID
                == "r"
        )
        #expect(throws: JWKError.useNotPermitted(use: "sig", required: "enc")) {
            try RSAEncrypter<RSAOAEP256>(jwk: JWK(rsa, metadata: JWKMetadata(use: .signature)))
        }
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "RSA-OAEP", required: "RSA-OAEP-256")) {
            try RSAEncrypter<RSAOAEP256>(jwk: JWK(rsa, metadata: JWKMetadata(algorithm: "RSA-OAEP")))
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "RSA", found: "EC")) {
            try RSAEncrypter<RSAOAEP256>(jwk: JWK(ec))
        }
    }

    @Test("symmetric encrypters and decrypters built from a JWK honour its restrictions and size")
    func symmetricJWKRestrictions() async throws {
        let material = secret(32)
        func jwk(_ metadata: JWKMetadata) -> SymmetricJWK {
            SymmetricJWK(material, metadata: metadata)
        }
        let wrapping = jwk(JWKMetadata(keyID: "w", use: .encryption, keyOperations: [.wrapKey, .unwrapKey]))
        let encrypter = try AESKeyWrapEncrypter<A256KW>(jwk: wrapping)
        let decrypter = try AESKeyWrapDecrypter<A256KW>(jwk: wrapping)
        #expect(encrypter.keyID == "w")
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: .a256gcm)
        #expect(
            try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(decrypter)])).plaintext == Self.plaintext
        )

        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["unwrapKey"], required: "wrapKey")) {
            try AESKeyWrapEncrypter<A256KW>(jwk: jwk(JWKMetadata(keyOperations: [.unwrapKey])))
        }
        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["wrapKey"], required: "unwrapKey")) {
            try AESGCMKeyWrapDecrypter<A256GCMKW>(jwk: jwk(JWKMetadata(keyOperations: [.wrapKey])))
        }
        #expect(throws: JWKError.useNotPermitted(use: "sig", required: "enc")) {
            try AESGCMKeyWrapEncrypter<A256GCMKW>(jwk: jwk(JWKMetadata(use: .signature)))
        }
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "A256GCMKW", required: "A256KW")) {
            try AESKeyWrapDecrypter<A256KW>(jwk: jwk(JWKMetadata(algorithm: "A256GCMKW")))
        }
        #expect(throws: JWKError.keyWrongSize(algorithm: "A128KW", expectedByteCount: 16, found: 32)) {
            try AESKeyWrapEncrypter<A128KW>(jwk: jwk(JWKMetadata()))
        }
        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["decrypt"], required: "encrypt")) {
            try DirectEncrypter(jwk: jwk(JWKMetadata(keyOperations: [.decrypt])))
        }
        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["encrypt"], required: "decrypt")) {
            try DirectDecrypter(jwk: jwk(JWKMetadata(keyOperations: [.encrypt])))
        }
        _ = try DirectEncrypter(jwk: jwk(JWKMetadata(algorithm: "dir")))
        _ = try DirectDecrypter(jwk: jwk(JWKMetadata(algorithm: "dir")))
    }

    @Test("a dir key whose alg names a content encryption algorithm is used with that algorithm only")
    func directKeyRestrictedToContentEncryption() async throws {
        // RFC 7520 §5.6 gives its dir key `"alg": "A128GCM"`.
        let restricted = SymmetricJWK(secret(32), metadata: JWKMetadata(use: .encryption, algorithm: "A256GCM"))
        let encrypter = try DirectEncrypter(jwk: restricted)
        let decrypter = try DirectDecrypter(jwk: restricted)
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: .a256gcm)
        #expect(
            try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(decrypter)])).plaintext == Self.plaintext
        )

        let refusal = JWEError.contentEncryptionNotPermitted(
            keyAlgorithm: "A256GCM",
            contentEncryption: "A128CBC-HS256"
        )
        await #expect(throws: refusal) {
            try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: .a128cbcHS256)
        }
        // The same key used for A128CBC-HS256 by someone else is refused on the way in too.
        let other = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: DirectEncrypter(key: restricted.key),
            using: .a128cbcHS256
        )
        #expect(
            await thrown { () async throws(JWEError) in
                try await other.decrypt(with: DecryptionKeys([AnyKeyDecrypter(decrypter)]))
            } == refusal
        )
    }

    @Test("decrypters can be built from private JWKs, for the listed algorithms only")
    func decryptersFromJWKs() async throws {
        let ec = try ECPrivateKey<P256Curve>()
        let rsa = try RSAPrivateKey()
        let ecJWK = PrivateJWK(.p256(ec), metadata: JWKMetadata(keyID: "ec", use: .encryption))
        let rsaJWK = PrivateJWK(.rsa(rsa), metadata: JWKMetadata(keyID: "rsa", keyOperations: [.unwrapKey]))
        let signingJWK = PrivateJWK(.p256(try ECPrivateKey<P256Curve>()), metadata: JWKMetadata(use: .signature))
        let keys = DecryptionKeys(
            jwks: [ecJWK, rsaJWK, signingJWK],
            allowing: [ECDHESA256KW.self, RSAOAEP256.self]
        )
        // Each key suits one algorithm; the signing key suits none.
        #expect(keys.decrypters.map(\.keyID) == ["ec", "rsa"])
        #expect(keys.algorithms == ["ECDH-ES+A256KW", "RSA-OAEP-256"])
        // RSA1_5 is offered only when it is listed, and never for a key whose alg names another.
        #expect(
            DecryptionKeys(jwks: [rsaJWK], allowing: [RSAOAEP256.self, RSA15.self]).algorithms == [
                "RSA-OAEP-256", "RSA1_5",
            ]
        )
        let oaepOnly = PrivateJWK(.rsa(rsa), metadata: JWKMetadata(algorithm: "RSA-OAEP-256"))
        #expect(
            DecryptionKeys(jwks: [oaepOnly], allowing: [RSAOAEP256.self, RSA15.self]).algorithms == ["RSA-OAEP-256"]
        )

        let toEC = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: ECDHESEncrypter<ECDHESA256KW>(recipient: ec.publicKey, keyID: "ec"),
            using: .a256gcm
        )
        #expect(try await toEC.decrypt(with: keys).plaintext == Self.plaintext)
        let toRSA = try await SimpleJWE.Encrypted(
            encrypting: Self.plaintext,
            to: try RSAEncrypter<RSAOAEP256>(publicKey: rsa.publicKey, keyID: "rsa"),
            using: .a256gcm
        )
        #expect(try await toRSA.decrypt(with: keys).plaintext == Self.plaintext)

        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["sign"], required: "unwrapKey")) {
            try RSADecrypter<RSAOAEP>(jwk: PrivateJWK(.rsa(rsa), metadata: JWKMetadata(keyOperations: [.sign])))
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "RSA", found: "EC")) {
            try RSADecrypter<RSAOAEP>(jwk: ecJWK)
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC or OKP X25519", found: "RSA")) {
            try ECDHES.decrypter(for: PrivateJWK(.rsa(rsa)))
        }
        #expect(throws: JWKError.useNotPermitted(use: "sig", required: "enc")) {
            try ECDHES.decrypter(for: signingJWK)
        }

        // The result builder takes a whole set of keys as well as single decrypters.
        let combined = DecryptionKeys {
            keys
            DirectDecrypter(key: secret(32))
        }
        #expect(combined.algorithms == ["ECDH-ES+A256KW", "RSA-OAEP-256", "dir"])
    }

    // MARK: Primitives

    @Test("PBES2 round-trips, writes its salt and count, and refuses the wrong password")
    func pbes2RoundTrip() async throws {
        let password = "correct horse battery staple"
        let encrypter = try PBES2Encrypter<PBES2HS256A128KW>(password: password, keyID: "pw")
        let sealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: encrypter, using: .a128cbcHS256)
        #expect(sealed.header.rawParameters["p2c"] == 2048)
        guard case .string(let salt) = try #require(sealed.header.rawParameters["p2s"]) else {
            Issue.record("p2s missing")
            return
        }
        #expect(try Data(base64URLEncoded: salt).count == 16)
        let decrypter = PBES2Decrypter<PBES2HS256A128KW>(password: password, keyID: "pw")
        #expect(
            try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(decrypter)])).plaintext == Self.plaintext
        )

        let wrong = PBES2Decrypter<PBES2HS256A128KW>(password: "correct horse battery stapler")
        #expect(
            await thrown { () async throws(JWEError) in
                try await sealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(wrong)]))
            }
                == .decryptionFailed
        )
        let stronger = try PBES2Encrypter<PBES2HS512A256KW>(password: "p", iterationCount: 5000)
        let strongSealed = try await SimpleJWE.Encrypted(encrypting: Self.plaintext, to: stronger, using: .a256gcm)
        #expect(strongSealed.header.rawParameters["p2c"] == 5000)
        let strongDecrypter = PBES2Decrypter<PBES2HS512A256KW>(password: "p", maximumIterationCount: 5000)
        #expect(
            try await strongSealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(strongDecrypter)])).plaintext
                == Self.plaintext
        )
        // The default maximum is 10 000, which is below what this token asks for.
        let cautious = PBES2Decrypter<PBES2HS512A256KW>(password: "p", maximumIterationCount: 4999)
        #expect(
            await thrown { () async throws(JWEError) in
                try await strongSealed.decrypt(with: DecryptionKeys([AnyKeyDecrypter(cautious)]))
            } == .invalidIterationCount(found: 5000, maximum: 4999)
        )
    }

    @Test("PBES2 iteration counts are bounded in both directions, and the salt input must be long enough")
    func pbes2Limits() async throws {
        let limit = PBES2HS256A128KW.iterationCountLimit
        #expect(limit == Int(clamping: UInt32.max))
        #expect(throws: JWEError.invalidIterationCount(found: 0, maximum: limit)) {
            try PBES2Encrypter<PBES2HS256A128KW>(password: "p", iterationCount: 0)
        }
        _ = try PBES2Encrypter<PBES2HS256A128KW>(password: "p", iterationCount: limit)
        #expect(PBES2Decrypter<PBES2HS256A128KW>(password: "p").maximumIterationCount == 10_000)
        // A maximum above what PBKDF2 can take is lowered to it, so no token can reach a count
        // that would not fit.
        let unbounded = PBES2Decrypter<PBES2HS256A128KW>(password: "p", maximumIterationCount: Int.max)
        #expect(unbounded.maximumIterationCount == limit)

        // A received token is checked before any derivation: the count is attacker-controlled.
        let key = PBES2Decrypter<PBES2HS256A128KW>(password: "p", maximumIterationCount: 1000)
        func outcome(_ header: [String: JSONValue]) async -> JWEError? {
            let request = KeyDecryptionRequest(
                encryptedKey: Data(count: 24),
                contentEncryption: "A128GCM",
                keyByteCount: 16,
                header: header
            )
            return await thrown { () async throws(JWEError) in try await key.decryptKey(request) }
        }
        let salt = JSONValue.string(String(base64URLEncoding: Data(count: 16)))
        #expect(await outcome(["p2s": salt, "p2c": 1000]) == .decryptionFailed)
        #expect(await outcome(["p2s": salt, "p2c": 1001]) == .invalidIterationCount(found: 1001, maximum: 1000))
        #expect(await outcome(["p2s": salt, "p2c": 0]) == .invalidIterationCount(found: 0, maximum: 1000))
        #expect(
            await outcome(["p2s": salt, "p2c": 1_000_000_000_000])
                == .invalidIterationCount(found: 1_000_000_000_000, maximum: 1000)
        )
        #expect(
            await outcome(["p2s": salt, "p2c": "1000"])
                == .headerParameterWrongType(name: "p2c", expected: "a positive integer")
        )
        #expect(await outcome(["p2s": salt]) == .missingHeaderParameter(name: "p2c", algorithm: "PBES2-HS256+A128KW"))
        #expect(await outcome(["p2c": 1000]) == .missingHeaderParameter(name: "p2s", algorithm: "PBES2-HS256+A128KW"))
        #expect(
            await outcome(["p2s": .string(String(base64URLEncoding: Data(count: 7))), "p2c": 1000])
                == .saltTooShort(algorithm: "PBES2-HS256+A128KW", minimum: 8, found: 7)
        )

        let tooMany = Int64(UInt32.max) + 1
        let request = KeyDecryptionRequest(
            encryptedKey: Data(count: 24),
            contentEncryption: "A128GCM",
            keyByteCount: 16,
            header: ["p2s": salt, "p2c": .integer(tooMany)]
        )
        #expect(
            await thrown { () async throws(JWEError) in try await unbounded.decryptKey(request) }
                == .invalidIterationCount(found: Int(clamping: tooMany), maximum: limit)
        )
    }

    @Test("AES-GCM-KW needs its iv and tag, of the right sizes")
    func gcmKeyWrapParameters() async throws {
        let key = try AESGCMKeyWrapDecrypter<A256GCMKW>(key: secret(32))
        func outcome(_ header: [String: JSONValue]) async -> JWEError? {
            let request = KeyDecryptionRequest(
                encryptedKey: Data(count: 32),
                contentEncryption: "A256GCM",
                keyByteCount: 32,
                header: header
            )
            return await thrown { () async throws(JWEError) in try await key.decryptKey(request) }
        }
        let iv = JSONValue.string(String(base64URLEncoding: Data(count: 12)))
        let tag = JSONValue.string(String(base64URLEncoding: Data(count: 16)))
        #expect(await outcome(["iv": iv, "tag": tag]) == .decryptionFailed)
        #expect(await outcome(["tag": tag]) == .missingHeaderParameter(name: "iv", algorithm: "A256GCMKW"))
        #expect(await outcome(["iv": iv]) == .missingHeaderParameter(name: "tag", algorithm: "A256GCMKW"))
        #expect(
            await outcome(["iv": 5, "tag": tag])
                == .headerParameterWrongType(name: "iv", expected: "a base64url string")
        )
        #expect(
            await outcome(["iv": .string(String(base64URLEncoding: Data(count: 8))), "tag": tag])
                == .wrongInitializationVectorSize(algorithm: "A256GCMKW", expected: 12, found: 8)
        )
        #expect(
            await outcome(["iv": iv, "tag": .string(String(base64URLEncoding: Data(count: 8)))])
                == .wrongAuthenticationTagSize(algorithm: "A256GCMKW", expected: 16, found: 8)
        )
    }

    @Test("CBC-HMAC checks the tag before decrypting, over the additional data, IV and ciphertext")
    func cbcHMAC() throws {
        let key = secret(32).rawRepresentation
        let iv = Data(count: 16)
        let aad = Data("header".utf8)
        let (ciphertext, tag) = try A128CBCHS256().encrypt(
            Self.plaintext,
            key: key,
            initializationVector: iv,
            additionalAuthenticatedData: aad
        )
        #expect(ciphertext.count == 32)
        #expect(tag.count == 16)
        #expect(
            try A128CBCHS256().decrypt(
                ciphertext,
                tag: tag,
                key: key,
                initializationVector: iv,
                additionalAuthenticatedData: aad
            ) == Self.plaintext
        )

        func fails(_ ciphertext: Data, _ tag: Data, _ key: Data, _ iv: Data, _ aad: Data) -> Bool {
            do {
                _ = try A128CBCHS256().decrypt(
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
        let cipher = PlatformAESCBC(key: key)
        for length in 0...48 {
            let plaintext = Data((0..<length).map { UInt8($0) })
            let ciphertext = try cipher.encrypt(plaintext, iv: iv)
            #expect(ciphertext.count == (length / 16 + 1) * 16)
            #expect(try cipher.decrypt(ciphertext, iv: iv) == plaintext)
        }
        #expect(throws: (any Error).self) { try cipher.encrypt(Data(count: 16), iv: Data(count: 8)) }
    }

    @Test("constant-time comparison is correct")
    func constantTime() {
        #expect(Data([1, 2, 3]).constantTimeEquals(Data([1, 2, 3])))
        #expect(!Data([1, 2, 3]).constantTimeEquals(Data([1, 2, 4])))
        #expect(!Data([0, 2, 3]).constantTimeEquals(Data([1, 2, 3])))
        #expect(!Data([1, 2, 3]).constantTimeEquals(Data([1, 2])))
        #expect(Data().constantTimeEquals(Data()))
    }

    @Test("decryption keys can be assembled with the result builder")
    func keysBuilder() throws {
        let includeRSA = false
        let keys = try DecryptionKeys {
            DirectDecrypter(key: secret(32))
            try AESKeyWrapDecrypter<A256KW>(key: secret(32), keyID: "a")
            if includeRSA {
                try RSADecrypter<RSAOAEP>(privateKey: try RSAPrivateKey())
            }
            for keyID in ["x", "y"] {
                try AESGCMKeyWrapDecrypter<A128GCMKW>(key: secret(16), keyID: KeyID(rawValue: keyID))
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
            (.unsupportedCompression(algorithm: "LZW"), "LZW"),
            (.compressionNotAllowed, "compressed"),
            (.decompressedSizeExceedsLimit(maximum: 1234), "1234"),
            (.invalidCompressedContent, "DEFLATE"),
            (.invalidCustomParameters(description: "bad"), "bad"),
            (.invalidJWKParameter(.symmetricKeyInPublicKey), "oct"),
            (.missingHeaderParameter(name: "epk", algorithm: "ECDH-ES"), "epk"),
            (.invalidEphemeralKey(.pointNotOnCurve(curve: "P-256")), "P-256"),
            (.ephemeralKeyCurveMismatch(expected: "P-256", found: "P-384"), "P-384"),
            (.invalidIterationCount(found: 5, maximum: 4), "5"),
            (.saltTooShort(algorithm: "PBES2-HS256+A128KW", minimum: 8, found: 2), "2 bytes"),
            (.unsupportedContentEncryption(algorithm: "X", allowed: ["A256GCM"]), "A256GCM"),
            (.noDecrypterForAlgorithm(algorithm: "RSA1_5", offered: ["dir"]), "RSA1_5"),
            (.noDecrypterForKeyID(keyID: "k9", algorithm: "dir"), "k9"),
            (.keyWrongSize(algorithm: "dir", expected: 32, found: 16), "16"),
            (.encryptedKeyNotEmpty(algorithm: "dir"), "dir"),
            (.contentEncryptionNotPermitted(keyAlgorithm: "A128GCM", contentEncryption: "A256GCM"), "A128GCM"),
            (.wrongInitializationVectorSize(algorithm: "A256GCM", expected: 12, found: 8), "8"),
            (.wrongAuthenticationTagSize(algorithm: "A256GCM", expected: 16, found: 12), "12"),
            (.noRecipientDecrypted(reasons: [.decryptionFailed, .missingAlgorithm]), "2 recipients"),
            (.noUsableRecipient(reasons: [.missingAlgorithm, .missingAlgorithm]), "usable header"),
            (.algorithmRequiresSingleRecipient(algorithm: "dir"), "dir"),
            (.noRecipients, "recipient"),
            (.sharedKeyIDWithMultipleRecipients, "\"kid\""),
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
