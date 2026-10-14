import Foundation
import JOSECore
import Testing

@testable import JOSEJWK

@Suite("Key agreement and RSA encryption")
struct KeyAgreementTests {
    private func sharedSecret(_ agreement: KeysFixture.Agreement) throws -> Data {
        let privateJWK = try PrivateJWK(json: try JSONEncoder().encode(agreement.privateJwk))
        let publicJWK = try JWK(json: try JSONEncoder().encode(agreement.publicJwk))
        switch (privateJWK.key, publicJWK.key) {
        case (.p256(let ours), .p256(let theirs)):
            return try ours.sharedSecret(with: theirs)
        case (.p384(let ours), .p384(let theirs)):
            return try ours.sharedSecret(with: theirs)
        case (.p521(let ours), .p521(let theirs)):
            return try ours.sharedSecret(with: theirs)
        case (.x25519(let ours), .x25519(let theirs)):
            return try ours.sharedSecret(with: theirs)
        default:
            throw FixtureError(description: "key pair for \(agreement.curve) did not parse as that curve")
        }
    }

    @Test("ECDH shared secrets equal OpenSSL's for P-256, P-384, P-521 and X25519")
    func sharedSecretsMatchCounterpart() throws {
        let agreements = try KeysFixture.load().agreements
        #expect(agreements.map(\.curve).filter { $0 == "X25519" }.count == 4)
        #expect(agreements.count == 16)
        let sizes = ["P-256": 32, "P-384": 48, "P-521": 66, "X25519": 32]
        for agreement in agreements {
            let secret = try sharedSecret(agreement)
            #expect(secret.hex == agreement.sharedSecret, "\(agreement.curve)")
            #expect(secret.count == sizes[agreement.curve], "\(agreement.curve)")
        }
    }

    @Test("X25519 JWKs from jose parse, re-export identically, and have jose's thumbprint")
    func x25519JWKs() throws {
        for agreement in try KeysFixture.load().agreements where agreement.curve == "X25519" {
            let publicJWK = try JWK(json: try JSONEncoder().encode(agreement.publicJwk))
            #expect(publicJWK.keyDescription == "OKP X25519")
            #expect(publicJWK.keyType == "OKP")
            #expect(try publicJWK.thumbprint().base64URLEncoded == agreement.publicThumbprint)
            let exported = try JSONDecoder().decode([String: String].self, from: try publicJWK.jsonRepresentation())
            #expect(exported == agreement.publicJwk)

            let privateJWK = try PrivateJWK(json: try JSONEncoder().encode(agreement.privateJwk))
            let privateExport = try JSONDecoder().decode(
                [String: String].self,
                from: try privateJWK.jsonRepresentation()
            )
            #expect(privateExport == agreement.privateJwk)

            // An X25519 key is not a signing key.
            #expect(throws: JWKError.keyTypeMismatch(expected: "OKP Ed25519", found: "OKP X25519")) {
                try Ed25519Verifier<EdDSA>(jwk: publicJWK)
            }
            var withPrivate = agreement.publicJwk
            withPrivate["d"] = agreement.privateJwk["d"]
            #expect(throws: JWKError.privateMemberInPublicKey(member: "d", keyType: "OKP")) {
                try JWK(json: try JSONEncoder().encode(withPrivate))
            }
        }
    }

    @Test("an X25519 private JWK whose d belongs to a different key is refused")
    func mismatchedX25519PrivateKey() throws {
        let pair = try KeysFixture.load().agreements.filter { $0.curve == "X25519" }
        var mixed = pair[0].privateJwk
        mixed["d"] = pair[1].privateJwk["d"]
        _ = try PrivateJWK(json: try JSONEncoder().encode(pair[0].privateJwk))
        #expect(throws: JWKError.privateKeyDoesNotMatchPublicKey(curve: "X25519")) {
            try PrivateJWK(json: try JSONEncoder().encode(mixed))
        }
    }

    @Test("both parties derive the same secret, and a different peer gives a different one")
    func agreementIsSymmetric() throws {
        let alice = try ECPrivateKey<P256Curve>()
        let bob = try ECPrivateKey<P256Curve>()
        let carol = try ECPrivateKey<P256Curve>()
        #expect(try alice.sharedSecret(with: bob.publicKey) == (try bob.sharedSecret(with: alice.publicKey)))
        #expect(try alice.sharedSecret(with: bob.publicKey) != (try alice.sharedSecret(with: carol.publicKey)))

        let xAlice = try X25519PrivateKey()
        let xBob = try X25519PrivateKey()
        #expect(try xAlice.sharedSecret(with: xBob.publicKey) == (try xBob.sharedSecret(with: xAlice.publicKey)))
        #expect(try X25519PrivateKey(rawRepresentation: xAlice.rawRepresentation).publicKey == xAlice.publicKey)
    }

    @Test("X25519 keys are checked for size, and a public key that forces a zero secret is refused")
    func x25519Validation() throws {
        #expect(throws: JWKError.wrongByteCount(member: "x", curve: "X25519", expected: 32, found: 31)) {
            try X25519PublicKey(rawRepresentation: Data(count: 31))
        }
        #expect(throws: JWKError.wrongByteCount(member: "d", curve: "X25519", expected: 32, found: 33)) {
            try X25519PrivateKey(rawRepresentation: Data(count: 33))
        }
        // The all-zero point is of small order: the shared secret with it is zero for every
        // private key, so an attacker who supplies it knows the "secret".
        let key = try X25519PrivateKey()
        _ = try key.sharedSecret(with: try X25519PrivateKey().publicKey)
        #expect(throws: JWKError.keyAgreementFailed(curve: "X25519")) {
            try key.sharedSecret(with: try X25519PublicKey(rawRepresentation: Data(count: 32)))
        }
        #expect("\(key)" == "X25519PrivateKey(redacted)")
    }

    private func oaepHash(_ name: String) throws -> RSAOAEPHash {
        switch name {
        case "sha1":
            return .sha1
        case "sha256":
            return .sha256
        default:
            throw FixtureError(description: "unknown OAEP hash \(name)")
        }
    }

    @Test("RSA-OAEP ciphertexts made by OpenSSL decrypt, with SHA-1 and SHA-256")
    func oaepDecryptsCounterpartCiphertexts() throws {
        var checked = 0
        for key in try KeysFixture.load().rsaKeys {
            guard case .rsa(let privateKey) = try PrivateJWK(json: try JSONEncoder().encode(key.privateJwk)).key else {
                Issue.record("not an RSA private key")
                continue
            }
            let decryptionKey = try RSAOAEPDecryptionKey(privateKey: privateKey)
            #expect(key.oaep.count == 6)
            for testCase in key.oaep {
                let hash = try oaepHash(testCase.hash)
                let ciphertext = try Data(hex: testCase.ciphertext)
                #expect(try decryptionKey.decrypt(ciphertext, hash: hash).hex == testCase.plaintext)

                // The wrong hash, and a ciphertext with one bit changed, both fail, and identically.
                var other = RSAOAEPHash.sha1
                if case .sha1 = hash {
                    other = .sha256
                }
                #expect(throws: JWKError.rsaDecryptionFailed) { try decryptionKey.decrypt(ciphertext, hash: other) }
                var tampered = ciphertext
                tampered[tampered.count - 1] ^= 0x01
                #expect(throws: JWKError.rsaDecryptionFailed) { try decryptionKey.decrypt(tampered, hash: hash) }
                checked += 1
            }
        }
        #expect(checked == 24)
    }

    @Test("RSA-OAEP encryption round-trips, is randomised, and refuses a message too long for the key")
    func oaepRoundTrip() throws {
        let privateKey = try RSAPrivateKey()
        let encryptionKey = try RSAOAEPEncryptionKey(publicKey: privateKey.publicKey)
        let decryptionKey = try RSAOAEPDecryptionKey(privateKey: privateKey)
        let message = Data((0..<32).map { UInt8($0) })
        for hash in [RSAOAEPHash.sha1, .sha256] {
            let ciphertext = try encryptionKey.encrypt(message, hash: hash)
            #expect(ciphertext.count == 256)
            #expect(try decryptionKey.decrypt(ciphertext, hash: hash) == message)
            #expect(try encryptionKey.encrypt(message, hash: hash) != ciphertext)
        }
        let other = try RSAOAEPDecryptionKey(privateKey: try RSAPrivateKey())
        #expect(throws: JWKError.rsaDecryptionFailed) {
            try other.decrypt(try encryptionKey.encrypt(message, hash: .sha256), hash: .sha256)
        }
        // A 2048-bit key with SHA-256 OAEP carries at most 190 bytes.
        _ = try encryptionKey.encrypt(Data(count: 190), hash: .sha256)
        #expect(throws: JWKError.self) { try encryptionKey.encrypt(Data(count: 191), hash: .sha256) }
    }
}
