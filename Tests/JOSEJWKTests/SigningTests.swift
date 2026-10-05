import Foundation
import JOSECore
import Testing

@testable import JOSEJWK

@Suite("Signers and verifiers")
struct SigningTests {
    /// Verifies one fixture key's signatures under `Curve`, and checks that tampered ones fail.
    private func checkECDSA<Curve: ECDSACurve>(_ curve: Curve.Type, key: KeysFixture.Key) async throws {
        let verifier = try ECDSAVerifier<Curve>(jwk: try JWK(json: try key.publicJSON()))
        #expect(key.algorithms == [Curve.Algorithm.identifier.rawValue])
        for testCase in key.signatures {
            let message = try Data(hex: testCase.message)
            let good = try Signature<Curve.Algorithm>(rawRepresentation: try Data(hex: testCase.signature))
            try verifier.verify(good, for: message)

            let tampered = try Signature<Curve.Algorithm>(rawRepresentation: try Data(hex: testCase.tamperedSignature))
            #expect(throws: VerificationError.self) { try verifier.verify(tampered, for: message) }
            #expect(throws: VerificationError.self) { try verifier.verify(good, for: message + [0x00]) }
        }

        // The private JWK from jose signs things its public JWK verifies.
        guard let privateKey = try Self.ecPrivateKey(Curve.self, from: try PrivateJWK(json: try key.privateJSON()))
        else {
            Issue.record("private JWK for \(key.curve) did not hold a \(Curve.name) key")
            return
        }
        let signer = try ECDSASigner(privateKey: privateKey, keyID: "k")
        let message = Data("signed in Swift".utf8)
        let signature = try await signer.sign(message)
        #expect(signature.rawRepresentation.count == Curve.coordinateByteCount * 2)
        try verifier.verify(signature, for: message)
        #expect(signer.keyID == "k")
    }

    private static func ecPrivateKey<Curve: EllipticCurve>(
        _ curve: Curve.Type,
        from jwk: PrivateJWK
    ) throws -> ECPrivateKey<Curve>? {
        switch jwk.key {
        case .p256(let key):
            return key as? ECPrivateKey<Curve>
        case .p384(let key):
            return key as? ECPrivateKey<Curve>
        case .p521(let key):
            return key as? ECPrivateKey<Curve>
        case .ed25519, .x25519, .rsa:
            return nil
        }
    }

    @Test("ECDSA signatures made by WebCrypto verify, and tampered ones do not")
    func ecdsaCounterpartSignatures() async throws {
        let fixture = try KeysFixture.load()
        var checked = 0
        for key in fixture.keys {
            switch key.curve {
            case "P-256":
                try await checkECDSA(P256Curve.self, key: key)
            case "P-384":
                try await checkECDSA(P384Curve.self, key: key)
            case "P-521":
                try await checkECDSA(P521Curve.self, key: key)
            default:
                continue
            }
            checked += 1
        }
        #expect(checked == 12)
    }

    @Test("Ed25519 signatures made by WebCrypto verify under both Ed25519 and EdDSA")
    func ed25519CounterpartSignatures() async throws {
        let keys = try KeysFixture.load().keys.filter { $0.curve == "Ed25519" }
        #expect(keys.count == 4)
        for key in keys {
            #expect(key.algorithms == ["Ed25519", "EdDSA"])
            let jwk = try JWK(json: try key.publicJSON())
            let modern = try Ed25519Verifier<JOSECore.Ed25519>(jwk: jwk)
            let legacy = try Ed25519Verifier<EdDSA>(jwk: jwk)
            for testCase in key.signatures {
                let message = try Data(hex: testCase.message)
                let bytes = try Data(hex: testCase.signature)
                let tampered = try Data(hex: testCase.tamperedSignature)
                try modern.verify(try Signature(rawRepresentation: bytes), for: message)
                try legacy.verify(try Signature(rawRepresentation: bytes), for: message)
                #expect(throws: VerificationError.self) {
                    try modern.verify(try Signature(rawRepresentation: tampered), for: message)
                }
                #expect(throws: VerificationError.self) {
                    try legacy.verify(try Signature(rawRepresentation: tampered), for: message)
                }
            }

            guard case .ed25519(let privateKey) = try PrivateJWK(json: try key.privateJSON()).key else {
                Issue.record("private JWK was not Ed25519")
                continue
            }
            let message = Data("signed in Swift".utf8)
            let signature = try await Ed25519Signer<JOSECore.Ed25519>(privateKey: privateKey).sign(message)
            try modern.verify(signature, for: message)
            let legacySignature = try await Ed25519Signer<EdDSA>(privateKey: privateKey).sign(message)
            #expect(legacySignature.rawRepresentation.count == 64)
            try legacy.verify(legacySignature, for: message)
        }
    }

    @Test("an EdDSA signature of the wrong length is refused by the verifier rather than the type")
    func edDSAWrongLength() throws {
        let key = try Ed25519PrivateKey()
        let verifier = try Ed25519Verifier<EdDSA>(publicKey: key.publicKey)
        let short = try Signature<EdDSA>(rawRepresentation: Data(count: 10))
        #expect(throws: VerificationError.self) { try verifier.verify(short, for: Data()) }
        #expect(throws: SignatureError.wrongLength(algorithm: "Ed25519", expected: 64, found: 10)) {
            try Signature<JOSECore.Ed25519>(rawRepresentation: Data(count: 10))
        }
    }

    private func checkHMAC<Algorithm: HMACAlgorithm>(
        _ algorithm: Algorithm.Type,
        _ testCase: KeysFixture.HMACCase
    ) async throws {
        let jwk = try SymmetricJWK(json: try JSONEncoder().encode(testCase.jwk))
        #expect(jwk.key.rawRepresentation == (try Data(hex: testCase.key)))
        let message = try Data(hex: testCase.message)
        let tag = try Data(hex: testCase.tag)

        let signature = try await HMACSigner<Algorithm>(jwk: jwk).sign(message)
        #expect(signature.rawRepresentation == tag)

        let verifier = try HMACVerifier<Algorithm>(jwk: jwk)
        try verifier.verify(try Signature(rawRepresentation: tag), for: message)
        #expect(throws: VerificationError.self) {
            try verifier.verify(try Signature(rawRepresentation: try Data(hex: testCase.tamperedTag)), for: message)
        }
        #expect(throws: VerificationError.self) {
            try verifier.verify(try Signature(rawRepresentation: tag), for: message + [0x00])
        }
    }

    @Test("HMAC tags equal the counterpart's for every algorithm and key length")
    func hmacMatchesCounterpart() async throws {
        let fixture = try KeysFixture.load()
        #expect(fixture.hmacs.count == 9)
        for testCase in fixture.hmacs {
            switch testCase.algorithm {
            case "HS256":
                try await checkHMAC(HS256.self, testCase)
            case "HS384":
                try await checkHMAC(HS384.self, testCase)
            case "HS512":
                try await checkHMAC(HS512.self, testCase)
            default:
                Issue.record("unexpected algorithm \(testCase.algorithm)")
            }
        }
    }

    @Test("an HMAC key shorter than the hash output is refused")
    func hmacKeyLength() throws {
        _ = try HMACSigner<HS256>(key: SymmetricKeyMaterial(randomByteCount: 32))
        _ = try HMACVerifier<HS512>(key: SymmetricKeyMaterial(randomByteCount: 64))
        #expect(throws: JWKError.keyTooShort(algorithm: "HS256", minimumByteCount: 32, found: 31)) {
            try HMACSigner<HS256>(key: SymmetricKeyMaterial(randomByteCount: 31))
        }
        #expect(throws: JWKError.keyTooShort(algorithm: "HS384", minimumByteCount: 48, found: 32)) {
            try HMACVerifier<HS384>(key: SymmetricKeyMaterial(randomByteCount: 32))
        }
        #expect(throws: JWKError.keyTooShort(algorithm: "HS512", minimumByteCount: 64, found: 0)) {
            try HMACVerifier<HS512>(key: SymmetricKeyMaterial(rawRepresentation: Data()))
        }
    }

    @Test("generated symmetric keys have the requested length and differ from each other")
    func symmetricKeyGeneration() {
        let first = SymmetricKeyMaterial(randomByteCount: 48)
        let second = SymmetricKeyMaterial(randomByteCount: 48)
        #expect(first.rawRepresentation.count == 48)
        #expect(first.rawRepresentation != second.rawRepresentation)
    }

    @Test("a signature from one key does not verify under another")
    func wrongKey() async throws {
        let signer = try ECDSASigner(privateKey: try ECPrivateKey<P256Curve>())
        let other = try ECDSAVerifier(publicKey: (try ECPrivateKey<P256Curve>()).publicKey)
        let own = try ECDSAVerifier(publicKey: signer.publicKey)
        let message = Data("message".utf8)
        let signature = try await signer.sign(message)
        try own.verify(signature, for: message)
        do {
            try other.verify(signature, for: message)
            Issue.record("verified under the wrong key")
        } catch {
            guard case .signatureMismatch(let algorithm) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(algorithm == "ES256")
        }
    }

    @Test("a verifier cannot be built from a JWK of another key type")
    func keyTypeMismatch() throws {
        let p256 = JWK(.p256((try ECPrivateKey<P256Curve>()).publicKey))
        let ed25519 = JWK(.ed25519((try Ed25519PrivateKey()).publicKey))
        _ = try ECDSAVerifier<P256Curve>(jwk: p256)
        _ = try Ed25519Verifier<EdDSA>(jwk: ed25519)
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC P-384", found: "EC P-256")) {
            try ECDSAVerifier<P384Curve>(jwk: p256)
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "EC P-256", found: "OKP Ed25519")) {
            try ECDSAVerifier<P256Curve>(jwk: ed25519)
        }
        #expect(throws: JWKError.keyTypeMismatch(expected: "OKP Ed25519", found: "EC P-256")) {
            try Ed25519Verifier<EdDSA>(jwk: p256)
        }
    }

    @Test("use, key_ops and alg on a JWK restrict what it can be used for")
    func metadataRestrictions() throws {
        let key = JWK.Key.p256((try ECPrivateKey<P256Curve>()).publicKey)

        let permitted = JWK(
            key,
            metadata: JWKMetadata(keyID: "a", use: .signature, keyOperations: [.verify], algorithm: "ES256")
        )
        #expect(try ECDSAVerifier<P256Curve>(jwk: permitted).keyID == "a")

        #expect(throws: JWKError.useNotPermitted(use: "enc", required: "sig")) {
            try ECDSAVerifier<P256Curve>(jwk: JWK(key, metadata: JWKMetadata(use: .encryption)))
        }
        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["sign"], required: "verify")) {
            try ECDSAVerifier<P256Curve>(jwk: JWK(key, metadata: JWKMetadata(keyOperations: [.sign])))
        }
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "ES384", required: "ES256")) {
            try ECDSAVerifier<P256Curve>(jwk: JWK(key, metadata: JWKMetadata(algorithm: "ES384")))
        }

        let edwards = JWK.Key.ed25519((try Ed25519PrivateKey()).publicKey)
        _ = try Ed25519Verifier<EdDSA>(jwk: JWK(edwards, metadata: JWKMetadata(algorithm: "EdDSA")))
        // The two identifiers are distinct algorithms; a key restricted to one is not usable as the other.
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "EdDSA", required: "Ed25519")) {
            try Ed25519Verifier<JOSECore.Ed25519>(jwk: JWK(edwards, metadata: JWKMetadata(algorithm: "EdDSA")))
        }
        #expect(throws: JWKError.useNotPermitted(use: "enc", required: "sig")) {
            try Ed25519Verifier<EdDSA>(jwk: JWK(edwards, metadata: JWKMetadata(use: .encryption)))
        }

        let secret = SymmetricKeyMaterial(randomByteCount: 32)
        _ = try HMACSigner<HS256>(jwk: SymmetricJWK(secret, metadata: JWKMetadata(keyOperations: [.sign])))
        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["verify"], required: "sign")) {
            try HMACSigner<HS256>(jwk: SymmetricJWK(secret, metadata: JWKMetadata(keyOperations: [.verify])))
        }
        #expect(throws: JWKError.keyOperationNotPermitted(operations: ["sign"], required: "verify")) {
            try HMACVerifier<HS256>(jwk: SymmetricJWK(secret, metadata: JWKMetadata(keyOperations: [.sign])))
        }
        #expect(throws: JWKError.algorithmMismatch(keyAlgorithm: "HS512", required: "HS256")) {
            try HMACVerifier<HS256>(jwk: SymmetricJWK(secret, metadata: JWKMetadata(algorithm: "HS512")))
        }
    }

    // The conversion itself lives in JOSECore; this is the every-platform version of the check
    // that JOSECore can only run where CryptoKit exists. It signs real messages and compares the
    // converter's output with the crypto library's own DER and raw forms.
    @Test("DER conversion agrees with the crypto library across 500 signatures per curve")
    func derConversionAgainstCryptoLibrary() async throws {
        try await Self.checkDERConversion(P256Curve.self, count: 500)
        try await Self.checkDERConversion(P384Curve.self, count: 500)
        try await Self.checkDERConversion(P521Curve.self, count: 500)
    }

    private static func checkDERConversion<Curve: ECDSACurve>(_ curve: Curve.Type, count: Int) async throws {
        let privateKey = try ECPrivateKey<Curve>()
        let signer = try ECDSASigner(privateKey: privateKey)
        let verifier = try ECDSAVerifier(publicKey: privateKey.publicKey)
        var sawShortComponent = false
        for index in 0..<count {
            let message = Data("message \(index)".utf8)
            let signature = try await signer.sign(message)
            let der = try signature.derRepresentation
            let roundTripped = try Signature<Curve.Algorithm>(derRepresentation: der)
            #expect(roundTripped.rawRepresentation == signature.rawRepresentation)
            try verifier.verify(roundTripped, for: message)
            #expect(try PlatformDER.matches(curve, raw: signature.rawRepresentation, der: der))
            let raw = signature.rawRepresentation
            sawShortComponent = sawShortComponent || raw[0] == 0 || raw[Curve.coordinateByteCount] == 0
        }
        // A zero leading byte is expected in ~98% of runs of 500 for P-256 and P-384 and always
        // for P-521; not asserted, so an unlucky run does not fail. JOSECore's fixture test
        // always covers the pad path.
        if !sawShortComponent {
            print("note: no short component among \(count) \(Curve.name) signatures in this run")
        }
    }
}
