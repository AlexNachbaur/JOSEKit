#if canImport(CryptoKit)
    import CryptoKit
    import Foundation
    import JOSECore
    import Testing

    @testable import JOSEJWK

    /// Software stand-in for a Secure Enclave key, injected through the same seam the real key uses.
    private struct MockEnclaveKey: SecureEnclaveSigningKey {
        enum Behaviour {
            case normal
            case signingFails
            case returnsDER
            case reportsCompressedPublicKey
        }
        struct Refused: Error {}

        let key = P256.Signing.PrivateKey()
        var behaviour = Behaviour.normal

        var x963PublicKey: Data {
            if behaviour == .reportsCompressedPublicKey {
                return key.publicKey.compressedRepresentation
            }
            return key.publicKey.x963Representation
        }

        var dataRepresentation: Data {
            Data("opaque-blob".utf8)
        }

        func rawSignature(for message: Data) throws -> Data {
            switch behaviour {
            case .signingFails:
                throw Refused()
            case .returnsDER:
                return try key.signature(for: message).derRepresentation
            case .normal, .reportsCompressedPublicKey:
                return try key.signature(for: message).rawRepresentation
            }
        }
    }

    @Suite("SecureEnclaveSigner")
    struct SecureEnclaveSignerTests {
        @Test("signs ES256 that the key's public JWK verifies (mock key)")
        func signsWithMock() async throws {
            let mock = MockEnclaveKey()
            let signer = try SecureEnclaveSigner(key: mock, keyID: "device-key")
            #expect(signer.keyID == "device-key")
            #expect(signer.publicKey.x963Representation == mock.key.publicKey.x963Representation)
            #expect(signer.dataRepresentation == Data("opaque-blob".utf8))

            let message = Data("attest".utf8)
            let signature = try await signer.sign(message)
            #expect(signature.rawRepresentation.count == 64)
            let verifier = try ECDSAVerifier<P256Curve>(jwk: JWK(.p256(signer.publicKey)))
            try await verifier.verify(signature, for: message)
            await #expect(throws: VerificationError.self) {
                try await verifier.verify(signature, for: Data("other".utf8))
            }
        }

        @Test("works through the Signer protocol as an existential")
        func asExistential() async throws {
            let signer: any Signer<ES256> = try SecureEnclaveSigner(key: MockEnclaveKey(), keyID: nil)
            #expect(try await signer.sign(Data()).rawRepresentation.count == 64)
        }

        @Test("a failure inside the key is reported as a key operation failure with its cause")
        func signingFailure() async throws {
            let signer = try SecureEnclaveSigner(key: MockEnclaveKey(behaviour: .signingFails), keyID: nil)
            do {
                _ = try await signer.sign(Data())
                Issue.record("signing should have failed")
            } catch {
                guard case .keyOperationFailed(let algorithm, let underlying) = error else {
                    Issue.record("unexpected error \(error)")
                    return
                }
                #expect(algorithm == "ES256")
                #expect(underlying.typeName.hasSuffix("Refused"))
            }
        }

        @Test("a key that returns something other than a 64-byte signature is caught")
        func malformedSignature() async throws {
            let signer = try SecureEnclaveSigner(key: MockEnclaveKey(behaviour: .returnsDER), keyID: nil)
            do {
                _ = try await signer.sign(Data("message".utf8))
                Issue.record("a DER signature was accepted as raw")
            } catch {
                guard case .invalidSignature(.wrongLength(let algorithm, let expected, let found)) = error else {
                    Issue.record("unexpected error \(error)")
                    return
                }
                #expect(algorithm == "ES256")
                #expect(expected == 64)
                #expect(found >= 68)
            }
        }

        @Test("a key reporting a public key that is not an uncompressed point is refused")
        func invalidPublicKey() {
            do {
                _ = try SecureEnclaveSigner(key: MockEnclaveKey(behaviour: .reportsCompressedPublicKey), keyID: nil)
                Issue.record("a compressed public key was accepted")
            } catch {
                guard case .invalidPublicKey(.x963WrongLength(_, let expected, let found)) = error else {
                    Issue.record("unexpected error \(error)")
                    return
                }
                #expect(expected == 65)
                #expect(found == 33)
            }
        }

        @Test("restoring from a blob that is not a Secure Enclave key fails with a restoration error")
        func restoreGarbage() {
            guard SecureEnclave.isAvailable else {
                return
            }
            do {
                _ = try SecureEnclaveSigner(dataRepresentation: Data("not a key".utf8))
                Issue.record("garbage was restored as a key")
            } catch {
                guard case .keyRestorationFailed = error else {
                    Issue.record("unexpected error \(error)")
                    return
                }
            }
        }

        // Runs against the real Secure Enclave when the machine running the tests has one and lets
        // this process use it. Elsewhere (CI runners, simulators) it does nothing, so a pass there
        // says nothing about hardware.
        @Test("real Secure Enclave: generate, sign, restore and sign again", .enabled(if: SecureEnclave.isAvailable))
        func realHardware() async throws {
            let signer: SecureEnclaveSigner
            do {
                signer = try SecureEnclaveSigner.generate(accessibility: .whenUnlockedThisDeviceOnly, keyID: "hw")
            } catch {
                print("note: Secure Enclave present but unusable from this process, hardware test skipped: \(error)")
                return
            }
            let verifier = try ECDSAVerifier(publicKey: signer.publicKey)
            let message = Data("hardware".utf8)
            try await verifier.verify(try await signer.sign(message), for: message)

            let restored = try SecureEnclaveSigner(dataRepresentation: signer.dataRepresentation, keyID: "hw")
            #expect(restored.publicKey == signer.publicKey)
            try await verifier.verify(try await restored.sign(message), for: message)
            print("note: Secure Enclave hardware test ran against real hardware")
        }

        @Test("accessibility choices map to this-device-only protection classes")
        func accessibility() {
            #expect(
                SecureEnclaveAccessibility.whenUnlockedThisDeviceOnly.protection
                    == kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            )
            #expect(
                SecureEnclaveAccessibility.afterFirstUnlockThisDeviceOnly.protection
                    == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            )
        }

        @Test("every error has a message")
        func descriptions() {
            struct Underlying: Error {}
            let errors: [SecureEnclaveError] = [
                .unavailable,
                .accessControlCreationFailed(description: "why"),
                .keyCreationFailed(underlying: Underlying()),
                .keyRestorationFailed(underlying: Underlying()),
                .invalidPublicKey(.pointNotOnCurve(curve: "P-256")),
            ]
            for error in errors {
                #expect(error.description.count > 20)
            }
        }
    }
#endif
