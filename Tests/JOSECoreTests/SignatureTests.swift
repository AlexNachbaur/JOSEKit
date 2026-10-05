import Foundation
import Testing

@testable import JOSECore

/// An algorithm defined outside the package, the way an add-on would define one.
private struct CustomAlgorithm: SignatureAlgorithm {
    static let identifier: AlgorithmIdentifier = "X-CUSTOM"
    static let signatureByteCount: Int? = nil
}

/// Stands in for a key. "Signs" by reversing the message; enough to exercise the protocol
/// plumbing, which is all JOSECore owns. Real algorithms are tested in jose-jwk.
private struct ReversingSigner: Signer {
    typealias Algorithm = CustomAlgorithm
    let keyID: KeyID?

    func sign(_ message: Data) async throws(SigningError) -> Signature<CustomAlgorithm> {
        do {
            return try Signature(rawRepresentation: Data(message.reversed()))
        } catch {
            throw .invalidSignature(error)
        }
    }
}

private struct ReversingVerifier: Verifier {
    typealias Algorithm = CustomAlgorithm
    let keyID: KeyID?

    func verify(_ signature: Signature<CustomAlgorithm>, for message: Data) throws(VerificationError) {
        guard signature.rawRepresentation == Data(message.reversed()) else {
            throw .signatureMismatch(algorithm: Algorithm.identifier)
        }
    }
}

private struct UnavailableKey: Error {}

private struct FailingSigner: Signer {
    typealias Algorithm = ES256
    let keyID: KeyID? = nil

    func sign(_ message: Data) async throws(SigningError) -> Signature<ES256> {
        throw .keyOperationFailed(algorithm: Algorithm.identifier, underlying: UnavailableKey())
    }
}

@Suite("Signature and signing protocols")
struct SignatureTests {
    @Test("the shipped algorithms have the identifiers and sizes RFC 7518 gives them")
    func algorithmConstants() {
        #expect(ES256.identifier.rawValue == "ES256")
        #expect(ES384.identifier.rawValue == "ES384")
        #expect(ES512.identifier.rawValue == "ES512")
        #expect(HS256.identifier.rawValue == "HS256")
        #expect(HS384.identifier.rawValue == "HS384")
        #expect(HS512.identifier.rawValue == "HS512")
        #expect(Ed25519.identifier.rawValue == "Ed25519")
        #expect(EdDSA.identifier.rawValue == "EdDSA")
        #expect(Ed25519.signatureByteCount == 64)
        #expect(EdDSA.signatureByteCount == nil)
        let rsa: [(any SignatureAlgorithm.Type, String)] = [
            (RS256.self, "RS256"), (RS384.self, "RS384"), (RS512.self, "RS512"),
            (PS256.self, "PS256"), (PS384.self, "PS384"), (PS512.self, "PS512"),
        ]
        for (algorithm, name) in rsa {
            #expect(algorithm.identifier.rawValue == name)
            #expect(algorithm.signatureByteCount == nil)
        }
        #expect(ES256.signatureByteCount == 64)
        #expect(ES384.signatureByteCount == 96)
        #expect(ES512.signatureByteCount == 132)
        #expect(HS256.signatureByteCount == 32)
        #expect(HS384.signatureByteCount == 48)
        #expect(HS512.signatureByteCount == 64)
    }

    @Test("a signature of the right length is accepted and one of the wrong length is refused")
    func lengthIsEnforced() throws {
        let signature = try Signature<ES256>(rawRepresentation: Data(count: 64))
        #expect(signature.rawRepresentation.count == 64)

        #expect(throws: SignatureError.wrongLength(algorithm: "ES256", expected: 64, found: 63)) {
            try Signature<ES256>(rawRepresentation: Data(count: 63))
        }
        // A DER signature handed over as if it were raw is the mistake this guards against.
        #expect(throws: SignatureError.wrongLength(algorithm: "ES256", expected: 64, found: 70)) {
            try Signature<ES256>(rawRepresentation: Data(count: 70))
        }
        #expect(throws: SignatureError.wrongLength(algorithm: "HS384", expected: 48, found: 32)) {
            try Signature<HS384>(rawRepresentation: Data(count: 32))
        }
    }

    @Test("an algorithm without a fixed size accepts any length")
    func variableLength() throws {
        #expect(try Signature<CustomAlgorithm>(rawRepresentation: Data(count: 7)).rawRepresentation.count == 7)
        #expect(try Signature<CustomAlgorithm>(rawRepresentation: Data()).rawRepresentation.isEmpty)
    }

    @Test("an ECDSA signature converts from and to DER using its algorithm's coordinate size")
    func derConversion() throws {
        let der = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])

        let es256 = try Signature<ES256>(derRepresentation: der)
        #expect(es256.rawRepresentation.count == 64)
        #expect(es256.rawRepresentation.last == 0x02)
        #expect(try es256.derRepresentation == der)

        let es384 = try Signature<ES384>(derRepresentation: der)
        #expect(es384.rawRepresentation.count == 96)
        let es512 = try Signature<ES512>(derRepresentation: der)
        #expect(es512.rawRepresentation.count == 132)

        #expect(throws: ECDSASignatureError.derTruncated(offset: 0)) {
            try Signature<ES256>(derRepresentation: Data())
        }
    }

    @Test("a custom algorithm signs and verifies through the protocols, including as an existential")
    func customAlgorithm() async throws {
        let signer: any Signer<CustomAlgorithm> = ReversingSigner(keyID: "key-1")
        let verifier: any Verifier<CustomAlgorithm> = ReversingVerifier(keyID: "key-1")
        let message = Data("payload".utf8)

        let signature = try await signer.sign(message)
        #expect(signer.keyID == "key-1")
        try verifier.verify(signature, for: message)

        // Written as do/catch rather than `#expect { } throws:` because the latter crashes the
        // Swift 6.0.3 compiler on Linux when the closure has a typed throw.
        do {
            try verifier.verify(signature, for: Data("other".utf8))
            Issue.record("a signature over a different message was accepted")
        } catch {
            guard case .signatureMismatch(let algorithm) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(algorithm == "X-CUSTOM")
        }
    }

    @Test("a signer's failure carries the algorithm and the underlying error")
    func signerFailure() async {
        do {
            _ = try await FailingSigner().sign(Data())
            Issue.record("signing should have failed")
        } catch {
            guard case .keyOperationFailed(let algorithm, let underlying) = error else {
                Issue.record("unexpected error \(error)")
                return
            }
            #expect(algorithm == "ES256")
            #expect(underlying is UnavailableKey)
            #expect(error.description.contains("ES256"))
            #expect(error.description.contains("UnavailableKey"))
        }
    }

    @Test("identifiers encode as plain JSON strings and compare case-sensitively")
    func identifiers() throws {
        struct Header: Codable, Equatable {
            let alg: AlgorithmIdentifier
            let kid: KeyID
        }
        let json = Data(#"{"alg":"ES256","kid":"abc"}"#.utf8)
        let header = try JSONDecoder().decode(Header.self, from: json)
        #expect(header == Header(alg: "ES256", kid: "abc"))

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        #expect(try encoder.encode(header) == json)

        #expect(AlgorithmIdentifier(rawValue: "ES256") != AlgorithmIdentifier(rawValue: "es256"))
        #expect(KeyID(rawValue: "A") != KeyID(rawValue: "a"))
        #expect(AlgorithmIdentifier(rawValue: "ES256").description == "ES256")
        #expect(KeyID(rawValue: "abc").description == "abc")
    }

    @Test("error messages name the algorithm and the sizes involved")
    func descriptions() {
        let wrongLength = SignatureError.wrongLength(algorithm: "ES256", expected: 64, found: 70)
        #expect(wrongLength.description == "ES256 signature is 70 bytes; expected 64")
        #expect(SigningError.invalidSignature(wrongLength).description.contains("70"))
        #expect(
            SigningError.invalidDERSignature(algorithm: "ES384", .derTruncated(offset: 3)).description
                .contains("ES384")
        )
        #expect(VerificationError.signatureMismatch(algorithm: "HS256").description.contains("HS256"))
        #expect(
            VerificationError.keyOperationFailed(algorithm: "ES512", underlying: UnavailableKey()).description
                .contains("ES512")
        )
    }
}
