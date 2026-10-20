import Foundation
import JOSECore
import Testing

@testable import JOSEJWK

/// The fixture written by `interop/jwk/generate-pem-fixtures.mjs`.
struct PEMFixture: Decodable {
    struct Encoding: Decodable {
        let label: String
        let pem: String
        let isPrivate: Bool
    }
    struct Key: Decodable {
        let label: String
        let publicJwk: [String: String]
        let privateJwk: [String: String]
        let encodings: [Encoding]
    }
    struct Refused: Decodable {
        let label: String
        let pem: String
        let isPrivate: Bool
        let reason: String
    }
    let keys: [Key]
    let refused: [Refused]

    static func load() throws -> PEMFixture {
        try PEMFixture(fixture: "pem")
    }

    func key(_ label: String) throws -> Key {
        guard let key = keys.first(where: { $0.label == label }) else {
            throw FixtureError(description: "pem.json has no key \(label)")
        }
        return key
    }
}

extension PEMFixture.Key {
    func encoding(_ label: String) throws -> String {
        guard let encoding = encodings.first(where: { $0.label == label }) else {
            throw FixtureError(description: "pem.json has no encoding \(label)")
        }
        return encoding.pem
    }
}

// DER for hand-made inputs, written independently of the reader under test.
extension [UInt8] {
    /// `NULL`.
    static var derNull: [UInt8] {
        [0x05, 0x00]
    }

    /// One element: `tag`, the definite length, then `content`.
    init(derTag tag: UInt8, _ content: [UInt8]) {
        guard content.count >= 0x80 else {
            self = [tag, UInt8(content.count)] + content
            return
        }
        var octets: [UInt8] = []
        var remaining = content.count
        while remaining > 0 {
            octets.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        self = [tag, 0x80 | UInt8(octets.count)] + octets + content
    }

    init(derSequence parts: [UInt8]...) {
        self.init(derTag: 0x30, parts.flatMap { $0 })
    }

    init(derInteger value: UInt8) {
        self.init(derTag: 0x02, [value])
    }

    init(derOctetString content: [UInt8]) {
        self.init(derTag: 0x04, content)
    }

    init(derBitString content: [UInt8], tag: UInt8 = 0x03) {
        self.init(derTag: tag, [0x00] + content)
    }

    init(derOID dotted: String) throws {
        var arcs: [UInt64] = []
        for part in dotted.split(separator: ".") {
            guard let arc = UInt64(part) else {
                throw FixtureError(description: "\(dotted) is not a dotted OID")
            }
            arcs.append(arc)
        }
        guard arcs.count >= 2 else {
            throw FixtureError(description: "\(dotted) has fewer than two arcs")
        }
        var content: [UInt8] = []
        for arc in [arcs[0] * 40 + arcs[1]] + arcs.dropFirst(2) {
            var groups = [UInt8(arc & 0x7F)]
            var remaining = arc >> 7
            while remaining > 0 {
                groups.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
                remaining >>= 7
            }
            content += groups
        }
        self.init(derTag: 0x06, content)
    }

    /// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }`
    init(spki algorithm: [UInt8], _ key: [UInt8], trailing: [UInt8] = []) {
        self.init(derSequence: [UInt8](derSequence: algorithm), [UInt8](derBitString: key), trailing)
    }

    /// `PrivateKeyInfo ::= SEQUENCE { version, privateKeyAlgorithm, privateKey OCTET STRING, ... }`
    init(pkcs8Version version: UInt8, _ algorithm: [UInt8], _ privateKey: [UInt8], _ rest: [UInt8] = []) {
        self.init(
            derSequence: [UInt8](derInteger: version),
            [UInt8](derSequence: algorithm),
            [UInt8](derOctetString: privateKey),
            rest
        )
    }

    /// `ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, [0] parameters, [1] publicKey }`
    init(sec1Version version: UInt8, _ scalar: Data, curve: [UInt8] = [], publicKey: [UInt8] = []) {
        var parts = [UInt8](derInteger: version) + [UInt8](derOctetString: [UInt8](scalar))
        if !curve.isEmpty {
            parts += [UInt8](derTag: 0xA0, curve)
        }
        if !publicKey.isEmpty {
            parts += [UInt8](derTag: 0xA1, publicKey)
        }
        self.init(derTag: 0x30, parts)
    }
}

extension String {
    /// `der` as a PEM block labelled `label`.
    init(pemLabel label: String, _ der: [UInt8]) {
        let body = Data(der).base64EncodedString(options: .lineLength64Characters)
        self = "-----BEGIN \(label)-----\n\(body)\n-----END \(label)-----\n"
    }
}

@Suite("PEM import")
struct PEMTests {
    private static let publicLabels = ["PUBLIC KEY", "RSA PUBLIC KEY"]
    private static let privateLabels = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]

    private func members(_ json: Data) throws -> [String: String] {
        try JSONDecoder().decode([String: String].self, from: json)
    }

    private func failure(_ body: () throws(JWKError) -> Void) -> JWKError? {
        do {
            try body()
            return nil
        } catch {
            return error
        }
    }

    private func publicFailure(_ pem: String) -> JWKError? {
        failure { () throws(JWKError) in _ = try JWK(pem: pem) }
    }

    private func privateFailure(_ pem: String) -> JWKError? {
        failure { () throws(JWKError) in _ = try PrivateJWK(pem: pem) }
    }

    private func caseName(_ error: JWKError) -> String {
        switch error {
        case .invalidPEM:
            return "invalidPEM"
        case .wrongPEMType:
            return "wrongPEMType"
        case .unsupportedKeyAlgorithm:
            return "unsupportedKeyAlgorithm"
        case .rsaKeyTooSmall:
            return "rsaKeyTooSmall"
        default:
            return "\(error)"
        }
    }

    // MARK: OpenSSL's encodings

    @Test("every PEM OpenSSL writes for a supported key reads as the same key as its JWK")
    func readsOpenSSLEncodings() throws {
        let fixture = try PEMFixture.load()
        #expect(fixture.keys.count == 7)
        var labels: Set<String> = []
        for key in fixture.keys {
            for encoding in key.encodings {
                labels.insert(try PEMDocument(encoding.pem).label)
                if encoding.isPrivate {
                    let jwk = try PrivateJWK(pem: encoding.pem)
                    #expect(try members(jwk.jsonRepresentation()) == key.privateJwk, "\(encoding.label)")
                    #expect(try members(jwk.publicJWK.jsonRepresentation()) == key.publicJwk, "\(encoding.label)")
                } else {
                    let jwk = try JWK(pem: encoding.pem)
                    #expect(try members(jwk.jsonRepresentation()) == key.publicJwk, "\(encoding.label)")
                }
            }
        }
        // Every PEM type the package reads is exercised.
        #expect(labels == Set(Self.publicLabels + Self.privateLabels))
    }

    @Test("a private PEM is not a public key, and a public PEM is not a private key")
    func wrongKind() throws {
        for key in try PEMFixture.load().keys {
            for encoding in key.encodings {
                let label = try PEMDocument(encoding.pem).label
                if encoding.isPrivate {
                    #expect(
                        publicFailure(encoding.pem) == .wrongPEMType(found: label, expected: Self.publicLabels),
                        "\(encoding.label)"
                    )
                } else {
                    #expect(
                        privateFailure(encoding.pem) == .wrongPEMType(found: label, expected: Self.privateLabels),
                        "\(encoding.label)"
                    )
                }
            }
        }
        let certificate = String(pemLabel: "CERTIFICATE", [UInt8](derSequence: [UInt8].derNull))
        #expect(publicFailure(certificate) == .wrongPEMType(found: "CERTIFICATE", expected: Self.publicLabels))
        #expect(privateFailure(certificate) == .wrongPEMType(found: "CERTIFICATE", expected: Self.privateLabels))
    }

    @Test("PEMs OpenSSL writes for keys this package does not support are refused for the recorded reason")
    func refusesUnsupported() throws {
        let fixture = try PEMFixture.load()
        #expect(fixture.refused.count == 8)
        for entry in fixture.refused {
            var error = publicFailure(entry.pem)
            if entry.isPrivate {
                error = privateFailure(entry.pem)
            }
            #expect(error.map(caseName) == entry.reason, "\(entry.label): \(String(describing: error))")
        }
        // The refused algorithm or curve is named by its OID.
        let oids = ["brainpoolP256r1": "1.3.36.3.3.2.8.1.1.7", "Ed448": "1.3.101.113"]
        for entry in fixture.refused {
            for (prefix, oid) in oids where entry.label.hasPrefix(prefix) {
                var error = publicFailure(entry.pem)
                if entry.isPrivate {
                    error = privateFailure(entry.pem)
                }
                #expect(error == .unsupportedKeyAlgorithm(oid: oid), "\(entry.label)")
            }
        }
    }

    @Test("metadata is attached to the key read from PEM")
    func metadata() throws {
        let key = try PEMFixture.load().key("P-256")
        let metadata = JWKMetadata(keyID: "pem-key", use: .signature)
        #expect(try JWK(pem: key.encoding("P-256 spki public"), metadata: metadata).metadata == metadata)
        #expect(try PrivateJWK(pem: key.encoding("P-256 sec1 private"), metadata: metadata).metadata == metadata)
    }

    // MARK: Armour

    @Test("PEM armour is read strictly")
    func armour() throws {
        let valid = try PEMFixture.load().key("P-256").encoding("P-256 spki public")
        let expected = try JWK(pem: valid)
        let lines = valid.split(separator: "\n").map(String.init)
        let body = lines.dropFirst().dropLast().joined(separator: "\n")

        // Surrounding whitespace, indentation, blank lines and CRLF line ends are allowed.
        let loose = "\n  \r\n" + lines.map { "  \($0) \t" }.joined(separator: "\r\n") + "\r\n   \n"
        #expect(try JWK(pem: loose) == expected)

        func reason(_ text: String) -> String? {
            guard case .invalidPEM(let reason) = publicFailure(text) else {
                return "other: \(String(describing: publicFailure(text)))"
            }
            return reason
        }
        #expect(reason("") == "there is no BEGIN and END line")
        #expect(reason("-----BEGIN PUBLIC KEY-----\n") == "there is no BEGIN and END line")
        #expect(reason("PUBLIC KEY\n\(body)\n-----END PUBLIC KEY-----") == "the first line is not a BEGIN line")
        #expect(
            reason("-----BEGAN PUBLIC KEY-----\n\(body)\n-----END PUBLIC KEY-----")
                == "the first line is not a BEGIN line"
        )
        #expect(
            reason("-----BEGIN PUBLIC KEY\n\(body)\n-----END PUBLIC KEY-----") == "the first line is not a BEGIN line"
        )
        #expect(reason("-----BEGIN -----\n\(body)\n-----END -----") == "the first line is not a BEGIN line")
        #expect(
            reason("-----BEGIN PUBLIC KEY-----\n\(body)\n-----END PRIVATE KEY-----")
                == "the last line is not END PUBLIC KEY"
        )
        #expect(reason(valid + valid) == "the text holds more than one PEM block")
        #expect(
            reason("-----BEGIN PUBLIC KEY-----\nProc-Type: 4,ENCRYPTED\n\(body)\n-----END PUBLIC KEY-----")
                == "the block has headers, as a legacy encrypted key does; these are not supported"
        )
        #expect(reason("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----") == "the body is not base64")
        #expect(reason("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----") == "the body is not base64")
    }

    // MARK: Hand-made structures

    private struct Keys {
        let rsa: RSAPrivateKey
        let otherRSA: RSAPrivateKey
        let p256: ECPrivateKey<P256Curve>
        let otherP256: ECPrivateKey<P256Curve>
        let ed25519: Ed25519PrivateKey
        let otherEd25519: Ed25519PrivateKey
        let x25519: X25519PrivateKey
        let otherX25519: X25519PrivateKey

        init() throws {
            let fixture = try PEMFixture.load()
            rsa = try Self.rsaKey(fixture.key("RSA 2048").encoding("RSA 2048 pkcs1 private"))
            otherRSA = try Self.rsaKey(fixture.key("RSA 3072").encoding("RSA 3072 pkcs1 private"))
            p256 = try ECPrivateKey<P256Curve>()
            otherP256 = try ECPrivateKey<P256Curve>()
            ed25519 = try Ed25519PrivateKey()
            otherEd25519 = try Ed25519PrivateKey()
            x25519 = try X25519PrivateKey()
            otherX25519 = try X25519PrivateKey()
        }

        private static func rsaKey(_ pem: String) throws -> RSAPrivateKey {
            guard case .rsa(let key) = try PrivateJWK(pem: pem).key else {
                throw FixtureError(description: "the RSA fixture is not an RSA key")
            }
            return key
        }
    }

    private func derReason(_ error: JWKError?) -> String? {
        guard case .invalidDER(let reason) = error else {
            return "other: \(String(describing: error))"
        }
        return reason
    }

    @Test("SubjectPublicKeyInfo is read strictly")
    func subjectPublicKeyInfo() throws {
        let keys = try Keys()
        let rsaAlgorithm = try [UInt8](derOID: KeyAlgorithmOID.rsaEncryption.rawValue)
        let rsaKey = [UInt8](keys.rsa.publicKey.pkcs1DERRepresentation)
        let ecAlgorithm =
            try [UInt8](derOID: KeyAlgorithmOID.ecPublicKey.rawValue) + [UInt8](derOID: NamedCurveOID.p256.rawValue)
        let ecKey = [UInt8](keys.p256.publicKey.x963Representation)
        func pem(_ der: [UInt8]) -> String {
            String(pemLabel: "PUBLIC KEY", der)
        }

        // RSA parameters are NULL, as OpenSSL writes them, or absent, as some encoders write them.
        #expect(
            try JWK(pem: pem([UInt8](spki: rsaAlgorithm + [UInt8].derNull, rsaKey))) == JWK(.rsa(keys.rsa.publicKey))
        )
        #expect(try JWK(pem: pem([UInt8](spki: rsaAlgorithm, rsaKey))) == JWK(.rsa(keys.rsa.publicKey)))
        #expect(
            derReason(
                publicFailure(
                    pem([UInt8](spki: rsaAlgorithm + (try [UInt8](derOID: NamedCurveOID.p256.rawValue)), rsaKey))
                )
            )
                == "10 unexpected bytes after algorithm"
        )
        #expect(
            derReason(publicFailure(pem([UInt8](spki: rsaAlgorithm + [UInt8](derTag: 0x05, [0x00]), rsaKey))))
                == "parameters is a NULL with content"
        )

        #expect(try JWK(pem: pem([UInt8](spki: ecAlgorithm, ecKey))) == JWK(.p256(keys.p256.publicKey)))
        #expect(
            derReason(
                publicFailure(pem([UInt8](spki: try [UInt8](derOID: KeyAlgorithmOID.ecPublicKey.rawValue), ecKey)))
            )
                == "input ends inside namedCurve"
        )
        #expect(
            derReason(publicFailure(pem([UInt8](spki: ecAlgorithm + [UInt8].derNull, ecKey))))
                == "2 unexpected bytes after algorithm"
        )
        #expect(
            derReason(publicFailure(pem([UInt8](spki: ecAlgorithm, ecKey, trailing: [UInt8].derNull))))
                == "2 unexpected bytes after SubjectPublicKeyInfo"
        )

        // RFC 8410 §3: Ed25519 and X25519 have no parameters.
        let edAlgorithm = try [UInt8](derOID: KeyAlgorithmOID.ed25519.rawValue)
        let edKey = [UInt8](keys.ed25519.publicKey.rawRepresentation)
        #expect(try JWK(pem: pem([UInt8](spki: edAlgorithm, edKey))) == JWK(.ed25519(keys.ed25519.publicKey)))
        #expect(
            derReason(publicFailure(pem([UInt8](spki: edAlgorithm + [UInt8].derNull, edKey))))
                == "2 unexpected bytes after algorithm"
        )
        let xAlgorithm = try [UInt8](derOID: KeyAlgorithmOID.x25519.rawValue)
        let xKey = [UInt8](keys.x25519.publicKey.rawRepresentation)
        #expect(try JWK(pem: pem([UInt8](spki: xAlgorithm, xKey))) == JWK(.x25519(keys.x25519.publicKey)))
        #expect(
            derReason(publicFailure(pem([UInt8](spki: xAlgorithm + [UInt8].derNull, xKey))))
                == "2 unexpected bytes after algorithm"
        )
    }

    @Test("PKCS#8 private keys are read strictly, and an embedded public key must match")
    func pkcs8() throws {
        let keys = try Keys()
        func pem(_ der: [UInt8]) -> String {
            String(pemLabel: "PRIVATE KEY", der)
        }
        func publicKey(_ bytes: Data) -> [UInt8] {
            [UInt8](derBitString: [UInt8](bytes), tag: 0x81)
        }
        func publicMembers(_ der: [UInt8]) throws -> [String: String] {
            try members(PrivateJWK(pem: pem(der)).publicJWK.jsonRepresentation())
        }

        let edAlgorithm = try [UInt8](derOID: KeyAlgorithmOID.ed25519.rawValue)
        let edKey = [UInt8](derOctetString: [UInt8](keys.ed25519.rawRepresentation))
        let edPublic = try members(JWK(.ed25519(keys.ed25519.publicKey)).jsonRepresentation())
        #expect(try publicMembers([UInt8](pkcs8Version: 0, edAlgorithm, edKey)) == edPublic)
        // Version 1 (RFC 5958) adds the public key; attributes are skipped.
        let edPublicKey = publicKey(keys.ed25519.publicKey.rawRepresentation)
        #expect(try publicMembers([UInt8](pkcs8Version: 1, edAlgorithm, edKey, edPublicKey)) == edPublic)
        let attributes = [UInt8](
            derTag: 0xA0,
            [UInt8](derSequence: try [UInt8](derOID: "1.2.840.113549.1.9.9.20"), [UInt8](derTag: 0x31, []))
        )
        #expect(try publicMembers([UInt8](pkcs8Version: 0, edAlgorithm, edKey, attributes)) == edPublic)
        #expect(try publicMembers([UInt8](pkcs8Version: 1, edAlgorithm, edKey, attributes + edPublicKey)) == edPublic)
        #expect(
            privateFailure(
                pem(
                    [UInt8](
                        pkcs8Version: 1,
                        edAlgorithm,
                        edKey,
                        publicKey(keys.otherEd25519.publicKey.rawRepresentation)
                    )
                )
            ) == .privateKeyDoesNotMatchPublicKey(curve: "Ed25519")
        )
        #expect(
            derReason(privateFailure(pem([UInt8](pkcs8Version: 2, edAlgorithm, edKey))))
                == "PrivateKeyInfo version is not 0 or 1"
        )
        #expect(
            derReason(privateFailure(pem([UInt8](pkcs8Version: 0, edAlgorithm, edKey, [UInt8].derNull))))
                == "2 unexpected bytes after PrivateKeyInfo"
        )
        #expect(
            derReason(privateFailure(pem([UInt8](pkcs8Version: 0, edAlgorithm + [UInt8].derNull, edKey))))
                == "2 unexpected bytes after privateKeyAlgorithm"
        )
        #expect(
            derReason(privateFailure(pem([UInt8](pkcs8Version: 0, edAlgorithm, edKey + [UInt8].derNull))))
                == "2 unexpected bytes after CurvePrivateKey"
        )

        let xAlgorithm = try [UInt8](derOID: KeyAlgorithmOID.x25519.rawValue)
        let xKey = [UInt8](derOctetString: [UInt8](keys.x25519.rawRepresentation))
        let xPublic = try members(JWK(.x25519(keys.x25519.publicKey)).jsonRepresentation())
        let xPublicKey = publicKey(keys.x25519.publicKey.rawRepresentation)
        #expect(try publicMembers([UInt8](pkcs8Version: 1, xAlgorithm, xKey, xPublicKey)) == xPublic)
        #expect(
            privateFailure(
                pem([UInt8](pkcs8Version: 1, xAlgorithm, xKey, publicKey(keys.otherX25519.publicKey.rawRepresentation)))
            ) == .privateKeyDoesNotMatchPublicKey(curve: "X25519")
        )
        #expect(
            derReason(privateFailure(pem([UInt8](pkcs8Version: 0, xAlgorithm + [UInt8].derNull, xKey))))
                == "2 unexpected bytes after privateKeyAlgorithm"
        )

        let rsaAlgorithm = try [UInt8](derOID: KeyAlgorithmOID.rsaEncryption.rawValue) + [UInt8].derNull
        let rsaKey = [UInt8](keys.rsa.pkcs1DERRepresentation)
        let rsaPublic = try members(JWK(.rsa(keys.rsa.publicKey)).jsonRepresentation())
        let rsaPublicKey = publicKey(keys.rsa.publicKey.pkcs1DERRepresentation)
        #expect(try publicMembers([UInt8](pkcs8Version: 1, rsaAlgorithm, rsaKey, rsaPublicKey)) == rsaPublic)
        #expect(
            privateFailure(
                pem(
                    [UInt8](
                        pkcs8Version: 1,
                        rsaAlgorithm,
                        rsaKey,
                        publicKey(keys.otherRSA.publicKey.pkcs1DERRepresentation)
                    )
                )
            ) == .privateKeyDoesNotMatchPublicKey(curve: "RSA")
        )
        #expect(
            derReason(
                privateFailure(
                    pem(
                        [UInt8](
                            pkcs8Version: 0,
                            rsaAlgorithm + (try [UInt8](derOID: NamedCurveOID.p256.rawValue)),
                            rsaKey
                        )
                    )
                )
            )
                == "10 unexpected bytes after algorithm"
        )

        let p256 = try [UInt8](derOID: NamedCurveOID.p256.rawValue)
        let p384 = try [UInt8](derOID: NamedCurveOID.p384.rawValue)
        let ecAlgorithm = try [UInt8](derOID: KeyAlgorithmOID.ecPublicKey.rawValue) + p256
        let ecPublic = try members(JWK(.p256(keys.p256.publicKey)).jsonRepresentation())
        let scalar = keys.p256.rawRepresentation
        let ecPublicKey = publicKey(keys.p256.publicKey.x963Representation)
        #expect(
            try publicMembers([UInt8](pkcs8Version: 1, ecAlgorithm, [UInt8](sec1Version: 1, scalar), ecPublicKey))
                == ecPublic
        )
        #expect(
            privateFailure(
                pem(
                    [UInt8](
                        pkcs8Version: 1,
                        ecAlgorithm,
                        [UInt8](sec1Version: 1, scalar),
                        publicKey(keys.otherP256.publicKey.x963Representation)
                    )
                )
            ) == .privateKeyDoesNotMatchPublicKey(curve: "P-256")
        )
        // The algorithm's curve and the key's own may both be given, and must then agree.
        #expect(
            try publicMembers([UInt8](pkcs8Version: 0, ecAlgorithm, [UInt8](sec1Version: 1, scalar, curve: p256)))
                == ecPublic
        )
        #expect(
            derReason(
                privateFailure(pem([UInt8](pkcs8Version: 0, ecAlgorithm, [UInt8](sec1Version: 1, scalar, curve: p384))))
            )
                == "the key's curve \(NamedCurveOID.p384.rawValue) differs from the algorithm's \(NamedCurveOID.p256.rawValue)"
        )
        #expect(
            derReason(
                privateFailure(
                    pem([UInt8](pkcs8Version: 0, ecAlgorithm + [UInt8].derNull, [UInt8](sec1Version: 1, scalar)))
                )
            )
                == "2 unexpected bytes after privateKeyAlgorithm"
        )
    }

    @Test("SEC1 EC private keys are read strictly, and an embedded public key must match")
    func sec1() throws {
        let keys = try Keys()
        func pem(_ der: [UInt8]) -> String {
            String(pemLabel: "EC PRIVATE KEY", der)
        }
        let p256 = try [UInt8](derOID: NamedCurveOID.p256.rawValue)
        let scalar = keys.p256.rawRepresentation
        let publicKey = [UInt8](derBitString: [UInt8](keys.p256.publicKey.x963Representation))
        let expected = try members(JWK(.p256(keys.p256.publicKey)).jsonRepresentation())

        #expect(
            try members(
                PrivateJWK(pem: pem([UInt8](sec1Version: 1, scalar, curve: p256))).publicJWK.jsonRepresentation()
            ) == expected
        )
        #expect(
            try members(
                PrivateJWK(pem: pem([UInt8](sec1Version: 1, scalar, curve: p256, publicKey: publicKey))).publicJWK
                    .jsonRepresentation()
            ) == expected
        )
        #expect(
            privateFailure(
                pem(
                    [UInt8](
                        sec1Version: 1,
                        scalar,
                        curve: p256,
                        publicKey: [UInt8](derBitString: [UInt8](keys.otherP256.publicKey.x963Representation))
                    )
                )
            ) == .privateKeyDoesNotMatchPublicKey(curve: "P-256")
        )
        #expect(derReason(privateFailure(pem([UInt8](sec1Version: 1, scalar)))) == "ECPrivateKey names no curve")
        #expect(
            derReason(privateFailure(pem([UInt8](sec1Version: 0, scalar, curve: p256))))
                == "ECPrivateKey version is not 1"
        )
        #expect(
            derReason(privateFailure(pem([UInt8](sec1Version: 1, scalar, curve: p256 + [UInt8].derNull))))
                == "2 unexpected bytes after parameters"
        )
        #expect(
            derReason(
                privateFailure(
                    pem([UInt8](sec1Version: 1, scalar, curve: p256, publicKey: publicKey + [UInt8].derNull))
                )
            )
                == "2 unexpected bytes after publicKey"
        )
        let trailing = [UInt8](
            derTag:
                0x30,
            [UInt8](derInteger: 1) + [UInt8](derOctetString: [UInt8](scalar)) + [UInt8](derTag: 0xA0, p256)
                + [UInt8].derNull
        )
        #expect(derReason(privateFailure(pem(trailing))) == "2 unexpected bytes after ECPrivateKey")
    }
}

@Suite("DER reading")
struct DERReaderTests {
    private func reason(_ body: (inout DERReader) throws(JWKError) -> Void, _ bytes: [UInt8]) -> String? {
        var reader = DERReader(Data(bytes))
        do {
            try body(&reader)
            return nil
        } catch {
            guard case .invalidDER(let reason) = error else {
                return "other: \(error)"
            }
            return reason
        }
    }

    private func objectIdentifier(_ content: [UInt8]) throws -> String {
        var reader = DERReader(Data([0x06, UInt8(content.count)] + content))
        return try reader.readObjectIdentifier("oid")
    }

    @Test("an OBJECT IDENTIFIER reads in dotted form, with the first two arcs unpacked")
    func objectIdentifiers() throws {
        #expect(try objectIdentifier([0x27]) == "0.39")
        #expect(try objectIdentifier([0x28]) == "1.0")
        #expect(try objectIdentifier([0x4F]) == "1.39")
        #expect(try objectIdentifier([0x50]) == "2.0")
        #expect(try objectIdentifier([0x88, 0x37]) == "2.999")
        #expect(
            try objectIdentifier([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]) == KeyAlgorithmOID.ecPublicKey.rawValue
        )
        // The largest arc that fits in 63 bits reads; one more group does not.
        let largest: [UInt8] = Array(repeating: 0xFF, count: 8) + [0x7F]
        #expect(try objectIdentifier([0x2A] + largest) == "1.2.\(UInt64.max >> 1)")

        let read: (inout DERReader) throws(JWKError) -> Void = { reader throws(JWKError) in
            _ = try reader.readObjectIdentifier("oid")
        }
        #expect(reason(read, [0x06, 0x00]) == "oid is not a complete OBJECT IDENTIFIER")
        #expect(reason(read, [0x06, 0x02, 0x2A, 0x86]) == "oid is not a complete OBJECT IDENTIFIER")
        #expect(reason(read, [0x06, 0x03, 0x2A, 0x80, 0x01]) == "oid has a non-minimal arc")
        #expect(reason(read, [0x06, 0x0B, 0x2A, 0xFF] + largest) == "oid has an arc too large to read")
    }

    @Test("BIT STRING, OCTET STRING and NULL are read with their constraints")
    func primitives() {
        let bitString: (inout DERReader) throws(JWKError) -> Void = { reader throws(JWKError) in
            _ = try reader.readBitString("bits")
        }
        #expect(reason(bitString, [0x03, 0x02, 0x00, 0xFF]) == nil)
        #expect(reason(bitString, [0x03, 0x00]) == "bits is an empty BIT STRING")
        #expect(reason(bitString, [0x03, 0x02, 0x01, 0xFE]) == "bits does not hold whole bytes")
        #expect(reason(bitString, [0x04, 0x01, 0x00]) == "bits has tag 0x4; expected 0x3")

        let null: (inout DERReader) throws(JWKError) -> Void = { reader throws(JWKError) in
            try reader.readNull("nothing")
        }
        #expect(reason(null, [0x05, 0x00]) == nil)
        #expect(reason(null, [0x05, 0x01, 0x00]) == "nothing is a NULL with content")
    }

    @Test("the next tag is visible without reading, and absent at the end")
    func nextTag() throws {
        var reader = DERReader(Data([0x05, 0x00]))
        #expect(reader.nextTag == DERReader.null)
        #expect(!reader.isAtEnd)
        try reader.readNull("nothing")
        #expect(reader.nextTag == nil)
        #expect(reader.isAtEnd)
    }
}
