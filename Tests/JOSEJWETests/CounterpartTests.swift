import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWE

private struct ValidFixture: Decodable {
    struct Compact: Decodable {
        let label: String
        let algorithm: String
        let encryption: String
        let jwk: String
        let plaintext: String
        let token: String
    }
    struct PartyInfo: Decodable {
        let algorithm: String
        let jwk: String
        let plaintext: String
        let token: String
    }
    struct Flattened: Decodable {
        let json: String
        let jwk: String
        let plaintext: String
        let aad: String
    }
    struct General: Decodable {
        struct Recipient: Decodable {
            let algorithm: String
            let keyID: String
            let jwk: String
        }
        let json: String
        let plaintext: String
        let recipients: [Recipient]
    }
    let compact: [Compact]
    let withPartyInfo: [PartyInfo]
    let flattened: Flattened
    let general: General
}

private struct DecryptionFixture: Decodable {
    struct Case: Decodable {
        struct Jose: Decodable {
            let accepted: Bool
            let plaintext: String?
        }
        let name: String
        let token: String
        let wrongKey: Bool
        let jose: Jose
    }
    let jwk: String
    let wrongJwk: String
    let cases: [Case]
}

@Suite("Against jose")
struct CounterpartTests {
    @Test("every pairing of key management and content encryption from jose decrypts")
    func compactTokens() async throws {
        let fixture = try ValidFixture(fixture: "valid")
        #expect(fixture.compact.count == 168)
        #expect(Set(fixture.compact.map(\.algorithm)).count == 16)
        #expect(Set(fixture.compact.map(\.encryption)).count == 6)
        for item in fixture.compact {
            let label = Comment(rawValue: item.label)
            let keys = DecryptionKeys([try AnyKeyDecrypter(algorithm: item.algorithm, jwk: item.jwk)])
            let jwe = try JWE<ExampleHeader>.Encrypted(compact: item.token)
            let decrypted = try await jwe.decrypt(with: keys)
            #expect(decrypted.plaintext.hex == item.plaintext, label)
            #expect(decrypted.header.algorithm.rawValue == item.algorithm, label)
            #expect(decrypted.header.contentEncryption.rawValue == item.encryption, label)
            #expect(decrypted.header.keyID == "key-1", label)
            #expect(decrypted.header.type == MediaType(rawValue: "application/example+jwe"), label)
            #expect(decrypted.header.custom.level == 7, label)
            #expect(decrypted.header.unprotectedParameterNames.isEmpty, label)
            #expect(decrypted.additionalAuthenticatedData == nil, label)
        }
    }

    @Test("ECDH-ES with party information (apu, apv) derives the same key as jose")
    func partyInfo() async throws {
        let fixture = try ValidFixture(fixture: "valid")
        #expect(fixture.withPartyInfo.count == 2)
        for item in fixture.withPartyInfo {
            let keys = DecryptionKeys([try AnyKeyDecrypter(algorithm: item.algorithm, jwk: item.jwk)])
            let jwe = try SimpleJWE.Encrypted(compact: item.token)
            #expect(jwe.header.rawParameters["apu"] == .string(String(base64URLEncoding: Data("Alice".utf8))))
            #expect(try await jwe.decrypt(with: keys).plaintext.hex == item.plaintext, "\(item.algorithm)")
        }
    }

    @Test("a flattened JWE from jose with additional data and unprotected headers decrypts")
    func flattened() async throws {
        let item = try ValidFixture(fixture: "valid").flattened
        let keys = DecryptionKeys([try AnyKeyDecrypter(algorithm: "A256KW", jwk: item.jwk)])
        let jwe = try SimpleJWE.Encrypted(json: Data(item.json.utf8))
        let decrypted = try await jwe.decrypt(with: keys)
        #expect(decrypted.plaintext.hex == item.plaintext)
        #expect(decrypted.additionalAuthenticatedData?.hex == item.aad)
        #expect(decrypted.header.algorithm == "A256KW")
        #expect(decrypted.header.keyID == "flat-key")
        #expect(decrypted.header.unprotectedParameterNames == ["alg", "kid", "urn:example:shared"])

        // The additional data is authenticated: changing it must make decryption fail.
        var document = try JSONDecoder().decode([String: JSONValue].self, from: Data(item.json.utf8))
        document["aad"] = .string(String(base64URLEncoding: Data("different".utf8)))
        let altered = try SimpleJWE.Encrypted(json: try JSONEncoder().encode(document))
        #expect(
            await thrown { () async throws(JWEError) in try await altered.decrypt(with: keys) } == .decryptionFailed
        )
    }

    @Test("a general JWE from jose decrypts with any one of its three recipients' keys")
    func general() async throws {
        let item = try ValidFixture(fixture: "valid").general
        let jwe = try SimpleJWE.Encrypted(json: Data(item.json.utf8))
        #expect(jwe.headers.map(\.algorithm) == ["RSA-OAEP-256", "ECDH-ES+A128KW", "A128KW"])
        for recipient in item.recipients {
            let keys = DecryptionKeys([try AnyKeyDecrypter(algorithm: recipient.algorithm, jwk: recipient.jwk)])
            let decrypted = try await jwe.decrypt(with: keys)
            #expect(decrypted.plaintext.hex == item.plaintext, "\(recipient.algorithm)")
            #expect(decrypted.header.keyID == KeyID(rawValue: recipient.keyID))
            #expect(decrypted.header.contentEncryption == "A128CBC-HS256")
        }
        // A key that belongs to none of the recipients decrypts nothing.
        let stranger = DecryptionKeys([
            AnyKeyDecrypter(
                try AESKeyWrapDecrypter<A128KW>(key: SymmetricKeyMaterial(randomByteCount: 16), keyID: "kw")
            )
        ])
        guard
            case .noRecipientDecrypted(let reasons) = await thrown({ () async throws(JWEError) in
                try await jwe.decrypt(with: stranger)
            })
        else {
            Issue.record("expected noRecipientDecrypted")
            return
        }
        #expect(reasons.count == 3)
        #expect(reasons.last == .decryptionFailed)
    }

    /// JWEs jose 6.2.12 accepts and this package refuses.
    ///
    /// - Padding and a trailing newline: jose's base64url decoder tolerates both. RFC 7516 uses
    ///   the unpadded encoding of RFC 7515 §2, and neither can come from an encoder.
    /// - `kid` as a number: RFC 7516 §4.1.6 defines it as a string.
    static let stricterThanJose: [String: JWEError] = [
        "tag segment padded": .paddingNotAllowed(part: "authentication tag"),
        "trailing newline": .invalidBase64URL(
            part: "authentication tag",
            .invalidCharacter(byte: 0x0A, offset: 22)
        ),
        "kid is a number": .headerParameterWrongType(name: "kid", expected: "a string"),
    ]

    @Test("compact JWEs: accepts and rejects what jose does, apart from the documented stricter cases")
    func compactVerdictsAgree() async throws {
        let fixture = try DecryptionFixture(fixture: "compact-decryption")
        func keys(_ jwk: String) throws -> DecryptionKeys {
            DecryptionKeys([
                try AnyKeyDecrypter(algorithm: "A256KW", jwk: jwk),
                try AnyKeyDecrypter(algorithm: "dir", jwk: jwk),
            ])
        }
        let right = try keys(fixture.jwk)
        let wrong = try keys(fixture.wrongJwk)
        var accepted = 0
        var rejected = 0
        var stricter = 0
        for testCase in fixture.cases {
            var selected = right
            if testCase.wrongKey {
                selected = wrong
            }
            let outcome: Result<Data, JWEError>
            do {
                outcome = .success(
                    try await SimpleJWE.Encrypted(compact: testCase.token).decrypt(with: selected).plaintext
                )
            } catch {
                outcome = .failure(error)
            }

            if let expected = Self.stricterThanJose[testCase.name] {
                #expect(testCase.jose.accepted, "listed as a deviation, but jose rejects it too: \(testCase.name)")
                #expect(outcome == .failure(expected), "\(testCase.name)")
                stricter += 1
            } else if testCase.jose.accepted {
                let expected = try Data(hex: try #require(testCase.jose.plaintext))
                #expect(outcome == .success(expected), "\(testCase.name)")
                accepted += 1
            } else {
                guard case .failure = outcome else {
                    Issue.record("accepted although jose rejects: \(testCase.name)")
                    continue
                }
                rejected += 1
            }
        }
        #expect(accepted >= 4)
        #expect(rejected >= 35)
        #expect(stricter == Self.stricterThanJose.count)
    }

    @Test("cryptographic failures are all the same error; structural ones name their cause")
    func failureReasons() async throws {
        let fixture = try DecryptionFixture(fixture: "compact-decryption")
        func keys(_ jwk: String) throws -> DecryptionKeys {
            DecryptionKeys([
                try AnyKeyDecrypter(algorithm: "A256KW", jwk: jwk),
                try AnyKeyDecrypter(algorithm: "dir", jwk: jwk),
            ])
        }
        let right = try keys(fixture.jwk)
        let wrong = try keys(fixture.wrongJwk)
        func outcome(_ name: String) async throws -> JWEError? {
            let testCase = try #require(fixture.cases.first { $0.name == name })
            var selected = right
            if testCase.wrongKey {
                selected = wrong
            }
            return await thrown { () async throws(JWEError) in
                try await SimpleJWE.Encrypted(compact: testCase.token).decrypt(with: selected)
            }
        }
        #expect(try await outcome("valid A256KW / A256GCM (positive control)") == nil)

        // Nothing here may be told apart from anything else in the group.
        for name in [
            "wrong key", "ciphertext altered", "tag altered", "iv altered", "encrypted key altered",
            "header altered (typ added)", "CBC ciphertext altered", "CBC tag altered",
            "CBC ciphertext truncated by a block", "encrypted key empty", "ciphertext empty",
            "enc changed to A128GCM",
        ] {
            #expect(try await outcome(name) == .decryptionFailed, "\(name)")
        }

        #expect(try await outcome("four segments") == .invalidCompactSerialization(segmentCount: 4))
        #expect(try await outcome("six segments") == .invalidCompactSerialization(segmentCount: 6))
        #expect(try await outcome("three segments (a JWS shape)") == .invalidCompactSerialization(segmentCount: 3))
        #expect(try await outcome("header empty") == .missingAlgorithm)
        #expect(try await outcome("alg missing") == .missingAlgorithm)
        #expect(try await outcome("enc missing") == .missingContentEncryption)
        #expect(try await outcome("alg is a number") == .headerParameterWrongType(name: "alg", expected: "a string"))
        #expect(
            try await outcome("alg unknown")
                == .noDecrypterForAlgorithm(algorithm: "A999KW", offered: ["A256KW", "dir"])
        )
        #expect(
            try await outcome("alg none") == .noDecrypterForAlgorithm(algorithm: "none", offered: ["A256KW", "dir"])
        )
        #expect(
            try await outcome("enc unknown")
                == .unsupportedContentEncryption(
                    algorithm: "A999GCM",
                    allowed: ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]
                )
        )
        #expect(
            try await outcome("alg changed to dir with the wrapping key") == .encryptedKeyNotEmpty(algorithm: "dir")
        )
        #expect(try await outcome("dir with a non-empty encrypted key") == .encryptedKeyNotEmpty(algorithm: "dir"))
        // Where zip is supported, adding it to an existing token is just another altered header.
        #if os(Windows)
            #expect(try await outcome("zip DEF") == .unsupportedCompression(algorithm: "DEF"))
        #else
            #expect(try await outcome("zip DEF") == .decryptionFailed)
        #endif
        #expect(
            try await outcome("crit names an unknown extension") == .unsupportedCriticalParameter(name: "urn:example:x")
        )
        #expect(try await outcome("crit is empty") == .invalidCritical(reason: "the list is empty"))
        #expect(
            try await outcome("tag truncated")
                == .wrongAuthenticationTagSize(algorithm: "A256GCM", expected: 16, found: 12)
        )
        #expect(
            try await outcome("tag empty") == .wrongAuthenticationTagSize(algorithm: "A256GCM", expected: 16, found: 0)
        )
        #expect(
            try await outcome("iv too short")
                == .wrongInitializationVectorSize(algorithm: "A256GCM", expected: 12, found: 8)
        )
        #expect(try await outcome("header segment padded") == .paddingNotAllowed(part: "protected header"))
        guard
            case .invalidHeaderStructure(.duplicateMember(let name, _)) = try await outcome("header has duplicate alg")
        else {
            Issue.record("duplicate alg was not reported as a duplicate")
            return
        }
        #expect(name == "alg")
    }
}
