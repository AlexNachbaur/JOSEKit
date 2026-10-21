import Foundation
import JOSECore
import JOSEJWK
import Testing

@testable import JOSEJWE

@Suite("JWE compression")
struct CompressionTests {
    /// Text that compresses well, so that the compressed form is clearly smaller.
    static let plaintext = Data(String(repeating: "the quick brown fox jumps over the lazy dog. ", count: 40).utf8)

    private func keyPair() throws -> (AESKeyWrapEncrypter<A256KW>, DecryptionKeys) {
        let material = SymmetricKeyMaterial(randomByteCount: 32)
        return (
            try AESKeyWrapEncrypter<A256KW>(key: material),
            DecryptionKeys([AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: material))])
        )
    }

    /// Parses a JWE whose protected header is `protected`, returning the error, if any.
    private func parse(_ protected: String, unprotected: String? = nil) -> JWEError? {
        let encoded = String(base64URLEncoding: Data(protected.utf8))
        var json = #"{"protected":"\#(encoded)","ciphertext":"AAAA","iv":"AAAA","tag":"AAAA""#
        if let unprotected {
            json += #","unprotected":\#(unprotected)"#
        }
        do {
            _ = try SimpleJWE.Encrypted(json: Data((json + "}").utf8))
            return nil
        } catch {
            return error
        }
    }

    // MARK: Every platform

    @Test("DEF names deflate everywhere except Windows, which has no system zlib")
    func platformCompressions() {
        #if os(Windows)
            #expect(JWECompression(rawValue: "DEF") == nil)
            #expect(parse(#"{"alg":"dir","enc":"A256GCM","zip":"DEF"}"#) == .unsupportedCompression(algorithm: "DEF"))
        #else
            #expect(JWECompression(rawValue: "DEF") == .deflate)
            #expect(JWECompression.deflate.rawValue == "DEF")
            #expect(parse(#"{"alg":"dir","enc":"A256GCM","zip":"DEF"}"#) == nil)
        #endif
        #expect(JWECompression(rawValue: "def") == nil)
        #expect(JWECompression.defaultMaximumDecompressedByteCount == 250_000)
    }

    @Test("zip must be protected and must name a supported compression")
    func zipHeaderRules() {
        #expect(
            parse(#"{"alg":"dir","enc":"A256GCM"}"#, unprotected: #"{"zip":"DEF"}"#)
                == .headerParameterNotProtected(name: "zip")
        )
        #expect(parse(#"{"alg":"dir","enc":"A256GCM","zip":"LZW"}"#) == .unsupportedCompression(algorithm: "LZW"))
        #expect(parse(#"{"alg":"dir","enc":"A256GCM","zip":"def"}"#) == .unsupportedCompression(algorithm: "def"))
        #expect(
            parse(#"{"alg":"dir","enc":"A256GCM","zip":1}"#)
                == .headerParameterWrongType(name: "zip", expected: "a string")
        )
    }
}

#if !os(Windows)
    extension CompressionTests {
        // MARK: Raw DEFLATE

        @Test("raw DEFLATE round-trips every size, including empty, and compresses repetitive text")
        func deflateRoundTrips() throws {
            let deflate = DeflateCompression()
            let chunk = deflate.chunkSize
            for count in [0, 1, 100, chunk - 1, chunk, chunk * 3 + 7] {
                let data = Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 / 7) })
                let compressed = try deflate.compress(data)
                #expect(try deflate.decompress(compressed, limit: count) == data, "\(count) bytes")
            }
            let compressed = try deflate.compress(Self.plaintext)
            #expect(compressed.count < Self.plaintext.count / 4)
        }

        @Test("decompression stops at the limit, and refuses malformed, truncated, trailing or zlib-wrapped input")
        func deflateRefusesBadInput() throws {
            let deflate = DeflateCompression()
            let compressed = try deflate.compress(Self.plaintext)
            #expect(try deflate.decompress(compressed, limit: Self.plaintext.count) == Self.plaintext)
            #expect(throws: CompressionError.tooLarge) {
                try deflate.decompress(compressed, limit: Self.plaintext.count - 1)
            }
            // A small input that expands far beyond the limit is stopped, not decompressed in full.
            let bomb = try deflate.compress(Data(count: 10_000_000))
            #expect(bomb.count < 20_000)
            #expect(throws: CompressionError.tooLarge) { try deflate.decompress(bomb, limit: 1_000) }

            #expect(throws: CompressionError.malformed) {
                try deflate.decompress(Data(compressed.prefix(compressed.count / 2)), limit: .max)
            }
            #expect(throws: CompressionError.malformed) {
                try deflate.decompress(compressed + Data([0x00, 0x01]), limit: .max)
            }
            #expect(throws: CompressionError.malformed) {
                try deflate.decompress(Data([0xFF, 0xFF, 0xFF, 0xFF]), limit: .max)
            }
            #expect(throws: CompressionError.malformed) { try deflate.decompress(Data(), limit: .max) }
            // A zlib stream (RFC 1950) is not raw DEFLATE: its two-byte header is not a valid block.
            let zlibWrapped = Data([0x78, 0x9C]) + compressed + Data([0x00, 0x00, 0x00, 0x00])
            #expect(throws: CompressionError.malformed) { try deflate.decompress(zlibWrapped, limit: .max) }
        }

        @Test("the enum case delegates to its algorithm")
        func caseDelegates() throws {
            let compressed = try JWECompression.deflate.compress(Self.plaintext)
            #expect(try DeflateCompression().decompress(compressed, limit: .max) == Self.plaintext)
            #expect(try JWECompression.deflate.decompress(compressed, limit: .max) == Self.plaintext)
            #expect(throws: CompressionError.tooLarge) {
                try JWECompression.deflate.decompress(compressed, limit: Self.plaintext.count - 1)
            }
        }

        // MARK: JWE

        @Test("a compressed JWE round-trips, with zip in the protected header and a smaller ciphertext")
        func compressedRoundTrip() async throws {
            let (encrypter, keys) = try keyPair()
            let compressed = try await SimpleJWE.encrypt(
                Self.plaintext,
                to: encrypter,
                using: A256GCM.self,
                header: JWEHeaderParameters(compression: .deflate)
            )
            let plain = try await SimpleJWE.encrypt(Self.plaintext, to: encrypter, using: A256GCM.self)
            #expect(compressed.ciphertext.count < plain.ciphertext.count / 4)
            #expect(compressed.header.compression == .deflate)
            #expect(compressed.header.rawParameters["zip"] == "DEF")
            #expect(!compressed.header.unprotectedParameterNames.contains("zip"))

            let parsed = try SimpleJWE.Encrypted(compact: try compressed.compactSerialization())
            let decrypted = try await parsed.decrypt(with: keys)
            #expect(decrypted.plaintext == Self.plaintext)
            #expect(decrypted.header.compression == .deflate)

            // zip stays in the protected header with several recipients too.
            let (second, secondKeys) = try keyPair()
            let multiple = try await SimpleJWE.encrypt(
                Self.plaintext,
                to: [AnyKeyEncrypter(encrypter), AnyKeyEncrypter(second)],
                using: A256GCM.self,
                header: JWEHeaderParameters(compression: .deflate)
            )
            let general = try SimpleJWE.Encrypted(json: try multiple.generalJSONSerialization())
            #expect(general.headers.allSatisfy { !$0.unprotectedParameterNames.contains("zip") })
            #expect(try await general.decrypt(with: secondKeys).plaintext == Self.plaintext)
        }

        @Test("decryption enforces the decompressed size limit, and 0 refuses compression before any cryptography")
        func decompressionLimits() async throws {
            let (encrypter, keys) = try keyPair()
            let sealed = try await SimpleJWE.encrypt(
                Self.plaintext,
                to: encrypter,
                using: A256GCM.self,
                header: JWEHeaderParameters(compression: .deflate)
            )
            #expect(
                try await sealed.decrypt(with: keys, maximumDecompressedByteCount: Self.plaintext.count).plaintext
                    == Self.plaintext
            )
            let limit = Self.plaintext.count - 1
            await #expect(throws: JWEError.decompressedSizeExceedsLimit(maximum: limit)) {
                try await sealed.decrypt(with: keys, maximumDecompressedByteCount: limit)
            }
            // With compression refused, even a key that cannot decrypt gets the precise answer.
            let (_, strangers) = try keyPair()
            await #expect(throws: JWEError.compressionNotAllowed) {
                try await sealed.decrypt(with: strangers, maximumDecompressedByteCount: 0)
            }
            // An uncompressed JWE ignores the limit.
            let uncompressed = try await SimpleJWE.encrypt(Self.plaintext, to: encrypter, using: A256GCM.self)
            #expect(
                try await uncompressed.decrypt(with: keys, maximumDecompressedByteCount: 0).plaintext == Self.plaintext
            )
        }

        @Test("authentic content that is not raw DEFLATE is reported as such")
        func invalidCompressedContent() async throws {
            // Built by hand: zip says DEF, but the encrypted content is not DEFLATE at all.
            let key = SymmetricKeyMaterial(randomByteCount: 32)
            let protected = String(base64URLEncoding: Data(#"{"alg":"dir","enc":"A256GCM","zip":"DEF"}"#.utf8))
            let iv = SymmetricKeyMaterial(randomByteCount: 12).rawRepresentation
            let (ciphertext, tag) = try A256GCM.encrypt(
                Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                key: key.rawRepresentation,
                initializationVector: iv,
                additionalAuthenticatedData: Data(protected.utf8)
            )
            let compact = [
                protected, "", String(base64URLEncoding: iv), String(base64URLEncoding: ciphertext),
                String(base64URLEncoding: tag),
            ]
            .joined(separator: ".")
            let jwe = try SimpleJWE.Encrypted(compact: compact)
            await #expect(throws: JWEError.invalidCompressedContent) {
                try await jwe.decrypt(with: DecryptionKeys([AnyKeyDecrypter(DirectDecrypter(key: key))]))
            }
        }
    }
#endif
