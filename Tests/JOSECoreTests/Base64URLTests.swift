import Foundation
import TestSupport
import Testing

@testable import JOSECore

private struct Base64URLFixture: Decodable {
    struct Encoding: Decodable {
        let hex: String
        let base64url: String
    }
    struct Decoding: Decodable {
        struct Jose: Decodable {
            let accepted: Bool
            let hex: String?
        }
        let input: String
        let jose: Jose
    }
    let encode: [Encoding]
    let decode: [Decoding]
}

@Suite("Base64URL")
struct Base64URLTests {
    /// Inputs that jose 6.2.12 decodes and this package refuses, with the reason. Everything else
    /// must match jose exactly. jose strips whitespace before decoding and ignores non-zero
    /// unused bits; here both are refused because the strings are compared for equality elsewhere
    /// and no encoder produces them.
    static let stricterThanJose: [String: Base64URLError] = [
        "YR": .nonCanonicalTrailingBits(offset: 1),
        "YX": .nonCanonicalTrailingBits(offset: 1),
        "YWJ": .nonCanonicalTrailingBits(offset: 2),
        "YWL": .nonCanonicalTrailingBits(offset: 2),
        "Zm9vYh": .nonCanonicalTrailingBits(offset: 5),
        "Y Q": .invalidCharacter(byte: 0x20, offset: 1),
        " YQ": .invalidCharacter(byte: 0x20, offset: 0),
        "YQ ": .invalidCharacter(byte: 0x20, offset: 2),
        "YQ\n": .invalidCharacter(byte: 0x0A, offset: 2),
        "YQ\r\n": .invalidCharacter(byte: 0x0D, offset: 2),
        "YW\tI": .invalidCharacter(byte: 0x09, offset: 2),
    ]

    @Test("encoding matches jose for every fixture input")
    func encodeMatchesCounterpart() throws {
        let fixture = try Base64URLFixture(fixture: "base64url", in: .module)
        #expect(fixture.encode.count > 50)
        for vector in fixture.encode {
            let bytes = try Data(hex: vector.hex)
            #expect(String(base64URLEncoding: bytes) == vector.base64url, "encoding \(vector.hex)")
        }
    }

    @Test("decoding jose's encodings returns the original bytes")
    func decodeMatchesCounterpart() throws {
        let fixture = try Base64URLFixture(fixture: "base64url", in: .module)
        for vector in fixture.encode {
            let decoded = try Data(base64URLEncoded: vector.base64url)
            let expected = try Data(hex: vector.hex)
            #expect(decoded == expected, "decoding \(vector.base64url)")
        }
    }

    @Test("decode accepts and rejects the same inputs as jose, apart from the documented stricter cases")
    func decodeAgreesWithCounterpart() throws {
        let fixture = try Base64URLFixture(fixture: "base64url", in: .module)
        var accepted = 0
        var rejected = 0
        var stricter = 0
        for vector in fixture.decode {
            let label = "input \(String(jsonQuoting: vector.input))"
            if let expectedError = Self.stricterThanJose[vector.input] {
                #expect(vector.jose.accepted, "\(label) is listed as a deviation but jose rejects it too")
                #expect(throws: expectedError, "\(label)") {
                    try Data(base64URLEncoded: vector.input)
                }
                stricter += 1
            } else if vector.jose.accepted {
                let expected = try Data(hex: try #require(vector.jose.hex))
                #expect(try Data(base64URLEncoded: vector.input) == expected, "\(label)")
                accepted += 1
            } else {
                #expect(throws: Base64URLError.self, "\(label)") {
                    try Data(base64URLEncoded: vector.input)
                }
                rejected += 1
            }
        }
        // The loop above proves nothing if a branch never ran.
        #expect(accepted >= 10)
        #expect(rejected >= 10)
        #expect(stricter == Self.stricterThanJose.count, "a listed deviation is missing from the fixture")
    }

    @Test("output is never padded")
    func encodeIsUnpadded() {
        #expect(String(base64URLEncoding: [UInt8]()) == "")
        #expect(String(base64URLEncoding: [0x61]) == "YQ")
        #expect(String(base64URLEncoding: [0x61, 0x62]) == "YWI")
        #expect(String(base64URLEncoding: [0x61, 0x62, 0x63]) == "YWJj")
    }

    @Test("accepts collections other than Data, including slices with a non-zero start index")
    func encodeSlices() {
        let data = Data([0x00, 0x61, 0x62, 0x63])
        #expect(String(base64URLEncoding: data.dropFirst()) == "YWJj")
        #expect(String(base64URLEncoding: [UInt8]([0xFB, 0xFF])[...]) == "-_8")
    }

    @Test("each rejection reports its specific cause")
    func specificErrors() {
        #expect(throws: Base64URLError.invalidLength(count: 1)) { try Data(base64URLEncoded: "Y") }
        #expect(throws: Base64URLError.invalidLength(count: 5)) { try Data(base64URLEncoded: "YWJjZ") }
        #expect(throws: Base64URLError.invalidLength(count: 5)) { try Data(base64URLEncoded: "YWJjZ===") }

        #expect(throws: Base64URLError.misplacedPadding(offset: 2)) { try Data(base64URLEncoded: "YQ=a") }
        #expect(throws: Base64URLError.misplacedPadding(offset: 0)) { try Data(base64URLEncoded: "=YQ") }
        #expect(throws: Base64URLError.misplacedPadding(offset: 2)) { try Data(base64URLEncoded: "YQ==YQ==") }

        #expect(throws: Base64URLError.wrongPaddingLength(expected: 2, found: 3)) {
            try Data(base64URLEncoded: "YQ===")
        }
        #expect(throws: Base64URLError.wrongPaddingLength(expected: 2, found: 1)) { try Data(base64URLEncoded: "YQ=") }
        #expect(throws: Base64URLError.wrongPaddingLength(expected: 1, found: 2)) {
            try Data(base64URLEncoded: "YWI==")
        }
        #expect(throws: Base64URLError.wrongPaddingLength(expected: 0, found: 1)) {
            try Data(base64URLEncoded: "YWJj=")
        }
        #expect(throws: Base64URLError.wrongPaddingLength(expected: 0, found: 4)) { try Data(base64URLEncoded: "====") }

        #expect(throws: Base64URLError.invalidCharacter(byte: 0x2B, offset: 2)) { try Data(base64URLEncoded: "YW+j") }
        #expect(throws: Base64URLError.invalidCharacter(byte: 0x2F, offset: 2)) { try Data(base64URLEncoded: "YW/j") }
        #expect(throws: Base64URLError.invalidCharacter(byte: 0x00, offset: 2)) {
            try Data(base64URLEncoded: "YQ\u{0}")
        }
        #expect(throws: Base64URLError.invalidCharacter(byte: 0xC3, offset: 2)) { try Data(base64URLEncoded: "YWé") }

        #expect(throws: Base64URLError.nonCanonicalTrailingBits(offset: 1)) { try Data(base64URLEncoded: "YR") }
        #expect(throws: Base64URLError.nonCanonicalTrailingBits(offset: 2)) { try Data(base64URLEncoded: "YWJ") }
    }

    @Test("correct padding is accepted")
    func correctPadding() throws {
        #expect(try Data(base64URLEncoded: "YQ==") == Data([0x61]))
        #expect(try Data(base64URLEncoded: "YWI=") == Data([0x61, 0x62]))
        #expect(try Data(base64URLEncoded: "") == Data())
    }

    @Test("round-trips every length from 0 to 300 bytes")
    func roundTrip() throws {
        var generator = SystemRandomNumberGenerator()
        for length in 0...300 {
            let bytes = Data((0..<length).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
            let encoded = String(base64URLEncoding: bytes)
            #expect(!encoded.contains("="))
            #expect(try Data(base64URLEncoded: encoded) == bytes)
        }
    }

    @Test("every error has a message naming the offending value")
    func descriptions() {
        #expect(Base64URLError.invalidLength(count: 5).description.contains("5"))
        #expect(Base64URLError.invalidCharacter(byte: 0x2B, offset: 7).description.contains("0x2b"))
        #expect(Base64URLError.invalidCharacter(byte: 0x2B, offset: 7).description.contains("7"))
        #expect(Base64URLError.misplacedPadding(offset: 3).description.contains("3"))
        #expect(Base64URLError.wrongPaddingLength(expected: 2, found: 3).description.contains("3"))
        #expect(Base64URLError.nonCanonicalTrailingBits(offset: 9).description.contains("9"))
    }
}
