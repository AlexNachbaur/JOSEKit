import Foundation
import Testing

@testable import JOSECore

#if canImport(CryptoKit)
    import CryptoKit
#endif

private struct ECDSAFixture: Decodable {
    struct Vector: Decodable {
        let der: String
        let raw: String
        let hasSignByte: Bool
        let hasShortComponent: Bool
    }
    struct Malformed: Decodable {
        let name: String
        let der: String
        let opensslAccepts: Bool
    }
    struct Curve: Decodable {
        let curve: String
        let coordinateByteCount: Int
        let vectors: [Vector]
        let malformedBase: String
        let malformed: [Malformed]
    }
    let curves: [Curve]
}

@Suite("ECDSASignatureConverter")
struct ECDSASignatureConverterTests {
    private func converter(_ coordinateByteCount: Int) throws(ECDSASignatureError) -> ECDSASignatureConverter {
        try ECDSASignatureConverter(coordinateByteCount: coordinateByteCount)
    }

    @Test("DER to raw matches OpenSSL-verified pairs, covering both the strip and the pad path")
    func derToRawMatchesCounterpart() throws {
        let fixture = try ECDSAFixture(fixture: "ecdsa-signatures")
        #expect(fixture.curves.map(\.curve) == ["P-256", "P-384", "P-521"])
        for curve in fixture.curves {
            // Without these the loop could pass while never meeting a sign byte or a short component.
            #expect(curve.vectors.contains(where: { $0.hasSignByte }), "\(curve.curve) has no sign-byte vector")
            #expect(curve.vectors.contains(where: { $0.hasShortComponent }), "\(curve.curve) has no short vector")
            let converter = try converter(curve.coordinateByteCount)
            for vector in curve.vectors {
                let raw = try converter.rawSignature(fromDER: try Data(hex: vector.der))
                #expect(raw.hex == vector.raw, "\(curve.curve) DER \(vector.der)")
            }
        }
    }

    @Test("raw to DER reproduces OpenSSL's DER byte for byte")
    func rawToDERMatchesCounterpart() throws {
        let fixture = try ECDSAFixture(fixture: "ecdsa-signatures")
        for curve in fixture.curves {
            let converter = try converter(curve.coordinateByteCount)
            for vector in curve.vectors {
                let der = try converter.derSignature(fromRaw: try Data(hex: vector.raw))
                #expect(der.hex == vector.der, "\(curve.curve) raw \(vector.raw)")
            }
        }
    }

    @Test("malformed DER that OpenSSL refuses is refused, and the signature it was derived from is accepted")
    func malformedDERAgreesWithCounterpart() throws {
        let fixture = try ECDSAFixture(fixture: "ecdsa-signatures")
        for curve in fixture.curves {
            let converter = try converter(curve.coordinateByteCount)
            // Positive control: the unmodified signature converts.
            _ = try converter.rawSignature(fromDER: try Data(hex: curve.malformedBase))
            #expect(curve.malformed.count >= 12)
            for malformed in curve.malformed {
                #expect(!malformed.opensslAccepts, "fixture changed: OpenSSL now accepts '\(malformed.name)'")
                #expect(throws: ECDSASignatureError.self, "\(curve.curve): \(malformed.name)") {
                    try converter.rawSignature(fromDER: try Data(hex: malformed.der))
                }
            }
        }
    }

    // SEQUENCE { INTEGER 1, INTEGER 2 }
    private static let minimalDER = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])

    @Test("a short component is left-padded to the coordinate size")
    func leftPads() throws {
        let p256 = try converter(32)
        let raw = try p256.rawSignature(fromDER: Self.minimalDER)
        #expect(raw.count == 64)
        var expected = Data(repeating: 0, count: 64)
        expected[31] = 0x01
        expected[63] = 0x02
        #expect(raw == expected)
        #expect(try p256.derSignature(fromRaw: raw) == Self.minimalDER)
    }

    @Test("a sign byte is stripped going to raw and restored going to DER")
    func stripsSignByte() throws {
        let p256 = try converter(32)
        let high = Data([0x80] + [UInt8](repeating: 0x11, count: 31))
        let der = Data([0x30, 0x46, 0x02, 0x21, 0x00]) + high + Data([0x02, 0x21, 0x00]) + high
        let raw = try p256.rawSignature(fromDER: der)
        #expect(raw == high + high)
        #expect(try p256.derSignature(fromRaw: raw) == der)
    }

    @Test("zero is encoded as a one-byte INTEGER and decoded back")
    func zeroComponent() throws {
        let p256 = try converter(32)
        let raw = Data(repeating: 0, count: 64)
        let der = try p256.derSignature(fromRaw: raw)
        #expect(der == Data([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]))
        #expect(try p256.rawSignature(fromDER: der) == raw)
    }

    @Test("a SEQUENCE of 128 bytes or more uses the long length form")
    func longFormLength() throws {
        let p521 = try converter(66)
        let raw = Data(repeating: 0x7F, count: 132)
        let der = try p521.derSignature(fromRaw: raw)
        #expect(der.prefix(3) == Data([0x30, 0x81, 0x88]))
        #expect(try p521.rawSignature(fromDER: der) == raw)
    }

    @Test("works on Data slices whose start index is not zero")
    func slices() throws {
        let p256 = try converter(32)
        let padded = Data([0xAA, 0xBB]) + Self.minimalDER
        let raw = try p256.rawSignature(fromDER: padded.dropFirst(2))
        let paddedRaw = Data([0xAA]) + raw
        #expect(try p256.derSignature(fromRaw: paddedRaw.dropFirst()) == Self.minimalDER)
    }

    @Test("each malformed DER input reports its specific cause")
    func specificDERErrors() {
        func convert(_ bytes: [UInt8], coordinateByteCount: Int = 32) throws(ECDSASignatureError) -> Data {
            try converter(coordinateByteCount).rawSignature(fromDER: Data(bytes))
        }

        #expect(throws: ECDSASignatureError.derTruncated(offset: 0)) { try convert([]) }
        #expect(throws: ECDSASignatureError.derTruncated(offset: 1)) { try convert([0x30]) }
        #expect(throws: ECDSASignatureError.derUnexpectedTag(expected: 0x30, found: 0x31, offset: 0)) {
            try convert([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        }
        #expect(throws: ECDSASignatureError.derUnexpectedTag(expected: 0x02, found: 0x03, offset: 2)) {
            try convert([0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02])
        }
        #expect(throws: ECDSASignatureError.derUnexpectedTag(expected: 0x02, found: 0x04, offset: 5)) {
            try convert([0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0x02])
        }
        #expect(throws: ECDSASignatureError.derLengthNotMinimal(offset: 1)) {
            try convert([0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        }
        #expect(throws: ECDSASignatureError.derLengthUnsupported(firstOctet: 0x80, offset: 1)) {
            try convert([0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00])
        }
        #expect(throws: ECDSASignatureError.derLengthUnsupported(firstOctet: 0x82, offset: 1)) {
            try convert([0x30, 0x82, 0x00, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        }
        // Declared 6, one byte missing.
        #expect(throws: ECDSASignatureError.derSequenceLengthMismatch(declared: 6, available: 5)) {
            try convert([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01])
        }
        // Declared 6, one byte extra after the SEQUENCE.
        #expect(throws: ECDSASignatureError.derSequenceLengthMismatch(declared: 6, available: 7)) {
            try convert([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00])
        }
        #expect(throws: ECDSASignatureError.derIntegerOverrun(component: .s, declared: 5, available: 1)) {
            try convert([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x05, 0x02])
        }
        #expect(throws: ECDSASignatureError.derIntegerEmpty(component: .r)) {
            try convert([0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x02])
        }
        #expect(throws: ECDSASignatureError.derIntegerNegative(component: .r)) {
            try convert([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x02])
        }
        #expect(throws: ECDSASignatureError.derIntegerNegative(component: .s)) {
            try convert([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0xFF])
        }
        #expect(throws: ECDSASignatureError.derIntegerNotMinimal(component: .r)) {
            try convert([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02])
        }
        #expect(throws: ECDSASignatureError.derIntegerNotMinimal(component: .s)) {
            try convert([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x7F])
        }
        #expect(throws: ECDSASignatureError.derIntegerTooLong(component: .r, maximum: 2, found: 3)) {
            try convert([0x30, 0x08, 0x02, 0x03, 0x01, 0x02, 0x03, 0x02, 0x01, 0x02], coordinateByteCount: 2)
        }
        // A sign byte does not count towards the coordinate size: 0x00 0x80 0x01 is two bytes of magnitude.
        #expect(throws: Never.self) {
            try convert([0x30, 0x08, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x01, 0x02], coordinateByteCount: 2)
        }
        #expect(throws: ECDSASignatureError.derTrailingBytes(count: 3)) {
            try convert([0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03])
        }
    }

    @Test("raw input must be exactly two coordinates, and the coordinate size must be supported")
    func rawErrors() throws {
        let p256 = try converter(32)
        #expect(throws: ECDSASignatureError.rawSignatureWrongLength(expected: 64, found: 63)) {
            try p256.derSignature(fromRaw: Data(count: 63))
        }
        #expect(throws: ECDSASignatureError.rawSignatureWrongLength(expected: 64, found: 65)) {
            try p256.derSignature(fromRaw: Data(count: 65))
        }
        #expect(throws: ECDSASignatureError.unsupportedCoordinateByteCount(0)) {
            try converter(0)
        }
        #expect(throws: ECDSASignatureError.unsupportedCoordinateByteCount(125)) {
            try converter(125)
        }
        #expect(throws: Never.self) {
            try converter(1)
        }
        #expect(try converter(ECDSASignatureConverter.maximumCoordinateByteCount).coordinateByteCount == 124)
    }

    @Test("the largest supported coordinate size round-trips with every byte's top bit set")
    func maximumCoordinateSize() throws {
        let size = ECDSASignatureConverter.maximumCoordinateByteCount
        let largest = try converter(size)
        let raw = Data(repeating: 0xFF, count: size * 2)
        let der = try largest.derSignature(fromRaw: raw)
        #expect(der.count == 3 + 2 * (size + 3))
        #expect(try largest.rawSignature(fromDER: der) == raw)
    }

    @Test("every error has a non-empty message")
    func descriptions() {
        let errors: [ECDSASignatureError] = [
            .unsupportedCoordinateByteCount(0),
            .rawSignatureWrongLength(expected: 64, found: 1),
            .derTruncated(offset: 4),
            .derUnexpectedTag(expected: 0x30, found: 0x31, offset: 0),
            .derLengthNotMinimal(offset: 1),
            .derLengthUnsupported(firstOctet: 0x82, offset: 1),
            .derSequenceLengthMismatch(declared: 6, available: 5),
            .derIntegerOverrun(component: .s, declared: 5, available: 1),
            .derIntegerEmpty(component: .r),
            .derIntegerNegative(component: .r),
            .derIntegerNotMinimal(component: .s),
            .derIntegerTooLong(component: .r, maximum: 32, found: 33),
            .derTrailingBytes(count: 3),
        ]
        for error in errors {
            #expect(error.description.count > 20)
        }
        #expect(ECDSASignatureError.derIntegerNegative(component: .s).description.contains(" s "))
    }

    // The platform comparison needs a real ECDSA implementation. JOSECore has no crypto
    // dependency, so this runs only where CryptoKit is part of the OS; the same check runs on
    // every platform in JOSEJWK, which depends on swift-crypto.
    #if canImport(CryptoKit)
        @Test("agrees with CryptoKit's own raw and DER representations across 500 P-256 signatures")
        func agreesWithCryptoKitP256() throws {
            let p256 = try converter(32)
            let key = P256.Signing.PrivateKey()
            var sawSignByte = false
            var sawShortComponent = false
            for index in 0..<500 {
                let signature = try key.signature(for: Data("message \(index)".utf8))
                let der = signature.derRepresentation
                let raw = signature.rawRepresentation
                #expect(try p256.rawSignature(fromDER: der) == raw)
                #expect(try p256.derSignature(fromRaw: raw) == der)
                sawSignByte = sawSignByte || der.count > 70
                sawShortComponent = sawShortComponent || raw[0] == 0 || raw[32] == 0
            }
            #expect(sawSignByte)
            // Expected in about 98% of runs of 500. Reported rather than asserted, so that an honest
            // unlucky run does not fail; the fixture test above always covers the pad path.
            if !sawShortComponent {
                Issue.record(
                    "no short component among 500 signatures; rerun (expected in about 1 run in 50)",
                    severity: .warning
                )
            }
        }

        @Test("agrees with CryptoKit across 200 P-384 and 200 P-521 signatures")
        func agreesWithCryptoKitLargerCurves() throws {
            let p384 = P384.Signing.PrivateKey()
            let p521 = P521.Signing.PrivateKey()
            let converter384 = try converter(48)
            let converter521 = try converter(66)
            for index in 0..<200 {
                let message = Data("message \(index)".utf8)

                let signature384 = try p384.signature(for: message)
                #expect(
                    try converter384.rawSignature(fromDER: signature384.derRepresentation)
                        == signature384.rawRepresentation
                )
                #expect(
                    try converter384.derSignature(fromRaw: signature384.rawRepresentation)
                        == signature384.derRepresentation
                )

                let signature521 = try p521.signature(for: message)
                #expect(
                    try converter521.rawSignature(fromDER: signature521.derRepresentation)
                        == signature521.rawRepresentation
                )
                #expect(
                    try converter521.derSignature(fromRaw: signature521.rawRepresentation)
                        == signature521.derRepresentation
                )
            }
        }
    #endif
}
