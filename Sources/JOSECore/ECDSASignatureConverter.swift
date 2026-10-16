import Foundation

/// Why an ECDSA signature could not be converted between DER and IEEE P1363.
public enum ECDSASignatureError: Error, Sendable, Equatable {
    /// Which of the two integers in the signature an error refers to.
    public enum Component: String, Sendable {
        case r
        case s
    }

    /// The coordinate size is outside `1...ECDSASignatureConverter.maximumCoordinateByteCount`.
    case unsupportedCoordinateByteCount(Int)
    /// A P1363 signature must be exactly two coordinates long.
    case rawSignatureWrongLength(expected: Int, found: Int)
    /// The DER input ended where another byte was required.
    case derTruncated(offset: Int)
    case derUnexpectedTag(expected: UInt8, found: UInt8, offset: Int)
    /// A length was not in DER's minimal form: long form used for a value below 128.
    case derLengthNotMinimal(offset: Int)
    /// An indefinite length, or one needing more than one length octet. No supported signature
    /// is that large.
    case derLengthUnsupported(firstOctet: UInt8, offset: Int)
    /// The SEQUENCE's declared length is not the number of bytes that follow its header. Covers
    /// both truncated input and bytes after the end of the SEQUENCE.
    case derSequenceLengthMismatch(declared: Int, available: Int)
    /// An INTEGER's declared length runs past the end of the input.
    case derIntegerOverrun(component: Component, declared: Int, available: Int)
    case derIntegerEmpty(component: Component)
    /// The INTEGER's top bit is set. DER INTEGERs are signed and `r`/`s` are positive, so a value
    /// with its top bit set must carry a leading `0x00`.
    case derIntegerNegative(component: Component)
    /// The INTEGER has a leading `0x00` that is not needed to keep it positive.
    case derIntegerNotMinimal(component: Component)
    /// The INTEGER's magnitude does not fit in one coordinate.
    case derIntegerTooLong(component: Component, maximum: Int, found: Int)
    /// Bytes remain inside the SEQUENCE after `s`.
    case derTrailingBytes(count: Int)
}

extension ECDSASignatureError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unsupportedCoordinateByteCount(let count):
            return "ECDSA coordinate size of \(count) bytes is not supported "
                + "(1...\(ECDSASignatureConverter.maximumCoordinateByteCount))"
        case .rawSignatureWrongLength(let expected, let found):
            return "raw (P1363) ECDSA signature is \(found) bytes; expected \(expected)"
        case .derTruncated(let offset):
            return "DER ECDSA signature ends at offset \(offset) where another byte is required"
        case .derUnexpectedTag(let expected, let found, let offset):
            return "DER ECDSA signature has tag 0x\(String(found, radix: 16)) at offset \(offset); "
                + "expected 0x\(String(expected, radix: 16))"
        case .derLengthNotMinimal(let offset):
            return "DER ECDSA signature has a non-minimal length encoding at offset \(offset)"
        case .derLengthUnsupported(let firstOctet, let offset):
            return "DER ECDSA signature has an unsupported length octet 0x\(String(firstOctet, radix: 16)) "
                + "at offset \(offset)"
        case .derSequenceLengthMismatch(let declared, let available):
            return "DER ECDSA signature declares a SEQUENCE of \(declared) bytes but \(available) follow its header"
        case .derIntegerOverrun(let component, let declared, let available):
            return "DER ECDSA signature declares \(declared) bytes for \(component.rawValue) "
                + "but only \(available) remain"
        case .derIntegerEmpty(let component):
            return "DER ECDSA signature has a zero-length INTEGER for \(component.rawValue)"
        case .derIntegerNegative(let component):
            return "DER ECDSA signature encodes a negative INTEGER for \(component.rawValue) "
                + "(top bit set without a leading 0x00)"
        case .derIntegerNotMinimal(let component):
            return "DER ECDSA signature has a redundant leading 0x00 on \(component.rawValue)"
        case .derIntegerTooLong(let component, let maximum, let found):
            return "DER ECDSA signature's \(component.rawValue) is \(found) bytes; "
                + "the curve allows at most \(maximum)"
        case .derTrailingBytes(let count):
            return "DER ECDSA signature has \(count) unexpected bytes after s"
        }
    }
}

/// Converts ECDSA signatures between ASN.1 DER (`SEQUENCE { INTEGER r, INTEGER s }`, what
/// Security.framework and most HSMs return) and IEEE P1363 (`r || s`, fixed width, what JOSE uses).
///
/// This is a change of encoding only. It does not check that `r` and `s` are in range for any
/// curve; that is the verifier's job.
public struct ECDSASignatureConverter: Sendable {
    private init() {}

    /// The largest coordinate for which the DER SEQUENCE length still fits in a single length
    /// octet (`2 * (2 + n + 1) <= 255`). P-521, the largest JOSE curve, uses 66.
    public static let maximumCoordinateByteCount = 124

    private static let sequenceTag: UInt8 = 0x30
    private static let integerTag: UInt8 = 0x02

    /// Converts a DER signature to `r || s`, each exactly `coordinateByteCount` bytes.
    ///
    /// The two adjustments run in opposite directions and each applies to a minority of
    /// signatures: a DER INTEGER with its top bit set carries a leading `0x00` that is dropped,
    /// and one with leading zero bytes is shorter than the coordinate and is left-padded.
    public static func rawSignature(
        fromDER der: Data,
        coordinateByteCount: Int
    ) throws(ECDSASignatureError) -> Data {
        try validate(coordinateByteCount: coordinateByteCount)

        var reader = DERReader(bytes: [UInt8](der))
        let sequenceLength = try reader.readHeader(expectedTag: sequenceTag)
        guard sequenceLength == reader.remaining else {
            throw .derSequenceLengthMismatch(declared: sequenceLength, available: reader.remaining)
        }
        let r = try reader.readPositiveInteger(.r, maximumByteCount: coordinateByteCount)
        let s = try reader.readPositiveInteger(.s, maximumByteCount: coordinateByteCount)
        guard reader.remaining == 0 else {
            throw .derTrailingBytes(count: reader.remaining)
        }

        var raw = Data(capacity: coordinateByteCount * 2)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - r.count))
        raw.append(contentsOf: r)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - s.count))
        raw.append(contentsOf: s)
        return raw
    }

    /// Converts `r || s` to a DER signature.
    public static func derSignature(
        fromRaw raw: Data,
        coordinateByteCount: Int
    ) throws(ECDSASignatureError) -> Data {
        try validate(coordinateByteCount: coordinateByteCount)

        let bytes = [UInt8](raw)
        guard bytes.count == coordinateByteCount * 2 else {
            throw .rawSignatureWrongLength(expected: coordinateByteCount * 2, found: bytes.count)
        }

        var body: [UInt8] = []
        body.reserveCapacity(bytes.count + 6)
        appendInteger(bytes[..<coordinateByteCount], to: &body)
        appendInteger(bytes[coordinateByteCount...], to: &body)

        var der = Data(capacity: body.count + 3)
        der.append(sequenceTag)
        // `maximumCoordinateByteCount` keeps `body.count` at or below 255.
        if body.count >= 0x80 {
            der.append(0x81)
        }
        der.append(UInt8(truncatingIfNeeded: body.count))
        der.append(contentsOf: body)
        return der
    }

    private static func validate(coordinateByteCount: Int) throws(ECDSASignatureError) {
        guard (1...maximumCoordinateByteCount).contains(coordinateByteCount) else {
            throw .unsupportedCoordinateByteCount(coordinateByteCount)
        }
    }

    private static func appendInteger(_ coordinate: ArraySlice<UInt8>, to output: inout [UInt8]) {
        var magnitude = coordinate.drop(while: { $0 == 0 })
        if magnitude.isEmpty {
            // Zero is encoded as a single 0x00, not as an empty INTEGER.
            magnitude = [0]
        }
        var needsSignByte = false
        if let first = magnitude.first {
            needsSignByte = first & 0x80 != 0
        }

        output.append(integerTag)
        if needsSignByte {
            output.append(UInt8(truncatingIfNeeded: magnitude.count + 1))
            output.append(0x00)
        } else {
            output.append(UInt8(truncatingIfNeeded: magnitude.count))
        }
        output.append(contentsOf: magnitude)
    }
}

private struct DERReader {
    let bytes: [UInt8]
    var offset = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int {
        bytes.count - offset
    }

    private mutating func readByte() throws(ECDSASignatureError) -> UInt8 {
        guard offset < bytes.count else {
            throw .derTruncated(offset: offset)
        }
        let byte = bytes[offset]
        offset += 1
        return byte
    }

    /// Reads a tag and a definite length, returning the length.
    mutating func readHeader(expectedTag: UInt8) throws(ECDSASignatureError) -> Int {
        let tagOffset = offset
        let tag = try readByte()
        guard tag == expectedTag else {
            throw .derUnexpectedTag(expected: expectedTag, found: tag, offset: tagOffset)
        }

        let lengthOffset = offset
        let first = try readByte()
        if first < 0x80 {
            return Int(first)
        }
        guard first == 0x81 else {
            throw .derLengthUnsupported(firstOctet: first, offset: lengthOffset)
        }
        let length = try readByte()
        guard length >= 0x80 else {
            throw .derLengthNotMinimal(offset: lengthOffset)
        }
        return Int(length)
    }

    /// Reads an INTEGER and returns its magnitude with any sign byte removed.
    mutating func readPositiveInteger(
        _ component: ECDSASignatureError.Component,
        maximumByteCount: Int
    ) throws(ECDSASignatureError) -> ArraySlice<UInt8> {
        let length = try readHeader(expectedTag: 0x02)
        guard length > 0 else {
            throw .derIntegerEmpty(component: component)
        }
        guard length <= remaining else {
            throw .derIntegerOverrun(component: component, declared: length, available: remaining)
        }
        var content = bytes[offset..<(offset + length)]
        offset += length

        let first = bytes[content.startIndex]
        guard first & 0x80 == 0 else {
            throw .derIntegerNegative(component: component)
        }
        if first == 0x00 && content.count > 1 {
            guard bytes[content.startIndex + 1] & 0x80 != 0 else {
                throw .derIntegerNotMinimal(component: component)
            }
            content = content.dropFirst()
        }
        guard content.count <= maximumByteCount else {
            throw .derIntegerTooLong(component: component, maximum: maximumByteCount, found: content.count)
        }
        return content
    }
}
