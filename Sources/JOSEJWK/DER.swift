import Foundation

/// Reads DER (ITU-T X.690): the strict, canonical encoding keys are stored in. Only what key
/// formats need: definite lengths in their shortest form, and the handful of types below.
struct DERReader {
    static let integer: UInt8 = 0x02
    static let bitString: UInt8 = 0x03
    static let octetString: UInt8 = 0x04
    static let null: UInt8 = 0x05
    static let objectIdentifier: UInt8 = 0x06
    static let sequence: UInt8 = 0x30
    /// `[0]` and `[1]` EXPLICIT, as SEC1 uses for its optional parameters and public key.
    static let contextConstructed0: UInt8 = 0xA0
    static let contextConstructed1: UInt8 = 0xA1
    /// `[1]` IMPLICIT BIT STRING, the public key of a PKCS#8 version 2 (RFC 5958) key.
    static let contextPrimitive1: UInt8 = 0x81

    private let bytes: [UInt8]
    private var offset = 0

    init(_ data: Data) {
        bytes = [UInt8](data)
    }

    var isAtEnd: Bool {
        offset == bytes.count
    }

    /// The tag of the next element, if there is one.
    var nextTag: UInt8? {
        guard offset < bytes.count else {
            return nil
        }
        return bytes[offset]
    }

    /// Fails unless every byte has been read: DER has exactly one encoding, so anything left
    /// over means the input was not the structure it claimed to be.
    func finish(_ name: String) throws(JWKError) {
        guard isAtEnd else {
            throw .invalidDER(reason: "\(bytes.count - offset) unexpected bytes after \(name)")
        }
    }

    private mutating func readByte(_ name: String) throws(JWKError) -> UInt8 {
        guard offset < bytes.count else {
            throw .invalidDER(reason: "input ends inside \(name)")
        }
        let byte = bytes[offset]
        offset += 1
        return byte
    }

    /// Opens the SEQUENCE that must make up the whole of `der`, and returns a reader over its
    /// content.
    static func wholeSequence(_ der: Data, _ name: String) throws(JWKError) -> DERReader {
        var outer = DERReader(der)
        let length = try outer.readHeader(tag: sequence, name)
        guard length == outer.bytes.count - outer.offset else {
            throw .invalidDER(
                reason: "SEQUENCE declares \(length) bytes but \(outer.bytes.count - outer.offset) follow"
            )
        }
        return DERReader(Data(outer.bytes[outer.offset...]))
    }

    /// Reads one element with tag `tag` and returns its content.
    mutating func read(tag: UInt8, _ name: String) throws(JWKError) -> Data {
        let length = try readHeader(tag: tag, name)
        guard length <= bytes.count - offset else {
            throw .invalidDER(reason: "\(name) declares \(length) bytes but \(bytes.count - offset) remain")
        }
        let content = Data(bytes[offset..<(offset + length)])
        offset += length
        return content
    }

    private mutating func readHeader(tag: UInt8, _ name: String) throws(JWKError) -> Int {
        let found = try readByte(name)
        guard found == tag else {
            throw .invalidDER(
                reason: "\(name) has tag 0x\(String(found, radix: 16)); expected 0x\(String(tag, radix: 16))"
            )
        }
        return try readLength(name)
    }

    private mutating func readLength(_ name: String) throws(JWKError) -> Int {
        let first = try readByte(name)
        if first < 0x80 {
            return Int(first)
        }
        let octetCount = Int(first & 0x7F)
        // Four octets is far more than any key needs; zero would be an indefinite length.
        guard (1...4).contains(octetCount) else {
            throw .invalidDER(reason: "\(name) has an unsupported length encoding")
        }
        var length = 0
        for _ in 0..<octetCount {
            length = length << 8 | Int(try readByte(name))
        }
        // DER requires the shortest form.
        guard length >= 0x80, length >> ((octetCount - 1) * 8) != 0 else {
            throw .invalidDER(reason: "\(name) has a non-minimal length encoding")
        }
        return length
    }

    /// Reads a SEQUENCE (or another constructed element) and returns a reader over its content.
    mutating func readConstructed(tag: UInt8 = DERReader.sequence, _ name: String) throws(JWKError) -> DERReader {
        DERReader(try read(tag: tag, name))
    }

    /// Reads a non-negative INTEGER and returns its magnitude without the sign byte.
    mutating func readUnsignedInteger(_ name: String) throws(JWKError) -> Data {
        var content = try read(tag: Self.integer, name)
        guard let first = content.first else {
            throw .invalidDER(reason: "\(name) is an empty INTEGER")
        }
        guard first & 0x80 == 0 else {
            throw .invalidDER(reason: "\(name) is negative")
        }
        if first == 0x00 && content.count > 1 {
            guard content[content.startIndex + 1] & 0x80 != 0 else {
                throw .invalidDER(reason: "\(name) has a redundant leading zero")
            }
            content = content.dropFirst()
        }
        return Data(content)
    }

    /// Reads a BIT STRING that holds whole bytes, as every key encoding does.
    mutating func readBitString(tag: UInt8 = DERReader.bitString, _ name: String) throws(JWKError) -> Data {
        let content = try read(tag: tag, name)
        guard let unusedBits = content.first else {
            throw .invalidDER(reason: "\(name) is an empty BIT STRING")
        }
        guard unusedBits == 0 else {
            throw .invalidDER(reason: "\(name) does not hold whole bytes")
        }
        return Data(content.dropFirst())
    }

    mutating func readOctetString(_ name: String) throws(JWKError) -> Data {
        try read(tag: Self.octetString, name)
    }

    mutating func readNull(_ name: String) throws(JWKError) {
        guard try read(tag: Self.null, name).isEmpty else {
            throw .invalidDER(reason: "\(name) is a NULL with content")
        }
    }

    /// Reads an OBJECT IDENTIFIER and returns it in dotted form, such as `1.2.840.10045.2.1`.
    mutating func readObjectIdentifier(_ name: String) throws(JWKError) -> String {
        let content = [UInt8](try read(tag: Self.objectIdentifier, name))
        guard let last = content.last, last & 0x80 == 0 else {
            throw .invalidDER(reason: "\(name) is not a complete OBJECT IDENTIFIER")
        }
        var arcs: [UInt64] = []
        var value: UInt64 = 0
        var started = false
        for byte in content {
            // Each arc is base 128, most significant group first, in its shortest form.
            guard started || byte != 0x80 else {
                throw .invalidDER(reason: "\(name) has a non-minimal arc")
            }
            guard value <= UInt64.max >> 7 else {
                throw .invalidDER(reason: "\(name) has an arc too large to read")
            }
            value = value << 7 | UInt64(byte & 0x7F)
            started = true
            if byte & 0x80 == 0 {
                arcs.append(value)
                value = 0
                started = false
            }
        }
        // The first value packs the first two arcs (X.690 §8.19.4).
        let first = arcs[0]
        var dotted: [UInt64] = []
        if first < 40 {
            dotted = [0, first]
        } else if first < 80 {
            dotted = [1, first - 40]
        } else {
            dotted = [2, first - 80]
        }
        dotted += arcs.dropFirst()
        return dotted.map(String.init).joined(separator: ".")
    }
}
