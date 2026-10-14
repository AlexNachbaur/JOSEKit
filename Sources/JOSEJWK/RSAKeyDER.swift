import Foundation

/// The values of an RSA private key, each as an unsigned big-endian integer with no leading zeros.
struct RSAPrivateKeyComponents: Sendable {
    var modulus: Data
    var publicExponent: Data
    var privateExponent: Data
    var prime1: Data
    var prime2: Data
    var exponent1: Data
    var exponent2: Data
    var coefficient: Data
}

/// PKCS#1 (RFC 8017 Appendix A.1) encoding of RSA keys. Both RSA backends take keys in this
/// form, and it is how keys commonly arrive from other systems.
///
///     RSAPublicKey  ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
///     RSAPrivateKey ::= SEQUENCE { version INTEGER (0), modulus, publicExponent,
///                                  privateExponent, prime1, prime2, exponent1, exponent2,
///                                  coefficient }
struct RSAKeyDER {
    private init() {}

    private static let sequenceTag: UInt8 = 0x30
    private static let integerTag: UInt8 = 0x02

    static func publicKey(modulus: Data, exponent: Data) -> Data {
        Data(sequence(integer(modulus) + integer(exponent)))
    }

    static func privateKey(_ components: RSAPrivateKeyComponents) -> Data {
        var body = integer(Data([0x00]))
        for value in [
            components.modulus, components.publicExponent, components.privateExponent, components.prime1,
            components.prime2, components.exponent1, components.exponent2, components.coefficient,
        ] {
            body += integer(value)
        }
        return Data(sequence(body))
    }

    static func parsePublicKey(_ der: Data) throws(JWKError) -> (modulus: Data, exponent: Data) {
        var reader = try Reader(sequence: der)
        let modulus = try reader.readUnsignedInteger("modulus")
        let exponent = try reader.readUnsignedInteger("publicExponent")
        try reader.finish()
        return (modulus, exponent)
    }

    static func parsePrivateKey(_ der: Data) throws(JWKError) -> RSAPrivateKeyComponents {
        var reader = try Reader(sequence: der)
        let version = try reader.readUnsignedInteger("version")
        guard version == Data([0x00]) else {
            // Version 1 means more than two primes, which RFC 7518 expresses with "oth".
            throw .unsupportedRSAPrivateKey(reason: "PKCS#1 version \(version.map(String.init).joined()) (multi-prime)")
        }
        let components = RSAPrivateKeyComponents(
            modulus: try reader.readUnsignedInteger("modulus"),
            publicExponent: try reader.readUnsignedInteger("publicExponent"),
            privateExponent: try reader.readUnsignedInteger("privateExponent"),
            prime1: try reader.readUnsignedInteger("prime1"),
            prime2: try reader.readUnsignedInteger("prime2"),
            exponent1: try reader.readUnsignedInteger("exponent1"),
            exponent2: try reader.readUnsignedInteger("exponent2"),
            coefficient: try reader.readUnsignedInteger("coefficient")
        )
        try reader.finish()
        return components
    }

    // MARK: Writing

    /// A DER INTEGER for an unsigned value: leading zeros dropped, and a `0x00` prepended when
    /// the top bit is set, since DER INTEGERs are signed.
    private static func integer(_ value: Data) -> [UInt8] {
        var magnitude = [UInt8](value.drop(while: { $0 == 0 }))
        if magnitude.isEmpty {
            magnitude = [0]
        }
        if magnitude[0] & 0x80 != 0 {
            magnitude.insert(0x00, at: 0)
        }
        return [integerTag] + length(magnitude.count) + magnitude
    }

    private static func sequence(_ body: [UInt8]) -> [UInt8] {
        [sequenceTag] + length(body.count) + body
    }

    private static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 {
            return [UInt8(count)]
        }
        var octets: [UInt8] = []
        var remaining = count
        while remaining > 0 {
            octets.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [0x80 | UInt8(octets.count)] + octets
    }

    // MARK: Reading

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0

        /// Opens the outer SEQUENCE, which must span the whole input.
        init(sequence der: Data) throws(JWKError) {
            bytes = [UInt8](der)
            let length = try readHeader(tag: RSAKeyDER.sequenceTag, name: "key")
            guard length == bytes.count - offset else {
                throw .invalidDER(reason: "SEQUENCE declares \(length) bytes but \(bytes.count - offset) follow")
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

        private mutating func readHeader(tag: UInt8, name: String) throws(JWKError) -> Int {
            let found = try readByte(name)
            guard found == tag else {
                throw .invalidDER(
                    reason: "\(name) has tag 0x\(String(found, radix: 16)); expected 0x\(String(tag, radix: 16))"
                )
            }
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

        /// Reads a non-negative INTEGER and returns its magnitude without the sign byte.
        mutating func readUnsignedInteger(_ name: String) throws(JWKError) -> Data {
            let length = try readHeader(tag: RSAKeyDER.integerTag, name: name)
            guard length > 0 else {
                throw .invalidDER(reason: "\(name) is an empty INTEGER")
            }
            guard length <= bytes.count - offset else {
                throw .invalidDER(reason: "\(name) declares \(length) bytes but \(bytes.count - offset) remain")
            }
            var content = bytes[offset..<(offset + length)]
            offset += length
            let first = bytes[content.startIndex]
            guard first & 0x80 == 0 else {
                throw .invalidDER(reason: "\(name) is negative")
            }
            if first == 0x00 && content.count > 1 {
                guard bytes[content.startIndex + 1] & 0x80 != 0 else {
                    throw .invalidDER(reason: "\(name) has a redundant leading zero")
                }
                content = content.dropFirst()
            }
            return Data(content)
        }

        func finish() throws(JWKError) {
            guard offset == bytes.count else {
                throw .invalidDER(reason: "\(bytes.count - offset) unexpected bytes after the last value")
            }
        }
    }
}
