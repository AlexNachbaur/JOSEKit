import Foundation

/// Why a base64url string was refused.
public enum Base64URLError: Error, Sendable, Equatable {
    /// The unpadded body has a length of 4n+1. No byte sequence encodes to that length.
    case invalidLength(count: Int)
    /// A byte outside the base64url alphabet (`A-Z a-z 0-9 - _`). This includes `+` and `/` from
    /// the standard alphabet, and whitespace.
    case invalidCharacter(byte: UInt8, offset: Int)
    /// A `=` that is followed by something other than `=`. `offset` is the position of the first `=`.
    case misplacedPadding(offset: Int)
    /// Trailing `=` characters whose number does not bring the length to a multiple of four.
    case wrongPaddingLength(expected: Int, found: Int)
    /// The final character carries bits that are not part of any decoded byte, and they are not
    /// zero. `"YR"` and `"YQ"` would otherwise both decode to `0x61`.
    case nonCanonicalTrailingBits(offset: Int)
}

extension Base64URLError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidLength(let count):
            return "base64url body is \(count) characters long; a length of 4n+1 cannot be produced by any input"
        case .invalidCharacter(let byte, let offset):
            return "base64url input has byte 0x\(String(byte, radix: 16)) at offset \(offset), "
                + "which is outside the base64url alphabet"
        case .misplacedPadding(let offset):
            return "base64url input has '=' at offset \(offset) followed by non-padding characters"
        case .wrongPaddingLength(let expected, let found):
            return "base64url input ends with \(found) '=' characters where \(expected) would be correct"
        case .nonCanonicalTrailingBits(let offset):
            return "base64url input's final character (offset \(offset)) has non-zero unused bits; "
                + "no encoder produces this"
        }
    }
}

/// base64url as used by JOSE (RFC 7515 §2, RFC 4648 §5).
///
/// Encoded values are compared for equality by other implementations (thumbprints, key coordinates),
/// so decoding accepts only strings an encoder could have produced. Foundation's
/// `Data(base64Encoded:)` is deliberately not used: it accepts over-padded input such as `"YQ==="`.
public struct Base64URL: Sendable {
    private init() {}

    private static let paddingByte = UInt8(ascii: "=")
    private static let invalid: UInt8 = 0xFF

    private static let alphabet: [UInt8] = Array(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8
    )

    private static let decodeTable: [UInt8] = {
        var table = [UInt8](repeating: invalid, count: 256)
        for (value, character) in alphabet.enumerated() {
            table[Int(character)] = UInt8(value)
        }
        return table
    }()

    /// Encodes `bytes` without padding.
    public static func encode(_ bytes: some Collection<UInt8>) -> String {
        var output: [UInt8] = []
        output.reserveCapacity((bytes.count * 4 + 2) / 3)
        var iterator = bytes.makeIterator()
        while let first = iterator.next() {
            let second = iterator.next()
            let third = iterator.next()
            output.append(alphabet[Int(first >> 2)])
            output.append(alphabet[Int((first & 0x03) << 4 | (second ?? 0) >> 4)])
            guard let second else {
                break
            }
            output.append(alphabet[Int((second & 0x0F) << 2 | (third ?? 0) >> 6)])
            guard let third else {
                break
            }
            output.append(alphabet[Int(third & 0x3F)])
        }
        return String(decoding: output, as: UTF8.self)
    }

    /// Decodes a base64url string.
    ///
    /// Padding is optional, but if present it must be exactly the amount that completes the final
    /// quantum. Everything else that is not canonical base64url is refused; see ``Base64URLError``.
    public static func decode(_ string: some StringProtocol) throws(Base64URLError) -> Data {
        let bytes = Array(string.utf8)

        var bodyCount = bytes.count
        if let firstPadding = bytes.firstIndex(of: paddingByte) {
            guard bytes[firstPadding...].allSatisfy({ $0 == paddingByte }) else {
                throw .misplacedPadding(offset: firstPadding)
            }
            bodyCount = firstPadding
        }

        let remainder = bodyCount % 4
        guard remainder != 1 else {
            throw .invalidLength(count: bodyCount)
        }

        let paddingCount = bytes.count - bodyCount
        if paddingCount > 0 {
            let expected = (4 - remainder) % 4
            guard paddingCount == expected else {
                throw .wrongPaddingLength(expected: expected, found: paddingCount)
            }
        }

        var output = Data()
        output.reserveCapacity(bodyCount * 3 / 4)
        var accumulator: UInt32 = 0
        var pendingBits: UInt32 = 0
        for offset in 0..<bodyCount {
            let value = decodeTable[Int(bytes[offset])]
            guard value != invalid else {
                throw .invalidCharacter(byte: bytes[offset], offset: offset)
            }
            accumulator = (accumulator << 6) | UInt32(value)
            pendingBits += 6
            if pendingBits >= 8 {
                pendingBits -= 8
                output.append(UInt8(truncatingIfNeeded: accumulator >> pendingBits))
            }
        }

        // A final partial quantum leaves 4 or 2 bits that belong to no output byte. An encoder
        // always writes them as zero.
        let unusedBits = accumulator & ((1 << pendingBits) - 1)
        guard unusedBits == 0 else {
            throw .nonCanonicalTrailingBits(offset: bodyCount - 1)
        }

        return output
    }
}
