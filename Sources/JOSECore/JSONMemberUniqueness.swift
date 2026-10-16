import Foundation

/// Why a JSON document was refused by ``JSONMemberUniqueness``.
public enum JSONStructureError: Error, Sendable, Equatable {
    /// The document is not a JSON object. JOSE headers and JWT claims sets are always objects.
    case rootNotObject
    /// An object contains the same member name twice. `offset` is where the second one starts.
    case duplicateMember(name: String, offset: Int)
    /// A byte that cannot start or continue a value, name or separator at this position.
    case unexpectedByte(byte: UInt8, offset: Int)
    /// The document ends inside a value, name or object.
    case unexpectedEnd
    /// Non-whitespace bytes follow the end of the root object.
    case trailingData(offset: Int)
    /// A `\` escape in a member name that JSON does not define, or a `\u` escape that is not four
    /// hex digits or is half of a surrogate pair.
    case invalidEscape(offset: Int)
    /// A member name contains a raw control character or is not valid UTF-8.
    case invalidMemberName(offset: Int)
}

extension JSONStructureError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .rootNotObject:
            return "JSON document is not an object"
        case .duplicateMember(let name, let offset):
            return "JSON object has a duplicate member \(JSONStringEscaper.quoted(name)) at offset \(offset)"
        case .unexpectedByte(let byte, let offset):
            return "JSON document has unexpected byte 0x\(String(byte, radix: 16)) at offset \(offset)"
        case .unexpectedEnd:
            return "JSON document ends before its root object is closed"
        case .trailingData(let offset):
            return "JSON document has data after its root object, at offset \(offset)"
        case .invalidEscape(let offset):
            return "JSON member name has an invalid escape sequence at offset \(offset)"
        case .invalidMemberName(let offset):
            return "JSON member name at offset \(offset) contains a control character or invalid UTF-8"
        }
    }
}

/// Rejects JSON objects that repeat a member name, at any depth.
///
/// RFC 7515 §4 allows a duplicate header parameter to be handled in exactly two ways: reject the
/// token, or take the last occurrence. Foundation's JSON decoding takes the *first* (measured on
/// macOS), while JavaScript's `JSON.parse` takes the last, so without this check two
/// implementations can read different values out of the same signed bytes.
///
/// This is a structural scan, not a JSON validator. It establishes that member names are unique
/// and that brackets nest; it does not check number or literal syntax. Run it before handing the
/// same bytes to `JSONDecoder`, which does the rest.
///
/// Names are compared after resolving escapes (`"alg"` is `"alg"`) and using `String`
/// equality, which treats canonically equivalent Unicode as equal. That is stricter than a
/// byte comparison, deliberately: `JSONDecoder` keys its containers by `String`, so two names
/// that differ only in normalisation would collide there too.
public struct JSONMemberUniqueness: Sendable {
    private init() {}

    /// Throws unless `json` is an object in which no object, at any depth, repeats a member name.
    public static func validate(_ json: Data) throws(JSONStructureError) {
        var scanner = MemberScanner(bytes: [UInt8](json))
        try scanner.scan()
    }
}

private struct MemberScanner {
    private enum State {
        case value
        case memberName
        case afterValue
    }

    /// One open object or array. `memberNames` is `nil` for an array.
    private struct Frame {
        var memberNames: Set<String>?
    }

    private let bytes: [UInt8]
    private var offset = 0
    // An explicit stack rather than recursion, so attacker-supplied nesting depth costs heap, not
    // call stack.
    private var frames: [Frame] = []

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    private var current: UInt8? {
        guard offset < bytes.count else {
            return nil
        }
        return bytes[offset]
    }

    mutating func scan() throws(JSONStructureError) {
        skipWhitespace()
        guard current == UInt8(ascii: "{") else {
            throw .rootNotObject
        }

        var state = State.value
        while true {
            skipWhitespace()
            switch state {
            case .value:
                state = try scanValueStart()
            case .memberName:
                try scanMemberName()
                state = .value
            case .afterValue:
                guard let frame = frames.last else {
                    if current == nil {
                        return
                    }
                    throw .trailingData(offset: offset)
                }
                state = try scanSeparator(inObject: frame.memberNames != nil)
            }
        }
    }

    private mutating func skipWhitespace() {
        while let byte = current {
            guard byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D else {
                return
            }
            offset += 1
        }
    }

    private mutating func scanValueStart() throws(JSONStructureError) -> State {
        guard let byte = current else {
            throw .unexpectedEnd
        }
        switch byte {
        case UInt8(ascii: "{"):
            offset += 1
            skipWhitespace()
            if current == UInt8(ascii: "}") {
                offset += 1
                return .afterValue
            }
            frames.append(Frame(memberNames: []))
            return .memberName
        case UInt8(ascii: "["):
            offset += 1
            skipWhitespace()
            if current == UInt8(ascii: "]") {
                offset += 1
                return .afterValue
            }
            frames.append(Frame(memberNames: nil))
            return .value
        case UInt8(ascii: "\""):
            try skipString()
            return .afterValue
        default:
            try skipScalar()
            return .afterValue
        }
    }

    private mutating func scanMemberName() throws(JSONStructureError) {
        let nameOffset = offset
        guard let byte = current else {
            throw .unexpectedEnd
        }
        guard byte == UInt8(ascii: "\"") else {
            throw .unexpectedByte(byte: byte, offset: offset)
        }
        let name = try readString()

        // Inserted in place. Copying the set out, inserting and writing it back would copy the
        // whole set on every member (the frame still holds the old storage), which made a
        // header of n members cost O(n²) before any signature was checked.
        guard frames[frames.count - 1].memberNames?.insert(name).inserted != false else {
            throw .duplicateMember(name: name, offset: nameOffset)
        }

        skipWhitespace()
        guard let separator = current else {
            throw .unexpectedEnd
        }
        guard separator == UInt8(ascii: ":") else {
            throw .unexpectedByte(byte: separator, offset: offset)
        }
        offset += 1
    }

    private mutating func scanSeparator(inObject: Bool) throws(JSONStructureError) -> State {
        guard let byte = current else {
            throw .unexpectedEnd
        }
        var closer = UInt8(ascii: "]")
        var next = State.value
        if inObject {
            closer = UInt8(ascii: "}")
            next = .memberName
        }

        if byte == UInt8(ascii: ",") {
            offset += 1
            return next
        }
        if byte == closer {
            offset += 1
            frames.removeLast()
            return .afterValue
        }
        throw .unexpectedByte(byte: byte, offset: offset)
    }

    /// Skips a number, `true`, `false` or `null` without checking its syntax.
    private mutating func skipScalar() throws(JSONStructureError) {
        let start = offset
        while let byte = current {
            let isDigit = byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")
            let isLetter = byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z")
            let isNumberPunctuation =
                byte == UInt8(ascii: "-") || byte == UInt8(ascii: "+") || byte == UInt8(ascii: ".")
                || byte == UInt8(ascii: "E")
            guard isDigit || isLetter || isNumberPunctuation else {
                break
            }
            offset += 1
        }
        guard offset > start else {
            guard let byte = current else {
                throw .unexpectedEnd
            }
            throw .unexpectedByte(byte: byte, offset: offset)
        }
    }

    /// Skips a string value. Its content does not matter here, only where it ends.
    private mutating func skipString() throws(JSONStructureError) {
        offset += 1
        while let byte = current {
            offset += 1
            if byte == UInt8(ascii: "\"") {
                return
            }
            if byte == UInt8(ascii: "\\") {
                // Whatever follows a backslash is part of the string, including a quote.
                offset += 1
            }
        }
        throw .unexpectedEnd
    }

    /// Reads a string and resolves its escapes, so that differently spelled but equal member
    /// names compare equal.
    private mutating func readString() throws(JSONStructureError) -> String {
        let start = offset
        offset += 1
        var content: [UInt8] = []
        while let byte = current {
            if byte == UInt8(ascii: "\"") {
                offset += 1
                return try decodeUTF8(content, nameOffset: start)
            }
            if byte == UInt8(ascii: "\\") {
                try readEscape(into: &content)
                continue
            }
            guard byte >= 0x20 else {
                throw .invalidMemberName(offset: start)
            }
            content.append(byte)
            offset += 1
        }
        throw .unexpectedEnd
    }

    /// Strict UTF-8 decoding. Foundation's `String(bytes:encoding:)` is not used because it drops
    /// a leading byte order mark, which would make the name U+FEFF equal to the empty name.
    private func decodeUTF8(_ content: [UInt8], nameOffset: Int) throws(JSONStructureError) -> String {
        var decoder = UTF8()
        var iterator = content.makeIterator()
        var name = String.UnicodeScalarView()
        while true {
            switch decoder.decode(&iterator) {
            case .scalarValue(let scalar):
                name.append(scalar)
            case .emptyInput:
                return String(name)
            case .error:
                throw .invalidMemberName(offset: nameOffset)
            }
        }
    }

    private mutating func readEscape(into content: inout [UInt8]) throws(JSONStructureError) {
        let escapeOffset = offset
        offset += 1
        guard let kind = current else {
            throw .unexpectedEnd
        }
        offset += 1
        switch kind {
        case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"):
            content.append(kind)
        case UInt8(ascii: "b"):
            content.append(0x08)
        case UInt8(ascii: "f"):
            content.append(0x0C)
        case UInt8(ascii: "n"):
            content.append(0x0A)
        case UInt8(ascii: "r"):
            content.append(0x0D)
        case UInt8(ascii: "t"):
            content.append(0x09)
        case UInt8(ascii: "u"):
            var value = try readHexQuad(escapeOffset: escapeOffset)
            if (0xD800...0xDBFF).contains(value) {
                // A high surrogate is only meaningful with the low surrogate that must follow it.
                guard current == UInt8(ascii: "\\"), offset + 1 < bytes.count, bytes[offset + 1] == UInt8(ascii: "u")
                else {
                    throw .invalidEscape(offset: escapeOffset)
                }
                offset += 2
                let low = try readHexQuad(escapeOffset: escapeOffset)
                guard (0xDC00...0xDFFF).contains(low) else {
                    throw .invalidEscape(offset: escapeOffset)
                }
                value = 0x10000 + ((value - 0xD800) << 10) + (low - 0xDC00)
            }
            // Fails for a lone low surrogate, the only remaining value that is not a scalar.
            guard let scalar = Unicode.Scalar(value) else {
                throw .invalidEscape(offset: escapeOffset)
            }
            content.append(contentsOf: Array(String(scalar).utf8))
        default:
            throw .invalidEscape(offset: escapeOffset)
        }
    }

    private mutating func readHexQuad(escapeOffset: Int) throws(JSONStructureError) -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 {
            guard let byte = current else {
                throw .unexpectedEnd
            }
            guard let digit = Character(Unicode.Scalar(byte)).hexDigitValue else {
                throw .invalidEscape(offset: escapeOffset)
            }
            value = value << 4 | UInt32(digit)
            offset += 1
        }
        return value
    }
}
