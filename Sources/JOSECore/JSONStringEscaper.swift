/// Writes a string as a JSON string literal, with a fixed and documented choice of escapes.
///
/// Used wherever JSON is built by hand because the exact bytes matter (RFC 7638 thumbprint input).
/// Interpolating a value straight into a template would let a value containing `","` forge
/// additional members; `JSONEncoder` is not used because its escaping choices (`/`, non-ASCII)
/// differ between platforms and versions.
///
/// The output matches ECMAScript `JSON.stringify` for the same string: `"` and `\` are escaped,
/// the five control characters with short forms use them, every other character below U+0020 is
/// written as `\u00xx` in lowercase hex, and everything else, including `/` and non-ASCII, is
/// written literally.
public struct JSONStringEscaper: Sendable {
    private init() {}

    /// Returns `string` as a JSON string literal, including the surrounding quotes.
    public static func quoted(_ string: String) -> String {
        var output = "\""
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\"":
                output += "\\\""
            case "\\":
                output += "\\\\"
            case "\u{08}":
                output += "\\b"
            case "\u{0C}":
                output += "\\f"
            case "\n":
                output += "\\n"
            case "\r":
                output += "\\r"
            case "\t":
                output += "\\t"
            default:
                if scalar.value < 0x20 {
                    let hex = String(scalar.value, radix: 16)
                    output += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                } else {
                    output.unicodeScalars.append(scalar)
                }
            }
        }
        output += "\""
        return output
    }
}
