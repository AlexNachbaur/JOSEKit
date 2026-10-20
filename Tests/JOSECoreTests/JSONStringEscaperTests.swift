import Foundation
import Testing

@testable import JOSECore

private struct JSONStringFixture: Decodable {
    struct Case: Decodable {
        let utf8Hex: String
        let stringified: String
    }
    let cases: [Case]
}

@Suite("JSONStringEscaper")
struct JSONStringEscaperTests {
    @Test("output is identical to JSON.stringify for every fixture string")
    func matchesCounterpart() throws {
        let fixture = try JSONStringFixture(fixture: "json-strings")
        #expect(fixture.cases.count >= 50)
        for testCase in fixture.cases {
            // Not `String(bytes:encoding:)`, which drops a leading byte order mark.
            let input = String(decoding: try Data(hex: testCase.utf8Hex), as: UTF8.self)
            #expect(JSONStringEscaper.quoted(input) == testCase.stringified, "input bytes \(testCase.utf8Hex)")
        }
    }

    @Test("a value cannot break out of its string and forge members")
    func cannotForgeMembers() throws {
        let hostile = #"","y":"forged"#
        let document = #"{"x":"# + JSONStringEscaper.quoted(hostile) + "}"
        let decoded = try JSONDecoder().decode([String: String].self, from: Data(document.utf8))
        #expect(decoded == ["x": hostile])
    }

    @Test("quotes, backslashes and control characters are escaped; slashes and non-ASCII are not")
    func escapes() {
        #expect(JSONStringEscaper.quoted("") == #""""#)
        #expect(JSONStringEscaper.quoted(#"a"b"#) == #""a\"b""#)
        #expect(JSONStringEscaper.quoted(#"a\b"#) == #""a\\b""#)
        #expect(JSONStringEscaper.quoted("\u{08}\u{0C}\n\r\t") == #""\b\f\n\r\t""#)
        #expect(JSONStringEscaper.quoted("\u{00}\u{1F}") == #""\u0000\u001f""#)
        #expect(JSONStringEscaper.quoted("a/b") == #""a/b""#)
        #expect(JSONStringEscaper.quoted("é😀") == "\"é😀\"")
    }
}
