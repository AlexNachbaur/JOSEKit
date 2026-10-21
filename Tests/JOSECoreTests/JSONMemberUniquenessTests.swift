import Foundation
import Testing

@testable import JOSECore

// These cases are written by hand. jose has no equivalent check (it takes the last duplicate, as
// `JSON.parse` does), so there is no counterpart to generate expectations from.
@Suite("JSONMemberUniqueness")
struct JSONMemberUniquenessTests {
    private func validate(_ json: String) throws(JSONStructureError) {
        try Data(json.utf8).requireUniqueJSONMembers()
    }

    @Test(
        "documents without duplicates are accepted",
        arguments: [
            "{}",
            " { } ",
            #"{"alg":"ES256"}"#,
            #"{"alg":"ES256","kid":"1","typ":"JWT"}"#,
            "\t{\n\"a\" : 1 ,\r\n\"b\" : [ 1 , 2 ] }\n",
            #"{"a":{"a":1},"b":{"a":2}}"#,
            #"{"a":[{"x":1},{"x":2}]}"#,
            #"{"a":[],"b":{},"c":[[]],"d":[{}]}"#,
            #"{"n":-1.5e+10,"t":true,"f":false,"z":null,"E":1E5}"#,
            #"{"s":"a \" quote and a \\","t":"}{][,:"}"#,
            #"{"s":"\\"}"#,
            #"{"a":"a","A":"a"}"#,
            #"{"":1," ":2}"#,
            #"{"a\"b":1,"a\\b":2,"a\/b":3,"\b\f\n\r\t":4}"#,
            #"{"😀":1,"\ud83d\ude01":2}"#,
        ]
    )
    func accepts(json: String) throws {
        try validate(json)
        // The scan must not accept anything Foundation would then refuse to read as an object.
        _ = try JSONDecoder().decode([String: JSONValue].self, from: Data(json.utf8))
    }

    @Test("a repeated member name is rejected, naming the member and where the repeat starts")
    func rejectsDuplicates() {
        #expect(throws: JSONStructureError.duplicateMember(name: "alg", offset: 15)) {
            try validate(#"{"alg":"ES256","alg":"none"}"#)
        }
        #expect(throws: JSONStructureError.duplicateMember(name: "a", offset: 13)) {
            try validate(#"{"a":1,"b":2,"a":3}"#)
        }
        #expect(throws: JSONStructureError.duplicateMember(name: "", offset: 6)) {
            try validate(#"{"":1,"":2}"#)
        }
    }

    @Test("duplicates are found inside nested objects and inside arrays")
    func rejectsNestedDuplicates() {
        #expect(throws: JSONStructureError.duplicateMember(name: "kty", offset: 19)) {
            try validate(#"{"jwk":{"kty":"EC","kty":"RSA"}}"#)
        }
        #expect(throws: JSONStructureError.duplicateMember(name: "x", offset: 21)) {
            try validate(#"{"a":[1,{"b":[{"x":1,"x":2}]}]}"#)
        }
        // A name seen in a closed sibling object, or in the parent, is not a duplicate; one seen
        // earlier in the same object is, even with a nested object in between.
        #expect(throws: JSONStructureError.duplicateMember(name: "a", offset: 13)) {
            try validate(#"{"a":{"a":1},"a":2}"#)
        }
    }

    @Test("names that differ only in how they are escaped are the same name")
    func comparesAfterResolvingEscapes() {
        #expect(throws: JSONStructureError.duplicateMember(name: "alg", offset: 15)) {
            try validate(#"{"alg":"ES256","\u0061lg":"none"}"#)
        }
        #expect(throws: JSONStructureError.duplicateMember(name: "a/b", offset: 9)) {
            try validate(#"{"a/b":1,"a\/b":2}"#)
        }
        #expect(throws: JSONStructureError.duplicateMember(name: "😀", offset: 10)) {
            try validate(#"{"😀":1,"\uD83D\uDE00":2}"#)
        }
        #expect(throws: JSONStructureError.duplicateMember(name: "\n", offset: 8)) {
            try validate(#"{"\n":1,"\u000a":2}"#)
        }
        #expect(throws: JSONStructureError.duplicateMember(name: "\t\u{08}\u{0C}\r\"\\", offset: 18)) {
            try validate(#"{"\t\b\f\r\"\\":1,"\u0009\u0008\u000c\u000d\u0022\u005c":2}"#)
        }
    }

    @Test("canonically equivalent names are the same name, as they are to JSONDecoder")
    func comparesWithCanonicalEquivalence() {
        // U+00E9 against U+0065 U+0301. Offset counts bytes: the first name is two bytes of UTF-8.
        #expect(throws: JSONStructureError.duplicateMember(name: "\u{E9}", offset: 8)) {
            try validate("{\"\u{E9}\":1,\"e\u{301}\":2}")
        }
    }

    @Test("a byte order mark is a character in a name, not something to discard")
    func byteOrderMarkIsSignificant() throws {
        // U+FEFF and the empty string are different names.
        try validate("{\"\":1,\"\u{FEFF}\":2}")
        #expect(throws: JSONStructureError.duplicateMember(name: "\u{FEFF}", offset: 9)) {
            try validate("{\"\u{FEFF}\":1,\"\\ufeff\":2}")
        }
    }

    @Test("a string value containing an escaped quote does not end early")
    func escapedQuoteInValue() {
        // If the value ended at the escaped quote, the text after it would be read as structure
        // and the real duplicate would be missed or misreported.
        #expect(throws: JSONStructureError.duplicateMember(name: "a", offset: 17)) {
            try validate(#"{"a":"x\",\"a\"","a":2}"#)
        }
    }

    @Test("only objects are accepted at the root")
    func rootMustBeObject() {
        #expect(throws: JSONStructureError.rootNotObject) { try validate("[]") }
        #expect(throws: JSONStructureError.rootNotObject) { try validate(#""alg""#) }
        #expect(throws: JSONStructureError.rootNotObject) { try validate("1") }
        #expect(throws: JSONStructureError.rootNotObject) { try validate("") }
        #expect(throws: JSONStructureError.rootNotObject) { try validate("   ") }
    }

    @Test("malformed structure reports its specific cause")
    func structuralErrors() {
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate("{") }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a""#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a":"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a":1"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a":1,"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a":[1"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a":"unterminated"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a":"x\"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"unterminated"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a\"#) }
        #expect(throws: JSONStructureError.unexpectedEnd) { try validate(#"{"a\u00"#) }

        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x61, offset: 1)) { try validate("{a:1}") }
        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x7D, offset: 7)) { try validate(#"{"a":1,}"#) }
        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x31, offset: 4)) { try validate(#"{"a"1}"#) }
        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x7D, offset: 5)) { try validate(#"{"a":}"#) }
        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x22, offset: 7)) { try validate(#"{"a":1 "b":2}"#) }
        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x5D, offset: 6)) { try validate(#"{"a":1]"#) }
        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x7D, offset: 7)) { try validate(#"{"a":[1}"#) }
        #expect(throws: JSONStructureError.unexpectedByte(byte: 0x3A, offset: 7)) { try validate(#"{"a":[1:2]}"#) }

        #expect(throws: JSONStructureError.trailingData(offset: 2)) { try validate("{}{}") }
        #expect(throws: JSONStructureError.trailingData(offset: 8)) { try validate(#"{"a":1} x"#) }
    }

    @Test("invalid escapes and control characters in a member name are rejected")
    func invalidMemberNames() {
        #expect(throws: JSONStructureError.invalidEscape(offset: 2)) { try validate(#"{"\x":1}"#) }
        #expect(throws: JSONStructureError.invalidEscape(offset: 2)) { try validate(#"{"\u00zz":1}"#) }
        // Lone high surrogate, high surrogate followed by a non-surrogate, lone low surrogate.
        #expect(throws: JSONStructureError.invalidEscape(offset: 2)) { try validate(#"{"\ud83d":1}"#) }
        #expect(throws: JSONStructureError.invalidEscape(offset: 2)) { try validate(#"{"\ud83d\u0041":1}"#) }
        #expect(throws: JSONStructureError.invalidEscape(offset: 2)) { try validate(#"{"\ud83dx":1}"#) }
        #expect(throws: JSONStructureError.invalidEscape(offset: 2)) { try validate(#"{"\ude00":1}"#) }

        #expect(throws: JSONStructureError.invalidMemberName(offset: 1)) { try validate("{\"a\nb\":1}") }
        #expect(throws: JSONStructureError.invalidMemberName(offset: 1)) {
            try Data([0x7B, 0x22, 0xFF, 0x22, 0x3A, 0x31, 0x7D]).requireUniqueJSONMembers()
        }
    }

    @Test("deep nesting does not exhaust the stack")
    func deepNesting() throws {
        let depth = 100_000
        let json = String(repeating: #"{"a":"#, count: depth) + "1" + String(repeating: "}", count: depth)
        try validate(json)
        let arrays = #"{"a":"# + String(repeating: "[", count: depth) + String(repeating: "]", count: depth) + "}"
        try validate(arrays)
    }

    @Test("an object with tens of thousands of members scans in linear time")
    func manyMembers() throws {
        // Regression: the scanner once copied its name set on every insert, which made this
        // take seconds. The bound is generous so that a slow CI machine does not fail it, but a
        // quadratic implementation takes well over it.
        let count = 60_000
        let json = "{" + (0..<count).map { #""m\#($0)":\#($0)"# }.joined(separator: ",") + "}"
        let start = ContinuousClock.now
        try validate(json)
        #expect(ContinuousClock.now - start < .seconds(2))
    }

    @Test("works on Data slices whose start index is not zero")
    func slices() throws {
        let data = Data("xx{\"a\":1}".utf8)
        try data.dropFirst(2).requireUniqueJSONMembers()
    }

    @Test("Foundation still takes the first duplicate, which is why this check exists")
    func foundationBehaviour() throws {
        // Not a test of this package. If this starts failing, Foundation's behaviour has changed
        // and the documentation on JSONMemberUniqueness needs correcting.
        let decoded = try JSONDecoder().decode(
            [String: String].self,
            from: Data(#"{"alg":"ES256","alg":"none"}"#.utf8)
        )
        #expect(decoded == ["alg": "ES256"])
    }

    @Test("every error has a message naming the offending value")
    func descriptions() {
        #expect(JSONStructureError.rootNotObject.description.contains("object"))
        #expect(JSONStructureError.duplicateMember(name: "alg", offset: 15).description.contains(#""alg""#))
        #expect(JSONStructureError.duplicateMember(name: "alg", offset: 15).description.contains("15"))
        #expect(JSONStructureError.unexpectedByte(byte: 0x7D, offset: 7).description.contains("0x7d"))
        #expect(JSONStructureError.unexpectedEnd.description.contains("ends"))
        #expect(JSONStructureError.trailingData(offset: 9).description.contains("9"))
        #expect(JSONStructureError.invalidEscape(offset: 4).description.contains("4"))
        #expect(JSONStructureError.invalidMemberName(offset: 6).description.contains("6"))
    }
}
