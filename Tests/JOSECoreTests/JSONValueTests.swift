import Foundation
import Testing

@testable import JOSECore

@Suite("JSONValue")
struct JSONValueTests {
    private func decode(_ json: String) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
    }

    private func encode(_ value: JSONValue) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }

    @Test("each JSON type decodes to its own case")
    func decodesEachType() throws {
        #expect(try decode("null") == .null)
        #expect(try decode("true") == .bool(true))
        #expect(try decode("false") == .bool(false))
        #expect(try decode("42") == .integer(42))
        #expect(try decode("-7") == .integer(-7))
        #expect(try decode("1.5") == .double(1.5))
        #expect(try decode(#""text""#) == .string("text"))
        #expect(try decode("[1,\"a\",null]") == .array([.integer(1), .string("a"), .null]))
        #expect(try decode(#"{"a":{"b":[true]}}"#) == .object(["a": .object(["b": .array([.bool(true)])])]))
    }

    @Test("booleans and numbers are not confused with each other")
    func boolAndNumberAreDistinct() throws {
        #expect(try decode("1") == .integer(1))
        #expect(try decode("0") == .integer(0))
        #expect(try decode("true") != .integer(1))
        #expect(try decode(#""1""#) == .string("1"))
    }

    @Test("64-bit integers survive without passing through Double")
    func largeIntegers() throws {
        #expect(try decode("9223372036854775807") == .integer(.max))
        #expect(try decode("-9223372036854775808") == .integer(.min))
        // 2^53 + 1 is not representable as a Double.
        #expect(try decode("9007199254740993") == .integer(9_007_199_254_740_993))
        #expect(try encode(.integer(9_007_199_254_740_993)) == "9007199254740993")
    }

    @Test("numbers outside Int64 decode as Double")
    func numbersBeyondInt64() throws {
        #expect(try decode("1e30") == .double(1e30))
        #expect(try decode("9223372036854775808") == .double(9_223_372_036_854_775_808))
    }

    @Test("a whole number written with a fraction decodes as an integer, as documented")
    func wholeNumberWithFraction() throws {
        #expect(try decode("1.0") == .integer(1))
    }

    @Test("values round-trip through encoding")
    func roundTrip() throws {
        let value: JSONValue = [
            "null": nil,
            "bool": true,
            "int": 3,
            "double": 2.5,
            "string": "https://example.com/a",
            "array": [1, "two", [3]],
            "object": ["nested": false],
        ]
        let json = try encode(value)
        #expect(
            json
                == #"{"array":[1,"two",[3]],"bool":true,"double":2.5,"int":3,"null":null,"#
                + #""object":{"nested":false},"string":"https://example.com/a"}"#
        )
        #expect(try decode(json) == value)
    }

    @Test("malformed JSON is an error, not a fallback to another case")
    func malformed() {
        #expect(throws: DecodingError.self) { try decode("{") }
        #expect(throws: DecodingError.self) { try decode("[1,") }
    }

    @Test("literals build the expected cases")
    func literals() {
        let null: JSONValue = nil
        let bool: JSONValue = false
        let integer: JSONValue = 5
        let double: JSONValue = 5.5
        let string: JSONValue = "s"
        let array: JSONValue = [1, 2]
        let object: JSONValue = ["k": "v"]
        #expect(null == .null)
        #expect(bool == .bool(false))
        #expect(integer == .integer(5))
        #expect(double == .double(5.5))
        #expect(string == .string("s"))
        #expect(array == .array([.integer(1), .integer(2)]))
        #expect(object == .object(["k": .string("v")]))
    }
}
