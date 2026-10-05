import Foundation
import Testing

@testable import JOSECore

// Hand-written: jose exposes no media type comparison of its own to generate expectations from.
// The rules are RFC 7515 §4.1.9 and RFC 2045 §5.1.
@Suite("MediaType")
struct MediaTypeTests {
    @Test("a value without a slash is the same type as its application/ form")
    func impliedPrefix() {
        #expect(MediaType(rawValue: "JWT") == MediaType(rawValue: "application/jwt"))
        #expect(MediaType(rawValue: "at+jwt") == MediaType(rawValue: "application/at+jwt"))
        #expect(MediaType(rawValue: "JWT").canonicalValue == "application/jwt")
    }

    @Test("type and subtype compare without regard to case")
    func caseInsensitive() {
        #expect(MediaType(rawValue: "JWT") == MediaType(rawValue: "jwt"))
        #expect(MediaType(rawValue: "Application/JWT") == MediaType(rawValue: "application/jwt"))
        #expect(MediaType(rawValue: "dpop+jwt") == MediaType(rawValue: "DPoP+JWT"))
    }

    @Test("different types are different")
    func distinct() {
        #expect(MediaType(rawValue: "JWT") != MediaType(rawValue: "at+jwt"))
        #expect(MediaType(rawValue: "JWT") != MediaType(rawValue: "text/jwt"))
        #expect(MediaType(rawValue: "JWT") != MediaType(rawValue: "JWT2"))
        #expect(MediaType(rawValue: "") != MediaType(rawValue: "JWT"))
    }

    @Test("a value that already has a slash gets no prefix")
    func noPrefixWhenSlashPresent() {
        #expect(MediaType(rawValue: "text/plain").canonicalValue == "text/plain")
        #expect(MediaType(rawValue: "text/plain") != MediaType(rawValue: "application/text/plain"))
        // A slash inside a parameter also counts: RFC 7515 allows omitting the prefix only when
        // no other "/" appears anywhere in the value.
        #expect(MediaType(rawValue: "example;part=\"1/2\"").canonicalValue == "example;part=\"1/2\"")
    }

    @Test("parameters are compared exactly, apart from surrounding whitespace")
    func parameters() {
        #expect(MediaType(rawValue: "JSON; charset=utf-8") == MediaType(rawValue: "application/json;charset=utf-8"))
        #expect(MediaType(rawValue: "json;charset=utf-8") != MediaType(rawValue: "json;charset=UTF-8"))
        #expect(MediaType(rawValue: "json;charset=utf-8") != MediaType(rawValue: "json"))
    }

    @Test("equal values hash equally, and the raw value is what is encoded")
    func hashingAndCoding() throws {
        #expect(Set([MediaType(rawValue: "JWT"), MediaType(rawValue: "application/jwt")]).count == 1)
        let encoded = try JSONEncoder().encode(["typ": MediaType(rawValue: "JWT")])
        #expect(String(decoding: encoded, as: UTF8.self) == #"{"typ":"JWT"}"#)
        let decoded = try JSONDecoder().decode([String: MediaType].self, from: encoded)
        #expect(decoded["typ"]?.rawValue == "JWT")
        let literal: MediaType = "at+jwt"
        #expect(literal.description == "at+jwt")
    }
}
