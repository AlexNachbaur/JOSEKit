import Foundation

// Shared with the closed-loop executables under Sources/jose-*-interop, each of which reads a
// challenge as JSON on standard input and writes its response as JSON on standard output.

extension Decodable {
    /// Decodes the JSON read from `handle` to its end, such as a challenge on standard input.
    public init(jsonFrom handle: FileHandle) throws {
        self = try JSONDecoder().decode(Self.self, from: handle.readDataToEndOfFile())
    }
}

extension Encodable {
    /// Writes this value to `handle` as JSON, such as a response on standard output.
    public func writeJSON(to handle: FileHandle) throws {
        handle.write(try JSONEncoder().encode(self))
    }
}

extension String {
    /// The UTF-8 text in `data`, as a JWK or a JWS in the JSON serialization is written.
    public init(utf8 data: Data) {
        self.init(decoding: data, as: UTF8.self)
    }
}
