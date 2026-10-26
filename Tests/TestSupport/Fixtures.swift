import Foundation

/// Test data that is missing or does not hold what the code reading it expects: a fixture, or a
/// closed-loop challenge.
public struct FixtureError: Error, CustomStringConvertible {
    public let description: String

    public init(description: String) {
        self.description = description
    }
}

extension Decodable {
    /// Loads `Fixtures/<name>.json` from `bundle`, which is the calling test target's
    /// `Bundle.module`: each target ships the fixtures its `interop/<module>/generate-*.mjs`
    /// script writes.
    public init(fixture name: String, in bundle: Bundle) throws {
        guard let url = bundle.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") else {
            throw FixtureError(description: "fixture \(name).json is missing from the test bundle")
        }
        self = try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }
}

extension Data {
    /// Bytes from lowercase or uppercase hex, as the fixtures write them.
    public init(hex: String) throws {
        let digits = Array(hex.utf8)
        guard digits.count.isMultiple(of: 2) else {
            throw FixtureError(description: "hex string has odd length \(digits.count)")
        }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[index..<(index + 2)], as: UTF8.self), radix: 16) else {
                throw FixtureError(description: "invalid hex at offset \(index)")
            }
            bytes.append(byte)
        }
        self.init(bytes)
    }

    /// These bytes as lowercase hex.
    public var hex: String {
        map { byte in
            let digits = String(byte, radix: 16)
            if digits.count == 1 {
                return "0" + digits
            }
            return digits
        }
        .joined()
    }
}
