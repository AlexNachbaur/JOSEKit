import Foundation
import Testing

struct FixtureError: Error, CustomStringConvertible {
    let description: String
}

extension Decodable {
    /// Loads a fixture written by `interop/jwk/generate-fixtures.mjs` or
    /// `interop/jwk/generate-pem-fixtures.mjs`.
    init(fixture name: String) throws {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") else {
            throw FixtureError(description: "fixture \(name).json is missing from the test bundle")
        }
        self = try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }
}

extension Data {
    init(hex: String) throws {
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

    var hex: String {
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

struct KeysFixture: Decodable {
    struct SignatureCase: Decodable {
        let message: String
        let signature: String
        let tamperedSignature: String
    }
    struct Key: Decodable {
        let curve: String
        let algorithms: [String]
        let publicJwk: [String: String]
        let privateJwk: [String: String]
        let rawPublicKey: String
        let thumbprints: [String: String]
        let thumbprintUris: [String: String]
        let signatures: [SignatureCase]

        func publicJSON() throws -> Data {
            try JSONEncoder().encode(publicJwk)
        }

        func privateJSON() throws -> Data {
            try JSONEncoder().encode(privateJwk)
        }
    }
    struct HMACCase: Decodable {
        let algorithm: String
        let jwk: [String: String]
        let key: String
        let message: String
        let tag: String
        let tamperedTag: String
    }
    struct RSASignatureCase: Decodable {
        let algorithm: String
        let message: String
        let signature: String
        let tamperedSignature: String
        let nonStandardSaltSignature: String?
    }
    struct OAEPCase: Decodable {
        let hash: String
        let plaintext: String
        let ciphertext: String
    }
    struct Agreement: Decodable {
        let curve: String
        let privateJwk: [String: String]
        let publicJwk: [String: String]
        let publicThumbprint: String
        let sharedSecret: String
    }
    struct RSAKey: Decodable {
        let oaep: [OAEPCase]
        let bitCount: Int
        let publicJwk: [String: String]
        let privateJwk: [String: String]
        let publicPkcs1: String
        let privatePkcs1: String
        let thumbprints: [String: String]
        let thumbprintUris: [String: String]
        let signatures: [RSASignatureCase]
    }
    let keys: [Key]
    let hmacs: [HMACCase]
    let rsaKeys: [RSAKey]
    let agreements: [Agreement]

    static func load() throws -> KeysFixture {
        try KeysFixture(fixture: "keys")
    }
}
