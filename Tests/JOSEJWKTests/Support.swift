import Foundation
import TestSupport
import Testing

// Fixtures here are written by `interop/jwk/generate-fixtures.mjs` and
// `interop/jwk/generate-pem-fixtures.mjs`.

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
        try KeysFixture(fixture: "keys", in: .module)
    }
}
