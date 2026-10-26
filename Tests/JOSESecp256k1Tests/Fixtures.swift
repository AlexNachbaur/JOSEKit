#if canImport(P256K)
    import Foundation
    import TestSupport

    // Fixtures here are written by `interop/secp256k1/generate-fixtures.mjs`.

    struct KeysFixture: Decodable {
        struct Key: Decodable {
            let publicJwk: String
            let privateJwk: String
            /// The uncompressed point, hex.
            let x963: String
            let thumbprints: [String: String]
        }
        let keys: [Key]
    }

    struct SignaturesFixture: Decodable {
        struct Case: Decodable {
            struct Verdict: Decodable {
                let accepted: Bool
            }
            let name: String
            let jwk: String
            let token: String
            /// The payload, hex.
            let payload: String
            let openssl: Verdict
        }
        let cases: [Case]
    }

    struct ParsingFixture: Decodable {
        struct Case: Decodable {
            struct Verdict: Decodable {
                let accepted: Bool
            }
            /// `public` or `private`: whether OpenSSL was asked for a public or a private key.
            let type: String
            let name: String
            let json: String
            let openssl: Verdict
        }
        let cases: [Case]
    }
#endif
