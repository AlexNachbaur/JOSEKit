import Foundation
import JOSECore
import Testing

@testable import JOSEJWK

@Suite("JWK thumbprints")
struct ThumbprintTests {
    @Test("thumbprints and thumbprint URIs match jose for SHA-256, SHA-384 and SHA-512")
    func matchesCounterpart() throws {
        let hashes: [(String, JWKThumbprint.HashAlgorithm)] = [
            ("sha256", .sha256), ("sha384", .sha384), ("sha512", .sha512),
        ]
        let fixture = try KeysFixture.load()
        for key in fixture.keys {
            let jwk = try JWK(json: try key.publicJSON())
            for (name, hash) in hashes {
                let thumbprint = try jwk.thumbprint(using: hash)
                #expect(thumbprint.base64URLEncoded == key.thumbprints[name], "\(key.curve) \(name)")
                #expect(thumbprint.uri == key.thumbprintUris[name], "\(key.curve) \(name) URI")
            }
            // SHA-256 is the default.
            #expect(try jwk.thumbprint().base64URLEncoded == key.thumbprints["sha256"])
        }
    }

    @Test("a private JWK has the thumbprint of its public key")
    func privateKeyThumbprint() throws {
        for key in try KeysFixture.load().keys {
            let privateJWK = try PrivateJWK(json: try key.privateJSON())
            #expect(try privateJWK.publicJWK.thumbprint().base64URLEncoded == key.thumbprints["sha256"])
        }
    }

    @Test("the canonical form has members in lexical order with no whitespace")
    func canonicalForm() throws {
        let key = (try ECPrivateKey<P256Curve>()).publicKey
        let x = String(base64URLEncoding: key.x)
        let y = String(base64URLEncoding: key.y)
        #expect(key.canonicalJSON == #"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#)

        let edwards = (try Ed25519PrivateKey()).publicKey
        let edwardsX = String(base64URLEncoding: edwards.rawRepresentation)
        #expect(edwards.canonicalJSON == #"{"crv":"Ed25519","kty":"OKP","x":"\#(edwardsX)"}"#)
    }

    @Test("different keys have different thumbprints, and different hashes give different lengths")
    func distinct() throws {
        let first = (try ECPrivateKey<P256Curve>()).publicKey
        let second = (try ECPrivateKey<P256Curve>()).publicKey
        #expect(first.thumbprint() != second.thumbprint())
        #expect(first.thumbprint() == first.thumbprint())
        #expect(first.thumbprint(using: .sha256).digest.count == 32)
        #expect(first.thumbprint(using: .sha384).digest.count == 48)
        #expect(first.thumbprint(using: .sha512).digest.count == 64)
        #expect(first.thumbprint().uri.hasPrefix("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"))
    }
}
