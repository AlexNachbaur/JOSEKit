import Foundation
import JOSECore

@testable import JOSEJWK

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

extension Signature {
    /// Whether the crypto library's own DER encoding of this raw signature is `der`, and its
    /// reading of `der` is this signature, for comparison with JOSECore's encoding.
    func matchesPlatformDER(_ der: Data, curve: String) throws -> Bool {
        let raw = rawRepresentation
        switch curve {
        case "P-256":
            let fromRaw = try P256.Signing.ECDSASignature(rawRepresentation: raw)
            let fromDER = try P256.Signing.ECDSASignature(derRepresentation: der)
            return fromRaw.derRepresentation == der && fromDER.rawRepresentation == raw
        case "P-384":
            let fromRaw = try P384.Signing.ECDSASignature(rawRepresentation: raw)
            let fromDER = try P384.Signing.ECDSASignature(derRepresentation: der)
            return fromRaw.derRepresentation == der && fromDER.rawRepresentation == raw
        case "P-521":
            let fromRaw = try P521.Signing.ECDSASignature(rawRepresentation: raw)
            let fromDER = try P521.Signing.ECDSASignature(derRepresentation: der)
            return fromRaw.derRepresentation == der && fromDER.rawRepresentation == raw
        default:
            throw FixtureError(description: "no platform DER comparison for \(curve)")
        }
    }
}
