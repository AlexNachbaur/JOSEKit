import Foundation

@testable import JOSEJWK

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// The crypto library's own DER encoding of a raw signature, for comparison with JOSECore's.
struct PlatformDER {
    private init() {}

    static func matches<Curve: ECDSACurve>(_ curve: Curve.Type, raw: Data, der: Data) throws -> Bool {
        switch Curve.name {
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
            throw FixtureError(description: "no platform DER comparison for \(Curve.name)")
        }
    }
}
