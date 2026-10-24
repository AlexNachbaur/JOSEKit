#if canImport(P256K)
    import Foundation
    import P256K

    // Temporary: checks that P256K builds and links. Removed before commit.
    func probe() throws -> Data {
        let key = try P256K.Signing.PrivateKey(format: .uncompressed)
        let signature = try key.signature(for: Data("x".utf8))
        _ = key.publicKey.isValidSignature(signature, for: Data("x".utf8))
        return key.publicKey.dataRepresentation + signature.compactRepresentation
    }
#endif
