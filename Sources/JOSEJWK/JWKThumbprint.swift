import Foundation
import JOSECore

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif

/// A JWK thumbprint (RFC 7638): a hash over the key's required members in a canonical form.
public struct JWKThumbprint: Sendable, Hashable {
    /// The hash function. Raw values are the names RFC 9278 uses in thumbprint URIs.
    public enum HashAlgorithm: String, Sendable {
        case sha256 = "sha-256"
        case sha384 = "sha-384"
        case sha512 = "sha-512"
    }

    public let hashAlgorithm: HashAlgorithm
    public let digest: Data

    /// The thumbprint as it is normally exchanged and compared.
    public var base64URLEncoded: String {
        Base64URL.encode(digest)
    }

    /// The thumbprint as a URI (RFC 9278).
    public var uri: String {
        "urn:ietf:params:oauth:jwk-thumbprint:\(hashAlgorithm.rawValue):\(base64URLEncoded)"
    }

    init(canonicalJSON: String, hashAlgorithm: HashAlgorithm) {
        let input = Data(canonicalJSON.utf8)
        self.hashAlgorithm = hashAlgorithm
        switch hashAlgorithm {
        case .sha256:
            digest = Data(SHA256.hash(data: input))
        case .sha384:
            digest = Data(SHA384.hash(data: input))
        case .sha512:
            digest = Data(SHA512.hash(data: input))
        }
    }
}

// The hash input for each key type is written out member by member, in the lexical order
// RFC 7638 §3.2 requires, rather than produced by sorting a dictionary. Adding a key type later
// therefore cannot change the thumbprint of a key that is already registered somewhere. Values go
// through the JSON string escaper rather than being interpolated, so a value containing `","`
// cannot make two different keys canonicalise to the same text.

extension ECPublicKey {
    var canonicalJSON: String {
        "{\"crv\":" + JSONStringEscaper.quoted(Curve.name)
            + ",\"kty\":\"EC\",\"x\":" + JSONStringEscaper.quoted(Base64URL.encode(x))
            + ",\"y\":" + JSONStringEscaper.quoted(Base64URL.encode(y))
            + "}"
    }

    public func thumbprint(using hashAlgorithm: JWKThumbprint.HashAlgorithm = .sha256) -> JWKThumbprint {
        JWKThumbprint(canonicalJSON: canonicalJSON, hashAlgorithm: hashAlgorithm)
    }
}

extension Ed25519PublicKey {
    var canonicalJSON: String {
        "{\"crv\":" + JSONStringEscaper.quoted(Self.curveName)
            + ",\"kty\":\"OKP\",\"x\":" + JSONStringEscaper.quoted(Base64URL.encode(rawRepresentation))
            + "}"
    }

    public func thumbprint(using hashAlgorithm: JWKThumbprint.HashAlgorithm = .sha256) -> JWKThumbprint {
        JWKThumbprint(canonicalJSON: canonicalJSON, hashAlgorithm: hashAlgorithm)
    }
}

extension JWK {
    /// The key's thumbprint. Metadata and additional parameters do not contribute.
    ///
    /// Throws for an unrecognised key type, because which members are "required" is defined per
    /// key type and is not known here.
    public func thumbprint(
        using hashAlgorithm: JWKThumbprint.HashAlgorithm = .sha256
    ) throws(JWKError) -> JWKThumbprint {
        switch key {
        case .p256(let key):
            return key.thumbprint(using: hashAlgorithm)
        case .p384(let key):
            return key.thumbprint(using: hashAlgorithm)
        case .p521(let key):
            return key.thumbprint(using: hashAlgorithm)
        case .ed25519(let key):
            return key.thumbprint(using: hashAlgorithm)
        case .unrecognized(let unrecognized):
            throw .thumbprintUnavailable(keyType: unrecognized.keyType)
        }
    }
}
