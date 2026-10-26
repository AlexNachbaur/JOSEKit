import Foundation
import JOSECore

/// A public key of a type ``JWK/Key`` does not list, such as an EC key on a curve another module
/// adds. Carried by ``JWK/Key/external(_:)``.
public protocol ExternalPublicKey: Sendable {
    /// The `kty` value.
    var keyType: String { get }
    /// The members that define the key, other than `kty`.
    var jwkMembers: [String: JSONValue] { get }
    /// The key type and curve, for error messages.
    var keyDescription: String { get }

    func thumbprint(using hashAlgorithm: JWKThumbprint.HashAlgorithm) -> JWKThumbprint
}

/// A private key of a type ``PrivateJWK/Key`` does not list. Carried by
/// ``PrivateJWK/Key/external(_:)``.
public protocol ExternalPrivateKey: Sendable {
    associatedtype PublicKey: ExternalPublicKey

    var publicKey: PublicKey { get }
    /// The private members, such as `d`. Only ``PrivateJWK/jsonRepresentation()`` writes them.
    var privateJWKMembers: [String: JSONValue] { get }
}

/// A key type that parsing can be told about, so that a JWK of that type is read as
/// ``JWK/Key/external(_:)`` rather than ``JWK/Key/unrecognized(_:)``. Passed as `keyTypes` to
/// ``JWK/init(json:keyTypes:)``, ``PrivateJWK/init(json:keyTypes:)`` and
/// ``JWKSet/init(json:keyTypes:)``.
public protocol ExternalKeyType: Sendable {
    /// The public key `members` describe, or `nil` if they describe a key of another type.
    func publicKey(from members: [String: JSONValue]) throws(JWKError) -> (any ExternalPublicKey)?
    /// The private key `members` describe, or `nil` if they describe a key of another type.
    func privateKey(from members: [String: JSONValue]) throws(JWKError) -> (any ExternalPrivateKey)?
}

/// An elliptic curve added outside JOSEJWK. Its keys are ``ECPublicKey`` and ``ECPrivateKey``, as
/// for the listed curves, and a JWK carries them as ``JWK/Key/external(_:)``.
public protocol ExternalCurve: EllipticCurve {}

extension ECPublicKey: ExternalPublicKey where Curve: ExternalCurve {
    public var keyType: String {
        "EC"
    }

    public var jwkMembers: [String: JSONValue] {
        var members = JWKMembers(values: [:])
        members.setECPublicKey(self)
        members.values["kty"] = nil
        return members.values
    }

    public var keyDescription: String {
        "EC \(Curve.name)"
    }
}

extension ECPrivateKey: ExternalPrivateKey where Curve: ExternalCurve {
    public var privateJWKMembers: [String: JSONValue] {
        ["d": .string(String(base64URLEncoding: rawRepresentation))]
    }
}

/// EC keys on `Curve`, for `keyTypes`.
public struct ECKeyType<Curve: ExternalCurve>: ExternalKeyType {
    public init() {}

    public func publicKey(from members: [String: JSONValue]) throws(JWKError) -> (any ExternalPublicKey)? {
        let key: ECPublicKey<Curve>? = try JWKMembers(values: members).ecPublicKey()
        return key
    }

    public func privateKey(from members: [String: JSONValue]) throws(JWKError) -> (any ExternalPrivateKey)? {
        let members = JWKMembers(values: members)
        guard try members.isEC(on: Curve.self) else {
            return nil
        }
        let key: ECPrivateKey<Curve> = try PrivateJWK.ecPrivateKey(members, keyType: "EC")
        return key
    }
}

extension JWKMembers {
    func isEC<Curve: EllipticCurve>(on curve: Curve.Type) throws(JWKError) -> Bool {
        guard try optionalString("kty") == "EC" else {
            return false
        }
        return try optionalString("crv") == Curve.name
    }

    /// The members as an EC public key on `Curve`, or `nil` if they describe another key.
    func ecPublicKey<Curve: EllipticCurve>() throws(JWKError) -> ECPublicKey<Curve>? {
        guard try isEC(on: Curve.self) else {
            return nil
        }
        return try JWK.ecPublicKey(self, keyType: "EC")
    }
}
