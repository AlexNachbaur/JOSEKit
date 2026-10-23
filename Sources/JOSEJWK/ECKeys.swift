import Foundation
import JOSECore

/// An elliptic-curve public key, known to be a point on `Curve`.
public struct ECPublicKey<Curve: EllipticCurve>: Sendable, Hashable {
    /// `0x04 || x || y`.
    public let x963Representation: Data

    /// The `x` coordinate, exactly ``EllipticCurve/coordinateByteCount`` bytes.
    public var x: Data {
        x963Representation.dropFirst().prefix(Curve.coordinateByteCount)
    }

    /// The `y` coordinate, exactly ``EllipticCurve/coordinateByteCount`` bytes.
    public var y: Data {
        x963Representation.suffix(Curve.coordinateByteCount)
    }

    /// Reads an uncompressed X9.63 point.
    ///
    /// The leading byte is checked rather than skipped. A buffer of the right length that starts
    /// with anything but `0x04` is not an uncompressed point, and reading `x` and `y` out of it
    /// anyway would produce a well-formed JWK for a key nobody holds.
    public init(x963Representation: Data) throws(JWKError) {
        let expected = 1 + 2 * Curve.coordinateByteCount
        guard x963Representation.count == expected else {
            throw .x963WrongLength(curve: Curve.name, expected: expected, found: x963Representation.count)
        }
        // Rebased so that stored slices and the accessors above can assume a zero start index.
        let bytes = Data(x963Representation)
        guard bytes[0] == 0x04 else {
            throw .x963NotUncompressed(curve: Curve.name, marker: bytes[0])
        }
        guard Curve().isPointOnCurve(x963: bytes) else {
            throw .pointNotOnCurve(curve: Curve.name)
        }
        self.x963Representation = bytes
    }

    /// Builds a key from its coordinates, each of which must be the full size of the curve.
    public init(x: Data, y: Data) throws(JWKError) {
        guard x.count == Curve.coordinateByteCount else {
            throw .wrongByteCount(member: "x", curve: Curve.name, expected: Curve.coordinateByteCount, found: x.count)
        }
        guard y.count == Curve.coordinateByteCount else {
            throw .wrongByteCount(member: "y", curve: Curve.name, expected: Curve.coordinateByteCount, found: y.count)
        }
        try self.init(x963Representation: [0x04] + x + y)
    }
}

extension ECPublicKey where Curve: ECDSACurve {
    /// Wraps a CryptoKit (or swift-crypto) signing public key.
    public init(_ key: Curve.VerifyingKey) throws(JWKError) {
        try self.init(x963Representation: Curve().x963(of: key))
    }
}

/// An elliptic-curve private key held in memory.
///
/// Not `Codable`, `Equatable` or `Hashable`, and its description is redacted, so that it does
/// not end up in JSON, logs or a dictionary key by accident. To write one out, go through
/// ``PrivateJWK``.
public struct ECPrivateKey<Curve: EllipticCurve>: Sendable {
    /// The private scalar `d`, exactly ``EllipticCurve/coordinateByteCount`` bytes.
    public let rawRepresentation: Data
    public let publicKey: ECPublicKey<Curve>

    /// Generates a new key.
    public init() throws(JWKError) {
        try self.init(rawRepresentation: Curve().generatePrivateScalar())
    }

    public init(rawRepresentation: Data) throws(JWKError) {
        guard rawRepresentation.count == Curve.coordinateByteCount else {
            throw .wrongByteCount(
                member: "d",
                curve: Curve.name,
                expected: Curve.coordinateByteCount,
                found: rawRepresentation.count
            )
        }
        let scalar = Data(rawRepresentation)
        guard let publicPoint = Curve().publicKeyX963(privateScalar: scalar) else {
            throw .invalidPrivateKey(curve: Curve.name)
        }
        self.rawRepresentation = scalar
        self.publicKey = try ECPublicKey(x963Representation: publicPoint)
    }
}

extension ECPrivateKey where Curve: ECDSACurve {
    /// Wraps a CryptoKit (or swift-crypto) signing private key.
    public init(_ key: Curve.SigningKey) throws(JWKError) {
        try self.init(rawRepresentation: Curve().privateScalar(of: key))
    }
}

extension ECPrivateKey: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String {
        "ECPrivateKey<\(Curve.name)>(redacted)"
    }

    public var debugDescription: String {
        description
    }
}
